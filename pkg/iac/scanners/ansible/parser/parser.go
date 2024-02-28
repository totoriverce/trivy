package parser

import (
	"fmt"
	"io/fs"
	"log"
	"os"
	"path"
	"path/filepath"
	"strings"

	"github.com/bmatcuk/doublestar/v4"
	"github.com/samber/lo"
	"gopkg.in/yaml.v3"

	iacTypes "github.com/aquasecurity/trivy/pkg/iac/types"
)

const ansibleCfgFile = "ansible.cfg"

type AnsibleProject struct {
	path string

	cfg AnsibleConfig
	// inventory Inventory
	mainPlaybook Playbook
	playbooks    []Playbook
}

func (p *AnsibleProject) Path() string {
	return p.path
}

// TODO(nikita): some tasks do not contain metadata
func (p *AnsibleProject) ListTasks() Tasks {
	var res Tasks
	if p.mainPlaybook != nil {
		res = append(res, p.mainPlaybook.Compile()...)
	} else {
		for _, playbook := range p.playbooks {
			res = append(res, playbook.Compile()...)
		}
	}
	return res
}

type AnsibleConfig struct{}

type Parser struct {
	fsys fs.FS
	root string

	// The cache key is the role name
	// The cache value is the path to the role definition directory
	roleCache map[string]string
}

func New(fsys fs.FS, root string) *Parser {
	return &Parser{
		fsys:      fsys,
		root:      root,
		roleCache: make(map[string]string),
	}
}

func ParseProjects(fsys fs.FS, dir string) ([]*AnsibleProject, error) {
	projectPaths, err := autoDetectProjects(fsys, dir)
	if err != nil {
		return nil, err
	}

	var projects []*AnsibleProject

	for _, projectPath := range projectPaths {
		parser := New(fsys, projectPath)
		project, err := parser.Parse()
		if err != nil {
			return nil, err
		}
		projects = append(projects, project)
	}
	return projects, nil
}

func (p *Parser) Parse(playbooks ...string) (*AnsibleProject, error) {
	project, err := p.initProject(p.root)
	if err != nil {
		return nil, err
	}

	if len(playbooks) == 0 {
		playbooks, err = p.resolvePlaybooksPaths(project)
		if err != nil {
			return nil, err
		}
	}

	if err := p.parsePlaybooks(project, playbooks); err != nil {
		return nil, err
	}
	return project, nil
}

func (p *Parser) initProject(root string) (*AnsibleProject, error) {
	cfg, err := p.readAnsibleConfig(root)
	if err != nil {
		return nil, fmt.Errorf("failed to read Ansible config: %w", err)
	}

	project := &AnsibleProject{
		path: root,
		cfg:  cfg,
	}

	return project, nil
}

func (p *Parser) parsePlaybooks(project *AnsibleProject, paths []string) error {
	for _, path := range paths {
		playbook, err := p.loadPlaybook(nil, path)
		if err != nil {
			return err
		}

		if playbook == nil {
			return nil
		}

		if isMainPlaybook(path) {
			project.mainPlaybook = playbook
		} else {
			project.playbooks = append(project.playbooks, playbook)
		}
	}
	return nil
}

func (p *Parser) loadPlaybook(sourceMetadata *iacTypes.Metadata, filePath string) (Playbook, error) {

	f, err := p.fsys.Open(filePath)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var playbook Playbook
	if err := yaml.NewDecoder(f).Decode(&playbook); err != nil {
		// not all YAML files are playbooks.
		log.Printf("Failed to decode playbook %q: %s", filePath, err)
		return nil, nil
	}
	for _, play := range playbook {
		play.updateMetadata(p.fsys, sourceMetadata, filePath)

		roles := make([]*Role, 0, len(play.roleDefinitions()))
		for _, roleDef := range play.roleDefinitions() {
			role, err := p.loadRole(&play.metadata, play, roleDef.name())
			if err != nil {
				return nil, fmt.Errorf("failed to load role %q: %w", roleDef.name(), err)
			}
			roles = append(roles, role)
		}
		play.roles = roles
	}
	return playbook, nil
}

type LoadRoleOptions struct {
	TasksFile    string
	DefaultsFile string
	VarsFile     string
	Public       *bool
}

func (o LoadRoleOptions) withDefaults() LoadRoleOptions {
	res := LoadRoleOptions{
		TasksFile:    "main",
		DefaultsFile: "main",
		VarsFile:     "main",
	}

	if o.TasksFile != "" {
		res.TasksFile = o.TasksFile
	}

	if o.DefaultsFile != "" {
		res.DefaultsFile = o.DefaultsFile
	}

	if o.VarsFile != "" {
		res.VarsFile = o.VarsFile
	}

	return res
}

func (p *Parser) loadRole(meta *iacTypes.Metadata, play *Play, roleName string) (*Role, error) {
	return p.loadRoleWithOptions(meta, play, roleName, LoadRoleOptions{})
}

func (p *Parser) loadRoleWithOptions(meta *iacTypes.Metadata, play *Play, roleName string, opt LoadRoleOptions) (*Role, error) {
	opt = opt.withDefaults()

	var rolePath string
	if val, exists := p.roleCache[roleName]; exists {
		rolePath = val
	} else if val, exists := p.resolveRolePath(roleName); exists {
		rolePath = val
	}

	if rolePath == "" {
		return nil, fmt.Errorf("role %q not found", roleName)
	}

	r := &Role{
		name: roleName,
		play: play,
	}
	r.updateMetadata(p.fsys, meta, rolePath)

	walkFn := func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}

		if d.IsDir() {
			return nil
		}

		dir, filename := filepath.Split(path)
		if !isYAMLFile(filename) {
			return nil
		}

		parts := strings.Split(dir, string(os.PathSeparator))
		parentFolder := parts[len(parts)-2]

		switch parentFolder {
		case "tasks":
			if cutExtension(filename) != opt.TasksFile {
				return nil
			}
			tasks, err := p.loadTasks(&r.metadata, r, path)
			if err != nil {
				return fmt.Errorf("failed to load tasks: %w", err)
			}
			r.tasks = tasks
		case "defaults":
			if cutExtension(filename) != opt.DefaultsFile {
				return nil
			}
			if err := p.decodeYAMLFile(path, &r.defaults); err != nil {
				return fmt.Errorf("failed to load defaults: %w", err)
			}
		case "vars":
			if cutExtension(filename) != opt.VarsFile {
				return nil
			}
			if err := p.decodeYAMLFile(path, &r.vars); err != nil {
				return fmt.Errorf("failed to load vars: %w", err)
			}
		case "meta":
			if cutExtension(filename) != "main" {
				return nil
			}
			meta, err := p.parseMetaFile(path, r)
			if err != nil {
				return fmt.Errorf("failed to load meta: %w", err)
			}
			r.meta = meta
		}
		return nil
	}
	if err := fs.WalkDir(p.fsys, rolePath, walkFn); err != nil {
		return nil, err
	}

	for _, dep := range r.meta.dependencies() {
		depRole, err := p.loadRole(&r.meta.metadata, r.play, dep.name())
		if err != nil {
			return nil, fmt.Errorf("failed to dependency %q of role %q: %w", dep.name(), r.name, err)
		}
		r.directDeps = append(r.directDeps, depRole)
	}

	p.roleCache[roleName] = rolePath

	return r, nil
}

func (p *Parser) parseMetaFile(filePath string, role *Role) (RoleMeta, error) {
	var meta RoleMeta
	if err := p.decodeYAMLFile(filePath, &meta); err != nil {
		return meta, err
	}
	meta.updateMetadata(p.fsys, &role.metadata, filePath)
	return meta, nil
}

func (p *Parser) resolveRolePath(name string) (string, bool) {
	paths := []string{filepath.Join(p.root, "roles", name)}
	if defaultRolesPath, exists := os.LookupEnv("DEFAULT_ROLES_PATH"); exists {
		paths = append(paths, defaultRolesPath)
	}

	for _, rolePath := range paths {
		if isPathExists(p.fsys, rolePath) {
			return rolePath, true
		}
	}

	return "", false
}

func (p *Parser) loadTasks(sourceMetadata *iacTypes.Metadata, role *Role, filePath string) (Tasks, error) {
	var tasks Tasks
	if err := p.decodeYAMLFile(filePath, &tasks); err != nil {
		return nil, fmt.Errorf("failed to decode tasks file %q: %w", filePath, err)
	}
	tasks = lo.Map(tasks, func(task *Task, _ int) *Task {
		task.updateMetadata(p.fsys, sourceMetadata, filePath)
		// task.role = role // TODO
		return task
	})
	return tasks, nil
}

func (p *Parser) decodeYAMLFile(filePath string, dst any) error {
	f, err := p.fsys.Open(filePath)
	if err != nil {
		return err
	}
	defer f.Close()
	return yaml.NewDecoder(f).Decode(dst)
}

func (p *Parser) readAnsibleConfig(projectPath string) (AnsibleConfig, error) {
	// TODO(simar): Implement ansible config setup
	return AnsibleConfig{}, nil
}

func (p *Parser) resolvePlaybooksPaths(project *AnsibleProject) ([]string, error) {
	entries, err := fs.ReadDir(p.fsys, project.path)
	if err != nil {
		return nil, err
	}

	var res []string

	for _, entry := range entries {
		if isYAMLFile(entry.Name()) {
			res = append(res, filepath.Join(project.path, entry.Name()))
		}
	}

	return res, nil
}

func autoDetectProjects(fsys fs.FS, root string) ([]string, error) {
	var res []string
	walkFn := func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}

		if !d.IsDir() {
			return nil
		}

		if !isAnsibleProject(fsys, path) {
			return nil
		}
		res = append(res, path)
		return fs.SkipDir
	}

	if err := fs.WalkDir(fsys, root, walkFn); err != nil {
		return nil, err
	}

	return res, nil
}

// TODO if there are no directories listed below, then find the playbook among yaml files
func isAnsibleProject(fsys fs.FS, filePath string) bool {
	requiredDirs := []string{
		ansibleCfgFile, "site.yml", "site.yaml", "group_vars", "host_vars", "inventory", "playbooks",
	}
	for _, filename := range requiredDirs {
		if isPathExists(fsys, filepath.Join(filePath, filename)) {
			return true
		}
	}

	if entries, err := doublestar.Glob(fsys, "**/roles/**/{tasks,defaults,vars}"); err == nil && len(entries) > 0 {
		return true
	}

	if entries, err := doublestar.Glob(fsys, "*.{.yml,yaml}"); err == nil && len(entries) > 0 {
		return true
	}

	return false
}

func isPathExists(fsys fs.FS, filePath string) bool {
	if filepath.IsAbs(filePath) {
		if _, err := os.Stat(filePath); err == nil {
			return true
		}
	}
	if _, err := fs.Stat(fsys, filePath); err == nil {
		return true
	}
	return false
}

func isYAMLFile(filePath string) bool {
	ext := filepath.Ext(filePath)
	return ext == ".yaml" || ext == ".yml"
}

func isMainPlaybook(filePath string) bool {
	return cutExtension(path.Base(filePath)) == "site"
}

func cutExtension(filePath string) string {
	ext := filepath.Ext(filePath)
	return filePath[0 : len(filePath)-len(ext)]
}
