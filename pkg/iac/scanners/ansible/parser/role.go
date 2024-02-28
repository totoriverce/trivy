package parser

import (
	"io/fs"

	"gopkg.in/yaml.v3"

	iacTypes "github.com/aquasecurity/trivy/pkg/iac/types"
)

// Role represent project role
type Role struct {
	name     string
	metadata iacTypes.Metadata
	play     *Play

	tasks    []*Task
	defaults Variables
	vars     Variables
	meta     RoleMeta

	directDeps []*Role
}

// compile returns the list of tasks for this role, which is created by first recursively
// compiling tasks for all direct dependencies and then adding tasks for this role.
// https://docs.ansible.com/ansible/latest/playbook_guide/playbooks_reuse_roles.html#using-role-dependencies
func (r *Role) compile() Tasks {
	var res Tasks

	for _, dep := range r.getDirectDeps() {
		res = append(res, dep.compile()...)
	}

	for _, task := range r.tasks {
		res = append(res, task.compile()...)
	}
	return res
}

func (m *Role) updateMetadata(fsys fs.FS, parent *iacTypes.Metadata, path string) {
	m.metadata = iacTypes.NewMetadata(
		iacTypes.NewRange(path, 0, 0, "", fsys), // TORO range
		"role",
	)
	m.metadata.SetParentPtr(parent)
}

func (r *Role) getDirectDeps() []*Role {
	return r.directDeps
}

type RoleMeta struct {
	metadata iacTypes.Metadata
	rng      Range
	inner    roleMetaInner
}

func (m *RoleMeta) updateMetadata(fsys fs.FS, parent *iacTypes.Metadata, path string) {
	m.metadata = iacTypes.NewMetadata(
		iacTypes.NewRange(path, m.rng.startLine, m.rng.endLine, "", fsys),
		"role-metadata",
	)
	m.metadata.SetParentPtr(parent)
}

func (m RoleMeta) dependencies() []*RoleDefinition {
	return m.inner.Dependencies
}

type roleMetaInner struct {
	Dependencies []*RoleDefinition `yaml:"dependencies"`
}

func (m *RoleMeta) UnmarshalYAML(node *yaml.Node) error {
	m.rng = rangeFromNode(node)
	return node.Decode(&m.inner)
}
