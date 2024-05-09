package plugin

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"

	"golang.org/x/xerrors"
	"gopkg.in/yaml.v3"

	"github.com/aquasecurity/trivy/pkg/downloader"
	"github.com/aquasecurity/trivy/pkg/log"
	"github.com/aquasecurity/trivy/pkg/types"
	"github.com/aquasecurity/trivy/pkg/utils/fsutils"
)

const (
	configFile = "plugin.yaml"
)

var (
	pluginsRelativeDir = filepath.Join(".trivy", "plugins")

	officialPlugins = map[string]string{
		"kubectl": "github.com/aquasecurity/trivy-plugin-kubectl",
		"aqua":    "github.com/aquasecurity/trivy-plugin-aqua",
	}
)

// Plugin represents a plugin.
type Plugin struct {
	Name        string     `yaml:"name"`
	Repository  string     `yaml:"repository"`
	Version     string     `yaml:"version"`
	Usage       string     `yaml:"usage"`
	Description string     `yaml:"description"`
	Platforms   []Platform `yaml:"platforms"`

	// runtime environment for testability
	GOOS   string `yaml:"_goos"`
	GOARCH string `yaml:"_goarch"`
}

// Platform represents where the execution file exists per platform.
type Platform struct {
	Selector *Selector
	URI      string
	Bin      string
}

// Selector represents the environment.
type Selector struct {
	OS   string
	Arch string
}

type RunOptions struct {
	Args  []string
	Stdin io.Reader
}

func (p Plugin) Cmd(ctx context.Context, opts RunOptions) (*exec.Cmd, error) {
	platform, err := p.selectPlatform()
	if err != nil {
		return nil, xerrors.Errorf("platform selection error: %w", err)
	}

	execFile := filepath.Join(dir(), p.Name, platform.Bin)

	cmd := exec.CommandContext(ctx, execFile, opts.Args...)
	cmd.Stdin = os.Stdin
	if opts.Stdin != nil {
		cmd.Stdin = opts.Stdin
	}
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.Env = os.Environ()

	return cmd, nil
}

type Wait func() error

// Start starts the plugin
//
// After a successful call to Start the Wait method must be called.
func (p Plugin) Start(ctx context.Context, opts RunOptions) (Wait, error) {
	cmd, err := p.Cmd(ctx, opts)
	if err != nil {
		return nil, xerrors.Errorf("cmd: %w", err)
	}

	if err = cmd.Start(); err != nil {
		return nil, xerrors.Errorf("plugin start: %w", err)
	}
	return cmd.Wait, nil
}

// Run runs the plugin
func (p Plugin) Run(ctx context.Context, opts RunOptions) error {
	cmd, err := p.Cmd(ctx, opts)
	if err != nil {
		return xerrors.Errorf("cmd: %w", err)
	}

	// If an error is found during the execution of the plugin, figure
	// out if the error was from not being able to execute the plugin or
	// an error set by the plugin itself.
	if err = cmd.Run(); err != nil {
		var execError *exec.ExitError
		if errors.As(err, &execError) {
			return &types.ExitError{
				Code: execError.ExitCode(),
			}
		}
		return xerrors.Errorf("plugin exec: %w", err)
	}
	return nil
}

func (p Plugin) selectPlatform() (Platform, error) {
	// These values are only filled in during unit tests.
	if p.GOOS == "" {
		p.GOOS = runtime.GOOS
	}
	if p.GOARCH == "" {
		p.GOARCH = runtime.GOARCH
	}

	for _, platform := range p.Platforms {
		if platform.Selector == nil {
			return platform, nil
		}

		selector := platform.Selector
		if (selector.OS == "" || p.GOOS == selector.OS) &&
			(selector.Arch == "" || p.GOARCH == selector.Arch) {
			log.Debug("Platform found",
				log.String("os", selector.OS), log.String("arch", selector.Arch))
			return platform, nil
		}
	}
	return Platform{}, xerrors.New("platform not found")
}

func (p Plugin) install(ctx context.Context, dst, pwd string) error {
	log.Debug("Installing the plugin...", log.String("path", dst))
	platform, err := p.selectPlatform()
	if err != nil {
		return xerrors.Errorf("platform selection error: %w", err)
	}

	log.Debug("Downloading the execution file...", log.String("uri", platform.URI))
	if err = downloader.Download(ctx, platform.URI, dst, pwd); err != nil {
		return xerrors.Errorf("unable to download the execution file (%s): %w", platform.URI, err)
	}
	return nil
}

func (p Plugin) dir() (string, error) {
	if p.Name == "" {
		return "", xerrors.Errorf("'name' is empty")
	}

	// e.g. ~/.trivy/plugins/kubectl
	return filepath.Join(dir(), p.Name), nil
}

// Install installs a plugin
func Install(ctx context.Context, url string, force bool) (Plugin, error) {
	// Replace short names with full qualified names
	// e.g. kubectl => github.com/aquasecurity/trivy-plugin-kubectl
	if v, ok := officialPlugins[url]; ok {
		url = v
	}

	if !force {
		// If the plugin is already installed, it skips installing the plugin.
		if p, installed := isInstalled(url); installed {
			return p, nil
		}
	}

	log.Info("Installing the plugin...", log.String("url", url))
	tempDir, err := downloader.DownloadToTempDir(ctx, url)
	if err != nil {
		return Plugin{}, xerrors.Errorf("download failed: %w", err)
	}
	defer os.RemoveAll(tempDir)

	log.Info("Loading the plugin metadata...")
	plugin, err := loadMetadata(tempDir)
	if err != nil {
		return Plugin{}, xerrors.Errorf("failed to load the plugin metadata: %w", err)
	}

	pluginDir, err := plugin.dir()
	if err != nil {
		return Plugin{}, xerrors.Errorf("failed to determine the plugin dir: %w", err)
	}

	if err = plugin.install(ctx, pluginDir, tempDir); err != nil {
		return Plugin{}, xerrors.Errorf("failed to install the plugin: %w", err)
	}

	// Copy plugin.yaml into the plugin dir
	if _, err = fsutils.CopyFile(filepath.Join(tempDir, configFile), filepath.Join(pluginDir, configFile)); err != nil {
		return Plugin{}, xerrors.Errorf("failed to copy plugin.yaml: %w", err)
	}

	return plugin, nil
}

// Uninstall installs the plugin
func Uninstall(name string) error {
	pluginDir := filepath.Join(dir(), name)
	return os.RemoveAll(pluginDir)
}

// Information gets the information about an installed plugin
func Information(name string) (string, error) {
	plugin, err := load(name)
	if err != nil {
		return "", xerrors.Errorf("plugin load error: %w", err)
	}

	return fmt.Sprintf(`
Plugin: %s
  Description: %s
  Version:     %s
  Usage:       %s
`, plugin.Name, plugin.Description, plugin.Version, plugin.Usage), nil
}

// List gets a list of all installed plugins
func List() (string, error) {
	if _, err := os.Stat(dir()); err != nil {
		if os.IsNotExist(err) {
			return "No Installed Plugins\n", nil
		}
		return "", xerrors.Errorf("stat error: %w", err)
	}
	plugins, err := LoadAll()
	if err != nil {
		return "", xerrors.Errorf("unable to load plugins: %w", err)
	}
	pluginList := []string{"Installed Plugins:"}
	for _, plugin := range plugins {
		pluginList = append(pluginList, fmt.Sprintf("  Name:    %s\n  Version: %s\n", plugin.Name, plugin.Version))
	}

	return strings.Join(pluginList, "\n"), nil
}

// Update updates an existing plugin
func Update(name string) error {
	plugin, err := load(name)
	if err != nil {
		return xerrors.Errorf("plugin load error: %w", err)
	}

	logger := log.With("name", name)
	logger.Info("Updating plugin...")
	updated, err := Install(nil, plugin.Repository, true)
	if err != nil {
		return xerrors.Errorf("unable to perform an update installation: %w", err)
	}

	if plugin.Version == updated.Version {
		logger.Info("The plugin is up-to-date", log.String("version", plugin.Version))
	} else {
		logger.Info("Plugin updated",
			log.String("from", plugin.Version), log.String("to", updated.Version))
	}
	return nil
}

// LoadAll loads all plugins
func LoadAll() ([]Plugin, error) {
	pluginsDir := dir()
	dirs, err := os.ReadDir(pluginsDir)
	if err != nil {
		return nil, xerrors.Errorf("failed to read %s: %w", pluginsDir, err)
	}

	var plugins []Plugin
	for _, d := range dirs {
		if !d.IsDir() {
			continue
		}
		plugin, err := loadMetadata(filepath.Join(pluginsDir, d.Name()))
		if err != nil {
			log.Warn("Plugin load error", log.Err(err))
			continue
		}
		plugins = append(plugins, plugin)
	}
	return plugins, nil
}

// Start starts the plugin
func Start(ctx context.Context, name string, opts RunOptions) (Wait, error) {
	plugin, err := load(name)
	if err != nil {
		return nil, xerrors.Errorf("plugin load error: %w", err)
	}

	wait, err := plugin.Start(ctx, opts)
	if err != nil {
		return nil, xerrors.Errorf("unable to run %s plugin: %w", plugin.Name, err)
	}
	return wait, nil
}

// RunWithURL runs the plugin with URL
func RunWithURL(ctx context.Context, url string, opts RunOptions) error {
	plugin, err := Install(ctx, url, false)
	if err != nil {
		return xerrors.Errorf("plugin install error: %w", err)
	}

	if err = plugin.Run(ctx, opts); err != nil {
		return xerrors.Errorf("unable to run %s plugin: %w", plugin.Name, err)
	}
	return nil
}

func IsPredefined(name string) bool {
	_, ok := officialPlugins[name]
	return ok
}

func load(name string) (Plugin, error) {
	pluginDir := filepath.Join(dir(), name)
	if _, err := os.Stat(pluginDir); err != nil {
		if os.IsNotExist(err) {
			return Plugin{}, xerrors.Errorf("could not find a plugin called '%s', did you install it?", name)
		}
		return Plugin{}, xerrors.Errorf("plugin stat error: %w", err)
	}

	plugin, err := loadMetadata(pluginDir)
	if err != nil {
		return Plugin{}, xerrors.Errorf("unable to load plugin metadata: %w", err)
	}

	return plugin, nil
}

func loadMetadata(dir string) (Plugin, error) {
	filePath := filepath.Join(dir, configFile)
	f, err := os.Open(filePath)
	if err != nil {
		return Plugin{}, xerrors.Errorf("file open error: %w", err)
	}
	defer f.Close()

	var plugin Plugin
	if err = yaml.NewDecoder(f).Decode(&plugin); err != nil {
		return Plugin{}, xerrors.Errorf("yaml decode error: %w", err)
	}

	return plugin, nil
}

func dir() string {
	return filepath.Join(fsutils.HomeDir(), pluginsRelativeDir)
}

func isInstalled(url string) (Plugin, bool) {
	installedPlugins, err := LoadAll()
	if err != nil {
		return Plugin{}, false
	}

	for _, plugin := range installedPlugins {
		if plugin.Repository == url {
			return plugin, true
		}
	}
	return Plugin{}, false
}
