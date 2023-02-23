package flag

import (
	"time"

	"github.com/spf13/cobra"

	"github.com/aquasecurity/trivy/pkg/utils"
)

var (
	ConfigFileFlag = Flag{
		Name:       "config",
		ConfigName: "config",
		Shorthand:  "c",
		Value:      "trivy.yaml",
		Usage:      "config path",
		Persistent: true,
	}
	ShowVersionFlag = Flag{
		Name:       "version",
		ConfigName: "version",
		Shorthand:  "v",
		Value:      false,
		Usage:      "show version",
		Persistent: true,
	}
	QuietFlag = Flag{
		Name:       "quiet",
		ConfigName: "quiet",
		Shorthand:  "q",
		Value:      false,
		Usage:      "suppress progress bar and log output",
		Persistent: true,
	}
	DebugFlag = Flag{
		Name:       "debug",
		ConfigName: "debug",
		Shorthand:  "d",
		Value:      false,
		Usage:      "debug mode",
		Persistent: true,
	}
	InsecureFlag = Flag{
		Name:       "insecure",
		ConfigName: "insecure",
		Value:      false,
		Usage:      "allow insecure server connections when using TLS",
		Persistent: true,
	}
	TimeoutFlag = Flag{
		Name:       "timeout",
		ConfigName: "timeout",
		Value:      time.Second * 300, // 5 mins
		Usage:      "timeout",
		Persistent: true,
	}
	CacheDirFlag = Flag{
		Name:       "cache-dir",
		ConfigName: "cache.dir",
		Value:      utils.DefaultCacheDir(),
		Usage:      "cache directory",
		Persistent: true,
	}
	GenerateDefaultConfigFlag = Flag{
		Name:       "generate-default-config",
		ConfigName: "generate-default-config",
		Value:      false,
		Usage:      "write the default config to trivy-default.yaml",
		Persistent: true,
	}
	ModuleDirFlag = Flag{
		Name:       "module-dir",
		ConfigName: "module.dir",
		Value:      "",
		Usage:      "specify directory to the wasm modules that can be loaded for module scan",
		Persistent: true,
	}
	EnableModulesFlag = Flag{
		Name:       "enable-modules",
		ConfigName: "enable.modules",
		Value:      []string{},
		Usage:      "specify directory to the wasm modules that can be loaded for module scan",
		Persistent: true,
	}
)

// GlobalFlagGroup composes global flags
type GlobalFlagGroup struct {
	ConfigFile            *Flag
	ShowVersion           *Flag // spf13/cobra can't override the logic of version printing like VersionPrinter in urfave/cli. -v needs to be defined ourselves.
	Quiet                 *Flag
	Debug                 *Flag
	Insecure              *Flag
	Timeout               *Flag
	CacheDir              *Flag
	GenerateDefaultConfig *Flag
	ModuleDir             *Flag
	EnableModules         *Flag
}

// GlobalOptions defines flags and other configuration parameters for all the subcommands
type GlobalOptions struct {
	ConfigFile            string
	ShowVersion           bool
	Quiet                 bool
	Debug                 bool
	Insecure              bool
	Timeout               time.Duration
	CacheDir              string
	GenerateDefaultConfig bool
	ModuleDir             string
	EnableModules         []string
}

func NewGlobalFlagGroup() *GlobalFlagGroup {
	return &GlobalFlagGroup{
		ConfigFile:            &ConfigFileFlag,
		ShowVersion:           &ShowVersionFlag,
		Quiet:                 &QuietFlag,
		Debug:                 &DebugFlag,
		Insecure:              &InsecureFlag,
		Timeout:               &TimeoutFlag,
		CacheDir:              &CacheDirFlag,
		GenerateDefaultConfig: &GenerateDefaultConfigFlag,
		ModuleDir:             &ModuleDirFlag,
		EnableModules:         &EnableModulesFlag,
	}
}

func (f *GlobalFlagGroup) flags() []*Flag {
	return []*Flag{f.ConfigFile, f.ShowVersion, f.Quiet, f.Debug, f.Insecure, f.Timeout, f.CacheDir, f.GenerateDefaultConfig, f.ModuleDir, f.EnableModules}
}

func (f *GlobalFlagGroup) AddFlags(cmd *cobra.Command) {
	for _, flag := range f.flags() {
		addFlag(cmd, flag)
	}
}

func (f *GlobalFlagGroup) Bind(cmd *cobra.Command) error {
	for _, flag := range f.flags() {
		if err := bind(cmd, flag); err != nil {
			return err
		}
	}
	return nil
}

func (f *GlobalFlagGroup) ToOptions() GlobalOptions {
	return GlobalOptions{
		ConfigFile:            getString(f.ConfigFile),
		ShowVersion:           getBool(f.ShowVersion),
		Quiet:                 getBool(f.Quiet),
		Debug:                 getBool(f.Debug),
		Insecure:              getBool(f.Insecure),
		Timeout:               getDuration(f.Timeout),
		CacheDir:              getString(f.CacheDir),
		GenerateDefaultConfig: getBool(f.GenerateDefaultConfig),
		ModuleDir:             getString(f.ModuleDir),
		EnableModules:         getStringSlice(f.EnableModules),
	}
}
