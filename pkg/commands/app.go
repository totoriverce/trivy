package commands

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"golang.org/x/xerrors"

	awsScanner "github.com/aquasecurity/trivy-aws/pkg/scanner"
	awscommands "github.com/aquasecurity/trivy/pkg/cloud/aws/commands"
	"github.com/aquasecurity/trivy/pkg/commands/artifact"
	"github.com/aquasecurity/trivy/pkg/commands/convert"
	"github.com/aquasecurity/trivy/pkg/commands/server"
	"github.com/aquasecurity/trivy/pkg/fanal/analyzer"
	"github.com/aquasecurity/trivy/pkg/flag"
	k8scommands "github.com/aquasecurity/trivy/pkg/k8s/commands"
	"github.com/aquasecurity/trivy/pkg/log"
	"github.com/aquasecurity/trivy/pkg/module"
	"github.com/aquasecurity/trivy/pkg/plugin"
	"github.com/aquasecurity/trivy/pkg/types"
	"github.com/aquasecurity/trivy/pkg/version"
	xstrings "github.com/aquasecurity/trivy/pkg/x/strings"
)

const (
	usageTemplate = `Usage:{{if .Runnable}}
  {{.UseLine}}{{end}}{{if .HasAvailableSubCommands}}
  {{.CommandPath}} [command]{{end}}{{if gt (len .Aliases) 0}}

Aliases:
  {{.NameAndAliases}}{{end}}{{if .HasExample}}

Examples:
{{.Example}}{{end}}{{if .HasAvailableSubCommands}}

Available Commands:{{range .Commands}}{{if (or .IsAvailableCommand (eq .Name "help"))}}
  {{rpad .Name .NamePadding }} {{.Short}}{{end}}{{end}}{{end}}{{if .HasAvailableLocalFlags}}

%s

Global Flags:
{{.InheritedFlags.FlagUsages | trimTrailingWhitespaces}}{{end}}{{if .HasHelpSubCommands}}

Additional help topics:{{range .Commands}}{{if .IsAdditionalHelpTopicCommand}}
  {{rpad .CommandPath .CommandPathPadding}} {{.Short}}{{end}}{{end}}{{end}}{{if .HasAvailableSubCommands}}

Use "{{.CommandPath}} [command] --help" for more information about a command.{{end}}
`

	groupScanning   = "scanning"
	groupManagement = "management"
	groupUtility    = "utility"
	groupPlugin     = "plugin"
)

// NewApp is the factory method to return Trivy CLI
func NewApp() *cobra.Command {
	globalFlags := flag.NewGlobalFlagGroup()
	rootCmd := NewRootCommand(globalFlags)
	rootCmd.AddGroup(
		&cobra.Group{
			ID:    groupScanning,
			Title: "Scanning Commands",
		},
		&cobra.Group{
			ID:    groupManagement,
			Title: "Management Commands",
		},
		&cobra.Group{
			ID:    groupUtility,
			Title: "Utility Commands",
		},
	)
	rootCmd.SetCompletionCommandGroupID(groupUtility)
	rootCmd.SetHelpCommandGroupID(groupUtility)
	rootCmd.AddCommand(
		NewImageCommand(globalFlags),
		NewFilesystemCommand(globalFlags),
		NewRootfsCommand(globalFlags),
		NewRepositoryCommand(globalFlags),
		NewClientCommand(globalFlags),
		NewServerCommand(globalFlags),
		NewConfigCommand(globalFlags),
		NewConvertCommand(globalFlags),
		NewPluginCommand(),
		NewModuleCommand(globalFlags),
		NewKubernetesCommand(globalFlags),
		NewSBOMCommand(globalFlags),
		NewVersionCommand(globalFlags),
		NewAWSCommand(globalFlags),
		NewVMCommand(globalFlags),
	)

	if plugins := loadPluginCommands(); len(plugins) > 0 {
		rootCmd.AddGroup(&cobra.Group{
			ID:    groupPlugin,
			Title: "Plugin Commands",
		})
		rootCmd.AddCommand(plugins...)
	}

	return rootCmd
}

func loadPluginCommands() []*cobra.Command {
	ctx := context.Background()
	manager := plugin.NewManager()

	var commands []*cobra.Command
	plugins, err := manager.LoadAll(ctx)
	if err != nil {
		log.DebugContext(ctx, "No plugins loaded")
		return nil
	}
	for _, p := range plugins {
		p := p
		cmd := &cobra.Command{
			Use:     fmt.Sprintf("%s [flags]", p.Name),
			Short:   p.Summary,
			Long:    p.Description,
			GroupID: groupPlugin,
			RunE: func(cmd *cobra.Command, args []string) error {
				if err = p.Run(cmd.Context(), plugin.Options{Args: args}); err != nil {
					return xerrors.Errorf("plugin error: %w", err)
				}
				return nil
			},
			DisableFlagParsing: true,
			SilenceUsage:       true,
			SilenceErrors:      true,
		}
		commands = append(commands, cmd)
	}
	return commands
}

func initConfig(configFile string) error {
	// Read from config
	viper.SetConfigFile(configFile)
	viper.SetConfigType("yaml")
	if err := viper.ReadInConfig(); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			log.Debug("Config file not found", log.String("file_path", configFile))
			return nil
		}
		return xerrors.Errorf("config file %q loading error: %s", configFile, err)
	}
	log.Info("Loaded", log.String("file_path", configFile))
	return nil
}

func NewRootCommand(globalFlags *flag.GlobalFlagGroup) *cobra.Command {
	var versionFormat string
	cmd := &cobra.Command{
		Use:   "trivy [global flags] command [flags] target",
		Short: "Unified security scanner",
		Long:  "Scanner for vulnerabilities in container images, file systems, and Git repositories, as well as for configuration issues and hard-coded secrets",
		Example: `  # Scan a container image
  $ trivy image python:3.4-alpine

  # Scan a container image from a tar archive
  $ trivy image --input ruby-3.1.tar

  # Scan local filesystem
  $ trivy fs .

  # Run in server mode
  $ trivy server`,
		Args: cobra.NoArgs,
		PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
			// Set the Trivy version here so that we can override version printer.
			cmd.Version = version.AppVersion()

			// viper.BindPFlag cannot be called in init().
			// cf. https://github.com/spf13/cobra/issues/875
			//     https://github.com/spf13/viper/issues/233
			if err := globalFlags.Bind(cmd); err != nil {
				return xerrors.Errorf("flag bind error: %w", err)
			}

			// The config path is needed for config initialization.
			// It needs to be obtained before ToOptions().
			configPath := viper.GetString(flag.ConfigFileFlag.ConfigName)

			// Configure environment variables and config file
			// It cannot be called in init() because it must be called after viper.BindPFlags.
			if err := initConfig(configPath); err != nil {
				return err
			}

			globalOptions, err := globalFlags.ToOptions()
			if err != nil {
				return err
			}

			// Initialize logger
			log.InitLogger(globalOptions.Debug, globalOptions.Quiet)

			return nil
		},
		RunE: func(cmd *cobra.Command, args []string) error {
			globalOptions, err := globalFlags.ToOptions()
			if err != nil {
				return err
			}

			if globalOptions.ShowVersion {
				// Customize version output
				return showVersion(globalOptions.CacheDir, versionFormat, cmd.OutOrStdout())
			} else {
				return cmd.Help()
			}
		},
	}

	// Add version format flag, only json is supported
	cmd.Flags().StringVarP(&versionFormat, flag.FormatFlag.Name, flag.FormatFlag.Shorthand, "", "version format (json)")

	globalFlags.AddFlags(cmd)

	return cmd
}

func NewImageCommand(globalFlags *flag.GlobalFlagGroup) *cobra.Command {
	scanFlagGroup := flag.NewScanFlagGroup()
	scanFlagGroup.IncludeDevDeps = nil // disable '--include-dev-deps'

	reportFlagGroup := flag.NewReportFlagGroup()
	report := flag.ReportFormatFlag.Clone()
	report.Default = "summary"                                   // override the default value as the summary is preferred for the compliance report
	report.Usage = "specify a format for the compliance report." // "--report" works only with "--compliance"
	reportFlagGroup.ReportFormat = report

	compliance := flag.ComplianceFlag.Clone()
	compliance.Values = []string{types.ComplianceDockerCIS}
	reportFlagGroup.Compliance = compliance // override usage as the accepted values differ for each subcommand.

	misconfFlagGroup := flag.NewMisconfFlagGroup()
	misconfFlagGroup.CloudformationParamVars = nil // disable '--cf-params'
	misconfFlagGroup.TerraformTFVars = nil         // disable '--tf-vars'

	imageFlags := &flag.Flags{
		GlobalFlagGroup:        globalFlags,
		CacheFlagGroup:         flag.NewCacheFlagGroup(),
		DBFlagGroup:            flag.NewDBFlagGroup(),
		ImageFlagGroup:         flag.NewImageFlagGroup(), // container image specific
		LicenseFlagGroup:       flag.NewLicenseFlagGroup(),
		MisconfFlagGroup:       misconfFlagGroup,
		ModuleFlagGroup:        flag.NewModuleFlagGroup(),
		RemoteFlagGroup:        flag.NewClientFlags(), // for client/server mode
		RegistryFlagGroup:      flag.NewRegistryFlagGroup(),
		RegoFlagGroup:          flag.NewRegoFlagGroup(),
		ReportFlagGroup:        reportFlagGroup,
		ScanFlagGroup:          scanFlagGroup,
		SecretFlagGroup:        flag.NewSecretFlagGroup(),
		VulnerabilityFlagGroup: flag.NewVulnerabilityFlagGroup(),
	}

	cmd := &cobra.Command{
		Use:     "image [flags] IMAGE_NAME",
		Aliases: []string{"i"},
		GroupID: groupScanning,
		Short:   "Scan a container image",
		Example: `  # Scan a container image
  $ trivy image python:3.4-alpine

  # Scan a container image from a tar archive
  $ trivy image --input ruby-3.1.tar

  # Filter by severities
  $ trivy image --severity HIGH,CRITICAL alpine:3.15

  # Ignore unfixed/unpatched vulnerabilities
  $ trivy image --ignore-unfixed alpine:3.15

  # Scan a container image in client mode
  $ trivy image --server http://127.0.0.1:4954 alpine:latest

  # Generate json result
  $ trivy image --format json --output result.json alpine:3.15

  # Generate a report in the CycloneDX format
  $ trivy image --format cyclonedx --output result.cdx alpine:3.15`,

		// 'Args' cannot be used since it is called before PreRunE and viper is not configured yet.
		// cmd.Args     -> cannot validate args here
		// cmd.PreRunE  -> configure viper && validate args
		// cmd.RunE     -> run the command
		PreRunE: func(cmd *cobra.Command, args []string) error {
			// viper.BindPFlag cannot be called in init(), so it is called in PreRunE.
			// cf. https://github.com/spf13/cobra/issues/875
			//     https://github.com/spf13/viper/issues/233
			if err := imageFlags.Bind(cmd); err != nil {
				return xerrors.Errorf("flag bind error: %w", err)
			}
			return validateArgs(cmd, args)
		},
		RunE: func(cmd *cobra.Command, args []string) error {
			options, err := imageFlags.ToOptions(args)
			if err != nil {
				return xerrors.Errorf("flag error: %w", err)
			}
			return artifact.Run(cmd.Context(), options, artifact.TargetContainerImage)
		},
		SilenceErrors: true,
		SilenceUsage:  true,
	}

	imageFlags.AddFlags(cmd)
	cmd.SetFlagErrorFunc(flagErrorFunc)
	cmd.SetUsageTemplate(fmt.Sprintf(usageTemplate, imageFlags.Usages(cmd)))

	return cmd
}

func NewFilesystemCommand(globalFlags *flag.GlobalFlagGroup) *cobra.Command {
	reportFlagGroup := flag.NewReportFlagGroup()
	reportFormat := flag.ReportFormatFlag.Clone()
	reportFormat.Usage = "specify a compliance report format for the output" // @TODO: support --report summary for non compliance reports
	reportFlagGroup.ReportFormat = reportFormat
	reportFlagGroup.ExitOnEOL = nil // disable '--exit-on-eol'

	fsFlags := &flag.Flags{
		GlobalFlagGroup:        globalFlags,
		CacheFlagGroup:         flag.NewCacheFlagGroup(),
		DBFlagGroup:            flag.NewDBFlagGroup(),
		LicenseFlagGroup:       flag.NewLicenseFlagGroup(),
		MisconfFlagGroup:       flag.NewMisconfFlagGroup(),
		ModuleFlagGroup:        flag.NewModuleFlagGroup(),
		RemoteFlagGroup:        flag.NewClientFlags(), // for client/server mode
		RegistryFlagGroup:      flag.NewRegistryFlagGroup(),
		RegoFlagGroup:          flag.NewRegoFlagGroup(),
		ReportFlagGroup:        reportFlagGroup,
		ScanFlagGroup:          flag.NewScanFlagGroup(),
		SecretFlagGroup:        flag.NewSecretFlagGroup(),
		VulnerabilityFlagGroup: flag.NewVulnerabilityFlagGroup(),
	}

	cmd := &cobra.Command{
		Use:     "filesystem [flags] PATH",
		Aliases: []string{"fs"},
		GroupID: groupScanning,
		Short:   "Scan local filesystem",
		Example: `  # Scan a local project including language-specific files
  $ trivy fs /path/to/your_project

  # Scan a single file
  $ trivy fs ./trivy-ci-test/Pipfile.lock`,
		PreRunE: func(cmd *cobra.Command, args []string) error {
			if err := fsFlags.Bind(cmd); err != nil {
				return xerrors.Errorf("flag bind error: %w", err)
			}
			return validateArgs(cmd, args)
		},
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := fsFlags.Bind(cmd); err != nil {
				return xerrors.Errorf("flag bind error: %w", err)
			}
			options, err := fsFlags.ToOptions(args)
			if err != nil {
				return xerrors.Errorf("flag error: %w", err)
			}
			return artifact.Run(cmd.Context(), options, artifact.TargetFilesystem)
		},
		SilenceErrors: true,
		SilenceUsage:  true,
	}

	cmd.SetFlagErrorFunc(flagErrorFunc)
	fsFlags.AddFlags(cmd)
	cmd.SetUsageTemplate(fmt.Sprintf(usageTemplate, fsFlags.Usages(cmd)))

	return cmd
}

func NewRootfsCommand(globalFlags *flag.GlobalFlagGroup) *cobra.Command {
	rootfsFlags := &flag.Flags{
		GlobalFlagGroup:        globalFlags,
		CacheFlagGroup:         flag.NewCacheFlagGroup(),
		DBFlagGroup:            flag.NewDBFlagGroup(),
		LicenseFlagGroup:       flag.NewLicenseFlagGroup(),
		MisconfFlagGroup:       flag.NewMisconfFlagGroup(),
		ModuleFlagGroup:        flag.NewModuleFlagGroup(),
		RemoteFlagGroup:        flag.NewClientFlags(), // for client/server mode
		RegistryFlagGroup:      flag.NewRegistryFlagGroup(),
		RegoFlagGroup:          flag.NewRegoFlagGroup(),
		ReportFlagGroup:        flag.NewReportFlagGroup(),
		ScanFlagGroup:          flag.NewScanFlagGroup(),
		SecretFlagGroup:        flag.NewSecretFlagGroup(),
		VulnerabilityFlagGroup: flag.NewVulnerabilityFlagGroup(),
	}
	rootfsFlags.ReportFlagGroup.ReportFormat = nil // TODO: support --report summary
	rootfsFlags.ReportFlagGroup.Compliance = nil   // disable '--compliance'
	rootfsFlags.ReportFlagGroup.ReportFormat = nil // disable '--report'
	rootfsFlags.ScanFlagGroup.IncludeDevDeps = nil // disable '--include-dev-deps'

	cmd := &cobra.Command{
		Use:     "rootfs [flags] ROOTDIR",
		Short:   "Scan rootfs",
		GroupID: groupScanning,
		Example: `  # Scan unpacked filesystem
  $ docker export $(docker create alpine:3.10.2) | tar -C /tmp/rootfs -xvf -
  $ trivy rootfs /tmp/rootfs

  # Scan from inside a container
  $ docker run --rm -it alpine:3.11
  / # curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh | sh -s -- -b /usr/local/bin
  / # trivy rootfs /`,
		PreRunE: func(cmd *cobra.Command, args []string) error {
			if err := rootfsFlags.Bind(cmd); err != nil {
				return xerrors.Errorf("flag bind error: %w", err)
			}
			return validateArgs(cmd, args)
		},
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := rootfsFlags.Bind(cmd); err != nil {
				return xerrors.Errorf("flag bind error: %w", err)
			}
			options, err := rootfsFlags.ToOptions(args)
			if err != nil {
				return xerrors.Errorf("flag error: %w", err)
			}
			return artifact.Run(cmd.Context(), options, artifact.TargetRootfs)
		},
		SilenceErrors: true,
		SilenceUsage:  true,
	}
	cmd.SetFlagErrorFunc(flagErrorFunc)
	rootfsFlags.AddFlags(cmd)
	cmd.SetUsageTemplate(fmt.Sprintf(usageTemplate, rootfsFlags.Usages(cmd)))

	return cmd
}

func NewRepositoryCommand(globalFlags *flag.GlobalFlagGroup) *cobra.Command {
	repoFlags := &flag.Flags{
		GlobalFlagGroup:        globalFlags,
		CacheFlagGroup:         flag.NewCacheFlagGroup(),
		DBFlagGroup:            flag.NewDBFlagGroup(),
		LicenseFlagGroup:       flag.NewLicenseFlagGroup(),
		MisconfFlagGroup:       flag.NewMisconfFlagGroup(),
		ModuleFlagGroup:        flag.NewModuleFlagGroup(),
		RegistryFlagGroup:      flag.NewRegistryFlagGroup(),
		RegoFlagGroup:          flag.NewRegoFlagGroup(),
		RemoteFlagGroup:        flag.NewClientFlags(), // for client/server mode
		ReportFlagGroup:        flag.NewReportFlagGroup(),
		ScanFlagGroup:          flag.NewScanFlagGroup(),
		SecretFlagGroup:        flag.NewSecretFlagGroup(),
		VulnerabilityFlagGroup: flag.NewVulnerabilityFlagGroup(),
		RepoFlagGroup:          flag.NewRepoFlagGroup(),
	}
	repoFlags.ReportFlagGroup.ReportFormat = nil // TODO: support --report summary
	repoFlags.ReportFlagGroup.Compliance = nil   // disable '--compliance'
	repoFlags.ReportFlagGroup.ExitOnEOL = nil    // disable '--exit-on-eol'

	cmd := &cobra.Command{
		Use:     "repository [flags] (REPO_PATH | REPO_URL)",
		Aliases: []string{"repo"},
		GroupID: groupScanning,
		Short:   "Scan a repository",
		Example: `  # Scan your remote git repository
  $ trivy repo https://github.com/knqyf263/trivy-ci-test
  # Scan your local git repository
  $ trivy repo /path/to/your/repository`,
		PreRunE: func(cmd *cobra.Command, args []string) error {
			if err := repoFlags.Bind(cmd); err != nil {
				return xerrors.Errorf("flag bind error: %w", err)
			}
			return validateArgs(cmd, args)
		},
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := repoFlags.Bind(cmd); err != nil {
				return xerrors.Errorf("flag bind error: %w", err)
			}
			options, err := repoFlags.ToOptions(args)
			if err != nil {
				return xerrors.Errorf("flag error: %w", err)
			}
			return artifact.Run(cmd.Context(), options, artifact.TargetRepository)
		},
		SilenceErrors: true,
		SilenceUsage:  true,
	}
	cmd.SetFlagErrorFunc(flagErrorFunc)
	repoFlags.AddFlags(cmd)
	cmd.SetUsageTemplate(fmt.Sprintf(usageTemplate, repoFlags.Usages(cmd)))

	return cmd
}

func NewConvertCommand(globalFlags *flag.GlobalFlagGroup) *cobra.Command {
	convertFlags := &flag.Flags{
		GlobalFlagGroup: globalFlags,
		ScanFlagGroup:   &flag.ScanFlagGroup{},
		ReportFlagGroup: flag.NewReportFlagGroup(),
	}
	cmd := &cobra.Command{
		Use:     "convert [flags] RESULT_JSON",
		Aliases: []string{"conv"},
		GroupID: groupUtility,
		Short:   "Convert Trivy JSON report into a different format",
		Example: `  # report conversion
  $ trivy image --format json --output result.json --list-all-pkgs debian:11
  $ trivy convert --format cyclonedx --output result.cdx result.json
`,
		PreRunE: func(cmd *cobra.Command, args []string) error {
			if err := convertFlags.Bind(cmd); err != nil {
				return xerrors.Errorf("flag bind error: %w", err)
			}
			return validateArgs(cmd, args)
		},
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := convertFlags.Bind(cmd); err != nil {
				return xerrors.Errorf("flag bind error: %w", err)
			}
			opts, err := convertFlags.ToOptions(args)
			if err != nil {
				return xerrors.Errorf("flag error: %w", err)
			}

			return convert.Run(cmd.Context(), opts)
		},
		SilenceErrors: true,
		SilenceUsage:  true,
	}
	cmd.SetFlagErrorFunc(flagErrorFunc)
	convertFlags.AddFlags(cmd)
	cmd.SetUsageTemplate(fmt.Sprintf(usageTemplate, convertFlags.Usages(cmd)))

	return cmd
}

// NewClientCommand returns the 'client' subcommand that is deprecated
func NewClientCommand(globalFlags *flag.GlobalFlagGroup) *cobra.Command {
	remoteFlags := flag.NewClientFlags()
	remoteAddr := flag.Flag[string]{
		Name:       "remote",
		ConfigName: "server.addr",
		Shorthand:  "",
		Default:    "http://localhost:4954",
		Usage:      "server address",
	}
	remoteFlags.ServerAddr = &remoteAddr // disable '--server' and enable '--remote' instead.

	clientFlags := &flag.Flags{
		GlobalFlagGroup:        globalFlags,
		CacheFlagGroup:         flag.NewCacheFlagGroup(),
		DBFlagGroup:            flag.NewDBFlagGroup(),
		MisconfFlagGroup:       flag.NewMisconfFlagGroup(),
		RegistryFlagGroup:      flag.NewRegistryFlagGroup(),
		RegoFlagGroup:          flag.NewRegoFlagGroup(),
		RemoteFlagGroup:        remoteFlags,
		ReportFlagGroup:        flag.NewReportFlagGroup(),
		ScanFlagGroup:          flag.NewScanFlagGroup(),
		VulnerabilityFlagGroup: flag.NewVulnerabilityFlagGroup(),
	}

	cmd := &cobra.Command{
		Use:     "client [flags] IMAGE_NAME",
		Aliases: []string{"c"},
		Hidden:  true, // 'client' command is deprecated
		PreRunE: func(cmd *cobra.Command, args []string) error {
			if err := clientFlags.Bind(cmd); err != nil {
				return xerrors.Errorf("flag bind error: %w", err)
			}
			return validateArgs(cmd, args)
		},
		RunE: func(cmd *cobra.Command, args []string) error {
			log.Warn("'client' subcommand is deprecated now. See https://github.com/aquasecurity/trivy/discussions/2119")

			if err := clientFlags.Bind(cmd); err != nil {
				return xerrors.Errorf("flag bind error: %w", err)
			}
			options, err := clientFlags.ToOptions(args)
			if err != nil {
				return xerrors.Errorf("flag error: %w", err)
			}
			return artifact.Run(cmd.Context(), options, artifact.TargetContainerImage)
		},
		SilenceErrors: true,
		SilenceUsage:  true,
	}
	cmd.SetFlagErrorFunc(flagErrorFunc)
	clientFlags.AddFlags(cmd)
	cmd.SetUsageTemplate(fmt.Sprintf(usageTemplate, clientFlags.Usages(cmd)))

	return cmd
}

func NewServerCommand(globalFlags *flag.GlobalFlagGroup) *cobra.Command {
	serverFlags := &flag.Flags{
		GlobalFlagGroup:   globalFlags,
		CacheFlagGroup:    flag.NewCacheFlagGroup(),
		DBFlagGroup:       flag.NewDBFlagGroup(),
		ModuleFlagGroup:   flag.NewModuleFlagGroup(),
		RemoteFlagGroup:   flag.NewServerFlags(),
		RegistryFlagGroup: flag.NewRegistryFlagGroup(),
	}

	// java-db only works on client side.
	serverFlags.DBFlagGroup.DownloadJavaDBOnly = nil // disable '--download-java-db-only'
	serverFlags.DBFlagGroup.SkipJavaDBUpdate = nil   // disable '--skip-java-db-update'
	serverFlags.DBFlagGroup.JavaDBRepository = nil   // disable '--java-db-repository'

	cmd := &cobra.Command{
		Use:     "server [flags]",
		Aliases: []string{"s"},
		GroupID: groupUtility,
		Short:   "Server mode",
		Example: `  # Run a server
  $ trivy server

  # Listen on 0.0.0.0:10000
  $ trivy server --listen 0.0.0.0:10000
`,
		Args: cobra.ExactArgs(0),
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := serverFlags.Bind(cmd); err != nil {
				return xerrors.Errorf("flag bind error: %w", err)
			}
			options, err := serverFlags.ToOptions(args)
			if err != nil {
				return xerrors.Errorf("flag error: %w", err)
			}
			return server.Run(cmd.Context(), options)
		},
		SilenceErrors: true,
		SilenceUsage:  true,
	}
	cmd.SetFlagErrorFunc(flagErrorFunc)
	serverFlags.AddFlags(cmd)
	cmd.SetUsageTemplate(fmt.Sprintf(usageTemplate, serverFlags.Usages(cmd)))

	return cmd
}

func NewConfigCommand(globalFlags *flag.GlobalFlagGroup) *cobra.Command {
	reportFlagGroup := flag.NewReportFlagGroup()
	reportFlagGroup.DependencyTree = nil // disable '--dependency-tree'
	reportFlagGroup.ListAllPkgs = nil    // disable '--list-all-pkgs'
	reportFlagGroup.ExitOnEOL = nil      // disable '--exit-on-eol'
	reportFlagGroup.ShowSuppressed = nil // disable '--show-suppressed'
	reportFormat := flag.ReportFormatFlag.Clone()
	reportFormat.Usage = "specify a compliance report format for the output" // @TODO: support --report summary for non compliance reports
	reportFlagGroup.ReportFormat = reportFormat

	scanFlags := &flag.ScanFlagGroup{
		// Enable only '--skip-dirs' and '--skip-files' and disable other flags
		SkipDirs:     flag.SkipDirsFlag.Clone(),
		SkipFiles:    flag.SkipFilesFlag.Clone(),
		FilePatterns: flag.FilePatternsFlag.Clone(),
	}

	configFlags := &flag.Flags{
		GlobalFlagGroup:   globalFlags,
		CacheFlagGroup:    flag.NewCacheFlagGroup(),
		MisconfFlagGroup:  flag.NewMisconfFlagGroup(),
		ModuleFlagGroup:   flag.NewModuleFlagGroup(),
		RegistryFlagGroup: flag.NewRegistryFlagGroup(),
		RegoFlagGroup:     flag.NewRegoFlagGroup(),
		K8sFlagGroup: &flag.K8sFlagGroup{
			// disable unneeded flags
			K8sVersion: flag.K8sVersionFlag.Clone(),
		},
		ReportFlagGroup: reportFlagGroup,
		ScanFlagGroup:   scanFlags,
	}

	cmd := &cobra.Command{
		Use:     "config [flags] DIR",
		Aliases: []string{"conf"},
		GroupID: groupScanning,
		Short:   "Scan config files for misconfigurations",
		PreRunE: func(cmd *cobra.Command, args []string) error {
			if err := configFlags.Bind(cmd); err != nil {
				return xerrors.Errorf("flag bind error: %w", err)
			}
			return validateArgs(cmd, args)
		},
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := configFlags.Bind(cmd); err != nil {
				return xerrors.Errorf("flag bind error: %w", err)
			}
			options, err := configFlags.ToOptions(args)
			if err != nil {
				return xerrors.Errorf("flag error: %w", err)
			}

			// Disable OS and language analyzers
			options.DisabledAnalyzers = append(analyzer.TypeOSes, analyzer.TypeLanguages...)

			// Scan only for misconfigurations
			options.Scanners = types.Scanners{types.MisconfigScanner}

			return artifact.Run(cmd.Context(), options, artifact.TargetFilesystem)
		},
		SilenceErrors: true,
		SilenceUsage:  true,
	}
	cmd.SetFlagErrorFunc(flagErrorFunc)
	configFlags.AddFlags(cmd)
	cmd.SetUsageTemplate(fmt.Sprintf(usageTemplate, configFlags.Usages(cmd)))

	return cmd
}

func NewPluginCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:           "plugin subcommand",
		Aliases:       []string{"p"},
		GroupID:       groupManagement,
		Short:         "Manage plugins",
		SilenceErrors: true,
		SilenceUsage:  true,
	}
	cmd.AddCommand(
		&cobra.Command{
			Use:     "install NAME | URL | FILE_PATH",
			Aliases: []string{"i"},
			Short:   "Install a plugin",
			Example: `  # Install a plugin from the plugin index
  $ trivy plugin install referrer

  # Specify the version of the plugin to install
  $ trivy plugin install referrer@v0.3.0

  # Install a plugin from a URL
  $ trivy plugin install github.com/aquasecurity/trivy-plugin-referrer`,
			SilenceErrors:         true,
			SilenceUsage:          true,
			DisableFlagsInUseLine: true,
			Args:                  cobra.ExactArgs(1),
			RunE: func(cmd *cobra.Command, args []string) error {
				if _, err := plugin.Install(cmd.Context(), args[0], plugin.Options{}); err != nil {
					return xerrors.Errorf("plugin install error: %w", err)
				}
				return nil
			},
		},
		&cobra.Command{
			Use:                   "uninstall PLUGIN_NAME",
			Aliases:               []string{"u"},
			DisableFlagsInUseLine: true,
			Short:                 "Uninstall a plugin",
			SilenceErrors:         true,
			SilenceUsage:          true,
			Args:                  cobra.ExactArgs(1),
			RunE: func(cmd *cobra.Command, args []string) error {
				if err := plugin.Uninstall(cmd.Context(), args[0]); err != nil {
					return xerrors.Errorf("plugin uninstall error: %w", err)
				}
				return nil
			},
		},
		&cobra.Command{
			Use:                   "list",
			Aliases:               []string{"l"},
			DisableFlagsInUseLine: true,
			SilenceErrors:         true,
			SilenceUsage:          true,
			Short:                 "List installed plugin",
			Args:                  cobra.NoArgs,
			RunE: func(cmd *cobra.Command, args []string) error {
				if err := plugin.List(cmd.Context()); err != nil {
					return xerrors.Errorf("plugin list display error: %w", err)
				}
				return nil
			},
		},
		&cobra.Command{
			Use:                   "info PLUGIN_NAME",
			Short:                 "Show information about the specified plugin",
			DisableFlagsInUseLine: true,
			SilenceErrors:         true,
			SilenceUsage:          true,
			Args:                  cobra.ExactArgs(1),
			RunE: func(_ *cobra.Command, args []string) error {
				if err := plugin.Information(args[0]); err != nil {
					return xerrors.Errorf("plugin information display error: %w", err)
				}
				return nil
			},
		},
		&cobra.Command{
			Use:                   "run NAME | URL | FILE_PATH",
			Aliases:               []string{"r"},
			DisableFlagsInUseLine: true,
			SilenceErrors:         true,
			SilenceUsage:          true,
			Short:                 "Run a plugin on the fly",
			Args:                  cobra.MinimumNArgs(1),
			RunE: func(cmd *cobra.Command, args []string) error {
				return plugin.RunWithURL(cmd.Context(), args[0], plugin.Options{Args: args[1:]})
			},
		},
		&cobra.Command{
			Use:                   "update",
			Short:                 "Update the local copy of the plugin index",
			DisableFlagsInUseLine: true,
			SilenceErrors:         true,
			SilenceUsage:          true,
			Args:                  cobra.NoArgs,
			RunE: func(cmd *cobra.Command, _ []string) error {
				if err := plugin.Update(cmd.Context()); err != nil {
					return xerrors.Errorf("plugin update error: %w", err)
				}
				return nil
			},
		},
		&cobra.Command{
			Use:                   "search [KEYWORD]",
			DisableFlagsInUseLine: true,
			SilenceErrors:         true,
			SilenceUsage:          true,
			Short:                 "List Trivy plugins available on the plugin index and search among them",
			Args:                  cobra.MaximumNArgs(1),
			RunE: func(cmd *cobra.Command, args []string) error {
				var keyword string
				if len(args) == 1 {
					keyword = args[0]
				}
				return plugin.Search(cmd.Context(), keyword)
			},
		},
		&cobra.Command{
			Use:                   "upgrade [PLUGIN_NAMES]",
			Short:                 "Upgrade installed plugins to newer versions",
			DisableFlagsInUseLine: true,
			SilenceErrors:         true,
			SilenceUsage:          true,
			RunE: func(cmd *cobra.Command, args []string) error {
				if err := plugin.Upgrade(cmd.Context(), args); err != nil {
					return xerrors.Errorf("plugin upgrade error: %w", err)
				}
				return nil
			},
		},
	)
	cmd.SetFlagErrorFunc(flagErrorFunc)
	return cmd
}

func NewModuleCommand(globalFlags *flag.GlobalFlagGroup) *cobra.Command {
	moduleFlags := &flag.Flags{
		GlobalFlagGroup: globalFlags,
		ModuleFlagGroup: flag.NewModuleFlagGroup(),
	}

	cmd := &cobra.Command{
		Use:           "module subcommand",
		Aliases:       []string{"m"},
		GroupID:       groupManagement,
		Short:         "Manage modules",
		SilenceErrors: true,
		SilenceUsage:  true,
	}

	// Add subcommands
	cmd.AddCommand(
		&cobra.Command{
			Use:     "install [flags] REPOSITORY",
			Aliases: []string{"i"},
			Short:   "Install a module",
			Args:    cobra.ExactArgs(1),
			PreRunE: func(cmd *cobra.Command, args []string) error {
				if err := moduleFlags.Bind(cmd); err != nil {
					return xerrors.Errorf("flag bind error: %w", err)
				}
				return nil
			},
			RunE: func(cmd *cobra.Command, args []string) error {
				if len(args) != 1 {
					return cmd.Help()
				}

				repo := args[0]
				opts, err := moduleFlags.ToOptions(args)
				if err != nil {
					return xerrors.Errorf("flag error: %w", err)
				}
				return module.Install(cmd.Context(), opts.ModuleDir, repo, opts.Quiet, opts.RegistryOpts())
			},
		},
		&cobra.Command{
			Use:     "uninstall [flags] REPOSITORY",
			Aliases: []string{"u"},
			Short:   "Uninstall a module",
			Args:    cobra.ExactArgs(1),
			PreRunE: func(cmd *cobra.Command, args []string) error {
				if err := moduleFlags.Bind(cmd); err != nil {
					return xerrors.Errorf("flag bind error: %w", err)
				}
				return nil
			},
			RunE: func(cmd *cobra.Command, args []string) error {
				if len(args) != 1 {
					return cmd.Help()
				}

				repo := args[0]
				opts, err := moduleFlags.ToOptions(args)
				if err != nil {
					return xerrors.Errorf("flag error: %w", err)
				}
				return module.Uninstall(cmd.Context(), opts.ModuleDir, repo)
			},
		},
	)
	moduleFlags.AddFlags(cmd)
	cmd.SetFlagErrorFunc(flagErrorFunc)
	return cmd
}

func NewKubernetesCommand(globalFlags *flag.GlobalFlagGroup) *cobra.Command {
	scanFlags := flag.NewScanFlagGroup()
	scanners := flag.ScannersFlag.Clone()
	// overwrite the default scanners
	scanners.Values = xstrings.ToStringSlice(types.Scanners{
		types.VulnerabilityScanner,
		types.MisconfigScanner,
		types.SecretScanner,
		types.RBACScanner,
	})
	scanners.Default = scanners.Values
	scanFlags.Scanners = scanners
	scanFlags.IncludeDevDeps = nil // disable '--include-dev-deps'

	// required only SourceFlag
	imageFlags := &flag.ImageFlagGroup{ImageSources: flag.SourceFlag.Clone()}

	reportFlagGroup := flag.NewReportFlagGroup()
	compliance := flag.ComplianceFlag.Clone()
	compliance.Values = []string{
		types.ComplianceK8sNsa,
		types.ComplianceK8sCIS,
		types.ComplianceK8sPSSBaseline,
		types.ComplianceK8sPSSRestricted,
	}
	reportFlagGroup.Compliance = compliance // override usage as the accepted values differ for each subcommand.
	reportFlagGroup.ExitOnEOL = nil         // disable '--exit-on-eol'

	formatFlag := flag.FormatFlag.Clone()
	formatFlag.Values = xstrings.ToStringSlice([]types.Format{
		types.FormatTable,
		types.FormatJSON,
		types.FormatCycloneDX,
	})
	reportFlagGroup.Format = formatFlag

	misconfFlagGroup := flag.NewMisconfFlagGroup()
	misconfFlagGroup.CloudformationParamVars = nil // disable '--cf-params'
	misconfFlagGroup.TerraformTFVars = nil         // disable '--tf-vars'

	k8sFlags := &flag.Flags{
		GlobalFlagGroup:        globalFlags,
		CacheFlagGroup:         flag.NewCacheFlagGroup(),
		DBFlagGroup:            flag.NewDBFlagGroup(),
		ImageFlagGroup:         imageFlags,
		K8sFlagGroup:           flag.NewK8sFlagGroup(), // kubernetes-specific flags
		MisconfFlagGroup:       misconfFlagGroup,
		RegoFlagGroup:          flag.NewRegoFlagGroup(),
		ReportFlagGroup:        reportFlagGroup,
		ScanFlagGroup:          scanFlags,
		SecretFlagGroup:        flag.NewSecretFlagGroup(),
		RegistryFlagGroup:      flag.NewRegistryFlagGroup(),
		VulnerabilityFlagGroup: flag.NewVulnerabilityFlagGroup(),
	}
	cmd := &cobra.Command{
		Use:     "kubernetes [flags] [CONTEXT]",
		Aliases: []string{"k8s"},
		GroupID: groupScanning,
		Short:   "[EXPERIMENTAL] Scan kubernetes cluster",
		Long:    `Default context in kube configuration will be used unless specified`,
		Example: `  # cluster scanning
  $ trivy k8s --report summary

  # cluster scanning with specific namespace:
  $ trivy k8s --include-namespaces kube-system --report summary 

  # cluster with specific context:
  $ trivy k8s kind-kind --report summary 
  
  
`,
		PreRunE: func(cmd *cobra.Command, args []string) error {
			if err := k8sFlags.Bind(cmd); err != nil {
				return xerrors.Errorf("flag bind error: %w", err)
			}
			return validateArgs(cmd, args)
		},
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := k8sFlags.Bind(cmd); err != nil {
				return xerrors.Errorf("flag bind error: %w", err)
			}
			opts, err := k8sFlags.ToOptions(args)
			if err != nil {
				return xerrors.Errorf("flag error: %w", err)
			}

			return k8scommands.Run(cmd.Context(), args, opts)
		},
		SilenceErrors: true,
		SilenceUsage:  true,
	}
	cmd.SetFlagErrorFunc(flagErrorFunc)
	k8sFlags.AddFlags(cmd)
	cmd.SetUsageTemplate(fmt.Sprintf(usageTemplate, k8sFlags.Usages(cmd)))

	return cmd
}

func NewAWSCommand(globalFlags *flag.GlobalFlagGroup) *cobra.Command {
	reportFlagGroup := flag.NewReportFlagGroup()
	compliance := flag.ComplianceFlag
	compliance.Values = []string{
		types.ComplianceAWSCIS12,
		types.ComplianceAWSCIS14,
	}
	reportFlagGroup.Compliance = &compliance // override usage as the accepted values differ for each subcommand.
	reportFlagGroup.ExitOnEOL = nil          // disable '--exit-on-eol'
	reportFlagGroup.ShowSuppressed = nil     // disable '--show-suppressed'

	awsFlags := &flag.Flags{
		GlobalFlagGroup:  globalFlags,
		AWSFlagGroup:     flag.NewAWSFlagGroup(),
		CloudFlagGroup:   flag.NewCloudFlagGroup(),
		MisconfFlagGroup: flag.NewMisconfFlagGroup(),
		RegoFlagGroup:    flag.NewRegoFlagGroup(),
		ReportFlagGroup:  reportFlagGroup,
	}

	services := awsScanner.AllSupportedServices()
	sort.Strings(services)

	cmd := &cobra.Command{
		Use:     "aws [flags]",
		Aliases: []string{},
		GroupID: groupScanning,
		Args:    cobra.ExactArgs(0),
		Short:   "[EXPERIMENTAL] Scan AWS account",
		Long: fmt.Sprintf(`Scan an AWS account for misconfigurations. Trivy uses the same authentication methods as the AWS CLI. See https://docs.aws.amazon.com/cli/latest/userguide/cli-chap-configure.html

The following services are supported:

- %s
`, strings.Join(services, "\n- ")),
		Example: `  # basic scanning
  $ trivy aws --region us-east-1

  # limit scan to a single service:
  $ trivy aws --region us-east-1 --service s3

  # limit scan to multiple services:
  $ trivy aws --region us-east-1 --service s3 --service ec2

  # force refresh of cache for fresh results
  $ trivy aws --region us-east-1 --update-cache
`,
		PreRunE: func(cmd *cobra.Command, args []string) error {
			if err := awsFlags.Bind(cmd); err != nil {
				return xerrors.Errorf("flag bind error: %w", err)
			}
			return nil
		},
		RunE: func(cmd *cobra.Command, args []string) error {
			opts, err := awsFlags.ToOptions(args)
			if err != nil {
				return xerrors.Errorf("flag error: %w", err)
			}
			if opts.Timeout < time.Hour {
				opts.Timeout = time.Hour
				log.Info("Timeout is set to less than 1 hour - upgrading to 1 hour for this command.")
			}
			return awscommands.Run(cmd.Context(), opts)
		},
		SilenceErrors: true,
		SilenceUsage:  true,
	}
	cmd.SetFlagErrorFunc(flagErrorFunc)
	awsFlags.AddFlags(cmd)
	cmd.SetUsageTemplate(fmt.Sprintf(usageTemplate, awsFlags.Usages(cmd)))

	return cmd
}

func NewVMCommand(globalFlags *flag.GlobalFlagGroup) *cobra.Command {
	vmFlags := &flag.Flags{
		GlobalFlagGroup:        globalFlags,
		CacheFlagGroup:         flag.NewCacheFlagGroup(),
		DBFlagGroup:            flag.NewDBFlagGroup(),
		MisconfFlagGroup:       flag.NewMisconfFlagGroup(),
		ModuleFlagGroup:        flag.NewModuleFlagGroup(),
		RemoteFlagGroup:        flag.NewClientFlags(), // for client/server mode
		ReportFlagGroup:        flag.NewReportFlagGroup(),
		ScanFlagGroup:          flag.NewScanFlagGroup(),
		SecretFlagGroup:        flag.NewSecretFlagGroup(),
		VulnerabilityFlagGroup: flag.NewVulnerabilityFlagGroup(),
		AWSFlagGroup: &flag.AWSFlagGroup{
			Region: &flag.Flag[string]{
				Name:       "aws-region",
				ConfigName: "aws.region",
				Usage:      "AWS region to scan",
			},
		},
	}
	vmFlags.ReportFlagGroup.ReportFormat = nil             // disable '--report'
	vmFlags.ScanFlagGroup.IncludeDevDeps = nil             // disable '--include-dev-deps'
	vmFlags.MisconfFlagGroup.CloudformationParamVars = nil // disable '--cf-params'
	vmFlags.MisconfFlagGroup.TerraformTFVars = nil         // disable '--tf-vars'

	cmd := &cobra.Command{
		Use:     "vm [flags] VM_IMAGE",
		Aliases: []string{},
		GroupID: groupScanning,
		Short:   "[EXPERIMENTAL] Scan a virtual machine image",
		Example: `  # Scan your AWS AMI
  $ trivy vm --scanners vuln ami:${your_ami_id}

  # Scan your AWS EBS snapshot
  $ trivy vm ebs:${your_ebs_snapshot_id}
`,
		PreRunE: func(cmd *cobra.Command, args []string) error {
			if err := vmFlags.Bind(cmd); err != nil {
				return xerrors.Errorf("flag bind error: %w", err)
			}
			return validateArgs(cmd, args)
		},
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := vmFlags.Bind(cmd); err != nil {
				return xerrors.Errorf("flag bind error: %w", err)
			}
			options, err := vmFlags.ToOptions(args)
			if err != nil {
				return xerrors.Errorf("flag error: %w", err)
			}
			if options.Timeout < time.Minute*30 {
				options.Timeout = time.Minute * 30
				log.Info("Timeout is set to less than 30 min - upgrading to 30 min for this command.")
			}
			return artifact.Run(cmd.Context(), options, artifact.TargetVM)
		},
		SilenceErrors: true,
		SilenceUsage:  true,
	}
	cmd.SetFlagErrorFunc(flagErrorFunc)
	vmFlags.AddFlags(cmd)
	cmd.SetUsageTemplate(fmt.Sprintf(usageTemplate, vmFlags.Usages(cmd)))

	return cmd
}

func NewSBOMCommand(globalFlags *flag.GlobalFlagGroup) *cobra.Command {
	reportFlagGroup := flag.NewReportFlagGroup()
	reportFlagGroup.DependencyTree = nil // disable '--dependency-tree'
	reportFlagGroup.ReportFormat = nil   // TODO: support --report summary

	scanners := flag.ScannersFlag.Clone()
	scanners.Values = xstrings.ToStringSlice(types.Scanners{
		types.VulnerabilityScanner,
		types.LicenseScanner,
	})
	scanners.Default = xstrings.ToStringSlice(types.Scanners{
		types.VulnerabilityScanner,
	})
	scanFlagGroup := flag.NewScanFlagGroup()
	scanFlagGroup.Scanners = scanners  // allow only 'vuln' and 'license' options for '--scanners'
	scanFlagGroup.IncludeDevDeps = nil // disable '--include-dev-deps'
	scanFlagGroup.Parallel = nil       // disable '--parallel'

	licenseFlagGroup := flag.NewLicenseFlagGroup()
	// License full-scan and confidence-level are for file content only
	licenseFlagGroup.LicenseFull = nil
	licenseFlagGroup.LicenseConfidenceLevel = nil

	sbomFlags := &flag.Flags{
		GlobalFlagGroup:        globalFlags,
		CacheFlagGroup:         flag.NewCacheFlagGroup(),
		DBFlagGroup:            flag.NewDBFlagGroup(),
		RemoteFlagGroup:        flag.NewClientFlags(), // for client/server mode
		ReportFlagGroup:        reportFlagGroup,
		ScanFlagGroup:          scanFlagGroup,
		SBOMFlagGroup:          flag.NewSBOMFlagGroup(),
		VulnerabilityFlagGroup: flag.NewVulnerabilityFlagGroup(),
		LicenseFlagGroup:       licenseFlagGroup,
	}

	cmd := &cobra.Command{
		Use:     "sbom [flags] SBOM_PATH",
		Short:   "Scan SBOM for vulnerabilities and licenses",
		GroupID: groupScanning,
		Example: `  # Scan CycloneDX and show the result in tables
  $ trivy sbom /path/to/report.cdx

  # Scan CycloneDX-type attestation and show the result in tables
  $ trivy sbom /path/to/report.cdx.intoto.jsonl
`,
		PreRunE: func(cmd *cobra.Command, args []string) error {
			if err := sbomFlags.Bind(cmd); err != nil {
				return xerrors.Errorf("flag bind error: %w", err)
			}
			return validateArgs(cmd, args)
		},
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := sbomFlags.Bind(cmd); err != nil {
				return xerrors.Errorf("flag bind error: %w", err)
			}
			options, err := sbomFlags.ToOptions(args)
			if err != nil {
				return xerrors.Errorf("flag error: %w", err)
			}

			return artifact.Run(cmd.Context(), options, artifact.TargetSBOM)
		},
		SilenceErrors: true,
		SilenceUsage:  true,
	}
	cmd.SetFlagErrorFunc(flagErrorFunc)
	sbomFlags.AddFlags(cmd)
	cmd.SetUsageTemplate(fmt.Sprintf(usageTemplate, sbomFlags.Usages(cmd)))

	return cmd
}

func NewVersionCommand(globalFlags *flag.GlobalFlagGroup) *cobra.Command {
	var versionFormat string
	cmd := &cobra.Command{
		Use:     "version [flags]",
		Short:   "Print the version",
		GroupID: groupUtility,
		Args:    cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			options, err := globalFlags.ToOptions()
			if err != nil {
				return err
			}
			return showVersion(options.CacheDir, versionFormat, cmd.OutOrStdout())
		},
		SilenceErrors: true,
		SilenceUsage:  true,
	}
	cmd.SetFlagErrorFunc(flagErrorFunc)

	// Add version format flag, only json is supported
	cmd.Flags().StringVarP(&versionFormat, flag.FormatFlag.Name, flag.FormatFlag.Shorthand, "", "version format (json)")

	return cmd
}

func showVersion(cacheDir, outputFormat string, w io.Writer) error {
	versionInfo := version.NewVersionInfo(cacheDir)
	switch outputFormat {
	case "json":
		if err := json.NewEncoder(w).Encode(versionInfo); err != nil {
			return xerrors.Errorf("json encode error: %w", err)
		}
	default:
		fmt.Fprint(w, versionInfo.String())
	}
	return nil
}

func validateArgs(cmd *cobra.Command, args []string) error {
	// '--clear-cache', '--download-db-only', '--download-java-db-only', '--reset', '--reset-checks-bundle' and '--generate-default-config' don't conduct the subsequent scanning
	if viper.GetBool(flag.ClearCacheFlag.ConfigName) || viper.GetBool(flag.DownloadDBOnlyFlag.ConfigName) ||
		viper.GetBool(flag.ResetFlag.ConfigName) || viper.GetBool(flag.GenerateDefaultConfigFlag.ConfigName) ||
		viper.GetBool(flag.DownloadJavaDBOnlyFlag.ConfigName) || viper.GetBool(flag.ResetChecksBundleFlag.ConfigName) {
		return nil
	}

	if len(args) == 0 && viper.GetString(flag.InputFlag.ConfigName) == "" && cmd.Name() != "kubernetes" {
		if err := cmd.Help(); err != nil {
			return err
		}

		if f := cmd.Flags().Lookup(flag.InputFlag.ConfigName); f != nil {
			return xerrors.New(`Require at least 1 argument or --input option`)
		}
		return xerrors.New(`Require at least 1 argument`)
	} else if cmd.Name() != "kubernetes" && len(args) > 1 {
		if err := cmd.Help(); err != nil {
			return err
		}
		return xerrors.New(`multiple targets cannot be specified`)
	}

	return nil
}

// show help on using the command when an invalid flag is encountered
func flagErrorFunc(command *cobra.Command, err error) error {
	if err := command.Help(); err != nil {
		return err
	}
	command.Println() // add empty line after list of flags
	return err
}
