package flag

import (
	"fmt"
	"strings"

	"github.com/spf13/viper"

	"github.com/aquasecurity/trivy/pkg/log"
	"github.com/aquasecurity/trivy/pkg/types"
	"github.com/samber/lo"
	"github.com/spf13/cobra"
	"golang.org/x/exp/slices"
)

const (
	InputFlag          = "input"
	SkipDirsFlag       = "skip-dirs"
	SkipFilesFlag      = "skip-files"
	OfflineScanFlag    = "offline-scan"
	VulnTypeFlag       = "vuln-type"
	SecurityChecksFlag = "security-checks"
)

type ScanFlags struct {
	Input          *string
	SkipDirs       *[]string
	SkipFiles      *[]string
	OfflineScan    *bool
	VulnType       *string
	SecurityChecks *string
}

type ScanOptions struct {
	Target         string
	Input          string
	SkipDirs       []string
	SkipFiles      []string
	OfflineScan    bool
	VulnType       []string
	SecurityChecks []string
}

func NewDefaultScanFlags() *ScanFlags {
	return &ScanFlags{
		Input:          lo.ToPtr(""),
		SkipDirs:       lo.ToPtr([]string{}),
		SkipFiles:      lo.ToPtr([]string{}),
		OfflineScan:    lo.ToPtr(false),
		VulnType:       lo.ToPtr(strings.Join([]string{types.VulnTypeOS, types.VulnTypeLibrary}, ",")),
		SecurityChecks: lo.ToPtr(fmt.Sprintf("%s,%s", types.SecurityCheckVulnerability, types.SecurityCheckSecret)),
	}
}

func (f *ScanFlags) AddFlags(cmd *cobra.Command) {
	if f.Input != nil {
		cmd.Flags().String(InputFlag, *f.Input, "input file path instead of image name")
	}
	if f.SkipDirs != nil {
		cmd.Flags().StringSlice(SkipDirsFlag, *f.SkipDirs, "specify the directories where the traversal is skipped")
	}
	if f.SkipFiles != nil {
		cmd.Flags().StringSlice(SkipFilesFlag, *f.SkipFiles, "specify the file paths to skip traversal")
	}
	if f.OfflineScan != nil {
		cmd.Flags().Bool(OfflineScanFlag, *f.OfflineScan, "do not issue API requests to identify dependencies")
	}
	if f.VulnType != nil {
		cmd.Flags().String(VulnTypeFlag, *f.VulnType, "comma-separated list of vulnerability types (os,library)")
	}
	if f.SecurityChecks != nil {
		cmd.Flags().String(SecurityChecksFlag, *f.SecurityChecks, "comma-separated list of what security issues to detect (vuln,config,secret)")
	}
}

func (f *ScanFlags) ToOptions(args []string) (ScanOptions, error) {
	input := viper.GetString(InputFlag)
	var target string
	if input == "" {
		target = args[0]
	}

	return ScanOptions{
		Target:         target,
		Input:          input,
		SkipDirs:       viper.GetStringSlice(SkipDirsFlag),
		SkipFiles:      viper.GetStringSlice(SkipFilesFlag),
		OfflineScan:    viper.GetBool(OfflineScanFlag),
		VulnType:       parseVulnType(viper.GetString(VulnTypeFlag)),
		SecurityChecks: parseSecurityCheck(viper.GetString(SecurityChecksFlag)),
	}, nil
}

func parseVulnType(vulnType string) []string {
	if vulnType == "" {
		return nil
	}

	var vulnTypes []string
	for _, v := range strings.Split(vulnType, ",") {
		if !slices.Contains(types.VulnTypes, v) {
			log.Logger.Warnf("unknown vulnerability type: %s", v)
			continue
		}
		vulnTypes = append(vulnTypes, v)
	}
	return vulnTypes
}

func parseSecurityCheck(securityCheck string) []string {
	if securityCheck == "" {
		return nil
	}

	var securityChecks []string
	for _, v := range strings.Split(securityCheck, ",") {
		if !slices.Contains(types.SecurityChecks, v) {
			log.Logger.Warnf("unknown security check: %s", v)
			continue
		}
		securityChecks = append(securityChecks, v)
	}
	return securityChecks
}
