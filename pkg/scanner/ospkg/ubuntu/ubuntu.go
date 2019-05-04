package ubuntu

import (
	"github.com/knqyf263/go-deb-version"
	"github.com/knqyf263/trivy/pkg/scanner/utils"

	"github.com/knqyf263/fanal/analyzer"
	"github.com/knqyf263/trivy/pkg/log"
	"github.com/knqyf263/trivy/pkg/types"
	"github.com/knqyf263/trivy/pkg/vulnsrc/ubuntu"
)

type Scanner struct{}

func NewScanner() *Scanner {
	return &Scanner{}
}

func (s *Scanner) Detect(osVer string, pkgs []analyzer.Package) ([]types.Vulnerability, error) {
	log.Logger.Debugf("ubuntu version: %s", osVer)

	var vulns []types.Vulnerability
	for _, pkg := range pkgs {
		advisories, err := ubuntu.Get(osVer, pkg.Name)
		if err != nil {
			return nil, err
		}

		installed := utils.FormatVersion(pkg)
		installedVersion, err := version.NewVersion(installed)
		if err != nil {
			log.Logger.Debugf("failed to parse Ubuntu installed package version: %w", err)
			continue
		}

		for _, adv := range advisories {
			vuln := types.Vulnerability{
				VulnerabilityID:  adv.VulnerabilityID,
				PkgName:          pkg.Name,
				InstalledVersion: installed,
				FixedVersion:     adv.FixedVersion,
			}

			if adv.FixedVersion == "" {
				vulns = append(vulns, vuln)
				continue
			}

			fixedVersion, err := version.NewVersion(adv.FixedVersion)
			if err != nil {
				log.Logger.Debugf("failed to parse Ubuntu package version: %w", err)
				continue
			}

			if installedVersion.LessThan(fixedVersion) {
				vulns = append(vulns, vuln)
			}
		}
	}
	return vulns, nil
}
