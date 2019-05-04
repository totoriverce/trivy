package debian

import (
	"strings"

	"github.com/knqyf263/go-deb-version"
	"github.com/knqyf263/trivy/pkg/scanner/utils"

	"github.com/knqyf263/fanal/analyzer"
	"github.com/knqyf263/trivy/pkg/log"
	"github.com/knqyf263/trivy/pkg/types"
	"github.com/knqyf263/trivy/pkg/vulnsrc/debian"
	debianoval "github.com/knqyf263/trivy/pkg/vulnsrc/debian-oval"
)

type Scanner struct{}

func NewScanner() *Scanner {
	return &Scanner{}
}

func (s *Scanner) Detect(osVer string, pkgs []analyzer.Package) ([]types.Vulnerability, error) {
	if strings.Count(osVer, ".") > 0 {
		osVer = osVer[:strings.Index(osVer, ".")]
	}
	log.Logger.Debugf("debian version: %s", osVer)

	var vulns []types.Vulnerability
	for _, pkg := range pkgs {
		if pkg.Type != analyzer.TypeSource {
			continue
		}
		advisories, err := debianoval.Get(osVer, pkg.Name)
		if err != nil {
			return nil, err
		}

		installed := utils.FormatVersion(pkg)
		installedVersion, err := version.NewVersion(installed)
		if err != nil {
			log.Logger.Debugf("failed to parse Debian installed package version: %w", err)
			continue
		}

		for _, adv := range advisories {
			fixedVersion, err := version.NewVersion(adv.FixedVersion)
			if err != nil {
				log.Logger.Debugf("failed to parse Debian package version: %w", err)
				continue
			}

			if installedVersion.LessThan(fixedVersion) {
				vuln := types.Vulnerability{
					VulnerabilityID:  adv.VulnerabilityID,
					PkgName:          pkg.Name,
					InstalledVersion: installed,
					FixedVersion:     adv.FixedVersion,
				}
				vulns = append(vulns, vuln)
			}
		}
		advisories, err = debian.Get(osVer, pkg.Name)
		if err != nil {
			return nil, err
		}
		for _, adv := range advisories {
			vuln := types.Vulnerability{
				VulnerabilityID:  adv.VulnerabilityID,
				PkgName:          pkg.Name,
				InstalledVersion: installed,
			}
			vulns = append(vulns, vuln)
		}
	}
	return vulns, nil
}
