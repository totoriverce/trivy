package spec

import (
	"fmt"
	"gopkg.in/yaml.v3"
	"os"
	"strings"

	sp "github.com/aquasecurity/defsec/pkg/spec"
	"github.com/aquasecurity/trivy/pkg/types"
	"golang.org/x/exp/maps"
	"golang.org/x/xerrors"
)

type Severity string

// ComplianceSpec represent the compliance specification
type ComplianceSpec struct {
	Spec Spec `yaml:"spec"`
}

type Spec struct {
	ID               string    `yaml:"id"`
	Title            string    `yaml:"title"`
	Description      string    `yaml:"description"`
	Version          string    `yaml:"version"`
	RelatedResources []string  `yaml:"relatedResources"`
	Controls         []Control `yaml:"controls"`
}

// Control represent the cps controls data and mapping checks
type Control struct {
	ID            string        `yaml:"id"`
	Name          string        `yaml:"name"`
	Description   string        `yaml:"description,omitempty"`
	Checks        []SpecCheck   `yaml:"checks"`
	Severity      Severity      `yaml:"severity"`
	DefaultStatus ControlStatus `yaml:"defaultStatus,omitempty"`
}

// SpecCheck represent the scanner who perform the control check
type SpecCheck struct {
	ID string `yaml:"id"`
}

// ControlCheck provides the result of conducting a single audit step.
type ControlCheck struct {
	ID          string   `yaml:"id"`
	Name        string   `yaml:"name"`
	Description string   `yaml:"description,omitempty"`
	PassTotal   int      `yaml:"passTotal"`
	FailTotal   int      `yaml:"failTotal"`
	Severity    Severity `yaml:"severity"`
}

type ControlStatus string

const (
	FailStatus ControlStatus = "FAIL"
	PassStatus ControlStatus = "PASS"
	WarnStatus ControlStatus = "WARN"
)

// SecurityChecks reads spec control and determines the scanners by check ID prefix
func (cs *ComplianceSpec) SecurityChecks() ([]types.SecurityCheck, error) {
	scannerTypes := map[types.SecurityCheck]struct{}{}
	for _, control := range cs.Spec.Controls {
		for _, check := range control.Checks {
			scannerType := securityCheckByCheckID(check.ID)
			if scannerType == types.SecurityCheckUnknown {
				return nil, xerrors.Errorf("unsupported check ID: %s", check.ID)
			}
			scannerTypes[scannerType] = struct{}{}
		}
	}
	return maps.Keys(scannerTypes), nil
}

// CheckIDs return list of compliance check IDs
func (cs *ComplianceSpec) CheckIDs() map[types.SecurityCheck][]string {
	checkIDsMap := map[types.SecurityCheck][]string{}
	for _, control := range cs.Spec.Controls {
		for _, check := range control.Checks {
			scannerType := securityCheckByCheckID(check.ID)
			checkIDsMap[scannerType] = append(checkIDsMap[scannerType], check.ID)
		}
	}
	return checkIDsMap
}

func securityCheckByCheckID(checkID string) types.SecurityCheck {
	checkID = strings.ToLower(checkID)
	switch {
	case strings.HasPrefix(checkID, "cve-") || strings.HasPrefix(checkID, "dla-"):
		return types.SecurityCheckVulnerability
	case strings.HasPrefix(checkID, "avd-"):
		return types.SecurityCheckConfig
	default:
		return types.SecurityCheckUnknown
	}
}

//GetComlianceSpec accepct compliance flag ane/path and return builtin or file system loaded spec
func GetComlianceSpec(specNameOrPath string) (*ComplianceSpec, error) {
	var cs string
	if strings.HasPrefix(specNameOrPath, "@") {
		buf, err := os.ReadFile(strings.TrimPrefix(specNameOrPath, "@"))
		if err != nil {
			return nil, fmt.Errorf("error retrieving complaince spec from path: %w", err)
		}
		cs = string(buf)
	} else {
		cs = sp.NewSpecLoader().GetSpecByName(specNameOrPath)
	}
	var complianceSpec ComplianceSpec
	err := yaml.Unmarshal([]byte(cs), &complianceSpec)
	if err != nil {
		return nil, fmt.Errorf("yaml unmarshal error: %w", err)
	}
	return &complianceSpec, nil
}
