package report

import (
	"fmt"
	"io"

	"github.com/owenrumney/go-sarif/sarif"
)

// SarifWriter implements result Writer
type SarifWriter struct {
	Output  io.Writer
	Version string
}

type sarifData struct {
	vulnerabilityId string
	title           string
	description     string
	severity        string
	pkgName         string
	fixedVersion    string
	url             string
	resourceType    string
	target          string
}

func addSarifRule(run *sarif.Run, data *sarifData) {
	description := data.description
	if description == "" {
		description = data.title
	}

	helpText := fmt.Sprintf("Vulnerability %v\\n%v\\nSeverity: %v\\nPackage: %v\\nFixed Version: %v\\nLink: [%v](%v)",
		data.vulnerabilityId, description, data.severity, data.pkgName, data.fixedVersion, data.vulnerabilityId, data.url)
	helpMarkdown := fmt.Sprintf("**Vulnerability %v**\n%v\n| Severity | Package | Fixed Version | Link |\n| --- | --- | --- | --- |\n|%v|%v|%v|[%v](%v)|\n",
		data.vulnerabilityId, description, data.severity, data.pkgName, data.fixedVersion, data.vulnerabilityId, data.url)

	run.AddRule(data.vulnerabilityId).
		WithName(toSarifRuleName(data.resourceType)).
		WithDescription(data.vulnerabilityId).
		WithFullDescription(&sarif.MultiformatMessageString{Text: &description}).
		WithHelp(helpText).
		WithMarkdownHelp(helpMarkdown).
		WithProperties(sarif.Properties{
			"tags": []string{
				"vulnerability",
				data.severity,
			},
			"precision": "very-high",
		})
}

func addSarifResult(run *sarif.Run, data *sarifData) {
	message := sarif.NewTextMessage(data.description)
	region := sarif.NewSimpleRegion(1, 1)

	location := sarif.NewPhysicalLocation().
		WithArtifactLocation(sarif.NewSimpleArtifactLocation(data.target).WithUriBaseId("ROOTPATH")).
		WithRegion(region)

	ruleResult := run.AddResult(data.vulnerabilityId)
	ruleResult.WithMessage(message).
		WithLevel(toSarifErrorLevel(data.severity)).
		WithLocation(sarif.NewLocation().WithPhysicalLocation(location))
}

func (sw SarifWriter) Write(report Report) error {
	sarifReport, err := sarif.New(sarif.Version210)
	if err != nil {
		return err
	}
	run := sarif.NewRun("Trivy", "https://github.com/aquasecurity/trivy")
	run.Tool.Driver.WithVersion(sw.Version)

	sarifReport.AddRun(run)

	rules := map[string]bool{}

	for _, res := range report.Results {
		for _, vuln := range res.Vulnerabilities {
			data := &sarifData{
				vulnerabilityId: vuln.VulnerabilityID,
				title:           vuln.Title,
				description:     vuln.Description,
				severity:        vuln.Severity,
				pkgName:         vuln.PkgName,
				fixedVersion:    vuln.FixedVersion,
				url:             vuln.PrimaryURL,
				resourceType:    res.Type,
				target:          res.Target,
			}
			if !rules[vuln.VulnerabilityID] {
				addSarifRule(run, data)
				rules[vuln.VulnerabilityID] = true
			}
			addSarifResult(run, data)
		}
	}
	return sarifReport.PrettyWrite(sw.Output)
}
