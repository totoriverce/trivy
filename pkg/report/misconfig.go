package report

import (
	"bytes"
	"fmt"
	"strings"

	"github.com/aquasecurity/trivy/pkg/types"
	"github.com/liamg/clinch/terminal"
	"github.com/liamg/tml"
)

type misconfigRenderer struct {
	target             string
	misconfs           []types.DetectedMisconfiguration
	includeNonFailures bool
	w                  *bytes.Buffer
	width              int
}

func NewMisconfigRenderer(target string, misconfs []types.DetectedMisconfiguration, includeNonFailures bool) *misconfigRenderer {
	width, _ := terminal.Size()
	if width <= 0 {
		width = 40
	}
	return &misconfigRenderer{
		w:                  bytes.NewBuffer([]byte{}),
		target:             target,
		misconfs:           misconfs,
		includeNonFailures: includeNonFailures,
		width:              width,
	}
}

func (r *misconfigRenderer) Render() string {
	for _, m := range r.misconfs {
		r.renderSingle(m)
	}
	return r.w.String()
}

func (r *misconfigRenderer) printf(format string, args ...interface{}) {
	// nolint
	_ = tml.Fprintf(r.w, format, args...)
}

func (r *misconfigRenderer) printDoubleDivider() {
	r.printf("<dim>%s\n", strings.Repeat("═", r.width))
}

func (r *misconfigRenderer) printSingleDivider() {
	r.printf("<dim>%s\n", strings.Repeat("─", r.width))
}

func (r *misconfigRenderer) renderSingle(misconf types.DetectedMisconfiguration) {
	r.renderSummary(misconf)
	r.renderCode(misconf)
	r.printf("\n")
}

func (r *misconfigRenderer) renderSummary(misconf types.DetectedMisconfiguration) {

	r.printDoubleDivider()

	// show pass/fail/exception unless we are only showing failures
	if r.includeNonFailures {
		switch misconf.Status {
		case types.StatusPassed:
			r.printf("<green><bold>%s: ", misconf.Status)
		case types.StatusFailure:
			r.printf("<red><bold>%s: ", misconf.Status)
		case types.StatusException:
			r.printf("<yellow><bold>%s: ", misconf.Status)
		}
	}

	// severity
	switch misconf.Severity {
	case "CRITICAL":
		r.printf("<red><bold>%s: ", misconf.Severity)
	case "HIGH":
		r.printf("<red>%s: ", misconf.Severity)
	case "MEDIUM":
		r.printf("<yellow>%s: ", misconf.Severity)
	case "LOW":
		r.printf("%s: ", misconf.Severity)
	default:
		r.printf("<blue>%s: ", misconf.Severity)
	}

	// heading
	r.printf("%s\n", misconf.Message)
	r.printDoubleDivider()

	// description
	r.printf("<italic><dim>%s\n", misconf.Description)

	// show link if we have one
	if misconf.PrimaryURL != "" {
		r.printf("\n<italic><dim>See %s\n", misconf.PrimaryURL)
	}

	r.printSingleDivider()
}

func (r *misconfigRenderer) renderCode(misconf types.DetectedMisconfiguration) {
	// highlight code if we can...
	if lines := misconf.CauseMetadata.Code.Lines; len(lines) > 0 {

		var lineInfo string
		if misconf.CauseMetadata.StartLine > 0 {
			lineInfo = tml.Sprintf("<dim>:</dim><blue>%d", misconf.CauseMetadata.StartLine)
			if misconf.CauseMetadata.EndLine > misconf.CauseMetadata.StartLine {
				lineInfo = tml.Sprintf("%s<blue>-%d", lineInfo, misconf.CauseMetadata.EndLine)
			}
		}
		r.printf(" <blue>%s%s\n", r.target, lineInfo)
		r.printSingleDivider()
		for i, line := range lines {
			if line.Truncated {
				r.printf("<dim>%4s   ", strings.Repeat(".", len(fmt.Sprintf("%d", line.Number))))
			} else if line.IsCause {
				r.printf("<red>%4d ", line.Number)
				switch {
				case (line.FirstCause && line.LastCause) || len(lines) == 1:
					r.printf("<red>[ ")
				case line.FirstCause || i == 0:
					r.printf("<red>┌ ")
				case line.LastCause || i == len(lines)-1:
					r.printf("<red>└ ")
				default:
					r.printf("<red>│ ")
				}
			} else {
				r.printf("<dim><italic>%4d   ", line.Number)
			}
			r.printf("%s\n", line.Highlighted)
		}
		r.printSingleDivider()
	}
}
