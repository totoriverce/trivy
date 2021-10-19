//go:build integration
// +build integration

package integration

import (
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"

	appinfo "github.com/aquasecurity/trivy/pkg/app"
	"github.com/aquasecurity/trivy/pkg/commands"
)

func TestFilesystem(t *testing.T) {
	type args struct {
		securityChecks string
		severity       []string
		ignoreIDs      []string
		policyPaths    []string
		namespaces     []string
		input          string
	}
	tests := []struct {
		name   string
		args   args
		golden string
	}{
		{
			name: "nodejs",
			args: args{
				securityChecks: "vuln",
				input:          "testdata/fixtures/fs/nodejs",
			},
			golden: "testdata/nodejs.json.golden",
		},
		{
			name: "pip",
			args: args{
				securityChecks: "vuln",
				input:          "testdata/fixtures/fs/pip",
			},
			golden: "testdata/pip.json.golden",
		},
		{
			name: "pom",
			args: args{
				securityChecks: "vuln",
				input:          "testdata/fixtures/fs/pom",
			},
			golden: "testdata/pom.json.golden",
		},
		{
			name: "dockerfile",
			args: args{
				securityChecks: "config",
				policyPaths:    []string{"testdata/fixtures/fs/dockerfile/policy"},
				input:          "testdata/fixtures/fs/dockerfile",
			},
			golden: "testdata/dockerfile.json.golden",
		},
		{
			name: "dockerfile with rule exception",
			args: args{
				securityChecks: "config",
				policyPaths:    []string{"testdata/fixtures/fs/rule-exception/policy"},
				input:          "testdata/fixtures/fs/rule-exception",
			},
			golden: "testdata/dockerfile-rule-exception.json.golden",
		},
		{
			name: "dockerfile with namespace exception",
			args: args{
				securityChecks: "config",
				policyPaths:    []string{"testdata/fixtures/fs/namespace-exception/policy"},
				input:          "testdata/fixtures/fs/namespace-exception",
			},
			golden: "testdata/dockerfile-namespace-exception.json.golden",
		},
		{
			name: "dockerfile with custom policies",
			args: args{
				securityChecks: "config",
				policyPaths:    []string{"testdata/fixtures/fs/custom-policy/policy"},
				namespaces:     []string{"user"},
				input:          "testdata/fixtures/fs/custom-policy",
			},
			golden: "testdata/dockerfile-custom-policies.json.golden",
		},
	}

	// Set up testing DB
	cacheDir := initDB(t)

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			osArgs := []string{"trivy", "--cache-dir", cacheDir, "fs", "--skip-db-update", "--skip-policy-update",
				"--format", "json", "--offline-scan", "--security-checks", tt.args.securityChecks}

			if len(tt.args.policyPaths) != 0 {
				for _, policyPath := range tt.args.policyPaths {
					osArgs = append(osArgs, "--config-policy", policyPath)
				}
			}

			if len(tt.args.namespaces) != 0 {
				for _, namespace := range tt.args.namespaces {
					osArgs = append(osArgs, "--policy-namespaces", namespace)
				}
			}

			if len(tt.args.severity) != 0 {
				osArgs = append(osArgs, "--severity", strings.Join(tt.args.severity, ","))
			}

			if len(tt.args.ignoreIDs) != 0 {
				trivyIgnore := ".trivyignore"
				err := os.WriteFile(trivyIgnore, []byte(strings.Join(tt.args.ignoreIDs, "\n")), 0444)
				assert.NoError(t, err, "failed to write .trivyignore")
				defer os.Remove(trivyIgnore)
			}

			// Setup the output file
			outputFile := filepath.Join(t.TempDir(), "output.json")
			if *update {
				outputFile = tt.golden
			}

			osArgs = append(osArgs, "--output", outputFile)
			osArgs = append(osArgs, tt.args.input)

			// Setup CLI App
			appinfo.Version = "dev"
			app := commands.NewApp()
			app.Writer = io.Discard

			// Run "trivy fs"
			assert.Nil(t, app.Run(osArgs))

			// Compare want and got
			compareReports(t, tt.golden, outputFile)
		})
	}
}
