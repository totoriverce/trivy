package rego_test

import (
	"bytes"
	"embed"
	"io"
	"strings"
	"testing"
	"testing/fstest"

	checks "github.com/aquasecurity/trivy-checks"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/trivy/pkg/iac/rego"
	"github.com/aquasecurity/trivy/pkg/iac/scanners/options"
	"github.com/aquasecurity/trivy/pkg/iac/types"
)

//go:embed all:testdata/policies
var testEmbedFS embed.FS

//go:embed testdata/embedded
var embeddedChecksFS embed.FS

func Test_RegoScanning_WithSomeInvalidPolicies(t *testing.T) {
	t.Run("allow no errors", func(t *testing.T) {
		var debugBuf bytes.Buffer
		scanner := rego.NewScanner(
			types.SourceDockerfile,
			options.ScannerWithRegoErrorLimits(0),
			options.ScannerWithDebug(&debugBuf),
		)

		err := scanner.LoadPolicies(false, false, testEmbedFS, []string{"."}, nil)
		require.ErrorContains(t, err, `want (one of): ["Cmd" "EndLine" "Flags" "JSON" "Original" "Path" "Stage" "StartLine" "SubCmd" "Value"]`)
		assert.Contains(t, debugBuf.String(), "Error(s) occurred while loading checks")
	})

	t.Run("allow up to max 1 error", func(t *testing.T) {
		var debugBuf bytes.Buffer
		scanner := rego.NewScanner(
			types.SourceDockerfile,
			options.ScannerWithRegoErrorLimits(1),
			options.ScannerWithDebug(&debugBuf),
		)

		err := scanner.LoadPolicies(false, false, testEmbedFS, []string{"."}, nil)
		require.NoError(t, err)

		assert.Contains(t, debugBuf.String(), "Error occurred while parsing: testdata/policies/invalid.rego, testdata/policies/invalid.rego:7")
	})

	t.Run("schema does not exist", func(t *testing.T) {
		check := `# METADATA
# schemas:
# - input: schema["fooschema"]
package mypackage

deny {
    input.evil == "foo bar"
}`
		scanner := rego.NewScanner(types.SourceJSON)

		err := scanner.LoadPolicies(false, false, fstest.MapFS{}, []string{"."}, []io.Reader{strings.NewReader(check)})
		assert.ErrorContains(t, err, "could not find schema \"fooschema\"")
	})

	t.Run("schema is invalid", func(t *testing.T) {
		check := `# METADATA
# schemas:
# - input: schema["fooschema"]
package mypackage

deny {
    input.evil == "foo bar"
}`
		scanner := rego.NewScanner(types.SourceJSON)

		fsys := fstest.MapFS{
			"schemas/fooschema.json": &fstest.MapFile{
				Data: []byte("bad json"),
			},
		}

		err := scanner.LoadPolicies(false, false, fsys, []string{"."}, []io.Reader{strings.NewReader(check)})
		assert.ErrorContains(t, err, "could not parse schema \"fooschema\"")
	})

	t.Run("schema is not specified", func(t *testing.T) {
		check := `package mypackage

deny {
    input.evil == "foo bar"
}`
		scanner := rego.NewScanner(types.SourceJSON)
		err := scanner.LoadPolicies(false, false, fstest.MapFS{}, []string{"."}, []io.Reader{strings.NewReader(check)})
		assert.NoError(t, err)
	})

}

func Test_FallbackToEmbedded(t *testing.T) {
	tests := []struct {
		name        string
		files       map[string]*fstest.MapFile
		expectedErr string
	}{
		{
			name: "match by namespace",
			files: map[string]*fstest.MapFile{
				"policies/my-check2.rego": {
					Data: []byte(`# METADATA
# schemas:
# - input: schema["fooschema"]

package builtin.test

deny {
	input.evil == "foo bar"
}`,
					),
				},
			},
		},
		{
			name: "match by check ID",
			files: map[string]*fstest.MapFile{
				"policies/my-check2.rego": {
					Data: []byte(`# METADATA
# schemas:
# - input: schema["fooschema"]
# custom:
#   avd_id: test-001
package builtin.test2

deny {
	input.evil == "foo bar"
}`,
					),
				},
			},
		},
		{
			name: "bad embedded check",
			files: map[string]*fstest.MapFile{
				"policies/my-check2.rego": {
					Data: []byte(`# METADATA
# schemas:
# - input: schema["fooschema"]
package builtin.bad.test

deny {
  input.evil == "foo bar"
}`,
					),
				},
			},
			expectedErr: "testdata/embedded/bad-check.rego:8: rego_type_error: undefined ref",
		},
		{
			name: "with non existent function",
			files: map[string]*fstest.MapFile{
				"policies/my-check2.rego": {
					Data: []byte(`# METADATA
# schemas:
# - input: schema["fooschema"]
package builtin.test

deny {
  input.foo == fn.is_foo("foo")
}`,
					),
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			scanner := rego.NewScanner(
				types.SourceDockerfile,
				options.ScannerWithRegoErrorLimits(0),
				options.ScannerWithEmbeddedPolicies(false),
			)

			tt.files["schemas/fooschema.json"] = &fstest.MapFile{
				Data: []byte(`{
						"$schema": "http://json-schema.org/draft-07/schema#",
						"type": "object",
						"properties": {
							"foo": {
								"type": "string"
							}
						}
					}`),
			}

			fsys := fstest.MapFS(tt.files)
			checks.EmbeddedPolicyFileSystem = embeddedChecksFS
			err := scanner.LoadPolicies(false, false, fsys, []string{"."}, nil)

			if tt.expectedErr != "" {
				assert.ErrorContains(t, err, tt.expectedErr)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}
