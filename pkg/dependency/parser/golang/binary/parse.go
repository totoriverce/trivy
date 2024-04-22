package binary

import (
	"debug/buildinfo"
	"strings"

	"golang.org/x/xerrors"

	"github.com/aquasecurity/trivy/pkg/dependency/types"
	xio "github.com/aquasecurity/trivy/pkg/x/io"
)

var (
	ErrUnrecognizedExe = xerrors.New("unrecognized executable format")
	ErrNonGoBinary     = xerrors.New("non go binary")
)

// convertError detects buildinfo.errUnrecognizedFormat and convert to
// ErrUnrecognizedExe and convert buildinfo.errNotGoExe to ErrNonGoBinary
func convertError(err error) error {
	errText := err.Error()
	if strings.HasSuffix(errText, "unrecognized file format") {
		return ErrUnrecognizedExe
	}
	if strings.HasSuffix(errText, "not a Go executable") {
		return ErrNonGoBinary
	}

	return err
}

type Parser struct{}

func NewParser() types.Parser {
	return &Parser{}
}

// Parse scans file to try to report the Go and module versions.
func (p *Parser) Parse(r xio.ReadSeekerAt) ([]types.Library, []types.Dependency, error) {
	info, err := buildinfo.Read(r)
	if err != nil {
		return nil, nil, convertError(err)
	}

	libs := make([]types.Library, 0, len(info.Deps)+1)
	libs = append(libs, types.Library{
		Name:    "stdlib",
		Version: strings.TrimPrefix(info.GoVersion, "go"),
	})

	// Add main module
	libs = append(libs, types.Library{
		Name: info.Main.Path,
		// Only binaries installed with `go install` contain the correct version of the core module.
		// Other binaries use the `(devel)` version.
		// See https://github.com/aquasecurity/trivy/issues/1837#issuecomment-1832523477.
		Version: info.Main.Version,
	})

	for _, dep := range info.Deps {
		// binaries with old go version may incorrectly add module in Deps
		// In this case Path == "", Version == "Devel"
		// we need to skip this
		if dep.Path == "" {
			continue
		}

		mod := dep
		if dep.Replace != nil {
			mod = dep.Replace
		}

		libs = append(libs, types.Library{
			Name:    mod.Path,
			Version: mod.Version,
		})
	}

	return libs, nil, nil
}
