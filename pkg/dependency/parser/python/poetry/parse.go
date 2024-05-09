package poetry

import (
	"sort"
	"strings"

	"github.com/BurntSushi/toml"
	"golang.org/x/xerrors"

	version "github.com/aquasecurity/go-pep440-version"
	"github.com/aquasecurity/trivy/pkg/dependency"
	ftypes "github.com/aquasecurity/trivy/pkg/fanal/types"
	"github.com/aquasecurity/trivy/pkg/log"
	xio "github.com/aquasecurity/trivy/pkg/x/io"
)

type Lockfile struct {
	Packages []struct {
		Category       string                 `toml:"category"`
		Description    string                 `toml:"description"`
		Marker         string                 `toml:"marker,omitempty"`
		Name           string                 `toml:"name"`
		Optional       bool                   `toml:"optional"`
		PythonVersions string                 `toml:"python-versions"`
		Version        string                 `toml:"version"`
		Dependencies   map[string]interface{} `toml:"dependencies"`
		Metadata       interface{}
	} `toml:"package"`
}

type Parser struct {
	logger *log.Logger
}

func NewParser() *Parser {
	return &Parser{
		logger: log.WithPrefix("poetry"),
	}
}

func (p *Parser) Parse(r xio.ReadSeekerAt) ([]ftypes.Package, []ftypes.Dependency, error) {
	var lockfile Lockfile
	if _, err := toml.NewDecoder(r).Decode(&lockfile); err != nil {
		return nil, nil, xerrors.Errorf("failed to decode poetry.lock: %w", err)
	}

	// Keep all installed versions
	pkgVersions := p.parseVersions(lockfile)

	var pkgs []ftypes.Package
	var deps []ftypes.Dependency
	for _, pkg := range lockfile.Packages {
		if pkg.Category == "dev" {
			continue
		}

		pkgID := packageID(pkg.Name, pkg.Version)
		pkgs = append(pkgs, ftypes.Package{
			ID:      pkgID,
			Name:    pkg.Name,
			Version: pkg.Version,
		})

		dependsOn := p.parseDependencies(pkg.Dependencies, pkgVersions)
		if len(dependsOn) != 0 {
			deps = append(deps, ftypes.Dependency{
				ID:        pkgID,
				DependsOn: dependsOn,
			})
		}
	}
	return pkgs, deps, nil
}

// parseVersions stores all installed versions of packages for use in dependsOn
// as the dependencies of packages use version range.
func (p *Parser) parseVersions(lockfile Lockfile) map[string][]string {
	pkgVersions := make(map[string][]string)
	for _, pkg := range lockfile.Packages {
		if pkg.Category == "dev" {
			continue
		}
		if vers, ok := pkgVersions[pkg.Name]; ok {
			pkgVersions[pkg.Name] = append(vers, pkg.Version)
		} else {
			pkgVersions[pkg.Name] = []string{pkg.Version}
		}
	}
	return pkgVersions
}

func (p *Parser) parseDependencies(deps map[string]any, pkgVersions map[string][]string) []string {
	var dependsOn []string
	for name, versRange := range deps {
		if dep, err := p.parseDependency(name, versRange, pkgVersions); err != nil {
			p.logger.Debug("Failed to parse poetry dependency", log.Err(err))
		} else if dep != "" {
			dependsOn = append(dependsOn, dep)
		}
	}
	sort.Slice(dependsOn, func(i, j int) bool {
		return dependsOn[i] < dependsOn[j]
	})
	return dependsOn
}

func (p *Parser) parseDependency(name string, versRange any, pkgVersions map[string][]string) (string, error) {
	name = normalizePkgName(name)
	vers, ok := pkgVersions[name]
	if !ok {
		return "", xerrors.Errorf("no version found for %q", name)
	}

	for _, ver := range vers {
		var vRange string

		switch r := versRange.(type) {
		case string:
			vRange = r
		case map[string]interface{}:
			for k, v := range r {
				if k == "version" {
					vRange = v.(string)
				}
			}
		}

		if matched, err := matchVersion(ver, vRange); err != nil {
			return "", xerrors.Errorf("failed to match version for %s: %w", name, err)
		} else if matched {
			return packageID(name, ver), nil
		}
	}
	return "", xerrors.Errorf("no matched version found for %q", name)
}

// matchVersion checks if the package version satisfies the given constraint.
func matchVersion(currentVersion, constraint string) (bool, error) {
	v, err := version.Parse(currentVersion)
	if err != nil {
		return false, xerrors.Errorf("python version error (%s): %s", currentVersion, err)
	}

	c, err := version.NewSpecifiers(constraint, version.WithPreRelease(true))
	if err != nil {
		return false, xerrors.Errorf("python constraint error (%s): %s", constraint, err)
	}

	return c.Check(v), nil
}

func normalizePkgName(name string) string {
	// The package names don't use `_`, `.` or upper case, but dependency names can contain them.
	// We need to normalize those names.
	name = strings.ToLower(name)              // e.g. https://github.com/python-poetry/poetry/blob/c8945eb110aeda611cc6721565d7ad0c657d453a/poetry.lock#L819
	name = strings.ReplaceAll(name, "_", "-") // e.g. https://github.com/python-poetry/poetry/blob/c8945eb110aeda611cc6721565d7ad0c657d453a/poetry.lock#L50
	name = strings.ReplaceAll(name, ".", "-") // e.g. https://github.com/python-poetry/poetry/blob/c8945eb110aeda611cc6721565d7ad0c657d453a/poetry.lock#L816
	return name
}

func packageID(name, ver string) string {
	return dependency.ID(ftypes.Poetry, name, ver)
}
