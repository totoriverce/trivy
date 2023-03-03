package yarn

import (
	"context"
	"errors"
	"github.com/aquasecurity/trivy/pkg/detector/library/compare/npm"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"golang.org/x/exp/maps"
	"golang.org/x/xerrors"

	dio "github.com/aquasecurity/go-dep-parser/pkg/io"
	"github.com/aquasecurity/go-dep-parser/pkg/nodejs/packagejson"
	"github.com/aquasecurity/go-dep-parser/pkg/nodejs/yarn"
	godeptypes "github.com/aquasecurity/go-dep-parser/pkg/types"
	godeputils "github.com/aquasecurity/go-dep-parser/pkg/utils"
	"github.com/aquasecurity/trivy/pkg/fanal/analyzer"
	"github.com/aquasecurity/trivy/pkg/fanal/analyzer/language"
	"github.com/aquasecurity/trivy/pkg/fanal/types"
	"github.com/aquasecurity/trivy/pkg/log"
	"github.com/aquasecurity/trivy/pkg/utils/fsutils"
)

func init() {
	analyzer.RegisterPostAnalyzer(types.Yarn, newYarnAnalyzer)
}

const version = 1

type yarnAnalyzer struct {
	packageJsonParser packagejson.Parser
	lockParser        godeptypes.Parser
	comparer          npm.Comparer
}

func newYarnAnalyzer(_ analyzer.AnalyzerOptions) (analyzer.PostAnalyzer, error) {
	return &yarnAnalyzer{
		packageJsonParser: packagejson.Parser{},
		lockParser:        yarn.NewParser(),
		comparer:          npm.Comparer{},
	}, nil
}

func (a yarnAnalyzer) PostAnalyze(_ context.Context, input analyzer.PostAnalysisInput) (*analyzer.AnalysisResult, error) {
	var apps []types.Application

	required := func(path string, d fs.DirEntry) bool {
		return filepath.Base(path) == types.YarnLock
	}

	err := fsutils.WalkDir(input.FS, ".", required, func(path string, d fs.DirEntry, r dio.ReadSeekerAt) error {
		// Parse yarn.lock
		app, err := a.parseYarnLock(path, r)
		if err != nil {
			return xerrors.Errorf("parse error: %w", err)
		} else if app == nil {
			return nil
		}

		// Parse package.json alongside yarn.lock to remove dev dependencies
		if err = a.removeDevDependencies(input.FS, filepath.Dir(path), app); err != nil {
			return err
		}
		apps = append(apps, *app)

		return nil
	})
	if err != nil {
		return nil, xerrors.Errorf("yarn walk error: %w", err)
	}

	return &analyzer.AnalysisResult{
		Applications: apps,
	}, nil
}

func (a yarnAnalyzer) Required(filePath string, _ os.FileInfo) bool {
	fileName := filepath.Base(filePath)
	return fileName == types.YarnLock || fileName == types.NpmPkg
}

func (a yarnAnalyzer) Type() analyzer.Type {
	return analyzer.TypeYarn
}

func (a yarnAnalyzer) Version() int {
	return version
}

func (a yarnAnalyzer) parseYarnLock(path string, r dio.ReadSeekerAt) (*types.Application, error) {
	libs, deps, err := a.lockParser.Parse(r)
	if err != nil {
		return nil, xerrors.Errorf("unable to parse yarn.lock: %w", err)
	}
	return language.ToApplication(types.Yarn, path, "", libs, deps), nil
}

func (a yarnAnalyzer) removeDevDependencies(fsys fs.FS, path string, app *types.Application) error {
	libs := map[string]types.Package{}
	packageJsonPath := filepath.Join(path, types.NpmPkg)
	rootDeps, err := a.parsePackageJsonDependencies(fsys, packageJsonPath)
	if errors.Is(err, fs.ErrNotExist) {
		log.Logger.Debugf("Yarn: %s not found", path)
		return nil
	} else if err != nil {
		return xerrors.Errorf("unable to parse %s: %w", path, err)
	}
	queue := newQueue()
	//usedLibs := lo.SliceToMap(app.Libraries, func(pkg types.Package) (string, types.Package) {
	//	return pkg.ID, pkg
	//})
	usedLibs := map[string]map[string]types.Package{}
	for _, pkg := range app.Libraries {
		if versions, ok := usedLibs[pkg.Name]; ok {
			// add new version to map
			versions[pkg.Version] = pkg
			usedLibs[pkg.Name] = versions
			continue
		}
		usedLibs[pkg.Name] = map[string]types.Package{pkg.Version: pkg}
	}

	// add direct deps to the queue
	for n, v := range rootDeps {
		item := Item{
			name:     n,
			version:  v,
			indirect: false,
		}
		queue.enqueue(item)
	}

	for !queue.isEmpty() {
		dep := queue.dequeue()

		versions, ok := usedLibs[dep.name]
		if !ok {
			return xerrors.Errorf("unable to find versions for : %s", dep.name)
		}
		var pkg types.Package
		for v, p := range versions {
			match, err := a.comparer.MatchVersion(v, dep.version)
			if err != nil {
				return xerrors.Errorf("unable to match version for %s", dep.name)
			}
			if match {
				// overwrite Indirect value
				p.Indirect = dep.indirect
				pkg = p
				break
			}
		}

		if pkg.ID == "" {
			return xerrors.Errorf("unable to find %q", godeputils.PackageID(dep.name, dep.version))
		}

		// skip if we have already added this library
		if _, ok := libs[pkg.ID]; ok {
			continue
		}
		libs[pkg.ID] = pkg

		// add indirect deps to the queue
		for _, d := range pkg.DependsOn {
			s := strings.Split(d, "@")
			item := Item{
				name:     s[0],
				version:  s[1],
				indirect: true,
			}
			queue.enqueue(item)
		}
	}

	libSlice := maps.Values(libs)
	sort.Slice(libSlice, func(i, j int) bool {
		return libSlice[i].ID < libSlice[j].ID
	})

	// Save only prod libraries
	app.Libraries = libSlice
	return nil
}

func (a yarnAnalyzer) parsePackageJsonDependencies(fsys fs.FS, path string) (map[string]string, error) {
	// Parse package.json
	f, err := fsys.Open(path)
	if err != nil {
		return nil, xerrors.Errorf("file open error: %w", err)
	}
	defer func() { _ = f.Close() }()

	file, ok := f.(dio.ReadSeekCloserAt)
	if !ok {
		return nil, xerrors.Errorf("type assertion error: %w", err)
	}

	rootDeps, err := a.packageJsonParser.ParseProdDependencies(file)
	if err != nil {
		return nil, err
	}
	return rootDeps, nil
}
