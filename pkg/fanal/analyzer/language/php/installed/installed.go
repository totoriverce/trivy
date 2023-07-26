package installed

import (
	"context"
	"os"
	"path/filepath"

	"github.com/aquasecurity/go-dep-parser/pkg/php/composer"
	"github.com/aquasecurity/trivy/pkg/fanal/analyzer"
	"github.com/aquasecurity/trivy/pkg/fanal/analyzer/language"
	"github.com/aquasecurity/trivy/pkg/fanal/types"
)

func init() {
	analyzer.RegisterAnalyzer(&composerInstalledAnalyzer{})
}

const (
	version = 1
)

// composerInstalledAnalyzer analyzes 'installed.json'
type composerInstalledAnalyzer struct{}

func (a composerInstalledAnalyzer) Analyze(_ context.Context, input analyzer.AnalysisInput) (*analyzer.AnalysisResult, error) {
	return language.AnalyzePackage(types.ComposerInstalled, input.FilePath, input.Content, composer.NewParser(), input.Options.FileChecksum)
}

func (a composerInstalledAnalyzer) Required(filePath string, _ os.FileInfo) bool {
	return filepath.Base(filePath) == types.ComposerInstalledJson
}

func (a composerInstalledAnalyzer) Type() analyzer.Type {
	return analyzer.TypeComposerInstalled
}

func (a composerInstalledAnalyzer) Version() int {
	return version
}