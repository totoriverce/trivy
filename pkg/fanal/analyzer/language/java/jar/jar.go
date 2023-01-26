package jar

import (
	"context"
	"github.com/aquasecurity/trivy/pkg/fanal/types"
	"github.com/aquasecurity/trivy/pkg/java_db"
	"golang.org/x/xerrors"
	"os"
	"path/filepath"
	"strings"

	"github.com/aquasecurity/go-dep-parser/pkg/java/jar"
	"github.com/aquasecurity/trivy/pkg/fanal/analyzer"
	"github.com/aquasecurity/trivy/pkg/fanal/analyzer/language"
)

func init() {
	analyzer.RegisterAnalyzer(&javaLibraryAnalyzer{})
}

const (
	version = 1
)

var requiredExtensions = []string{".jar", ".war", ".ear", ".par"}

// javaLibraryAnalyzer analyzes jar/war/ear/par files
type javaLibraryAnalyzer struct{}

func (a javaLibraryAnalyzer) Analyze(_ context.Context, input analyzer.AnalysisInput) (*analyzer.AnalysisResult, error) {
	_, err := java_db.UpdateJavaDB()
	if err != nil {
		return nil, xerrors.Errorf("trivy-java-db update error: %w", err) // TODO just skip using trivy-java-db????
	}
	// TODO use cacheDir from db.UpdateJavaDB() in jar.NewParse to find out where trivy-java-db is stored
	p := jar.NewParser(jar.WithSize(input.Info.Size()), jar.WithFilePath(input.FilePath), jar.WithOffline(input.Options.Offline))
	libs, deps, err := p.Parse(input.Content)
	if err != nil {
		return nil, xerrors.Errorf("jar/war/ear/par parse error: %w", err)
	}

	return language.ToAnalysisResult(types.Jar, input.FilePath, input.FilePath, libs, deps), nil
}

func (a javaLibraryAnalyzer) Required(filePath string, _ os.FileInfo) bool {
	ext := filepath.Ext(filePath)
	for _, required := range requiredExtensions {
		if strings.EqualFold(ext, required) {
			return true
		}
	}
	return false
}

func (a javaLibraryAnalyzer) Type() analyzer.Type {
	return analyzer.TypeJar
}

func (a javaLibraryAnalyzer) Version() int {
	return version
}
