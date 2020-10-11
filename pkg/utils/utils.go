package utils

import (
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
	"golang.org/x/xerrors"

	fixtures "github.com/aquasecurity/bolt-fixtures"
	"github.com/aquasecurity/trivy-db/pkg/db"
	"github.com/aquasecurity/trivy/pkg/log"
)

var cacheDir string

// DefaultCacheDir returns/creates the cache-dir to be used for trivu operations
func DefaultCacheDir() string {
	tmpDir, err := os.UserCacheDir()
	if err != nil {
		tmpDir = os.TempDir()
	}
	return filepath.Join(tmpDir, "trivy")
}

// CacheDir returns the directory used for caching
func CacheDir() string {
	return cacheDir
}

// SetCacheDir sets the tricy cacheDir
func SetCacheDir(dir string) {
	cacheDir = dir
}

// FileWalk walks the directory and performs operations on files defined by walkFn
func FileWalk(root string, targetFiles map[string]struct{}, walkFn func(r io.Reader, path string) error) error {
	err := filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() {
			return nil
		}

		rel, err := filepath.Rel(root, path)
		if err != nil {
			return xerrors.Errorf("error in filepath rel: %w", err)
		}

		if _, ok := targetFiles[rel]; !ok {
			return nil
		}

		if info.Size() == 0 {
			log.Logger.Debugf("invalid size: %s", path)
			return nil
		}

		f, err := os.Open(filepath.Clean(path))
		if err != nil {
			return xerrors.Errorf("failed to open file: %w", err)
		}
		defer f.Close() // nolint: errcheck,gosec

		if err = walkFn(f, path); err != nil {
			return err
		}
		return nil
	})
	if err != nil {
		return xerrors.Errorf("error in file walk: %w", err)
	}
	return nil
}

// StringInSlice checks if strings exist in list of strings
func StringInSlice(a string, list []string) bool {
	for _, b := range list {
		if b == a {
			return true
		}
	}
	return false
}

// FilterTargets filters the target based on prefixPath
func FilterTargets(prefixPath string, targets map[string]struct{}) (map[string]struct{}, error) {
	filtered := map[string]struct{}{}
	for filename := range targets {
		if strings.HasPrefix(filename, prefixPath) {
			rel, err := filepath.Rel(prefixPath, filename)
			if err != nil {
				return nil, xerrors.Errorf("error in filepath rel: %w", err)
			}
			if strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
				continue
			}
			filtered[rel] = struct{}{}
		}
	}
	return filtered, nil
}

// CopyFile copies the file content from scr to dst
func CopyFile(src, dst string) (int64, error) {
	sourceFileStat, err := os.Stat(src)
	if err != nil {
		return 0, err
	}

	if !sourceFileStat.Mode().IsRegular() {
		return 0, fmt.Errorf("%s is not a regular file", src)
	}

	source, err := os.Open(filepath.Clean(src))
	if err != nil {
		return 0, err
	}
	defer source.Close() // nolint: errcheck,gosec

	destination, err := os.Create(dst)
	if err != nil {
		return 0, err
	}
	defer destination.Close() // nolint: errcheck,gosec
	n, err := io.Copy(destination, source)
	return n, err
}

// InitTestDB is a utility function initializing BoltDB for unit testing
func InitTestDB(t *testing.T, fixtureFiles []string) string {
	// Create a temp dir
	dir, err := ioutil.TempDir("", "TestDB")
	require.NoError(t, err)

	dbPath := db.Path(dir)
	dbDir := filepath.Dir(dbPath)
	err = os.MkdirAll(dbDir, 0700)
	require.NoError(t, err)

	// Load testdata into BoltDB
	loader, err := fixtures.New(dbPath, fixtureFiles)
	require.NoError(t, err)
	require.NoError(t, loader.Load())
	require.NoError(t, loader.Close())

	// Initialize DB
	require.NoError(t, db.Init(dir))

	return dir
}
