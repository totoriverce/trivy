package module

import (
	"context"
	"fmt"
	"os"
	"path/filepath"

	"github.com/google/go-containerregistry/pkg/name"

	"github.com/aquasecurity/trivy/pkg/fanal/types"
	"github.com/aquasecurity/trivy/pkg/log"
	"github.com/aquasecurity/trivy/pkg/oci"
)

const mediaType = "application/vnd.module.wasm.content.layer.v1+wasm"

// Install installs a module
func Install(ctx context.Context, dir, repo string, quiet bool, opt types.RegistryOptions) error {
	ref, err := name.ParseReference(repo)
	if err != nil {
		return fmt.Errorf("repository parse error: %w", err)
	}

	log.Info("Installing the module from the repository...", log.String("repo", repo))
	artifact, err := oci.NewArtifact(repo, quiet, opt)
	if err != nil {
		return fmt.Errorf("module initialize error: %w", err)
	}

	dst := filepath.Join(dir, ref.Context().Name())
	log.Debug("Installing the module...", log.String("dst", dst))

	if err = artifact.Download(ctx, dst, oci.DownloadOption{MediaType: mediaType}); err != nil {
		return fmt.Errorf("module download error: %w", err)
	}

	return nil
}

// Uninstall uninstalls a module
func Uninstall(_ context.Context, dir, repo string) error {
	ref, err := name.ParseReference(repo)
	if err != nil {
		return fmt.Errorf("repository parse error: %w", err)
	}

	log.Info("Uninstalling the module ...", log.String("module", repo))
	dst := filepath.Join(dir, ref.Context().Name())
	if err = os.RemoveAll(dst); err != nil {
		return fmt.Errorf("remove error: %w", err)
	}

	return nil
}
