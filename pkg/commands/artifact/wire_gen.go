// Code generated by Wire. DO NOT EDIT.

//go:generate wire
//go:build !wireinject
// +build !wireinject

package artifact

import (
	"context"
	"github.com/aquasecurity/fanal/analyzer/config"
	"github.com/aquasecurity/fanal/applier"
	"github.com/aquasecurity/fanal/artifact"
	image2 "github.com/aquasecurity/fanal/artifact/image"
	local2 "github.com/aquasecurity/fanal/artifact/local"
	"github.com/aquasecurity/fanal/artifact/remote"
	"github.com/aquasecurity/fanal/cache"
	"github.com/aquasecurity/fanal/image"
	"github.com/aquasecurity/trivy-db/pkg/db"
	"github.com/aquasecurity/trivy/pkg/detector/ospkg"
	"github.com/aquasecurity/trivy/pkg/result"
	"github.com/aquasecurity/trivy/pkg/scanner"
	"github.com/aquasecurity/trivy/pkg/scanner/local"
	"github.com/aquasecurity/trivy/pkg/types"
	"time"
)

// Injectors from inject.go:

func initializeDockerScanner(ctx context.Context, imageName string, artifactCache cache.ArtifactCache, localArtifactCache cache.LocalArtifactCache, timeout time.Duration, artifactOption artifact.Option, configScannerOption config.ScannerOption) (scanner.Scanner, func(), error) {
	applierApplier := applier.NewApplier(localArtifactCache)
	detector := ospkg.Detector{}
	localScanner := local.NewScanner(applierApplier, detector)
	dockerOption, err := types.GetDockerOption(timeout)
	if err != nil {
		return scanner.Scanner{}, nil, err
	}
	typesImage, cleanup, err := image.NewDockerImage(ctx, imageName, dockerOption)
	if err != nil {
		return scanner.Scanner{}, nil, err
	}
	artifactArtifact, err := image2.NewArtifact(typesImage, artifactCache, artifactOption, configScannerOption)
	if err != nil {
		cleanup()
		return scanner.Scanner{}, nil, err
	}
	scannerScanner := scanner.NewScanner(localScanner, artifactArtifact)
	return scannerScanner, func() {
		cleanup()
	}, nil
}

func initializeArchiveScanner(ctx context.Context, filePath string, artifactCache cache.ArtifactCache, localArtifactCache cache.LocalArtifactCache, timeout time.Duration, artifactOption artifact.Option, configScannerOption config.ScannerOption) (scanner.Scanner, error) {
	applierApplier := applier.NewApplier(localArtifactCache)
	detector := ospkg.Detector{}
	localScanner := local.NewScanner(applierApplier, detector)
	typesImage, err := image.NewArchiveImage(filePath)
	if err != nil {
		return scanner.Scanner{}, err
	}
	artifactArtifact, err := image2.NewArtifact(typesImage, artifactCache, artifactOption, configScannerOption)
	if err != nil {
		return scanner.Scanner{}, err
	}
	scannerScanner := scanner.NewScanner(localScanner, artifactArtifact)
	return scannerScanner, nil
}

func initializeFilesystemScanner(ctx context.Context, dir string, artifactCache cache.ArtifactCache, localArtifactCache cache.LocalArtifactCache, artifactOption artifact.Option, configScannerOption config.ScannerOption) (scanner.Scanner, func(), error) {
	applierApplier := applier.NewApplier(localArtifactCache)
	detector := ospkg.Detector{}
	localScanner := local.NewScanner(applierApplier, detector)
	artifactArtifact, err := local2.NewArtifact(dir, artifactCache, artifactOption, configScannerOption)
	if err != nil {
		return scanner.Scanner{}, nil, err
	}
	scannerScanner := scanner.NewScanner(localScanner, artifactArtifact)
	return scannerScanner, func() {
	}, nil
}

func initializeRepositoryScanner(ctx context.Context, url string, artifactCache cache.ArtifactCache, localArtifactCache cache.LocalArtifactCache, artifactOption artifact.Option, configScannerOption config.ScannerOption) (scanner.Scanner, func(), error) {
	applierApplier := applier.NewApplier(localArtifactCache)
	detector := ospkg.Detector{}
	localScanner := local.NewScanner(applierApplier, detector)
	artifactArtifact, cleanup, err := remote.NewArtifact(url, artifactCache, artifactOption, configScannerOption)
	if err != nil {
		return scanner.Scanner{}, nil, err
	}
	scannerScanner := scanner.NewScanner(localScanner, artifactArtifact)
	return scannerScanner, func() {
		cleanup()
	}, nil
}

func initializeResultClient() result.Client {
	dbConfig := db.Config{}
	client := result.NewClient(dbConfig)
	return client
}
