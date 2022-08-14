package sbom

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/aquasecurity/trivy/pkg/fanal/image"
	"github.com/aquasecurity/trivy/pkg/rekor"
	digest "github.com/opencontainers/go-digest"
	"golang.org/x/xerrors"

	"github.com/aquasecurity/trivy/pkg/attestation"
	"github.com/aquasecurity/trivy/pkg/fanal/analyzer"
	"github.com/aquasecurity/trivy/pkg/fanal/analyzer/config"
	"github.com/aquasecurity/trivy/pkg/fanal/artifact"
	"github.com/aquasecurity/trivy/pkg/fanal/cache"
	"github.com/aquasecurity/trivy/pkg/fanal/handler"
	"github.com/aquasecurity/trivy/pkg/fanal/types"
	"github.com/aquasecurity/trivy/pkg/log"
	"github.com/aquasecurity/trivy/pkg/sbom"
	"github.com/aquasecurity/trivy/pkg/sbom/cyclonedx"
)

const (
	TargetTypeFile       = "file"
	TargetTypeRekorImage = "rekor-image"
)

type Artifact struct {
	filePath       string
	cache          cache.ArtifactCache
	analyzer       analyzer.AnalyzerGroup
	handlerManager handler.Manager

	artifactOption      artifact.Option
	configScannerOption config.ScannerOption
}

func NewArtifact(filePath string, c cache.ArtifactCache, opt artifact.Option) (artifact.Artifact, error) {
	return Artifact{
		filePath:       filepath.Clean(filePath),
		cache:          c,
		artifactOption: opt,
	}, nil
}

func fetchRepoDigest(refname string) (string, error) {

	// TODO: need docker option and other options?
	img, cleanup, err := image.NewContainerImage(context.TODO(), refname, types.DockerOption{})
	defer cleanup()

	if err != nil {
		panic(err)
	}

	// TODO: when do we get multiple digests?
	for _, rd := range img.RepoDigests() {
		if _, d, found := strings.Cut(rd, "@"); found {
			return d, nil
		} else {
			return "", fmt.Errorf("invalid repo digest")
		}
	}
	return "", fmt.Errorf("repo digest not found")

}

func (a Artifact) Inspect(_ context.Context) (types.ArtifactReference, error) {
	var (
		f      io.ReadSeeker
		format sbom.Format
		err    error
	)

	// TODO: use switch(a.artifactOption.TargetType) {}
	if a.artifactOption.TargetType == TargetTypeRekorImage {
		// TODO: rename a.filePath. artifactName, artifactPath
		d, err := fetchRepoDigest(a.filePath)
		if err != nil {
			return types.ArtifactReference{}, xerrors.Errorf("failed to get repo digest: %w", err)
		}
		log.Logger.Debugf("Repo digest: %s", d)

		client, err := rekor.NewClient()
		if err != nil {
			return types.ArtifactReference{}, xerrors.Errorf("failed to create rekor client: %w", err)
		}

		uuids, err := client.Search(d)
		if err != nil {
			return types.ArtifactReference{}, xerrors.Errorf("failed to search rekor records: %w", err)
		}
		log.Logger.Debugf("Found matching entries: %s", uuids)

		for _, u := range uuids {
			log.Logger.Debugf("Fetching rekor record: %s", u)

			record, err := client.GetByUUID(u)
			if err != nil {
				return types.ArtifactReference{}, xerrors.Errorf("failed to get rekor record: %w", err)
			}
			f = strings.NewReader(record.Attestation())

			format, err = sbom.DetectFormat(f)
			if err != nil {
				log.Logger.Debugf("failed to detect SBOM format")
				continue
			}
			if format == sbom.FormatUnknown {
				continue
			}
			log.Logger.Infof("Recor record: %s", u)
			break
		}

		if format == sbom.FormatUnknown {
			return types.ArtifactReference{}, xerrors.Errorf("failed to detect type")
		}

	} else if a.artifactOption.TargetType == TargetTypeFile {
		ff, err := os.ReadFile(a.filePath)
		if err != nil {
			return types.ArtifactReference{}, xerrors.Errorf("failed to read sbom file error: %w", err)
		}
		f = bytes.NewReader(ff)

		// Format auto-detection
		format, err = sbom.DetectFormat(f)
		if err != nil {
			return types.ArtifactReference{}, xerrors.Errorf("failed to detect SBOM format: %w", err)
		}
	} else {
		return types.ArtifactReference{}, xerrors.Errorf("unknown target type: %s", a.artifactOption.TargetType)
	}

	log.Logger.Infof("Detected SBOM format: %s", format)

	// Rewind the SBOM file
	if _, err = f.Seek(0, io.SeekStart); err != nil {
		return types.ArtifactReference{}, xerrors.Errorf("seek error: %w", err)
	}

	bom, err := a.Decode(f, format)
	if err != nil {
		return types.ArtifactReference{}, xerrors.Errorf("SBOM decode error: %w", err)
	}

	blobInfo := types.BlobInfo{
		SchemaVersion: types.BlobJSONSchemaVersion,
		OS:            bom.OS,
		PackageInfos:  bom.Packages,
		Applications:  bom.Applications,
	}

	cacheKey, err := a.calcCacheKey(blobInfo)
	if err != nil {
		return types.ArtifactReference{}, xerrors.Errorf("failed to calculate a cache key: %w", err)
	}

	if err = a.cache.PutBlob(cacheKey, blobInfo); err != nil {
		return types.ArtifactReference{}, xerrors.Errorf("failed to store blob (%s) in cache: %w", cacheKey, err)
	}

	var artifactType types.ArtifactType
	switch format {
	case sbom.FormatCycloneDXJSON, sbom.FormatCycloneDXXML, sbom.FormatAttestCycloneDXJSON:
		artifactType = types.ArtifactCycloneDX
	}

	return types.ArtifactReference{
		Name:    a.filePath,
		Type:    artifactType,
		ID:      cacheKey, // use a cache key as pseudo artifact ID
		BlobIDs: []string{cacheKey},

		// Keep an original report
		CycloneDX: bom.CycloneDX,
	}, nil
}

func (a Artifact) Decode(f io.Reader, format sbom.Format) (sbom.SBOM, error) {
	var (
		v       interface{}
		bom     sbom.SBOM
		decoder interface{ Decode(any) error }
	)

	switch format {
	case sbom.FormatCycloneDXJSON:
		v = &cyclonedx.CycloneDX{SBOM: &bom}
		decoder = json.NewDecoder(f)
	case sbom.FormatAttestCycloneDXJSON:
		// in-toto attestation
		//   => cosign predicate
		//     => CycloneDX JSON
		v = &attestation.Statement{
			Predicate: &attestation.CosignPredicate{
				Data: &cyclonedx.CycloneDX{SBOM: &bom},
			},
		}
		decoder = json.NewDecoder(f)
	default:
		return sbom.SBOM{}, xerrors.Errorf("%s scanning is not yet supported", format)

	}

	// Decode a file content into sbom.SBOM
	if err := decoder.Decode(v); err != nil {
		return sbom.SBOM{}, xerrors.Errorf("failed to decode: %w", err)
	}

	return bom, nil
}

func (a Artifact) Clean(reference types.ArtifactReference) error {
	return a.cache.DeleteBlobs(reference.BlobIDs)
}

func (a Artifact) calcCacheKey(blobInfo types.BlobInfo) (string, error) {
	// calculate hash of JSON and use it as pseudo artifactID and blobID
	h := sha256.New()
	if err := json.NewEncoder(h).Encode(blobInfo); err != nil {
		return "", xerrors.Errorf("json error: %w", err)
	}

	d := digest.NewDigest(digest.SHA256, h)
	cacheKey, err := cache.CalcKey(d.String(), a.analyzer.AnalyzerVersions(), a.handlerManager.Versions(), a.artifactOption)
	if err != nil {
		return "", xerrors.Errorf("cache key: %w", err)
	}

	return cacheKey, nil
}
