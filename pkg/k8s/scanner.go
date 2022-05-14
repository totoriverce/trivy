package k8s

import (
	"context"
	"io"

	"github.com/cheggaaa/pb/v3"
	"golang.org/x/xerrors"

	cmd "github.com/aquasecurity/trivy/pkg/commands/artifact"
	"github.com/aquasecurity/trivy/pkg/log"
	"github.com/aquasecurity/trivy/pkg/types"

	"github.com/aquasecurity/trivy-kubernetes/pkg/artifacts"
)

type scanner struct {
	runner *cmd.Runner
	opt    cmd.Option
}

func (s *scanner) run(ctx context.Context, artifacts []*artifacts.Artifact) (Report, error) {
	// Todo move to run.go
	s.opt.SecurityChecks = []string{types.SecurityCheckVulnerability, types.SecurityCheckConfig}

	// progress bar
	bar := pb.StartNew(len(artifacts))
	if s.opt.NoProgress {
		bar.SetWriter(io.Discard)
	}
	defer bar.Finish()

	vulns := make([]Resource, 0)
	misconfigs := make([]Resource, 0)

	// disable logs before scanning
	err := log.InitLogger(s.opt.Debug, true)
	if err != nil {
		return Report{}, xerrors.Errorf("logger error: %w", err)
	}

	// Loops once over all artifacts, and execute scanners as necessary. Not every artifacts has an image,
	// so image scanner is not always executed.
	for _, artifact := range artifacts {
		bar.Increment()

		resources, err := s.scanVulns(ctx, artifact)
		if err != nil {
			return Report{}, xerrors.Errorf("scanning vulnerabilities error: %w", err)
		}
		vulns = append(vulns, resources...)

		resource, err := s.scanMisconfigs(ctx, artifact)
		if err != nil {
			return Report{}, xerrors.Errorf("scanning misconfigurations error: %w", err)
		}
		misconfigs = append(misconfigs, resource)
	}

	// enable logs after scanning
	err = log.InitLogger(s.opt.Debug, s.opt.Quiet)
	if err != nil {
		return Report{}, xerrors.Errorf("logger error: %w", err)
	}

	return Report{
		SchemaVersion:     0,
		Vulnerabilities:   vulns,
		Misconfigurations: misconfigs,
	}, nil
}

func (s *scanner) scanVulns(ctx context.Context, artifact *artifacts.Artifact) ([]Resource, error) {
	resources := make([]Resource, 0, len(artifact.Images))

	for _, image := range artifact.Images {

		s.opt.Target = image

		imageReport, err := s.runner.ScanImage(ctx, s.opt)

		if err != nil {
			log.Logger.Debugf("failed to scan image %s: %s", image, err)
			resources = append(resources, createResource(artifact, imageReport, err))
			continue
		}

		imageReport, err = s.runner.Filter(ctx, s.opt, imageReport)
		if err != nil {
			return nil, xerrors.Errorf("filter error: %w", err)
		}

		resources = append(resources, createResource(artifact, imageReport, nil))
	}

	return resources, nil
}

func (s *scanner) scanMisconfigs(ctx context.Context, artifact *artifacts.Artifact) (Resource, error) {
	configFile, err := createTempFile(artifact)
	if err != nil {
		return Resource{}, xerrors.Errorf("scan error: %w", err)
	}

	s.opt.Target = configFile

	configReport, err := s.runner.ScanFilesystem(ctx, s.opt)
	//remove config file after scanning
	removeFile(configFile)
	if err != nil {
		log.Logger.Debugf("failed to scan config %s/%s: %s", artifact.Kind, artifact.Name, err)
		return createResource(artifact, configReport, err), err
	}

	configReport, err = s.runner.Filter(ctx, s.opt, configReport)
	if err != nil {
		return Resource{}, xerrors.Errorf("filter error: %w", err)
	}

	return createResource(artifact, configReport, nil), nil
}
