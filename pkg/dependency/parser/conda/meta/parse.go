package meta

import (
	"encoding/json"
	"fmt"

	"github.com/samber/lo"

	ftypes "github.com/aquasecurity/trivy/pkg/fanal/types"
	xio "github.com/aquasecurity/trivy/pkg/x/io"
)

type packageJSON struct {
	Name    string `json:"name"`
	Version string `json:"version"`
	License string `json:"license"`
}

type Parser struct{}

func NewParser() *Parser {
	return &Parser{}
}

// Parse parses Anaconda (a.k.a. conda) environment metadata.
// e.g. <conda-root>/envs/<env>/conda-meta/<package>.json
// For details see https://conda.io/projects/conda/en/latest/user-guide/concepts/environments.html
func (p *Parser) Parse(r xio.ReadSeekerAt) ([]ftypes.Package, []ftypes.Dependency, error) {
	var data packageJSON
	err := json.NewDecoder(r).Decode(&data)
	if err != nil {
		return nil, nil, fmt.Errorf("JSON decode error: %w", err)
	}

	if data.Name == "" || data.Version == "" {
		return nil, nil, fmt.Errorf("unable to parse conda package")
	}

	return []ftypes.Package{
		{
			Name:     data.Name,
			Version:  data.Version,
			Licenses: lo.Ternary(data.License != "", []string{data.License}, nil),
		},
	}, nil, nil
}
