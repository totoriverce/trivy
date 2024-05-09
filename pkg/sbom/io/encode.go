package io

import (
	"fmt"
	"slices"
	"strconv"

	"github.com/package-url/packageurl-go"
	"github.com/samber/lo"
	"golang.org/x/xerrors"

	"github.com/aquasecurity/trivy/pkg/digest"
	ftypes "github.com/aquasecurity/trivy/pkg/fanal/types"
	"github.com/aquasecurity/trivy/pkg/purl"
	"github.com/aquasecurity/trivy/pkg/sbom/core"
	"github.com/aquasecurity/trivy/pkg/scanner/utils"
	"github.com/aquasecurity/trivy/pkg/types"
)

type Encoder struct {
	bom  *core.BOM
	opts core.Options
}

func NewEncoder(opts core.Options) *Encoder {
	return &Encoder{opts: opts}
}

func (e *Encoder) Encode(report types.Report) (*core.BOM, error) {
	// Metadata component
	root, err := e.rootComponent(report)
	if err != nil {
		return nil, xerrors.Errorf("failed to create root component: %w", err)
	}

	e.bom = core.NewBOM(e.opts)
	e.bom.AddComponent(root)

	for _, result := range report.Results {
		e.encodeResult(root, report.Metadata, result)
	}

	// Components that do not have their own dependencies MUST be declared as empty elements within the graph.
	if _, ok := e.bom.Relationships()[root.ID()]; !ok {
		e.bom.AddRelationship(root, nil, "")
	}
	return e.bom, nil
}

func (e *Encoder) rootComponent(r types.Report) (*core.Component, error) {
	root := &core.Component{
		Root: true,
		Name: r.ArtifactName,
	}

	props := []core.Property{
		{
			Name:  core.PropertySchemaVersion,
			Value: strconv.Itoa(r.SchemaVersion),
		},
	}

	switch r.ArtifactType {
	case ftypes.ArtifactContainerImage:
		root.Type = core.TypeContainerImage
		props = append(props, core.Property{
			Name:  core.PropertyImageID,
			Value: r.Metadata.ImageID,
		})

		p, err := purl.New(purl.TypeOCI, r.Metadata, ftypes.Package{})
		if err != nil {
			return nil, xerrors.Errorf("failed to new package url for oci: %w", err)
		}
		if p != nil {
			root.PkgID.PURL = p.Unwrap()
		}

	case ftypes.ArtifactVM:
		root.Type = core.TypeVM
	case ftypes.ArtifactFilesystem:
		root.Type = core.TypeFilesystem
	case ftypes.ArtifactRepository:
		root.Type = core.TypeRepository
	case ftypes.ArtifactCycloneDX:
		return r.BOM.Root(), nil
	}

	if r.Metadata.Size != 0 {
		props = append(props, core.Property{
			Name:  core.PropertySize,
			Value: strconv.FormatInt(r.Metadata.Size, 10),
		})
	}

	for _, d := range r.Metadata.RepoDigests {
		props = append(props, core.Property{
			Name:  core.PropertyRepoDigest,
			Value: d,
		})
	}

	for _, id := range r.Metadata.DiffIDs {
		props = append(props, core.Property{
			Name:  core.PropertyDiffID,
			Value: id,
		})
	}

	for _, tag := range r.Metadata.RepoTags {
		props = append(props, core.Property{
			Name:  core.PropertyRepoTag,
			Value: tag,
		})
	}

	root.Properties = filterProperties(props)

	return root, nil
}

func (e *Encoder) encodeResult(root *core.Component, metadata types.Metadata, result types.Result) {
	if slices.Contains(ftypes.AggregatingTypes, result.Type) {
		// If a package is language-specific package that isn't associated with a lock file,
		// it will be a dependency of a component under "metadata".
		// e.g.
		//   Container component (alpine:3.15) ----------------------- #1
		//     -> Library component (npm package, express-4.17.3) ---- #2
		//     -> Library component (python package, django-4.0.2) --- #2
		//     -> etc.
		// ref. https://cyclonedx.org/use-cases/#inventory

		// Dependency graph from #1 to #2
		e.encodePackages(root, result)
	} else if result.Class == types.ClassOSPkg || result.Class == types.ClassLangPkg {
		// If a package is OS package, it will be a dependency of "Operating System" component.
		// e.g.
		//   Container component (alpine:3.15) --------------------- #1
		//     -> Operating System Component (Alpine Linux 3.15) --- #2
		//       -> Library component (bash-4.12) ------------------ #3
		//       -> Library component (vim-8.2)   ------------------ #3
		//       -> etc.
		//
		// Else if a package is language-specific package associated with a lock file,
		// it will be a dependency of "Application" component.
		// e.g.
		//   Container component (alpine:3.15) ------------------------ #1
		//     -> Application component (/app/package-lock.json) ------ #2
		//       -> Library component (npm package, express-4.17.3) --- #3
		//       -> Library component (npm package, lodash-4.17.21) --- #3
		//       -> etc.

		// #2
		appComponent := e.resultComponent(root, result, metadata.OS)

		// #3
		e.encodePackages(appComponent, result)
	}
}

func (e *Encoder) encodePackages(parent *core.Component, result types.Result) {
	// Get dependency parents first
	parents := ftypes.Packages(result.Packages).ParentDeps()

	// Group vulnerabilities by package ID
	vulns := make(map[string][]core.Vulnerability)
	for _, vuln := range result.Vulnerabilities {
		v := e.vulnerability(vuln)
		vulns[v.PkgID] = append(vulns[v.PkgID], v)
	}

	// Convert packages into components and add them to the BOM
	parentRelationship := core.RelationshipContains
	components := make(map[string]*core.Component, len(result.Packages))
	for i, pkg := range result.Packages {
		pkgID := lo.Ternary(pkg.ID == "", fmt.Sprintf("%s@%s", pkg.Name, pkg.Version), pkg.ID)
		result.Packages[i].ID = pkgID

		// Convert packages to components
		c := e.component(result, pkg)
		components[pkgID+pkg.FilePath] = c

		// Add a component
		e.bom.AddComponent(c)

		// Add vulnerabilities
		if vv := vulns[pkgID]; vv != nil {
			e.bom.AddVulnerabilities(c, vv)
		}

		// Handle a root package
		if pkg.Relationship == ftypes.RelationshipRoot {
			// If the package is a root package, add a relationship between the parent and the root package
			e.bom.AddRelationship(parent, c, core.RelationshipContains)
			// Replace the parent with the root package
			parent = c
			parentRelationship = core.RelationshipDependsOn
		}
	}

	// Build a dependency graph between packages
	for _, pkg := range result.Packages {
		if pkg.Relationship == ftypes.RelationshipRoot {
			continue
		}
		c := components[pkg.ID+pkg.FilePath]

		// Add a relationship between the parent and the package if needed
		if e.belongToParent(pkg, parents) {
			e.bom.AddRelationship(parent, c, parentRelationship)
		}

		// Add relationships between the package and its dependencies
		for _, dep := range pkg.DependsOn {
			dependsOn, ok := components[dep]
			if !ok {
				continue
			}
			e.bom.AddRelationship(c, dependsOn, core.RelationshipDependsOn)
		}

		// Components that do not have their own dependencies MUST be declared as empty elements within the graph.
		// TODO: Should check if the component has actually no dependencies or the dependency graph is not supported.
		if len(pkg.DependsOn) == 0 {
			e.bom.AddRelationship(c, nil, "")
		}
	}
}

func (e *Encoder) resultComponent(root *core.Component, r types.Result, osFound *ftypes.OS) *core.Component {
	component := &core.Component{
		Name: r.Target,
		Properties: []core.Property{
			{
				Name:  core.PropertyType,
				Value: string(r.Type),
			},
			{
				Name:  core.PropertyClass,
				Value: string(r.Class),
			},
		},
	}

	switch r.Class {
	case types.ClassOSPkg:
		if osFound != nil {
			component.Name = string(osFound.Family)
			component.Version = osFound.Name
		}
		component.Type = core.TypeOS
	case types.ClassLangPkg:
		component.Type = core.TypeApplication
	}

	e.bom.AddRelationship(root, component, core.RelationshipContains)
	return component
}

func (*Encoder) component(result types.Result, pkg ftypes.Package) *core.Component {
	name := pkg.Name
	version := utils.FormatVersion(pkg)
	var group string
	// there are cases when we can't build purl
	// e.g. local Go packages
	if pu := pkg.Identifier.PURL; pu != nil {
		version = pu.Version
		for _, q := range pu.Qualifiers {
			if q.Key == "epoch" && q.Value != "0" {
				version = fmt.Sprintf("%s:%s", q.Value, version)
			}
		}

		// Use `group` field for GroupID and `name` for ArtifactID for java files
		// https://github.com/aquasecurity/trivy/issues/4675
		// Use `group` field for npm scopes
		// https://github.com/aquasecurity/trivy/issues/5908
		if pu.Type == packageurl.TypeMaven || pu.Type == packageurl.TypeNPM {
			name = pu.Name
			group = pu.Namespace
		}
	}

	properties := []core.Property{
		{
			Name:  core.PropertyPkgID,
			Value: pkg.ID,
		},
		{
			Name:  core.PropertyPkgType,
			Value: string(result.Type),
		},
		{
			Name:  core.PropertyFilePath,
			Value: pkg.FilePath,
		},
		{
			Name:  core.PropertySrcName,
			Value: pkg.SrcName,
		},
		{
			Name:  core.PropertySrcVersion,
			Value: pkg.SrcVersion,
		},
		{
			Name:  core.PropertySrcRelease,
			Value: pkg.SrcRelease,
		},
		{
			Name:  core.PropertySrcEpoch,
			Value: strconv.Itoa(pkg.SrcEpoch),
		},
		{
			Name:  core.PropertyModularitylabel,
			Value: pkg.Modularitylabel,
		},
		{
			Name:  core.PropertyLayerDigest,
			Value: pkg.Layer.Digest,
		},
		{
			Name:  core.PropertyLayerDiffID,
			Value: pkg.Layer.DiffID,
		},
	}

	var files []core.File
	if pkg.FilePath != "" || pkg.Digest != "" {
		files = append(files, core.File{
			Path:    pkg.FilePath,
			Digests: lo.Ternary(pkg.Digest != "", []digest.Digest{pkg.Digest}, nil),
		})
	}

	// TODO(refactor): simplify the list of conditions
	var srcFile string
	if result.Class == types.ClassLangPkg && !slices.Contains(ftypes.AggregatingTypes, result.Type) {
		srcFile = result.Target
	}

	return &core.Component{
		Type:       core.TypeLibrary,
		Name:       name,
		Group:      group,
		Version:    version,
		SrcName:    pkg.SrcName,
		SrcVersion: utils.FormatSrcVersion(pkg),
		SrcFile:    srcFile,
		PkgID: core.PkgID{
			PURL: pkg.Identifier.PURL,
		},
		Supplier:   pkg.Maintainer,
		Licenses:   pkg.Licenses,
		Files:      files,
		Properties: filterProperties(properties),
	}
}

func (*Encoder) vulnerability(vuln types.DetectedVulnerability) core.Vulnerability {
	return core.Vulnerability{
		Vulnerability:    vuln.Vulnerability,
		ID:               vuln.VulnerabilityID,
		PkgID:            lo.Ternary(vuln.PkgID == "", fmt.Sprintf("%s@%s", vuln.PkgName, vuln.InstalledVersion), vuln.PkgID),
		PkgName:          vuln.PkgName,
		InstalledVersion: vuln.InstalledVersion,
		FixedVersion:     vuln.FixedVersion,
		PrimaryURL:       vuln.PrimaryURL,
		DataSource:       vuln.DataSource,
	}
}

// belongToParent determines if a package should be directly included in the parent based on its relationship and dependencies.
func (*Encoder) belongToParent(pkg ftypes.Package, parents map[string]ftypes.Packages) bool {
	// Case 1: Direct/Indirect: known , DependsOn: known
	//         1-1: Only direct packages are included in the parent (RelationshipContains or RelationshipDependsOn)
	//         1-2: Each direct package includes its dependent packages (RelationshipDependsOn).
	// Case 2: Direct/Indirect: unknown, DependsOn: unknown (e.g., conan lockfile v2)
	//         All packages are included in the parent (RelationshipContains or RelationshipDependsOn).
	// Case 3: Direct/Indirect: unknown, DependsOn: known (e.g., OS packages)
	//         All packages are included in the parent (RelationshipContains or RelationshipDependsOn).
	// Case 4: Direct/Indirect: known , DependsOn: unknown (e.g., go.mod without $GOPATH)
	//         All packages are included in the parent (RelationshipContains or RelationshipDependsOn).
	switch {
	// Case 1-1: direct packages
	case pkg.Relationship == ftypes.RelationshipDirect:
		return true
	// Case 1-2: indirect packages
	case pkg.Relationship == ftypes.RelationshipIndirect && len(parents[pkg.ID]) != 0:
		return false
	// Case 2 & 3:
	case pkg.Relationship == ftypes.RelationshipUnknown:
		return true
	// Case 4:
	case pkg.Relationship == ftypes.RelationshipIndirect && len(parents[pkg.ID]) == 0:
		return true
	default:
		return true
	}
}

func filterProperties(props []core.Property) []core.Property {
	return lo.Filter(props, func(property core.Property, _ int) bool {
		return !(property.Value == "" || (property.Name == core.PropertySrcEpoch && property.Value == "0"))
	})
}
