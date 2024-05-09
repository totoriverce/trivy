package rego

import (
	"context"
	"fmt"
	"io"
	"io/fs"
	"strings"

	"github.com/open-policy-agent/opa/ast"
	"github.com/open-policy-agent/opa/bundle"
	"github.com/samber/lo"
)

var builtinNamespaces = map[string]struct{}{
	"builtin":   {},
	"defsec":    {},
	"appshield": {},
}

func BuiltinNamespaces() []string {
	return lo.Keys(builtinNamespaces)
}

func IsBuiltinNamespace(namespace string) bool {
	return lo.ContainsBy(BuiltinNamespaces(), func(ns string) bool {
		return strings.HasPrefix(namespace, ns+".")
	})
}

func IsRegoFile(name string) bool {
	return strings.HasSuffix(name, bundle.RegoExt) && !strings.HasSuffix(name, "_test"+bundle.RegoExt)
}

func IsDotFile(name string) bool {
	return strings.HasPrefix(name, ".")
}

func (s *Scanner) loadPoliciesFromReaders(readers []io.Reader) (map[string]*ast.Module, error) {
	modules := make(map[string]*ast.Module)
	for i, r := range readers {
		moduleName := fmt.Sprintf("reader_%d", i)
		data, err := io.ReadAll(r)
		if err != nil {
			return nil, err
		}
		module, err := ast.ParseModuleWithOpts(moduleName, string(data), ast.ParserOptions{
			ProcessAnnotation: true,
		})
		if err != nil {
			return nil, err
		}
		modules[moduleName] = module
	}
	return modules, nil
}

func (s *Scanner) loadEmbedded() error {
	loaded, err := LoadEmbeddedLibraries()
	if err != nil {
		return fmt.Errorf("failed to load embedded rego libraries: %w", err)
	}
	s.embeddedLibs = loaded
	s.debug.Log("Loaded %d embedded libraries.", len(loaded))

	loaded, err = LoadEmbeddedPolicies()
	if err != nil {
		return fmt.Errorf("failed to load embedded rego policies: %w", err)
	}
	s.embeddedChecks = loaded
	s.debug.Log("Loaded %d embedded policies.", len(loaded))

	return nil
}

func (s *Scanner) LoadPolicies(enableEmbeddedLibraries, enableEmbeddedPolicies bool, srcFS fs.FS, paths []string, readers []io.Reader) error {

	if s.policies == nil {
		s.policies = make(map[string]*ast.Module)
	}

	if s.policyFS != nil {
		s.debug.Log("Overriding filesystem for checks!")
		srcFS = s.policyFS
	}

	if err := s.loadEmbedded(); err != nil {
		return err
	}

	if enableEmbeddedPolicies {
		s.policies = lo.Assign(s.policies, s.embeddedChecks)
	}

	if enableEmbeddedLibraries {
		s.policies = lo.Assign(s.policies, s.embeddedLibs)
	}

	var err error
	if len(paths) > 0 {
		loaded, err := LoadPoliciesFromDirs(srcFS, paths...)
		if err != nil {
			return fmt.Errorf("failed to load rego policies from %s: %w", paths, err)
		}
		for name, policy := range loaded {
			s.policies[name] = policy
		}
		s.debug.Log("Loaded %d policies from disk.", len(loaded))
	}

	if len(readers) > 0 {
		loaded, err := s.loadPoliciesFromReaders(readers)
		if err != nil {
			return fmt.Errorf("failed to load rego checks from reader(s): %w", err)
		}
		for name, policy := range loaded {
			s.policies[name] = policy
		}
		s.debug.Log("Loaded %d checks from reader(s).", len(loaded))
	}

	// gather namespaces
	uniq := make(map[string]struct{})
	for _, module := range s.policies {
		namespace := getModuleNamespace(module)
		uniq[namespace] = struct{}{}
	}
	var namespaces []string
	for namespace := range uniq {
		namespaces = append(namespaces, namespace)
	}

	dataFS := srcFS
	if s.dataFS != nil {
		s.debug.Log("Overriding filesystem for data!")
		dataFS = s.dataFS
	}
	store, err := initStore(dataFS, s.dataDirs, namespaces)
	if err != nil {
		return fmt.Errorf("unable to load data: %w", err)
	}
	s.store = store

	return s.compilePolicies(srcFS, paths)
}

func (s *Scanner) fallbackChecks(compiler *ast.Compiler) {

	var excludedFiles []string

	for _, e := range compiler.Errors {
		if e.Location == nil {
			continue
		}

		loc := e.Location.File

		if lo.Contains(excludedFiles, loc) {
			continue
		}

		badPolicy, exists := s.policies[loc]
		if !exists || badPolicy == nil {
			continue
		}

		if !IsBuiltinNamespace(getModuleNamespace(badPolicy)) {
			continue
		}

		s.debug.Log("Error occurred while parsing: %s, %s. Trying to fallback to embedded check.", loc, e.Error())

		embedded := s.findMatchedEmbeddedCheck(badPolicy)
		if embedded == nil {
			s.debug.Log("Failed to find embedded check: %s", loc)
			continue
		}

		s.debug.Log("Found embedded check: %s", embedded.Package.Location.File)
		delete(s.policies, loc) // remove bad check
		s.policies[embedded.Package.Location.File] = embedded
		delete(s.embeddedChecks, embedded.Package.Location.File) // avoid infinite loop if embedded check contains ref error
		excludedFiles = append(excludedFiles, e.Location.File)
	}

	compiler.Errors = lo.Filter(compiler.Errors, func(e *ast.Error, _ int) bool {
		return !lo.Contains(excludedFiles, e.Location.File)
	})
}

func (s *Scanner) findMatchedEmbeddedCheck(badPolicy *ast.Module) *ast.Module {
	for _, embeddedCheck := range s.embeddedChecks {
		if embeddedCheck.Package.Path.String() == badPolicy.Package.Path.String() {
			return embeddedCheck
		}
	}

	badPolicyMeta, err := metadataFromRegoModule(badPolicy)
	if err != nil {
		return nil
	}

	for _, embeddedCheck := range s.embeddedChecks {
		meta, err := metadataFromRegoModule(embeddedCheck)
		if err != nil {
			continue
		}
		if badPolicyMeta.AVDID != "" && badPolicyMeta.AVDID == meta.AVDID {
			return embeddedCheck
		}
	}
	return nil
}

func (s *Scanner) prunePoliciesWithError(compiler *ast.Compiler) error {
	if len(compiler.Errors) > s.regoErrorLimit {
		s.debug.Log("Error(s) occurred while loading checks")
		return compiler.Errors
	}

	for _, e := range compiler.Errors {
		s.debug.Log("Error occurred while parsing: %s, %s", e.Location.File, e.Error())
		delete(s.policies, e.Location.File)
	}
	return nil
}

func (s *Scanner) compilePolicies(srcFS fs.FS, paths []string) error {

	schemaSet, custom, err := BuildSchemaSetFromPolicies(s.policies, paths, srcFS)
	if err != nil {
		return err
	}
	if custom {
		s.inputSchema = nil // discard auto detected input schema in favor of check defined schema
	}

	compiler := ast.NewCompiler().
		WithUseTypeCheckAnnotations(true).
		WithCapabilities(ast.CapabilitiesForThisVersion()).
		WithSchemas(schemaSet)

	compiler.Compile(s.policies)
	if compiler.Failed() {
		s.fallbackChecks(compiler)
		if err := s.prunePoliciesWithError(compiler); err != nil {
			return err
		}
		return s.compilePolicies(srcFS, paths)
	}
	retriever := NewMetadataRetriever(compiler)

	if err := s.filterModules(retriever); err != nil {
		return err
	}
	if s.inputSchema != nil {
		schemaSet := ast.NewSchemaSet()
		schemaSet.Put(ast.MustParseRef("schema.input"), s.inputSchema)
		compiler.WithSchemas(schemaSet)
		compiler.Compile(s.policies)
		if compiler.Failed() {
			if err := s.prunePoliciesWithError(compiler); err != nil {
				return err
			}
			return s.compilePolicies(srcFS, paths)
		}
	}
	s.compiler = compiler
	s.retriever = retriever
	return nil
}

func (s *Scanner) filterModules(retriever *MetadataRetriever) error {

	filtered := make(map[string]*ast.Module)
	for name, module := range s.policies {
		meta, err := retriever.RetrieveMetadata(context.TODO(), module)
		if err != nil {
			return err
		}
		if len(meta.InputOptions.Selectors) == 0 {
			s.debug.Log("WARNING: Module %s has no input selectors - it will be loaded for all inputs!", name)
			filtered[name] = module
			continue
		}
		for _, selector := range meta.InputOptions.Selectors {
			if selector.Type == string(s.sourceType) {
				filtered[name] = module
				break
			}
		}
	}

	s.policies = filtered
	return nil
}
