package server

import (
	"context"
	"fmt"

	"github.com/aquasecurity/trivy-db/pkg/db"
	"github.com/aquasecurity/trivy/pkg/commands/operation"
	"github.com/aquasecurity/trivy/pkg/flag"
	"github.com/aquasecurity/trivy/pkg/log"
	"github.com/aquasecurity/trivy/pkg/module"
	rpcServer "github.com/aquasecurity/trivy/pkg/rpc/server"
	"github.com/aquasecurity/trivy/pkg/utils/fsutils"
)

// Run runs the scan
func Run(ctx context.Context, opts flag.Options) (err error) {
	log.InitLogger(opts.Debug, opts.Quiet)

	// configure cache dir
	fsutils.SetCacheDir(opts.CacheDir)
	cache, err := operation.NewCache(opts.CacheOptions)
	if err != nil {
		return fmt.Errorf("server cache error: %w", err)
	}
	defer cache.Close()
	log.Debug("Cache", log.String("dir", fsutils.CacheDir()))

	if opts.Reset {
		return cache.ClearDB()
	}

	// download the database file
	if err = operation.DownloadDB(ctx, opts.AppVersion, opts.CacheDir, opts.DBRepository,
		true, opts.SkipDBUpdate, opts.RegistryOpts()); err != nil {
		return err
	}

	if opts.DownloadDBOnly {
		return nil
	}

	if err = db.Init(opts.CacheDir); err != nil {
		return fmt.Errorf("error in vulnerability DB initialize: %w", err)
	}

	// Initialize WASM modules
	m, err := module.NewManager(ctx, module.Options{
		Dir:            opts.ModuleDir,
		EnabledModules: opts.EnabledModules,
	})
	if err != nil {
		return fmt.Errorf("WASM module error: %w", err)
	}
	m.Register()

	server := rpcServer.NewServer(opts.AppVersion, opts.Listen, opts.CacheDir, opts.Token, opts.TokenHeader,
		opts.DBRepository, opts.RegistryOpts())
	return server.ListenAndServe(ctx, cache, opts.SkipDBUpdate)
}
