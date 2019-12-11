// +build wireinject

package server

import (
	"github.com/aquasecurity/trivy/pkg/rpc/server/library"
	"github.com/aquasecurity/trivy/pkg/rpc/server/ospkg"
	"github.com/google/wire"
)

func initializeOspkgServer() *ospkg.Server {
	wire.Build(ospkg.SuperSet)
	return &ospkg.Server{}
}

func initializeLibServer() *library.Server {
	wire.Build(library.SuperSet)
	return &library.Server{}
}

func initializeDBWorker() dbWorker {
	wire.Build(SuperSet)
	return dbWorker{}
}
