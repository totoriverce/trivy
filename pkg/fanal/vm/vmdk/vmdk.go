package vmdk

import (
	"github.com/aquasecurity/trivy/pkg/fanal/vm"
	"github.com/masahiro331/go-vmdk-parser/pkg/virtualization/vmdk"
	"golang.org/x/xerrors"
	"io"
)

func init() {
	vm.RegisterVMReader(&VMDK{})
}

type VMDK struct{}

func (V VMDK) Try(rs io.ReadSeeker) (bool, error) {
	defer rs.Seek(0, io.SeekStart)
	ok, err := vmdk.Check(rs)
	if err != nil {
		return false, xerrors.Errorf("vmdk check error: %w", err)
	}
	return ok, nil
}

func (V VMDK) NewVMReader(rs io.ReadSeeker) (*io.SectionReader, error) {
	reader, err := vmdk.Open(rs)
	if err != nil {
		return nil, xerrors.Errorf("failed to open vmdk: %w", err)
	}
	return reader, nil
}
