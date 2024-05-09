package binary_test

import (
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/trivy/pkg/dependency/parser/golang/binary"
	ftypes "github.com/aquasecurity/trivy/pkg/fanal/types"
)

func TestParse(t *testing.T) {
	wantPkgs := []ftypes.Package{
		{
			Name:         "github.com/aquasecurity/test",
			Version:      "",
			Relationship: ftypes.RelationshipRoot,
		},
		{
			Name:         "stdlib",
			Version:      "1.15.2",
			Relationship: ftypes.RelationshipDirect,
		},
		{
			Name:    "github.com/aquasecurity/go-pep440-version",
			Version: "v0.0.0-20210121094942-22b2f8951d46",
		},
		{
			Name:    "github.com/aquasecurity/go-version",
			Version: "v0.0.0-20210121072130-637058cfe492",
		},
		{
			Name:    "golang.org/x/xerrors",
			Version: "v0.0.0-20200804184101-5ec99f83aff1",
		},
	}

	tests := []struct {
		name      string
		inputFile string
		want      []ftypes.Package
		wantErr   string
	}{
		{
			name:      "ELF",
			inputFile: "testdata/test.elf",
			want:      wantPkgs,
		},
		{
			name:      "PE",
			inputFile: "testdata/test.exe",
			want:      wantPkgs,
		},
		{
			name:      "Mach-O",
			inputFile: "testdata/test.macho",
			want:      wantPkgs,
		},
		{
			name:      "with replace directive",
			inputFile: "testdata/replace.elf",
			want: []ftypes.Package{
				{
					Name:         "github.com/ebati/trivy-mod-parse",
					Version:      "",
					Relationship: ftypes.RelationshipRoot,
				},
				{
					Name:         "stdlib",
					Version:      "1.16.4",
					Relationship: ftypes.RelationshipDirect,
				},
				{
					Name:    "github.com/davecgh/go-spew",
					Version: "v1.1.1",
				},
				{
					Name:    "github.com/go-sql-driver/mysql",
					Version: "v1.5.0",
				},
			},
		},
		{
			name:      "with semver main module version",
			inputFile: "testdata/semver-main-module-version.macho",
			want: []ftypes.Package{
				{
					Name:         "go.etcd.io/bbolt",
					Version:      "v1.3.5",
					Relationship: ftypes.RelationshipRoot,
				},
				{
					Name:         "stdlib",
					Version:      "1.20.6",
					Relationship: ftypes.RelationshipDirect,
				},
			},
		},
		{
			name:      "with -ldflags=\"-X main.version=v1.0.0\"",
			inputFile: "testdata/main-version-via-ldflags.elf",
			want: []ftypes.Package{
				{
					Name:         "github.com/aquasecurity/test",
					Version:      "v1.0.0",
					Relationship: ftypes.RelationshipRoot,
				},
				{
					Name:         "stdlib",
					Version:      "1.22.1",
					Relationship: ftypes.RelationshipDirect,
				},
			},
		},
		{
			name:      "sad path",
			inputFile: "testdata/dummy",
			wantErr:   "unrecognized executable format",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f, err := os.Open(tt.inputFile)
			require.NoError(t, err)
			defer f.Close()

			got, _, err := binary.NewParser().Parse(f)
			if tt.wantErr != "" {
				require.NotNil(t, err)
				assert.Contains(t, err.Error(), tt.wantErr)
				return
			}

			assert.NoError(t, err)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestParser_ParseLDFlags(t *testing.T) {
	type args struct {
		name  string
		flags []string
	}
	tests := []struct {
		name string
		args args
		want string
	}{
		{
			name: "with version suffix",
			args: args{
				name: "github.com/aquasecurity/trivy",
				flags: []string{
					"-s",
					"-w",
					"-X=foo=bar",
					"-X='github.com/aquasecurity/trivy/pkg/version.version=v0.50.1'",
				},
			},
			want: "v0.50.1",
		},
		{
			name: "with version suffix titlecased",
			args: args{
				name: "github.com/aquasecurity/trivy",
				flags: []string{
					"-s",
					"-w",
					"-X=foo=bar",
					"-X='github.com/aquasecurity/trivy/pkg/version.Version=v0.50.1'",
				},
			},
			want: "v0.50.1",
		},
		{
			name: "with ver suffix",
			args: args{
				name: "github.com/aquasecurity/trivy",
				flags: []string{
					"-s",
					"-w",
					"-X=foo=bar",
					"-X='github.com/aquasecurity/trivy/pkg/version.ver=v0.50.1'",
				},
			},
			want: "v0.50.1",
		},
		{
			name: "with ver suffix titlecased",
			args: args{
				name: "github.com/aquasecurity/trivy",
				flags: []string{
					"-s",
					"-w",
					"-X=foo=bar",
					"-X='github.com/aquasecurity/trivy/pkg/version.Ver=v0.50.1'",
				},
			},
			want: "v0.50.1",
		},
		{
			name: "with double quoted flag",
			args: args{
				name: "github.com/aquasecurity/trivy",
				flags: []string{
					"-s",
					"-w",
					"-X=foo=bar",
					"-X=\"github.com/aquasecurity/trivy/pkg/version.Ver=0.50.1\"",
				},
			},
			want: "0.50.1",
		},
		{
			name: "with semver version without v prefix",
			args: args{
				name: "github.com/aquasecurity/trivy",
				flags: []string{
					"-s",
					"-w",
					"-X=foo=bar",
					"-X='github.com/aquasecurity/trivy/pkg/version.Ver=0.50.1'",
				},
			},
			want: "0.50.1",
		},
		{
			name: "with no flags",
			args: args{
				name:  "github.com/aquasecurity/test",
				flags: []string{},
			},
			want: "",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := binary.NewParser()
			assert.Equal(t, tt.want, p.ParseLDFlags(tt.args.name, tt.args.flags))
		})
	}
}
