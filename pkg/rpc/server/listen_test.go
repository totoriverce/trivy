package server

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
	"golang.org/x/xerrors"

	"github.com/aquasecurity/trivy-db/pkg/db"
	"github.com/aquasecurity/trivy-db/pkg/metadata"
	dbFile "github.com/aquasecurity/trivy/pkg/db"
	"github.com/aquasecurity/trivy/pkg/fanal/cache"
	ftypes "github.com/aquasecurity/trivy/pkg/fanal/types"
	"github.com/aquasecurity/trivy/pkg/policy"
	"github.com/aquasecurity/trivy/pkg/utils/fsutils"
	"github.com/aquasecurity/trivy/pkg/version"
	rpcCache "github.com/aquasecurity/trivy/rpc/cache"
)

func Test_dbWorker_update(t *testing.T) {
	timeNextUpdate := time.Date(3000, 1, 1, 0, 0, 0, 0, time.UTC)
	timeUpdateAt := time.Date(3000, 1, 1, 0, 0, 0, 0, time.UTC)

	type needsUpdateInput struct {
		appVersion string
		skip       bool
	}
	type needsUpdateOutput struct {
		needsUpdate bool
		err         error
	}
	type needsUpdate struct {
		input  needsUpdateInput
		output needsUpdateOutput
	}

	type download struct {
		call bool
		err  error
	}

	type args struct {
		appVersion string
	}
	tests := []struct {
		name        string
		needsUpdate needsUpdate
		download    download
		args        args
		want        metadata.Metadata
		wantErr     string
	}{
		{
			name: "happy path",
			needsUpdate: needsUpdate{
				input: needsUpdateInput{
					appVersion: "1",
					skip:       false,
				},
				output: needsUpdateOutput{needsUpdate: true},
			},
			download: download{
				call: true,
			},
			args: args{appVersion: "1"},
			want: metadata.Metadata{
				Version:    1,
				NextUpdate: timeNextUpdate,
				UpdatedAt:  timeUpdateAt,
			},
		},
		{
			name: "not update",
			needsUpdate: needsUpdate{
				input: needsUpdateInput{
					appVersion: "1",
					skip:       false,
				},
				output: needsUpdateOutput{needsUpdate: false},
			},
			args: args{appVersion: "1"},
		},
		{
			name: "skip update",
			needsUpdate: needsUpdate{
				input: needsUpdateInput{
					appVersion: "1",
					skip:       true,
				},
				output: needsUpdateOutput{needsUpdate: false},
			},
			args: args{appVersion: "1"},
		},
		{
			name: "NeedsUpdate returns an error",
			needsUpdate: needsUpdate{
				input: needsUpdateInput{
					appVersion: "1",
					skip:       false,
				},
				output: needsUpdateOutput{err: xerrors.New("fail")},
			},
			args:    args{appVersion: "1"},
			wantErr: "failed to check if db needs an update",
		},
		{
			name: "Download returns an error",
			needsUpdate: needsUpdate{
				input: needsUpdateInput{
					appVersion: "1",
					skip:       false,
				},
				output: needsUpdateOutput{needsUpdate: true},
			},
			download: download{
				call: true,
				err:  xerrors.New("fail"),
			},
			args:    args{appVersion: "1"},
			wantErr: "failed DB hot update",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cacheDir := t.TempDir()

			require.NoError(t, db.Init(cacheDir), tt.name)

			mockDBClient := new(dbFile.MockOperation)
			mockDBClient.On("NeedsUpdate",
				tt.needsUpdate.input.appVersion, tt.needsUpdate.input.skip).Return(
				tt.needsUpdate.output.needsUpdate, tt.needsUpdate.output.err)

			defer func() { _ = db.Close() }()

			if tt.download.call {
				mockDBClient.On("Download", mock.Anything, mock.Anything, mock.Anything).Run(
					func(args mock.Arguments) {
						// fake download: copy testdata/new.db to tmpDir/db/trivy.db
						tmpDir := args.String(1)
						err := os.MkdirAll(db.Dir(tmpDir), 0744)
						require.NoError(t, err)

						_, err = fsutils.CopyFile("testdata/new.db", db.Path(tmpDir))
						require.NoError(t, err)

						// fake download: copy testdata/metadata.json to tmpDir/db/metadata.json
						_, err = fsutils.CopyFile("testdata/metadata.json", metadata.Path(tmpDir))
						require.NoError(t, err)
					}).Return(tt.download.err)
			}

			w := newDBWorker(mockDBClient)

			var dbUpdateWg, requestWg sync.WaitGroup
			err := w.update(context.Background(), tt.args.appVersion, cacheDir,
				tt.needsUpdate.input.skip, &dbUpdateWg, &requestWg, ftypes.RegistryOptions{})
			if tt.wantErr != "" {
				require.Error(t, err, tt.name)
				assert.Contains(t, err.Error(), tt.wantErr, tt.name)
				return
			}
			require.NoError(t, err, tt.name)

			if !tt.download.call {
				return
			}

			mc := metadata.NewClient(cacheDir)
			got, err := mc.Get()
			assert.NoError(t, err, tt.name)
			assert.Equal(t, tt.want, got, tt.name)

			mockDBClient.AssertExpectations(t)
		})
	}
}

func Test_newServeMux(t *testing.T) {
	type args struct {
		token       string
		tokenHeader string
	}
	tests := []struct {
		name   string
		args   args
		path   string
		header http.Header
		want   int
	}{
		{
			name: "health check",
			path: "/healthz",
			want: http.StatusOK,
		},
		{
			name: "cache endpoint",
			path: path.Join(rpcCache.CachePathPrefix, "MissingBlobs"),
			header: http.Header{
				"Content-Type": []string{"application/protobuf"},
			},
			want: http.StatusOK,
		},
		{
			name: "with token",
			args: args{
				token:       "test",
				tokenHeader: "Authorization",
			},
			path: path.Join(rpcCache.CachePathPrefix, "MissingBlobs"),
			header: http.Header{
				"Authorization": []string{"test"},
				"Content-Type":  []string{"application/protobuf"},
			},
			want: http.StatusOK,
		},
		{
			name: "sad path: no handler",
			path: "/sad",
			header: http.Header{
				"Content-Type": []string{"application/protobuf"},
			},
			want: http.StatusNotFound,
		},
		{
			name: "sad path: invalid token",
			args: args{
				token:       "test",
				tokenHeader: "Authorization",
			},
			path: path.Join(rpcCache.CachePathPrefix, "MissingBlobs"),
			header: http.Header{
				"Content-Type": []string{"application/protobuf"},
			},
			want: http.StatusUnauthorized,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dbUpdateWg, requestWg := &sync.WaitGroup{}, &sync.WaitGroup{}

			c, err := cache.NewFSCache(t.TempDir())
			require.NoError(t, err)
			defer func() { _ = c.Close() }()

			ts := httptest.NewServer(newServeMux(context.Background(), c, dbUpdateWg, requestWg, tt.args.token,
				tt.args.tokenHeader, ""),
			)
			defer ts.Close()

			var resp *http.Response
			url := ts.URL + tt.path
			if tt.header == nil {
				resp, err = http.Get(url)
			} else {
				req, err := http.NewRequest(http.MethodPost, url, nil)
				require.NoError(t, err)

				req.Header = tt.header
				client := new(http.Client)
				resp, err = client.Do(req)
			}

			require.NoError(t, err)
			assert.Equal(t, tt.want, resp.StatusCode)
			defer resp.Body.Close()
		})
	}
}

func Test_VersionEndpoint(t *testing.T) {
	dbUpdateWg, requestWg := &sync.WaitGroup{}, &sync.WaitGroup{}
	c, err := cache.NewFSCache(t.TempDir())
	require.NoError(t, err)
	defer func() { _ = c.Close() }()

	ts := httptest.NewServer(newServeMux(context.Background(), c, dbUpdateWg, requestWg, "", "",
		"testdata/testcache"),
	)
	defer ts.Close()

	resp, err := http.Get(ts.URL + "/version")
	require.NoError(t, err)
	defer resp.Body.Close()

	assert.Equal(t, http.StatusOK, resp.StatusCode)

	var versionInfo version.VersionInfo
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&versionInfo))

	expected := version.VersionInfo{
		Version: "dev",
		VulnerabilityDB: &metadata.Metadata{
			Version:      2,
			NextUpdate:   time.Date(2023, 7, 20, 18, 11, 37, 696263532, time.UTC),
			UpdatedAt:    time.Date(2023, 7, 20, 12, 11, 37, 696263932, time.UTC),
			DownloadedAt: time.Date(2023, 7, 25, 7, 1, 41, 239158000, time.UTC),
		},
		CheckBundle: &policy.Metadata{
			Digest:       "sha256:829832357626da2677955e3b427191212978ba20012b6eaa03229ca28569ae43",
			DownloadedAt: time.Date(2023, 7, 23, 16, 40, 33, 122462000, time.UTC),
		},
	}
	assert.Equal(t, expected, versionInfo)
}
