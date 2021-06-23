// Code generated by mockery v1.0.0. DO NOT EDIT.

package scanner

import (
	fanaltypes "github.com/aquasecurity/fanal/types"
	mock "github.com/stretchr/testify/mock"

	report "github.com/aquasecurity/trivy/pkg/report"

	types "github.com/aquasecurity/trivy/pkg/types"
)

// MockDriver is an autogenerated mock type for the Driver type
type MockDriver struct {
	mock.Mock
}

type DriverScanArgs struct {
	Target           string
	TargetAnything   bool
	ImageID          string
	ImageIDAnything  bool
	LayerIDs         []string
	LayerIDsAnything bool
	Options          types.ScanOptions
	OptionsAnything  bool
}

type DriverScanReturns struct {
	Results report.Results
	OsFound *fanaltypes.OS
	Eols    bool
	Err     error
}

type DriverScanExpectation struct {
	Args    DriverScanArgs
	Returns DriverScanReturns
}

func (_m *MockDriver) ApplyScanExpectation(e DriverScanExpectation) {
	var args []interface{}
	if e.Args.TargetAnything {
		args = append(args, mock.Anything)
	} else {
		args = append(args, e.Args.Target)
	}
	if e.Args.ImageIDAnything {
		args = append(args, mock.Anything)
	} else {
		args = append(args, e.Args.ImageID)
	}
	if e.Args.LayerIDsAnything {
		args = append(args, mock.Anything)
	} else {
		args = append(args, e.Args.LayerIDs)
	}
	if e.Args.OptionsAnything {
		args = append(args, mock.Anything)
	} else {
		args = append(args, e.Args.Options)
	}
	_m.On("Scan", args...).Return(e.Returns.Results, e.Returns.OsFound, e.Returns.Eols, e.Returns.Err)
}

func (_m *MockDriver) ApplyScanExpectations(expectations []DriverScanExpectation) {
	for _, e := range expectations {
		_m.ApplyScanExpectation(e)
	}
}

// Scan provides a mock function with given fields: target, imageID, layerIDs, options
func (_m *MockDriver) Scan(target string, imageID string, layerIDs []string, options types.ScanOptions) (report.Results, *fanaltypes.OS, bool, error) {
	ret := _m.Called(target, imageID, layerIDs, options)

	var r0 report.Results
	if rf, ok := ret.Get(0).(func(string, string, []string, types.ScanOptions) report.Results); ok {
		r0 = rf(target, imageID, layerIDs, options)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(report.Results)
		}
	}

	var r1 *fanaltypes.OS
	if rf, ok := ret.Get(1).(func(string, string, []string, types.ScanOptions) *fanaltypes.OS); ok {
		r1 = rf(target, imageID, layerIDs, options)
	} else {
		if ret.Get(1) != nil {
			r1 = ret.Get(1).(*fanaltypes.OS)
		}
	}

	var r2 bool
	if rf, ok := ret.Get(2).(func(string, string, []string, types.ScanOptions) bool); ok {
		r2 = rf(target, imageID, layerIDs, options)
	} else {
		r2 = ret.Get(2).(bool)
	}

	var r3 error
	if rf, ok := ret.Get(3).(func(string, string, []string, types.ScanOptions) error); ok {
		r3 = rf(target, imageID, layerIDs, options)
	} else {
		r3 = ret.Error(3)
	}

	return r0, r1, r2, r3
}

func (_m *MockDriver) GetCache() fanaltypes.CacheType {
	return fanaltypes.BuiltInCache
}
