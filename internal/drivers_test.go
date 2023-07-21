package pkg_test

import (
	"errors"
	"fmt"
	pkg "loldriverscan/internal"
	"testing"

	"bou.ke/monkey"
	"github.com/stretchr/testify/assert"
	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/svc/mgr"
)

func TestConnectToServiceManager(t *testing.T) {
	mockWinHandle := windows.Handle(123)

	t.Run("ConnectToServiceManager without error", func(t *testing.T) {
		// Monkey patching to mock implementation  of windows.OpenSCmanager
		patch := monkey.Patch(windows.OpenSCManager, func(host *uint16, database *uint16, access uint32) (windows.Handle, error) {
			return mockWinHandle, nil
		})

		defer patch.Unpatch()

		mgr, err := pkg.ConnectToServiceManager()
		if err != nil {
			t.Error("Could not connect to service manager")
		}
		assert.NoError(t, err, "Unexpected error")
		assert.NotNil(t, mgr, "Manager is nil")
		assert.Equalf(t, mockWinHandle, mgr.Handle, "Unexpected handle value: Expected %v, got %v", mockWinHandle, mgr.Handle)

	})

	t.Run("ConnectToServiceManager error", func(t *testing.T) {
		mockwinError := windows.ERROR_ACCOUNT_RESTRICTION //  Make it throws some error
		patch := monkey.Patch(windows.OpenSCManager, func(host *uint16, database *uint16, access uint32) (windows.Handle, error) {
			return mockWinHandle, mockwinError
		})

		defer patch.Unpatch()

		_, err := pkg.ConnectToServiceManager()
		assert.Error(t, mockwinError, err)
		assert.ErrorContainsf(t, err, "Account restrictions", "Expected error message %v, got %v", "Account restrictions", err)

	})
}

func TestListDriverServices(t *testing.T) {

	// Case 1: passing an invalid Mgr
	t.Run("Invalid Mgr", func(t *testing.T) {
		_, err := pkg.ListDriverServices(&mgr.Mgr{})
		assert.ErrorContains(t, err, "handle is invalid")
	})

	t.Run("Passing a valid service manager", func(t *testing.T) {

		patchListDriverService := monkey.Patch(pkg.ListDriverServices, func(m *mgr.Mgr) ([]string, error) {
			if m.Handle == 123 {
				return []string{"Sample service 1"}, nil
			} else if m.Handle > 400 {
				return []string{"Sample service 2"}, nil
			} else {
				return nil, fmt.Errorf("Invalid service manager handle")
			}

		})
		defer patchListDriverService.Unpatch()

		res, err := pkg.ListDriverServices(&mgr.Mgr{Handle: 123})
		if err != nil {
			t.Fatalf("Unexpected error: %v", err)
		}

		assert.Containsf(t, res, "Sample service 1", "Expected service %v , got %v", "Sample service 1", res)

	})

}

func TestOpenService(t *testing.T) {
	OpenServicePatch := monkey.Patch(windows.OpenService, func(m windows.Handle, servicename *uint16, access uint32) (handle windows.Handle, err error) {
		if m == 12345 {
			return windows.Handle(12345), nil
		} else {
			return 0, fmt.Errorf("Invalid service Handle")
		}

	})

	defer OpenServicePatch.Unpatch()

	t.Run("Proper Service Openec", func(t *testing.T) {
		mockOpenService, err := pkg.OpenService(&mgr.Mgr{Handle: 12345}, "Sample new service")
		if err != nil {
			t.Errorf("Unexpected error opening Handle %v", err)
		}

		assert.Equalf(t, "Sample new service", mockOpenService.Name, "Expected service name %v but got %v:", "Sample new service", mockOpenService.Name)
		assert.EqualValues(t, uintptr(12345), mockOpenService.Handle)
	})

	t.Run("Error new opening service", func(t *testing.T) {
		mockOpenService, err := pkg.OpenService(&mgr.Mgr{Handle: 121}, "Sample new service 2")
		if assert.Error(t, err) {
			assert.Equal(t, errors.New("Invalid service Handle"), err)
		}
		assert.Nil(t, mockOpenService)
	})
}
