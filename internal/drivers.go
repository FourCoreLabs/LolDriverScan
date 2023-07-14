package pkg

import (
	"unsafe"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/svc/mgr"
)

func ConnectToServiceManager() (*mgr.Mgr, error) {

	host := windows.StringToUTF16Ptr("")
	h, err := windows.OpenSCManager(host, nil, windows.SC_MANAGER_ENUMERATE_SERVICE)
	if err != nil {
		return nil, err
	}
	return &mgr.Mgr{Handle: h}, nil
}

func ListDriverServices(m *mgr.Mgr) ([]string, error) {
	var err error
	var bytesNeeded, servicesReturned uint32
	var buf []byte
	for {
		var p *byte
		if len(buf) > 0 {
			p = &buf[0]
		}
		err = windows.EnumServicesStatusEx(m.Handle, windows.SC_ENUM_PROCESS_INFO,
			windows.SERVICE_DRIVER, windows.SERVICE_STATE_ALL,
			p, uint32(len(buf)), &bytesNeeded, &servicesReturned, nil, nil)
		if err == nil {
			break
		}
		if err != windows.ERROR_MORE_DATA {
			return nil, err
		}
		if bytesNeeded <= uint32(len(buf)) {
			return nil, err
		}
		buf = make([]byte, bytesNeeded)
	}
	if servicesReturned == 0 {
		return nil, nil
	}

	services := unsafe.Slice((*windows.ENUM_SERVICE_STATUS_PROCESS)(unsafe.Pointer(&buf[0])), servicesReturned)

	var names []string
	for _, s := range services {
		name := windows.UTF16PtrToString(s.ServiceName)
		names = append(names, name)
	}
	return names, nil
}

func OpenService(m *mgr.Mgr, name string) (*mgr.Service, error) {
	h, err := windows.OpenService(m.Handle, windows.StringToUTF16Ptr(name), windows.SERVICE_QUERY_CONFIG|windows.SERVICE_QUERY_STATUS)
	if err != nil {
		return nil, err
	}
	return &mgr.Service{Name: name, Handle: h}, nil
}
