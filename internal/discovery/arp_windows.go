//go:build windows
// +build windows

package discovery

import (
	"net"
	"syscall"
	"unsafe"
)

var (
	iphlpapi    = syscall.NewLazyDLL("iphlpapi.dll")
	procSendARP = iphlpapi.NewProc("SendARP")
)

// checkARP envia un paquete ARP nativo en Windows
// Retorna (alive, supported)
func checkARP(ipStr string) (bool, bool) {
	ip := net.ParseIP(ipStr).To4()
	if ip == nil {
		return false, true
	}

	destIP := uint32(ip[0]) | uint32(ip[1])<<8 | uint32(ip[2])<<16 | uint32(ip[3])<<24

	var mac [6]byte
	macLen := uint32(6)

	ret, _, _ := procSendARP.Call(
		uintptr(destIP),
		0,
		uintptr(unsafe.Pointer(&mac[0])), // #nosec G103 - Required for Windows Syscall
		uintptr(unsafe.Pointer(&macLen)), // #nosec G103 - Required for Windows Syscall
	)

	return ret == 0, true
}
