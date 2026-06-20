package fingerprint

import (
	"fmt"
	"net"
	"syscall"
	"unsafe"
)

// GetLocalMAC resuelve la dirección física (MAC) de un host IPv4 local
// usando la API nativa de Windows SendARP (iphlpapi.dll).
// Retorna cadena vacía si no se puede resolver (ej. IP en subred externa).
func GetLocalMAC(ipStr string) (string, error) {
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return "", fmt.Errorf("invalid IP")
	}
	ip = ip.To4()
	if ip == nil {
		return "", fmt.Errorf("not an IPv4 address")
	}

	// Windows SendARP espera la IP destino como un uint32 en formato network byte order.
	var destIP uint32 = uint32(ip[0]) | uint32(ip[1])<<8 | uint32(ip[2])<<16 | uint32(ip[3])<<24

	iphlpapi := syscall.NewLazyDLL("iphlpapi.dll")
	sendARP := iphlpapi.NewProc("SendARP")

	macAddr := make([]byte, 6)
	var macLen uint32 = 6

	// SendARP(DestIP, SrcIP, pMacAddr, PhyAddrLen)
	ret, _, _ := sendARP.Call(
		uintptr(destIP),
		0,
		uintptr(unsafe.Pointer(&macAddr[0])), // #nosec G103 - Required for Syscall
		uintptr(unsafe.Pointer(&macLen)),     // #nosec G103 - Required for Syscall
	)

	if ret != 0 {
		return "", fmt.Errorf("SendARP failed with code: %d", ret)
	}

	if macLen != 6 {
		return "", fmt.Errorf("invalid MAC length returned: %d", macLen)
	}

	mac := fmt.Sprintf("%02X:%02X:%02X:%02X:%02X:%02X", macAddr[0], macAddr[1], macAddr[2], macAddr[3], macAddr[4], macAddr[5])
	return mac, nil
}
