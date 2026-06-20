package fingerprint

import (
	"bufio"
	"fmt"
	"os"
	"strings"
)

// GetLocalMAC resuelve la dirección física de un host IPv4 local en Linux
// leyendo la caché del sistema en /proc/net/arp.
// Retorna cadena vacía si no se encuentra.
func GetLocalMAC(ipStr string) (string, error) {
	file, err := os.Open("/proc/net/arp")
	if err != nil {
		return "", err
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	// Saltar cabecera
	if scanner.Scan() {
		// "IP address       HW type     Flags       HW address            Mask     Device"
	}

	for scanner.Scan() {
		line := scanner.Text()
		fields := strings.Fields(line)
		if len(fields) >= 4 {
			ip := fields[0]
			mac := fields[3]
			if ip == ipStr {
				if mac != "00:00:00:00:00:00" {
					return strings.ToUpper(mac), nil
				}
			}
		}
	}

	if err := scanner.Err(); err != nil {
		return "", err
	}

	return "", fmt.Errorf("MAC not found in ARP cache")
}
