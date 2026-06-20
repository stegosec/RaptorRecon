package fingerprint

import (
	"bytes"
	"fmt"
	"os/exec"
	"strings"
)

// GetLocalMAC resuelve la dirección física de un host IPv4 local en macOS (Darwin)
// parseando la salida de la tabla ARP nativa.
func GetLocalMAC(ipStr string) (string, error) {
	cmd := exec.Command("arp", "-n", ipStr)
	var out bytes.Buffer
	cmd.Stdout = &out
	if err := cmd.Run(); err != nil {
		return "", err
	}

	output := out.String()
	// Si no está en caché el comando arp devuelve "no entry"
	if strings.Contains(output, "no entry") {
		return "", fmt.Errorf("MAC no encontrada en caché ARP")
	}

	fields := strings.Fields(output)
	// Output típico de macOS: "? (192.168.1.1) at 00:11:22:33:44:55 on en0 ifscope [ethernet]"
	for i, field := range fields {
		if field == "at" && i+1 < len(fields) {
			mac := fields[i+1]
			if mac != "00:00:00:00:00:00" {
				return strings.ToUpper(mac), nil
			}
		}
	}

	return "", fmt.Errorf("no se pudo extraer la MAC de la salida ARP")
}
