package discovery

import (
	"net"
	"os/exec"
	"runtime"
	"strings"
)

// getOSRoutes extrae las rutas activas de la tabla de enrutamiento del OS.
func getOSRoutes() []string {
	var routes []string
	var out []byte
	var err error

	if runtime.GOOS == "windows" {
		cmd := exec.Command("route", "print", "-4")
		out, err = cmd.Output()
		if err == nil {
			routes = parseWindowsRoutes(out)
		}
	} else if runtime.GOOS == "linux" {
		cmd := exec.Command("ip", "route")
		out, err = cmd.Output()
		if err == nil {
			routes = parseLinuxRoutes(out)
		}
	} else if runtime.GOOS == "darwin" {
		cmd := exec.Command("netstat", "-rn", "-f", "inet")
		out, err = cmd.Output()
		if err == nil {
			routes = parseDarwinRoutes(out)
		}
	}

	// Filter out non-RFC1918 and loopback/multicast routes
	var valid []string
	seen := make(map[string]bool)
	for _, r := range routes {
		_, ipnet, err := net.ParseCIDR(r)
		if err != nil {
			continue
		}
		ip := ipnet.IP.To4()
		if ip == nil {
			continue
		}
		
		// Omitir default gateway, loopback, multicast, link-local
		if ip.IsLoopback() || ip.IsMulticast() || ip.IsLinkLocalUnicast() || ip.Equal(net.IPv4zero) {
			continue
		}

		// Solo nos interesan redes privadas RFC1918 y Carrier-Grade NAT (opcionalmente)
		if isPrivateIP(ip) {
			cidr := ipnet.String()
			if !seen[cidr] {
				seen[cidr] = true
				valid = append(valid, cidr)
			}
		}
	}

	return valid
}

func isPrivateIP(ip net.IP) bool {
	// RFC 1918
	if ip[0] == 10 || (ip[0] == 172 && ip[1] >= 16 && ip[1] <= 31) || (ip[0] == 192 && ip[1] == 168) {
		return true
	}
	return false
}

func parseWindowsRoutes(output []byte) []string {
	var routes []string
	lines := strings.Split(string(output), "\n")
	for _, line := range lines {
		fields := strings.Fields(line)
		if len(fields) >= 3 {
			dest := fields[0]
			mask := fields[1]
			
			destIP := net.ParseIP(dest)
			maskIP := net.ParseIP(mask)
			if destIP != nil && maskIP != nil && destIP.To4() != nil && maskIP.To4() != nil {
				ipnet := net.IPNet{
					IP:   destIP,
					Mask: net.IPv4Mask(maskIP[0], maskIP[1], maskIP[2], maskIP[3]),
				}
				routes = append(routes, ipnet.String())
			}
		}
	}
	return routes
}

func parseLinuxRoutes(output []byte) []string {
	var routes []string
	lines := strings.Split(string(output), "\n")
	for _, line := range lines {
		fields := strings.Fields(line)
		if len(fields) > 0 {
			dest := fields[0]
			if dest == "default" {
				continue
			}
			if strings.Contains(dest, "/") {
				routes = append(routes, dest)
			} else {
				// Assume /32 for exact IP matches if no mask provided by 'ip route'
				routes = append(routes, dest+"/32")
			}
		}
	}
	return routes
}

func parseDarwinRoutes(output []byte) []string {
	var routes []string
	lines := strings.Split(string(output), "\n")
	for _, line := range lines {
		fields := strings.Fields(line)
		if len(fields) >= 2 {
			dest := fields[0]
			if dest == "default" || dest == "Destination" {
				continue
			}
			// macOS netstat -rn might show "10.10.0.0/16" or "10.10" or "10.10/16"
			// This is a naive parse for standard CIDR formats
			if strings.Contains(dest, "/") {
				_, _, err := net.ParseCIDR(dest)
				if err == nil {
					routes = append(routes, dest)
				}
			}
		}
	}
	return routes
}
