package fingerprint

import (
	"net"
	"os"
	"runtime"
	"strings"
	"time"

	"github.com/raptor-recon/raptor/internal/raw"
	"github.com/raptor-recon/raptor/internal/scanner"
	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
)

// IsLocalIP checks if the IP belongs to any local interface.
func IsLocalIP(ip string) bool {
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return false
	}
	for _, addr := range addrs {
		var ipAddr net.IP
		switch v := addr.(type) {
		case *net.IPNet:
			ipAddr = v.IP
		case *net.IPAddr:
			ipAddr = v.IP
		}
		if ipAddr != nil && ipAddr.String() == ip {
			return true
		}
	}
	return false
}

// DetectOS attempts to determine the OS using a two-layer approach:
// 1. Localhost check
// 2. Layer 3 (ICMP TTL based)
// 3. Layer 7 (Banner heuristic fallback)
func DetectOS(ip string, openPorts []scanner.Result) string {
	if IsLocalIP(ip) {
		osName := runtime.GOOS
		if osName == "windows" {
			return "Windows"
		} else if osName == "darwin" {
			return "macOS"
		} else if osName == "linux" {
			return "Linux"
		}
		return strings.ToTitle(osName)
	}

	if res, err := raw.DetectOS(ip); err == nil && res != nil && res.OSName != "Desconocido" {
		return res.OSName
	}
	// Fallback to banner inferring if raw failed
	return inferOSByBanner(openPorts)
}

func detectOSByTTL(ip string) string {
	// Require raw sockets for ICMP (usually needs root/admin)
	conn, err := net.ListenPacket("ip4:icmp", "0.0.0.0")
	if err != nil {
		// Silent failure, likely due to lack of privileges
		return "Desconocido"
	}
	defer conn.Close()

	p := ipv4.NewPacketConn(conn)
	// Ask to receive TTL in control messages
	if err := p.SetControlMessage(ipv4.FlagTTL, true); err != nil {
		return "Desconocido"
	}

	_ = p.SetDeadline(time.Now().Add(1 * time.Second))

	wm := icmp.Message{
		Type: ipv4.ICMPTypeEcho, Code: 0,
		Body: &icmp.Echo{
			ID: os.Getpid() & 0xffff, Seq: 1,
			Data: []byte("RAPTOR"),
		},
	}
	wb, err := wm.Marshal(nil)
	if err != nil {
		return "Desconocido"
	}

	dst, err := net.ResolveIPAddr("ip4", ip)
	if err != nil {
		return "Desconocido"
	}

	if _, err := p.WriteTo(wb, nil, dst); err != nil {
		return "Desconocido"
	}

	rb := make([]byte, 1500)
	for {
		n, cm, _, err := p.ReadFrom(rb)
		if err != nil {
			return "Desconocido"
		}

		if cm != nil {
			// Try to parse as ICMP to make sure it's an echo reply
			rm, err := icmp.ParseMessage(ipv4.ICMPTypeEchoReply.Protocol(), rb[:n])
			if err == nil && rm.Type == ipv4.ICMPTypeEchoReply {
				// We got an echo reply, let's check TTL
				ttl := cm.TTL
				if ttl > 0 && ttl <= 64 {
					return "Linux/Unix"
				} else if ttl > 64 && ttl <= 128 {
					return "Windows"
				} else if ttl > 128 && ttl <= 255 {
					return "Network Device/Other"
				}
			}
		}
	}
}

func inferOSByBanner(openPorts []scanner.Result) string {
	for _, p := range openPorts {
		bannerLower := strings.ToLower(p.Banner)
		
		// Windows signatures
		if strings.Contains(bannerLower, "windows") ||
			strings.Contains(bannerLower, "iis") ||
			strings.Contains(bannerLower, "win32") {
			return "Windows"
		}
		
		// Linux/Unix signatures
		if strings.Contains(bannerLower, "linux") ||
			strings.Contains(bannerLower, "ubuntu") ||
			strings.Contains(bannerLower, "debian") ||
			strings.Contains(bannerLower, "centos") ||
			strings.Contains(bannerLower, "red hat") ||
			strings.Contains(bannerLower, "freebsd") {
			return "Linux/Unix"
		}
	}
	return "Desconocido"
}
