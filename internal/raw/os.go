package raw

import (
	"fmt"
	"net"
	"os"
	"time"
	"golang.org/x/net/ipv4"
	"golang.org/x/net/icmp"
)

// FingerprintResult contains the OS deduction based on raw IP headers.
type FingerprintResult struct {
	OSName     string
	Confidence string
	TTL        int
}

// DetectOS sends an ICMP Echo Request and analyzes the TTL of the response 
// to infer the base Operating System without relying on Npcap/CGO.
func DetectOS(targetIP string) (*FingerprintResult, error) {
	// Solo funciona si se tienen privilegios elevados.
	conn, err := icmp.ListenPacket("ip4:icmp", "0.0.0.0")
	if err != nil {
		return nil, fmt.Errorf("requiere privilegios para raw sockets: %v", err)
	}
	defer conn.Close()

	ipConn := conn.IPv4PacketConn()
	if err := ipConn.SetControlMessage(ipv4.FlagTTL|ipv4.FlagSrc|ipv4.FlagDst, true); err != nil {
		return nil, fmt.Errorf("no se pudo activar lectura de TTL: %v", err)
	}

	dst, err := net.ResolveIPAddr("ip4", targetIP)
	if err != nil {
		return nil, err
	}

	msg := icmp.Message{
		Type: ipv4.ICMPTypeEcho, Code: 0,
		Body: &icmp.Echo{
			ID: os.Getpid() & 0xffff, Seq: 1,
			Data: []byte("RAPTOR-OS-DETECT"),
		},
	}
	b, err := msg.Marshal(nil)
	if err != nil {
		return nil, err
	}

	if _, err := conn.WriteTo(b, dst); err != nil {
		return nil, err
	}

	if err := conn.SetReadDeadline(time.Now().Add(2 * time.Second)); err != nil {
		return nil, err
	}

	reply := make([]byte, 1500)
	n, cm, peer, err := ipConn.ReadFrom(reply)
	if err != nil {
		return nil, fmt.Errorf("timeout o error leyendo ICMP: %v", err)
	}

	if peer.String() != dst.String() {
		return nil, fmt.Errorf("respuesta de IP incorrecta")
	}

	rm, err := icmp.ParseMessage(1, reply[:n])
	if err != nil {
		return nil, err
	}

	if rm.Type == ipv4.ICMPTypeEchoReply && cm != nil {
		// Heurística de TTL simplificada
		osName := "Desconocido"
		confidence := "Low"

		if cm.TTL <= 64 {
			osName = "Linux/Unix/macOS"
			confidence = "High"
		} else if cm.TTL <= 128 {
			osName = "Windows"
			confidence = "High"
		} else if cm.TTL <= 255 {
			osName = "Network Device (Cisco/Router)"
			confidence = "Medium"
		}

		return &FingerprintResult{
			OSName:     osName,
			Confidence: confidence,
			TTL:        cm.TTL,
		}, nil
	}

	return nil, fmt.Errorf("no se recibió ICMP Echo Reply")
}
