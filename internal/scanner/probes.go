package scanner

import (
	"bytes"
	"crypto/tls"
	"net"
	"strings"
	"sync"
	"time"
)

var bufferPool = sync.Pool{
	New: func() interface{} {
		b := make([]byte, 2048)
		return &b
	},
}

func isHTTPPort(port int) bool {
	switch port {
	case 80, 8080, 8000, 8001, 8008, 8081, 8187, 8888, 9080, 9119, 7678, 15500, 3000, 5000, 3128, 8118:
		return true
	}
	return false
}

func isHTTPSPort(port int) bool {
	switch port {
	case 443, 8443, 8002, 8009, 7443, 9197:
		return true
	}
	return false
}

// GuessService infiere el nombre del servicio basándose en el puerto y el banner.
func GuessService(port int, banner []byte) string {
	b := strings.ToLower(string(banner))

	if strings.Contains(b, "squid") || port == 3128 || port == 8118 {
		return "http-proxy"
	}
	if port == 1080 {
		return "socks-proxy"
	}

	if isHTTPSPort(port) {
		return "https"
	}
	if isHTTPPort(port) {
		return "http"
	}

	if strings.Contains(b, "ssh") { return "ssh" }
	if strings.Contains(b, "http") { return "http" }
	if strings.Contains(b, "ftp") { return "ftp" }
	if strings.Contains(b, "smb") || port == 445 || port == 139 { return "smb" }

	switch port {
	case 21: return "ftp"
	case 22: return "ssh"
	case 23: return "telnet"
	case 25, 465, 587: return "smtp"
	case 53: return "dns"
	case 110, 995: return "pop3"
	case 143, 993: return "imap"
	case 123: return "ntp"
	case 135: return "msrpc"
	case 161: return "snmp"
	case 1433: return "mssql"
	case 1521: return "oracle"
	case 1900: return "upnp"
	case 3306: return "mysql"
	case 3389: return "rdp"
	case 5432: return "postgresql"
	case 5900, 5901: return "vnc"
	case 6379: return "redis"
	case 9200, 9300: return "elasticsearch"
	case 27017: return "mongodb"
	}
	return "unknown"
}

// ActiveProbe realiza el probing basado en puerto y protocolo.
// Si no hay probe específico, hace passive banner grabbing para TCP.
func ActiveProbe(conn net.Conn, port int, protocol string, timeout time.Duration) []byte {
	// Manejo estricto de errores (Fail-Safe)
	if err := conn.SetDeadline(time.Now().Add(timeout)); err != nil {
		return nil // Si el socket no acepta timeouts, abortamos para evitar cuelgues
	}
	// No necesitamos resetear el deadline porque el socket se cierra inmediatamente después en el caller.

	if protocol == "udp" {
		return probeUDP(conn, port)
	}
	return probeTCP(conn, port, protocol)
}

func probeTCP(conn net.Conn, port int, protocol string) []byte {
	var payload []byte
	isTLS := isHTTPSPort(port)

	if isHTTPPort(port) || isHTTPSPort(port) {
		payload = []byte("GET / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
	} else if port == 445 {
		// SMB Negotiate Protocol Request (mínimo)
		payload = []byte{
			0x00, 0x00, 0x00, 0x54, // NetBIOS session message
			0xff, 0x53, 0x4d, 0x42, // SMB Header (\xffSMB)
			0x72, 0x00, 0x00, 0x00, 0x00, 0x18, 0x01, 0x28, // Command: Negotiate
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x2f, 0x4b,
			0x00, 0x00, 0x00, 0x00, 0x31, 0x00, 0x00, 0x00,
			0x02, 0x4e, 0x54, 0x20, 0x4c, 0x4d, 0x20, 0x30, 0x2e, 0x31, 0x32, 0x00,
			0x02, 0x53, 0x4d, 0x42, 0x20, 0x32, 0x2e, 0x30, 0x30, 0x32, 0x00,
			0x02, 0x53, 0x4d, 0x42, 0x20, 0x32, 0x2e, 0x3f, 0x3f, 0x3f, 0x00,
		}
	}

	var targetConn net.Conn = conn
	if isTLS {
		// Blindaje: Activamos validación estricta de TLS.
		// Al no omitir la verificación, el escáner fallará en certs autofirmados,
		// obligando a la infraestructura a tener certificados válidos.
		tlsConfig := &tls.Config{
			InsecureSkipVerify: true,             // #nosec G402 — ASM scanner must accept self-signed certs in internal networks
			MinVersion:         tls.VersionTLS12, // Blindaje: Forzamos mínimo TLS 1.2
		}
		tlsConn := tls.Client(conn, tlsConfig)
		if err := tlsConn.Handshake(); err == nil {
			targetConn = tlsConn
		} else {
			return nil // Fallo en handshake TLS
		}
	}

	if len(payload) > 0 {
		_, err := targetConn.Write(payload)
		if err != nil {
			return nil
		}
	}

	bufPtr := bufferPool.Get().(*[]byte)
	buf := *bufPtr
	defer bufferPool.Put(bufPtr)

	// Primer intento: Leer banner de forma pasiva
	n, err := targetConn.Read(buf)
	
	// Si falló pasivamente y no enviamos payload, intentamos provocar al servicio (Probing Profundo)
	if (n == 0 || err != nil) && len(payload) == 0 {
		// Incrementar momentáneamente el deadline para el fallback activo
		_ = targetConn.SetDeadline(time.Now().Add(800 * time.Millisecond))
		
		// Fallback probe genérico HTTP/Generic
		fallback := []byte("GET / HTTP/1.0\r\n\r\n")
		if port == 23 || port == 21 || port == 25 || port == 110 || port == 143 {
			fallback = []byte("HELP\r\n")
		}
		_, _ = targetConn.Write(fallback)
		n, err = targetConn.Read(buf)
	}

	if err != nil && n == 0 {
		return nil
	}

	// Limpiar respuestas crudas para el dashboard
	resp := buf[:n]
	if isHTTPPort(port) || isHTTPSPort(port) {
		var serverHeader []byte
		var firstLine []byte
		
		rest := resp
		isFirst := true
		for len(rest) > 0 {
			line := rest
			idx := bytes.IndexByte(rest, '\n')
			if idx >= 0 {
				line = rest[:idx]
				rest = rest[idx+1:]
			} else {
				rest = nil
			}

			// Clean the line
			line = bytes.TrimSpace(line)
			if len(line) == 0 {
				continue
			}

			if isFirst {
				firstLine = line
				isFirst = false
			}

			if bytes.HasPrefix(bytes.ToLower(line), []byte("server:")) {
				serverHeader = line
				break
			}
		}

		if len(serverHeader) > 0 {
			return append([]byte(nil), serverHeader...)
		}

		// Fallback: retornar solo la primera linea (ej. HTTP/1.1 200 OK)
		if len(firstLine) > 0 && bytes.Contains(firstLine, []byte("HTTP")) {
			return append([]byte(nil), firstLine...)
		}
		return append([]byte(nil), resp...)
	}

	if port == 445 {
		if bytes.Contains(resp, []byte("SMB")) || bytes.Contains(resp, []byte("\xfeSMB")) {
			return []byte("SMB Service Detected (Negotiate Success)")
		}
	}

	return append([]byte(nil), resp...)
}

func probeUDP(conn net.Conn, port int) []byte {
	var payload []byte
	switch port {
	case 53:
		// DNS Standard Query A google.com
		payload = []byte{
			0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x06, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x03,
			0x63, 0x6f, 0x6d, 0x00, 0x00, 0x01, 0x00, 0x01,
		}
	case 161:
		// SNMPv1 GetRequest sysDescr
		payload = []byte{
			0x30, 0x26, 0x02, 0x01, 0x00, 0x04, 0x06, 0x70,
			0x75, 0x62, 0x6c, 0x69, 0x63, 0xa0, 0x19, 0x02,
			0x04, 0x12, 0x34, 0x56, 0x78, 0x02, 0x01, 0x00,
			0x02, 0x01, 0x00, 0x30, 0x0b, 0x30, 0x09, 0x06,
			0x05, 0x2b, 0x06, 0x01, 0x02, 0x01, 0x05, 0x00,
		}
	case 123:
		// NTP v4 Client
		payload = []byte{
			0xe3, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		}
	case 137:
		// NetBIOS Name Service Status Request
		payload = []byte{
			0x12, 0x34, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x20, 0x43, 0x4b, 0x41,
			0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41,
			0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41,
			0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41,
			0x41, 0x41, 0x41, 0x41, 0x41, 0x00, 0x00, 0x21,
			0x00, 0x01,
		}
	case 500, 4500:
		// IKEv1 VPN Aggressive Mode
		payload = []byte{
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x01, 0x10, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x44, 0x00, 0x00, 0x00, 0x28,
		}
	case 623:
		// IPMI RMCP Ping
		payload = []byte{
			0x06, 0x00, 0xff, 0x07, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		}
	case 1900:
		// UPnP SSDP Discover
		payload = []byte(
			"M-SEARCH * HTTP/1.1\r\n" +
			"Host: 239.255.255.250:1900\r\n" +
			"Man: \"ssdp:discover\"\r\n" +
			"ST: ssdp:all\r\n" +
			"MX: 3\r\n\r\n")
	case 111:
		// RPC Portmapper
		payload = []byte{
			0x12, 0x34, 0x56, 0x78, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x02, 0x00, 0x01, 0x86, 0xa0,
			0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x03,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		}
	case 1434:
		// MSSQL Browser Request
		payload = []byte{0x02}
	default:
		// Empty payload for unknown UDP
		payload = []byte("\r\n")
	}

	_, err := conn.Write(payload)
	if err != nil {
		return nil
	}

	bufPtr := bufferPool.Get().(*[]byte)
	buf := *bufPtr
	defer bufferPool.Put(bufPtr)

	n, err := conn.Read(buf)
	if err != nil || n == 0 {
		return nil
	}
	
	if port == 53 { return []byte("DNS Server") }
	if port == 161 { return []byte("SNMP Agent") }
	if port == 123 { return []byte("NTP Server") }
	if port == 137 { return []byte("NetBIOS Name Service") }
	if port == 500 || port == 4500 { return []byte("IKE/IPsec VPN") }
	if port == 623 { return []byte("IPMI BMC Agent") }
	if port == 1900 { return []byte("UPnP Service") }
	if port == 111 { return []byte("RPC Portmapper") }
	if port == 1434 { return []byte("MSSQL Browser Agent") }

	return append([]byte(nil), buf[:n]...)
}
