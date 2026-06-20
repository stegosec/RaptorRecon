// Package pivot implementa la detección de proxies abiertos y el sub-escaneo
// de redes internas a través de ellos (Proxy Pivot Detection).
// Cero dependencias de binarios externos — solo stdlib + proxy interno.
package pivot

import (
	"fmt"
	"net"
	"strings"
	"time"
)

// VerifyHTTPConnect verifica que el servidor en host:port acepta peticiones
// HTTP CONNECT arbitrarias, confirmando que es un Open Proxy abusable.
//
// Envía: CONNECT google.com:443 HTTP/1.1 (destino externo inocuo)
// Acepta: respuesta conteniendo "200" (agnostico al texto exacto para
// máxima compatibilidad con proxies no-standard como Squid, Privoxy, tinyproxy).
//
// SetLinger(0) antes de cerrar previene acumulación de sockets TIME_WAIT
// durante escaneos masivos.
func VerifyHTTPConnect(host string, port int, timeout time.Duration) bool {
	addr := fmt.Sprintf("%s:%d", host, port)
	conn, err := net.DialTimeout("tcp", addr, timeout)
	if err != nil {
		return false
	}
	defer func() {
		if tcpConn, ok := conn.(*net.TCPConn); ok {
			_ = tcpConn.SetLinger(0)
		}
		_ = conn.Close()
	}()

	_ = conn.SetDeadline(time.Now().Add(timeout))

	req := "CONNECT google.com:443 HTTP/1.1\r\n" +
		"Host: google.com:443\r\n" +
		"User-Agent: RaptorRecon/1.0\r\n" +
		"Proxy-Connection: keep-alive\r\n\r\n"

	if _, err := conn.Write([]byte(req)); err != nil {
		return false
	}

	buf := make([]byte, 512)
	n, _ := conn.Read(buf)
	if n == 0 {
		return false
	}

	resp := string(buf[:n])
	// Aceptar 200 (OK), 403 (Forbidden por ACL), 503/504 (Error de red)
	// Siempre y cuando tenga formato HTTP/1.x, es casi seguro un proxy.
	isHTTP := strings.HasPrefix(resp, "HTTP/1.0") || strings.HasPrefix(resp, "HTTP/1.1")
	hasCode := strings.Contains(resp, " 200 ") || strings.Contains(resp, " 403 ") || 
			   strings.Contains(resp, " 502 ") || strings.Contains(resp, " 503 ") || 
			   strings.Contains(resp, " 504 ") || strings.Contains(resp, "squid")

	return isHTTP && hasCode
}

// VerifySOCKS5 verifica que el servidor en host:port es un proxy SOCKS5
// que acepta conexiones sin autenticación (METHOD=0x00).
//
// Protocolo SOCKS5 (RFC 1928):
//   - Cliente envía: VER(1)=0x05, NMETHODS(1)=0x01, METHODS(1)=0x00
//   - Servidor responde: VER(1)=0x05, METHOD(1)=0x00 (aceptado sin auth)
//   - Si METHOD=0xFF → rechazado (requiere autenticación)
func VerifySOCKS5(host string, port int, timeout time.Duration) bool {
	addr := fmt.Sprintf("%s:%d", host, port)
	conn, err := net.DialTimeout("tcp", addr, timeout)
	if err != nil {
		return false
	}
	defer func() {
		if tcpConn, ok := conn.(*net.TCPConn); ok {
			_ = tcpConn.SetLinger(0)
		}
		_ = conn.Close()
	}()

	_ = conn.SetDeadline(time.Now().Add(timeout))

	// SOCKS5 greeting: VER=5, NMETHODS=1, METHOD=0x00 (no-auth)
	greeting := []byte{0x05, 0x01, 0x00}
	if _, err := conn.Write(greeting); err != nil {
		return false
	}

	// Leer exactamente 2 bytes de respuesta
	buf := make([]byte, 2)
	n, err := conn.Read(buf)
	if err != nil || n < 2 {
		return false
	}

	// VER=0x05, METHOD=0x00 → sin autenticación aceptada
	return buf[0] == 0x05 && buf[1] == 0x00
}
