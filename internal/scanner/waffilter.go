package scanner

import (
	"context"
	"fmt"
	"net"
	"time"

	"github.com/raptor-recon/raptor/internal/proxy"
)

// CheckWAF realiza una prueba heurística proactiva antes de un escaneo masivo.
// Intenta conectar a 2 puertos TCP de alto rango, poco comunes (31337 y 60000).
// Si AMBOS responden afirmativamente, se asume que el host es un Tarpit / Honeypot,
// ya que abre sistemáticamente todos los puertos.
func CheckWAF(ctx context.Context, ip string, timeout time.Duration, dialer proxy.ContextDialer) bool {
	ports := []int{31337, 60000}
	openCount := 0

	for _, port := range ports {
		if checkPort(ctx, ip, port, timeout, dialer) {
			openCount++
		}
	}

	return openCount == 2
}

func checkPort(ctx context.Context, ip string, port int, timeout time.Duration, dialer proxy.ContextDialer) bool {
	addr := net.JoinHostPort(ip, fmt.Sprintf("%d", port))
	var d proxy.ContextDialer
	if dialer != nil {
		d = dialer
	} else {
		d = &net.Dialer{Timeout: timeout}
	}

	dialCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	// Proteger contra agotamiento de sockets globales
	conn, err := d.DialContext(dialCtx, "tcp", addr)
	if err == nil {
		if tcpConn, ok := conn.(*net.TCPConn); ok {
			_ = tcpConn.SetLinger(0)
		}
		_ = conn.Close()
		return true
	}

	return false
}
