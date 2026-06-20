package proxy

import (
	"bufio"
	"context"
	"encoding/base64"
	"fmt"
	"net"
	"net/url"
	"strings"
	"time"

	"golang.org/x/net/proxy"
)

// ContextDialer is an interface for a dialer that supports context timeouts.
type ContextDialer interface {
	DialContext(ctx context.Context, network, address string) (net.Conn, error)
}

// defaultContextDialer envuelve proxy.Dialer cuando no soporta Context nativamente.
// Implementa cancelación limpia compitiendo ctx.Done() contra el Dial subyacente.
type defaultContextDialer struct {
	d proxy.Dialer
}

// dialResult agrupa el resultado de una conexión asíncrona.
type dialResult struct {
	conn net.Conn
	err  error
}

func (d *defaultContextDialer) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	// Verificar cancelación previa antes de lanzar la goroutine
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	ch := make(chan dialResult, 1)
	go func() {
		conn, err := d.d.Dial(network, address)
		ch <- dialResult{conn: conn, err: err}
	}()

	select {
	case <-ctx.Done():
		// El contexto fue cancelado/expiró antes de que el Dial terminara.
		// Esperamos en background para cerrar la conexión si llega a abrirse,
		// previniendo el file-descriptor leak.
		go func() {
			if r := <-ch; r.conn != nil {
				_ = r.conn.Close()
			}
		}()
		return nil, ctx.Err()
	case r := <-ch:
		return r.conn, r.err
	}
}

// NewDialer creates a new ContextDialer based on the proxy URL.
// Supported schemes: http, https, socks5
func NewDialer(proxyURL string, timeout time.Duration) (ContextDialer, error) {
	if proxyURL == "" {
		return &net.Dialer{Timeout: timeout}, nil
	}

	u, err := url.Parse(proxyURL)
	if err != nil {
		return nil, fmt.Errorf("invalid proxy URL: %v", err)
	}

	switch u.Scheme {
	case "socks5":
		baseDialer := &net.Dialer{Timeout: timeout}
		d, err := proxy.FromURL(u, baseDialer)
		if err != nil {
			return nil, err
		}
		
		// proxy.FromURL returns a proxy.Dialer, we need a ContextDialer
		if cd, ok := d.(ContextDialer); ok {
			return cd, nil
		}
		
		return &defaultContextDialer{d: d}, nil

	case "http", "https":
		return &httpProxyDialer{
			URL:     u,
			Timeout: timeout,
		}, nil
	default:
		return nil, fmt.Errorf("unsupported proxy scheme: %s", u.Scheme)
	}
}

// httpProxyDialer implements HTTP CONNECT tunneling.
type httpProxyDialer struct {
	URL     *url.URL
	Timeout time.Duration
}

func (d *httpProxyDialer) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	if !strings.HasPrefix(network, "tcp") {
		return nil, fmt.Errorf("http proxy only supports tcp, not %s", network)
	}

	dialer := &net.Dialer{Timeout: d.Timeout}
	// Conectar al proxy
	proxyAddr := d.URL.Host
	if !strings.Contains(proxyAddr, ":") {
		if d.URL.Scheme == "https" {
			proxyAddr += ":443"
		} else {
			proxyAddr += ":80"
		}
	}

	conn, err := dialer.DialContext(ctx, "tcp", proxyAddr)
	if err != nil {
		return nil, err
	}

	// Túnel CONNECT
	req := fmt.Sprintf("CONNECT %s HTTP/1.1\r\nHost: %s\r\n", address, address)
	if d.URL.User != nil {
		auth := d.URL.User.String()
		encodedAuth := base64.StdEncoding.EncodeToString([]byte(auth))
		req += fmt.Sprintf("Proxy-Authorization: Basic %s\r\n", encodedAuth)
	}
	req += "\r\n"

	if _, err := conn.Write([]byte(req)); err != nil {
		_ = conn.Close()
		return nil, err
	}

	// Leer respuesta del proxy
	br := bufio.NewReader(conn)
	statusLine, err := br.ReadString('\n')
	if err != nil {
		_ = conn.Close()
		return nil, err
	}

	if !strings.Contains(statusLine, " 200") {
		_ = conn.Close()
		return nil, fmt.Errorf("proxy connection failed: %s", strings.TrimSpace(statusLine))
	}

	// Consumir el resto de los headers
	for {
		line, err := br.ReadString('\n')
		if err != nil {
			_ = conn.Close()
			return nil, err
		}
		if line == "\r\n" || line == "\n" {
			break
		}
	}

	// Importante: No podemos simplemente retornar conn porque bufio.Reader podría tener
	// bytes cacheados del servidor remoto (ej. si el servidor envía un banner inmediatamente).
	// Necesitamos envolver la conexión para leer primero del buffer antes de leer del socket.
	return &bufferedConn{Conn: conn, br: br}, nil
}

// bufferedConn envuelve un net.Conn con un bufio.Reader para consumir bytes remanentes.
type bufferedConn struct {
	net.Conn
	br *bufio.Reader
}

func (c *bufferedConn) Read(b []byte) (int, error) {
	return c.br.Read(b)
}
