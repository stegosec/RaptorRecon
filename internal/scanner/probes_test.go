package scanner

import (
	"testing"
)

func TestGuessService(t *testing.T) {
	tests := []struct {
		port     int
		banner   []byte
		expected string
	}{
		{22, []byte("SSH-2.0-OpenSSH"), "ssh"},
		{80, []byte("HTTP/1.1 200 OK\r\nServer: nginx"), "http"},
		{443, []byte(""), "https"}, // inferred by port
		{21, []byte("220 (vsFTPd 3.0.3)"), "ftp"},
	}

	for _, tt := range tests {
		actual := GuessService(tt.port, tt.banner)
		if actual != tt.expected {
			t.Errorf("GuessService(%d, %q) = %q; want %q", tt.port, tt.banner, actual, tt.expected)
		}
	}
}
