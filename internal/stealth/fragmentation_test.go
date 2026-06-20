package stealth

import (
	"bytes"
	"context"
	"net"
	"testing"
	"time"
)

func TestFragmentedConn_LowProfile(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()

	ctx := context.Background()
	fc := WrapConn(ctx, client, ProfileLow)

	payload := make([]byte, 100)
	for i := range payload {
		payload[i] = byte(i)
	}

	go func() {
		fc.Write(payload)
	}()

	buf := make([]byte, 100)
	n, err := server.Read(buf)
	if err != nil {
		t.Fatalf("Read error: %v", err)
	}

	// For ProfileLow, chunk size is 64
	if n != 64 {
		t.Errorf("Expected first read of 64 bytes, got %d", n)
	}

	n, err = server.Read(buf[64:])
	if err != nil {
		t.Fatalf("Read error: %v", err)
	}

	if n != 36 {
		t.Errorf("Expected second read of 36 bytes, got %d", n)
	}

	if !bytes.Equal(buf, payload) {
		t.Errorf("Payload mismatch")
	}
}

func TestFragmentedConn_TLSClientHello(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()

	ctx := context.Background()
	fc := WrapConn(ctx, client, ProfileLow) // Use low, but it should be overridden to 1 byte chunks because of TLS

	// Simulate TLS Client Hello (0x16, 0x03)
	payload := []byte{0x16, 0x03, 0x01, 0x00, 0x5a, 0x01, 0x02, 0x03}

	go func() {
		fc.Write(payload)
	}()

	// Expect 1 byte read for the first byte
	buf := make([]byte, 1)
	n, err := server.Read(buf)
	if err != nil {
		t.Fatalf("Read error: %v", err)
	}
	if n != 1 {
		t.Errorf("Expected 1 byte read due to TLS fragmentation, got %d", n)
	}
	if buf[0] != 0x16 {
		t.Errorf("Expected 0x16, got %x", buf[0])
	}
}

func TestFragmentedConn_Cancellation(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()

	ctx, cancel := context.WithCancel(context.Background())
	fc := WrapConn(ctx, client, ProfileMedium)

	payload := make([]byte, 20)

	go func() {
		// Cancel while writing
		cancel()
	}()

	// Give cancellation a little time to propagate
	time.Sleep(10 * time.Millisecond)

	_, err := fc.Write(payload)
	if err == nil {
		t.Errorf("Expected cancellation error, got nil")
	}
}
