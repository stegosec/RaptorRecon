package stealth

import (
	"context"
	"math/rand/v2"
	"net"
	"time"
)

// FragmentProfile defines the aggressive level of DPI evasion.
type FragmentProfile string

const (
	ProfileOff    FragmentProfile = "off"
	ProfileLow    FragmentProfile = "low"
	ProfileMedium FragmentProfile = "medium"
	ProfileHigh   FragmentProfile = "high"
	ProfileAuto   FragmentProfile = "auto"
)

// FragmentedConn wraps a net.Conn to fragment outgoing writes for DPI evasion.
type FragmentedConn struct {
	net.Conn
	profile    FragmentProfile
	chunkSize  int
	minDelay   time.Duration
	maxDelay   time.Duration
	firstWrite bool
	ctx        context.Context
}

// WrapConn wraps an existing net.Conn with fragmentation if the profile is not Off.
func WrapConn(ctx context.Context, conn net.Conn, profile FragmentProfile) net.Conn {
	if profile == ProfileOff || profile == "" {
		return conn
	}

	fc := &FragmentedConn{
		Conn:       conn,
		profile:    profile,
		firstWrite: true,
		ctx:        ctx,
	}

	switch profile {
	case ProfileLow:
		fc.chunkSize = 64
		fc.minDelay = 0
		fc.maxDelay = 0
	case ProfileMedium:
		fc.chunkSize = 8
		fc.minDelay = 5 * time.Millisecond
		fc.maxDelay = 15 * time.Millisecond
	case ProfileHigh, ProfileAuto: // Auto gets resolved to High/Medium upstream, but fallback to High
		fc.chunkSize = 1
		fc.minDelay = 10 * time.Millisecond
		fc.maxDelay = 50 * time.Millisecond
	default:
		return conn
	}

	return fc
}

// Write implements the net.Conn Write method with fragmentation and jitter.
func (c *FragmentedConn) Write(b []byte) (n int, err error) {
	if len(b) == 0 {
		return c.Conn.Write(b)
	}

	if c.firstWrite {
		c.firstWrite = false
		// Force TCP_NODELAY on underlying TCP connections to disable Nagle's algorithm.
		// This ensures OS doesn't coalesce our carefully fragmented chunks.
		if tcpConn, ok := c.Conn.(*net.TCPConn); ok {
			_ = tcpConn.SetNoDelay(true)
		}
	}

	chunkSize := c.chunkSize

	// TLS ClientHello fingerprinting evasion.
	// TLS Handshake (0x16), Version TLS 1.0/1.1/1.2/1.3 (0x03)
	if len(b) >= 2 && b[0] == 0x16 && b[1] == 0x03 {
		chunkSize = 1 // Force 1-byte chunks for the TLS ClientHello
	}

	totalWritten := 0
	for totalWritten < len(b) {
		// Check for context cancellation before each chunk
		if c.ctx != nil && c.ctx.Err() != nil {
			return totalWritten, c.ctx.Err()
		}

		end := totalWritten + chunkSize
		if end > len(b) {
			end = len(b)
		}

		chunk := b[totalWritten:end]
		written, err := c.Conn.Write(chunk)
		totalWritten += written

		if err != nil {
			return totalWritten, err
		}

		if totalWritten < len(b) && c.maxDelay > 0 {
			delay := c.minDelay
			if c.maxDelay > c.minDelay {
				// Jitter random calculation
				diff := int64(c.maxDelay - c.minDelay)
				/* #nosec G404 */
				delay += time.Duration(rand.Int64N(diff))
			}
			time.Sleep(delay)
		}
	}

	return totalWritten, nil
}
