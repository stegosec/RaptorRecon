//go:build !windows
// +build !windows

package system

func getFreeMemory() uint64 {
	// Fallback/stub for non-windows platforms.
	// In a real implementation we would parse /proc/meminfo or use sysctl.
	return 0
}
