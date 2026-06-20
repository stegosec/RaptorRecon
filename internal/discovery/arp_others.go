//go:build !windows
// +build !windows

package discovery

// checkARP para sistemas que no son Windows
// Retorna (alive, supported)
func checkARP(ipStr string) (bool, bool) {
	return false, false // Forzamos fallback a TCP
}
