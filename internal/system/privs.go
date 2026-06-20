package system

import (
	"os"
	"runtime"
)

// HasAdminPrivileges checks if the current process is running with elevated privileges.
// On Windows, it attempts to open the physical drive.
// On Linux/macOS, it checks if the effective UID is 0 (root).
func HasAdminPrivileges() bool {
	if runtime.GOOS == "windows" {
		// En Windows, abrir un disco físico requiere privilegios de Administrador.
		f, err := os.Open("\\\\.\\PHYSICALDRIVE0")
		if err != nil {
			return false
		}
		_ = f.Close()
		return true
	}
	// Para sistemas basados en Unix (Linux, macOS, BSD)
	return os.Geteuid() == 0
}
