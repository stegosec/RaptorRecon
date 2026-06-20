package system

import (
	"syscall"
	"unsafe"
)

type memoryStatusEx struct {
	cbSize                  uint32
	dwMemoryLoad            uint32
	ullTotalPhys            uint64
	ullAvailPhys            uint64
	ullTotalPageFile        uint64
	ullAvailPageFile        uint64
	ullTotalVirtual         uint64
	ullAvailVirtual         uint64
	ullAvailExtendedVirtual uint64
}

func getFreeMemory() uint64 {
	kernel32, err := syscall.LoadDLL("kernel32.dll")
	if err != nil {
		return 0
	}
	defer kernel32.Release()

	globalMemoryStatusEx, err := kernel32.FindProc("GlobalMemoryStatusEx")
	if err != nil {
		return 0
	}

	var memInfo memoryStatusEx
	memInfo.cbSize = uint32(unsafe.Sizeof(memInfo))

	ret, _, _ := globalMemoryStatusEx.Call(uintptr(unsafe.Pointer(&memInfo))) // #nosec G103 - Requires unsafe.Pointer for Syscall
	if ret == 0 {
		return 0
	}

	return memInfo.ullAvailPhys
}
