//go:build windows

package main

import (
	"golang.org/x/sys/windows"
)

func init() {
	disableQuickEdit()
}

// disableQuickEdit desactiva el "QuickEdit Mode" en la consola de Windows.
// Esto evita que el programa se pause accidentalmente (pareciendo que se traba)
// cuando el usuario hace clic dentro de la ventana de CMD o PowerShell.
func disableQuickEdit() {
	handle, err := windows.GetStdHandle(windows.STD_INPUT_HANDLE)
	if err != nil {
		return
	}
	var mode uint32
	err = windows.GetConsoleMode(handle, &mode)
	if err != nil {
		return
	}
	// Desactivar ENABLE_QUICK_EDIT_MODE (0x0040)
	mode &^= windows.ENABLE_QUICK_EDIT_MODE
	_ = windows.SetConsoleMode(handle, mode)
}
