package system

import (
	"log"
	"runtime/debug"
)

// EnableAutoMemoryLimit dynamically sets Go's soft memory limit to 75% of the OS's available free memory.
// This forces the Garbage Collector to work aggressively before reaching the OS limits, preventing OOM kills.
func EnableAutoMemoryLimit() {
	freeRAM := getFreeMemory()
	if freeRAM <= 0 {
		log.Println("WARN: No se pudo determinar la memoria libre del SO. Usando GC por defecto.")
		return
	}

	// Calculate 75% of the free memory
	limit := int64(float64(freeRAM) * 0.75)
	
	// Enforce minimum limit of 100MB just in case
	if limit < 100*1024*1024 {
		limit = 100 * 1024 * 1024
	}

	previousLimit := debug.SetMemoryLimit(limit)
	log.Printf("INFO: Memoria libre detectada: %d MB. GOMEMLIMIT ajustado al 75%%: %d MB (Anterior: %d MB)\n", 
		freeRAM/(1024*1024), limit/(1024*1024), previousLimit/(1024*1024))
}
