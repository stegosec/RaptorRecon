package baselining

import (
	"encoding/json"
	"os"
	"path/filepath"
	"time"
)

// HostState representa el estado de los puertos de un host en un momento dado.
type HostState struct {
	OpenPorts []int `json:"open_ports"`
}

// StateSnapshot es la foto de la red descubierta.
type StateSnapshot struct {
	Timestamp time.Time            `json:"timestamp"`
	Hosts     map[string]HostState `json:"hosts"`
}

// DeltaReport contiene las diferencias entre el escaneo anterior y el actual.
type DeltaReport struct {
	NewHosts     []string `json:"new_hosts"`     // IPs que no estaban en el snapshot anterior
	MissingHosts []string `json:"missing_hosts"` // IPs que estaban pero ya no responden
	NewPorts     int      `json:"new_ports"`     // Puertos recién expuestos en hosts existentes
}

// LoadState lee el snapshot previo desde el archivo indicado.
func LoadState(filePath string) (*StateSnapshot, error) {
	cleanPath := filepath.Clean(filePath)
	file, err := os.Open(cleanPath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil // Es la primera vez que se escanea, no hay estado previo
		}
		return nil, err
	}
	defer file.Close()

	var state StateSnapshot
	decoder := json.NewDecoder(file)
	if err := decoder.Decode(&state); err != nil {
		return nil, err
	}
	return &state, nil
}

// SaveState escribe el snapshot actual al archivo indicado.
func SaveState(filePath string, state *StateSnapshot) error {
	cleanPath := filepath.Clean(filePath)
	file, err := os.Create(cleanPath)
	if err != nil {
		return err
	}
	defer file.Close()

	encoder := json.NewEncoder(file)
	encoder.SetIndent("", "  ")
	return encoder.Encode(state)
}

// ComputeDelta compara el snapshot viejo con el nuevo y devuelve el reporte de diferencias.
func ComputeDelta(oldState *StateSnapshot, newState *StateSnapshot) DeltaReport {
	delta := DeltaReport{
		NewHosts:     []string{},
		MissingHosts: []string{},
		NewPorts:     0,
	}

	if oldState == nil {
		// Todo es nuevo
		for host := range newState.Hosts {
			delta.NewHosts = append(delta.NewHosts, host)
		}
		return delta
	}

	// Buscar hosts desaparecidos
	for oldHost := range oldState.Hosts {
		if _, exists := newState.Hosts[oldHost]; !exists {
			delta.MissingHosts = append(delta.MissingHosts, oldHost)
		}
	}

	// Buscar hosts nuevos y puertos nuevos
	for newHost, newStateHost := range newState.Hosts {
		oldStateHost, exists := oldState.Hosts[newHost]
		if !exists {
			delta.NewHosts = append(delta.NewHosts, newHost)
			continue
		}

		// Host ya existía, checar si hay puertos nuevos
		oldPortsMap := make(map[int]bool)
		for _, p := range oldStateHost.OpenPorts {
			oldPortsMap[p] = true
		}

		for _, p := range newStateHost.OpenPorts {
			if !oldPortsMap[p] {
				delta.NewPorts++
			}
		}
	}

	return delta
}
