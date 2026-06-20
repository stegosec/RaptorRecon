package scanner

import (
	"github.com/raptor-recon/raptor/internal/stealth"
)

// CommonPorts es la lista de puertos que se escanean por defecto.
var CommonPorts = []int{
	21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143,
	443, 445, 993, 995, 1080, 1433, 1723, 3128, 3306, 3389, 5432,
	5900, 6379, 8080, 8118, 8443, 9200, 27017,
}

// targetSlice implementa stealth.Shuffleable para poder aplicar Fisher-Yates
// sin exponer los internos del paquete scanner al paquete stealth.
type targetSlice []Target

func (t targetSlice) Len() int      { return len(t) }
func (t targetSlice) Swap(i, j int) { t[i], t[j] = t[j], t[i] }

// GenerateTargetsFromIPs genera targets a partir de un canal de IPs.
//
// Si shuffle es true (Ghost Mode), acumula todos los targets en un slice,
// aplica un Fisher-Yates shuffle para aleatorizar completamente el orden
// de escaneo, y luego los envía al canal. Esto evita que los IDS/IPS
// detecten barridos lineales (192.168.1.1, .2, .3...).
//
// Si shuffle es false, los targets se envían en orden secuencial por IP
// (comportamiento original, streaming sin buffering completo).
func GenerateTargetsFromIPs(ips <-chan string, ports []Target, buffer int, shuffle bool) <-chan Target {
	ch := make(chan Target, buffer)
	go func() {
		defer close(ch)

		if shuffle {
			// Ghost Mode: Chunked Shuffle para no devorar la RAM
			chunkSize := 5000
			chunk := make(targetSlice, 0, chunkSize)

			for ip := range ips {
				for _, p := range ports {
					chunk = append(chunk, Target{Host: ip, Port: p.Port, Protocol: p.Protocol})
					if len(chunk) >= chunkSize {
						stealth.Shuffle(chunk)
						for _, t := range chunk {
							ch <- t
						}
						chunk = chunk[:0] // Limpiar reteniendo capacidad
					}
				}
			}
			// Vaciar remanentes
			if len(chunk) > 0 {
				stealth.Shuffle(chunk)
				for _, t := range chunk {
					ch <- t
				}
			}
		} else {
			// Generación secuencial perezosa pura (Lazy Evaluation)
			for ip := range ips {
				for _, p := range ports {
					ch <- Target{Host: ip, Port: p.Port, Protocol: p.Protocol}
				}
			}
		}
	}()
	return ch
}
