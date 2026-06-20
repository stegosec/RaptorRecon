// Package stealth proporciona utilidades de evasión para Raptor Recon (Ghost Mode).
// Centraliza las técnicas anti-IDS/IPS que pueden ser consumidas por cualquier módulo
// sin crear ciclos de dependencias.
//
// Tácticas implementadas:
//   - RandomUserAgent: rotación de User-Agents reales para evadir WAFs
//   - Jitter: ruido temporal aleatorio para romper timing signatures
//   - ShuffleTargets: aleatorización Fisher-Yates del orden de escaneo
package stealth

import (
	"crypto/rand"
	"math/big"
	"time"
)

// ──────────────────────────────────────────────
// User-Agent Rotation
// ──────────────────────────────────────────────

// userAgents contiene User-Agents reales y actualizados (2025/2026) de navegadores
// populares en distintos sistemas operativos. NUNCA usar "Go-http-client/1.1"
// ya que es una bandera roja instantánea para cualquier WAF/IDS.
var userAgents = []string{
	// Chrome 125 — Windows 10
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36",
	// Chrome 124 — macOS 14 Sonoma
	"Mozilla/5.0 (Macintosh; Intel Mac OS X 14_5) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
	// Firefox 126 — Ubuntu Linux
	"Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:126.0) Gecko/20100101 Firefox/126.0",
	// Safari 17.5 — macOS 14 Sonoma
	"Mozilla/5.0 (Macintosh; Intel Mac OS X 14_5) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.5 Safari/605.1.15",
	// Edge 125 — Windows 11
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36 Edg/125.0.0.0",
	// Chrome 125 — Android 14
	"Mozilla/5.0 (Linux; Android 14; Pixel 8 Pro) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Mobile Safari/537.36",
	// Firefox 125 — Windows 10
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:125.0) Gecko/20100101 Firefox/125.0",
	// Safari 17 — iPhone iOS 17
	"Mozilla/5.0 (iPhone; CPU iPhone OS 17_5 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.5 Mobile/15E148 Safari/604.1",
}

// RandomUserAgent retorna un User-Agent aleatorio del pool.
// Cada invocación selecciona uno distinto, distribuyendo la huella digital
// de las peticiones HTTP de Raptor entre múltiples identidades de navegador.
func RandomUserAgent() string {
	n, _ := rand.Int(rand.Reader, big.NewInt(int64(len(userAgents))))
	return userAgents[n.Int64()]
}

// ──────────────────────────────────────────────
// Temporal Jitter (Ruido Blanco)
// ──────────────────────────────────────────────

// Jitter introduce un delay aleatorio entre min y max.
// Esto rompe la "timing signature" predecible del escáner, haciendo que los
// intervalos entre conexiones TCP sean irregulares y no correlacionables
// por un IDS/IPS basado en patrones temporales.
//
// Ejemplo: Jitter(5ms, 50ms) → sleep entre 5ms y 50ms
func Jitter(min, max time.Duration) {
	if max <= min {
		time.Sleep(min)
		return
	}
	delta := max - min
	n, _ := rand.Int(rand.Reader, big.NewInt(int64(delta)))
	jitter := min + time.Duration(n.Int64())
	time.Sleep(jitter)
}

// ──────────────────────────────────────────────
// Target Shuffling (Fisher-Yates)
// ──────────────────────────────────────────────

// Shuffleable es una interfaz genérica para tipos que pueden ser mezclados.
// Esto permite reutilizar el algoritmo de shuffle sin acoplar el paquete
// a los tipos del scanner.
type Shuffleable interface {
	Len() int
	Swap(i, j int)
}

// Shuffle aplica el algoritmo Fisher-Yates (Knuth shuffle) in-place
// a cualquier tipo que implemente Shuffleable.
// Complejidad: O(n) tiempo, O(1) espacio.
func Shuffle(s Shuffleable) {
	n := s.Len()
	for i := n - 1; i > 0; i-- {
		jBig, _ := rand.Int(rand.Reader, big.NewInt(int64(i+1)))
		s.Swap(i, int(jBig.Int64()))
	}
}
