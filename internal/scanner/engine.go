// Package scanner implementa el motor de escaneo TCP nativo de Raptor Recon.
// CERO dependencias externas: usa exclusivamente net, sync, context de la stdlib de Go.
package scanner

import (
	"context"
	"fmt"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/raptor-recon/raptor/internal/stealth"
	"github.com/raptor-recon/raptor/internal/proxy"
	"github.com/raptor-recon/raptor/internal/rules"
)

// ──────────────────────────────────────────────
// Tipos públicos
// ──────────────────────────────────────────────

// Target representa un par (host, puerto, protocolo) a escanear.
type Target struct {
	Host     string
	Port     int
	Protocol string // "tcp" o "udp"
}

// Result es la salida de escanear un único Target.
type Result struct {
	Host     string        `json:"host"`
	Port     int           `json:"port"`
	Protocol string        `json:"protocol"`
	Service  string        `json:"service"`
	Open     bool          `json:"open"`
	Latency  time.Duration `json:"latency"`
	Banner   string        `json:"banner,omitempty"`
}

type Config struct {
	Workers     int           // goroutines concurrentes (default 500)
	Timeout     time.Duration // timeout de cada conexión TCP (default 500ms)
	RateLimit   int           // conexiones/segundo; 0 = sin límite
	GrabBanners bool          // intentar leer banner tras conectar
	Jitter      bool          // Ghost Mode: delay aleatorio (5-50ms) entre conexiones
	SafeMode    bool          // Safe Mode: Desactivar comprobaciones agresivas (Fuzzing, etc.)
	FragProfile stealth.FragmentProfile // Profile de fragmentación para evasión DPI
	ForceRate   int           // Si > 0, deshabilita AIMD y fuerza el rate limit absoluto.
	Throttle    int           // Milisegundos de pausa fija entre tareas por worker
	Dialer      proxy.ContextDialer // Proxy dialer personalizado (opcional)
	L7Templates map[int][]rules.L7Template // Reglas L7 indexadas por puerto (O(1) lookup)

	// L7 Port-Triggered Execution Policy
	// IsAutoMode=true: todos los templates se ejecutan si coincide el puerto (--auto o CLI sin restricciones).
	// IsAutoMode=false + AllowedL7IDs=[...]: solo los IDs explicitamente seleccionados en la TUI se ejecutan.
	IsAutoMode   bool     // true = Modo Autónomo (todos los templates autorizados)
	AllowedL7IDs []string // IDs de templates autorizados en Modo Manual/TUI
}

// DefaultConfig devuelve valores listos para producción.
func DefaultConfig() Config {
	return Config{
		Workers:     500,
		Timeout:     500 * time.Millisecond,
		RateLimit:   2000,
		GrabBanners: false,
		Jitter:      false,
	}
}

// Stats expone contadores atómicos de la sesión de escaneo.
type Stats struct {
	Scanned   atomic.Int64
	Open      atomic.Int64
	StartTime time.Time
}

// Snapshot devuelve una copia de los contadores en el instante actual.
func (s *Stats) Snapshot() (scanned, open int64, elapsed time.Duration) {
	return s.Scanned.Load(), s.Open.Load(), time.Since(s.StartTime)
}

// ──────────────────────────────────────────────
// Engine
// ──────────────────────────────────────────────

// Engine es el motor central de escaneo.
// Crear con NewEngine; llamar a Scan para iniciar.
type Engine struct {
	cfg              Config
	Stats            *Stats
	tokens           chan struct{}
	ctx              context.Context // Para cancelar refillTokens
	currentRate      atomic.Int64
	congestionSignal chan bool
}

// Config returns the current configuration of the engine.
func (e *Engine) Config() Config {
	return e.cfg
}

// NewEngine crea un nuevo Engine con sus workers.
func NewEngine(ctx context.Context, cfg Config) *Engine {
	e := &Engine{
		cfg:              cfg,
		Stats:            &Stats{},
		ctx:              ctx,
		congestionSignal: make(chan bool, 100),
	}

	if cfg.RateLimit > 0 {
		e.tokens = make(chan struct{}, cfg.RateLimit)
		// pre-fill the bucket
		for i := 0; i < cfg.RateLimit; i++ {
			e.tokens <- struct{}{}
		}
		go e.refillTokens()
	}
	return e
}

// refillTokens pone un token en el cubo a la tasa configurada.
// Corre en su propia goroutine durante toda la vida del Engine.
func (e *Engine) refillTokens() {
	var initialRate int64 = int64(e.cfg.RateLimit)
	if e.cfg.ForceRate > 0 {
		initialRate = int64(e.cfg.ForceRate)
	}
	if initialRate <= 0 {
		initialRate = 2000
	}
	e.currentRate.Store(initialRate)

	updateTicker := func(rate int64) *time.Ticker {
		if rate <= 0 {
			rate = 1
		}
		return time.NewTicker(time.Second / time.Duration(rate))
	}

	ticker := updateTicker(initialRate)
	defer ticker.Stop()

	successCounter := 0

	for {
		select {
		case <-ticker.C:
			select {
			case e.tokens <- struct{}{}:
			default:
			}
		case isError := <-e.congestionSignal:
			if e.cfg.ForceRate == 0 { // AIMD active
				if isError {
					// Multiplicative decrease
					newRate := e.currentRate.Load() / 2
					if newRate < 50 {
						newRate = 50
					}
					if newRate != e.currentRate.Load() {
						e.currentRate.Store(newRate)
						ticker.Stop()
						ticker = updateTicker(newRate)
						successCounter = 0
					}
				} else {
					// Additive increase
					successCounter++
					if successCounter > 100 {
						newRate := e.currentRate.Load() + 100
						maxRate := int64(e.cfg.RateLimit)
						if maxRate <= 0 {
							maxRate = 2000
						}
						if newRate > maxRate {
							newRate = maxRate
						}
						if newRate != e.currentRate.Load() {
							e.currentRate.Store(newRate)
							ticker.Stop()
							ticker = updateTicker(newRate)
						}
						successCounter = 0
					}
				}
			}
		case <-e.ctx.Done():
			return // cleanup goroutine when context cancels
		}
	}
}

// Scan lanza el pool de workers y retorna un canal de Results.
// El canal se cierra cuando todos los targets han sido procesados o el contexto cancela.
// El caller envía targets al canal `targets` y lo cierra al terminar.
//
// Uso típico:
//
//	targets := GenerateTargets("10.0.0.0/24", commonPorts)
//	results := engine.Scan(ctx, targets)
//	for r := range results {
//	    if r.Open { ... }
//	}
func (e *Engine) Scan(ctx context.Context, targets <-chan Target) <-chan Result {
	e.Stats.StartTime = time.Now()
	e.Stats.Scanned.Store(0)
	e.Stats.Open.Store(0)

	out := make(chan Result, e.cfg.Workers*4)

	var wg sync.WaitGroup
	wg.Add(e.cfg.Workers)

	for i := 0; i < e.cfg.Workers; i++ {
		go func() {
			defer wg.Done()
			for {
				select {
				case <-ctx.Done():
					return
				case t, ok := <-targets:
					if !ok {
						return // canal cerrado: no quedan targets
					}
					// Adquirir token antes de conectar (rate limiting)
					if e.tokens != nil {
						select {
						case <-e.tokens:
						case <-ctx.Done():
							return
						}
					}
					// Ghost Mode: inyectar jitter temporal antes de cada probe
					// para romper la timing signature del escáner.
					if e.cfg.Jitter {
						stealth.Jitter(5*time.Millisecond, 50*time.Millisecond)
					}
					// Throttle limit: delay duro para evitar DoS en infraestructuras sensibles
					if e.cfg.Throttle > 0 {
						time.Sleep(time.Duration(e.cfg.Throttle) * time.Millisecond)
					}
					r := e.probe(ctx, t)
					e.Stats.Scanned.Add(1)
					if r.Open {
						e.Stats.Open.Add(1)
					}
					select {
					case out <- r:
					case <-ctx.Done():
						return
					}
				}
			}
		}()
	}

	// Cerrar el canal de salida cuando todos los workers terminen.
	go func() {
		wg.Wait()
		close(out)
	}()

	return out
}

// probe realiza el TCP connect scan en un único target.
// "Connection refused" se maneja silenciosamente (puerto cerrado, host activo).
func (e *Engine) probe(ctx context.Context, t Target) Result {
	addr := fmt.Sprintf("%s:%d", t.Host, t.Port)
	start := time.Now()

	var dialer proxy.ContextDialer
	if e.cfg.Dialer != nil {
		dialer = e.cfg.Dialer
	} else {
		dialer = &net.Dialer{Timeout: e.cfg.Timeout}
	}
	
	var conn net.Conn
	var err error
	var latency time.Duration
	protocol := t.Protocol
	if protocol == "" {
		protocol = "tcp"
	}

	for retries := 0; retries < 3; retries++ {
		if ctx.Err() != nil {
			return Result{Host: t.Host, Port: t.Port, Open: false, Latency: time.Since(start)}
		}


		conn, err = dialer.DialContext(ctx, protocol, addr)
		latency = time.Since(start)

		if err != nil {
			errStr := err.Error()
			// Graceful Degradation: backoff on resource exhaustion
			if strings.Contains(errStr, "WSAENOBUFS") || strings.Contains(errStr, "too many open files") || strings.Contains(errStr, "socket: no buffer space") || strings.Contains(errStr, "10055") {
				select {
				case e.congestionSignal <- true:
				default:
				}
				time.Sleep(50 * time.Millisecond)
				continue
			}
			return Result{Host: t.Host, Port: t.Port, Open: false, Latency: latency}
		}
		
		select {
		case e.congestionSignal <- false:
		default:
		}
		break // Conexión exitosa
	}

	if err != nil {
		return Result{Host: t.Host, Port: t.Port, Open: false, Latency: latency}
	}
	
	// Prevenir agotamiento de puertos efímeros (Evitar estado TIME_WAIT)
	if tcpConn, ok := conn.(*net.TCPConn); ok {
		_ = tcpConn.SetLinger(0)
	}

	// Evasión de DPI: Fragmentación de Payload
	if e.cfg.FragProfile != stealth.ProfileOff && e.cfg.FragProfile != "" {
		prof := e.cfg.FragProfile
		if prof == stealth.ProfileAuto {
			if t.Port == 443 || t.Port == 8443 {
				prof = stealth.ProfileHigh
			} else if t.Port == 80 || t.Port == 8080 {
				prof = stealth.ProfileMedium
			} else {
				prof = stealth.ProfileLow
			}
		}
		conn = stealth.WrapConn(ctx, conn, prof)
	}

	defer conn.Close()

	if protocol == "udp" {
		udpTimeout := 800 * time.Millisecond
		banner := ActiveProbe(conn, t.Port, protocol, udpTimeout)
		if len(banner) == 0 {
			return Result{Host: t.Host, Port: t.Port, Open: false, Latency: latency}
		}
		r := Result{Host: t.Host, Port: t.Port, Protocol: protocol, Open: true, Latency: latency}
		if e.cfg.GrabBanners && !e.cfg.SafeMode {
			r.Banner = string(banner)
		}
		r.Service = GuessService(t.Port, banner)
		return r
	}

	r := Result{Host: t.Host, Port: t.Port, Protocol: protocol, Open: true, Latency: latency}

	if e.cfg.GrabBanners && !e.cfg.SafeMode {
		r.Banner = string(ActiveProbe(conn, t.Port, protocol, e.cfg.Timeout))
	}
	r.Service = GuessService(t.Port, []byte(r.Banner))
	return r
}
