package discovery

import (
	"context"
	"fmt"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/raptor-recon/raptor/internal/proxy"
)

// maxProbesPerHost limita las goroutines concurrentes de probing por host
// para no agotar file descriptors al barrer muchos puertos simultáneamente.
const maxProbesPerHost = 50

// globalDialSem limita la concurrencia ABSOLUTA de creación de sockets.
// Previene que Windows entre en pánico en `net.dialSingle` por falta de buffers (WSAENOBUFS).
var globalDialSem = make(chan struct{}, 1500)

// Discover realiza resolución de DNS y/o barrido TCP agresivo para encontrar hosts vivos.
// A diferencia del enfoque conservador (solo 80/443), barre TODOS los probePorts
// para cada IP, con early-exit al primer signo de vida (SYN-ACK o RST).
// independiente del timeout del scanner principal.
func Discover(ctx context.Context, target string, probePorts []int, workers int, discoveryTimeout time.Duration, dialer proxy.ContextDialer, statusChan chan<- string) (<-chan string, error) {
	// Si no se proporcionan puertos de discovery, usar un set mínimo de fallback
	if len(probePorts) == 0 {
		probePorts = []int{80, 443, 22, 445, 8080}
	}

	// Determinar si es un CIDR
	if _, _, err := net.ParseCIDR(target); err == nil {
		return sweepCIDR(ctx, target, probePorts, workers, discoveryTimeout, dialer, statusChan)
	}

	// Si no es CIDR, asumir que es un dominio
	return discoverDomain(ctx, target, probePorts, workers, discoveryTimeout, dialer, statusChan)
}

// sweepCIDR genera todas las IPs de un rango CIDR y lanza el barrido agresivo.
func sweepCIDR(ctx context.Context, cidr string, probePorts []int, workers int, timeout time.Duration, dialer proxy.ContextDialer, statusChan chan<- string) (<-chan string, error) {
	_, ipnet, err := net.ParseCIDR(cidr)
	if err != nil {
		return nil, err
	}

	ipChan := generateIPs(ctx, ipnet)

	return launchSweep(ctx, ipChan, probePorts, workers, timeout, dialer, statusChan), nil
}

// discoverDomain resuelve un dominio a IPs (IPv4 + IPv6) y lanza el barrido agresivo.
func discoverDomain(ctx context.Context, domain string, probePorts []int, workers int, timeout time.Duration, dialer proxy.ContextDialer, statusChan chan<- string) (<-chan string, error) {
	// Resolución DNS concurrente (IPv4 + IPv6)
	var resolvedIPs []string
	var wg sync.WaitGroup
	var mu sync.Mutex

	// Query IPv4
	wg.Add(1)
	go func() {
		defer wg.Done()
		if addrs, err := net.DefaultResolver.LookupIP(ctx, "ip4", domain); err == nil {
			mu.Lock()
			for _, ip := range addrs {
				resolvedIPs = append(resolvedIPs, ip.String())
			}
			mu.Unlock()
		}
	}()

	// Query IPv6
	wg.Add(1)
	go func() {
		defer wg.Done()
		if addrs, err := net.DefaultResolver.LookupIP(ctx, "ip6", domain); err == nil {
			mu.Lock()
			for _, ip := range addrs {
				resolvedIPs = append(resolvedIPs, ip.String())
			}
			mu.Unlock()
		}
	}()

	wg.Wait()

	if len(resolvedIPs) == 0 {
		return nil, fmt.Errorf("no se pudo resolver el dominio %q a ninguna dirección IP", domain)
	}

	// De-duplicar IPs
	seen := make(map[string]struct{})
	ipChan := make(chan string, len(resolvedIPs))
	for _, ip := range resolvedIPs {
		if _, exists := seen[ip]; !exists {
			seen[ip] = struct{}{}
			ipChan <- ip
		}
	}
	close(ipChan)

	return launchSweep(ctx, ipChan, probePorts, workers, timeout, dialer, statusChan), nil
}

// ──────────────────────────────────────────────
// Motor de barrido agresivo
// ──────────────────────────────────────────────

// launchSweep orquesta el pool de workers que prueban cada IP contra todos los puertos.
// Retorna un canal que emite IPs confirmadas como vivas.
func launchSweep(ctx context.Context, ipChan <-chan string, probePorts []int, workers int, timeout time.Duration, dialer proxy.ContextDialer, statusChan chan<- string) <-chan string {
	out := make(chan string, workers*2)

	if workers <= 0 {
		workers = 500
	}

	var wg sync.WaitGroup
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for ip := range ipChan {
				if ctx.Err() != nil {
					return
				}
				if statusChan != nil {
					select {
					case statusChan <- ip:
					default:
					}
				}
				if probeHost(ctx, ip, probePorts, timeout, dialer) {
					select {
					case out <- ip:
					case <-ctx.Done():
						return
					}
				}
			}
		}()
	}

	go func() {
		wg.Wait()
		close(out)
	}()

	return out
}

// probeHost barre TODOS los puertos de discovery en una IP de forma concurrente.
//
// Lógica de Supervivencia (early-exit):
//   - Crea un sub-contexto cancelable para este host.
//   - Lanza goroutines (limitadas por semáforo) para cada puerto.
//   - Si CUALQUIER puerto responde con conexión exitosa O con RST/Connection Refused,
//     cancela inmediatamente el sub-contexto y retorna true.
//   - Si NINGÚN puerto responde tras probar todos, retorna false.
//
// Esto garantiza que un host con un único servicio en un puerto exótico (ej. 54321)
// sea detectado como vivo, en vez de ser descartado por no responder en 80/443.
func probeHost(ctx context.Context, ip string, ports []int, timeout time.Duration, dialer proxy.ContextDialer) bool {
	// Sub-contexto exclusivo para este host: al primer signo de vida, cancelamos todo.
	hostCtx, hostCancel := context.WithCancel(ctx)
	defer hostCancel()

	// Si es red local, usamos ARP antes que TCP
	if isLocalIP(ip) {
		aliveARP, supported := checkARP(ip)
		if supported {
			if aliveARP {
				return true
			}
			return false // Si ARP no lo encuentra en red local, no está
		}
	}

	// Canal atómico de resultado: el primer goroutine que detecte vida escribe aquí.
	alive := make(chan struct{}, 1)

	portCh := make(chan int, len(ports))
	for _, p := range ports {
		portCh <- p
	}
	close(portCh)

	var wg sync.WaitGroup
	workers := maxProbesPerHost
	if workers > len(ports) {
		workers = len(ports)
	}

	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for p := range portCh {
				// Verificar cancelación antes de conectar
				if hostCtx.Err() != nil {
					return
				}

				if probePort(hostCtx, ip, p, timeout, dialer) {
					// ¡Host vivo! Señalar y cancelar el resto de probes.
					select {
					case alive <- struct{}{}:
					default:
					}
					hostCancel()
					return
				}
			}
		}()
	}

	// Esperar en background a que todos los goroutines terminen
	doneCh := make(chan struct{})
	go func() {
		wg.Wait()
		close(doneCh)
	}()

	// Esperar: o detectamos vida, o todos terminan sin respuesta, o el contexto padre muere.
	select {
	case <-alive:
		return true
	case <-doneCh:
		// Todos los probes terminaron sin detectar vida
		select {
		case <-alive:
			return true
		default:
			return false
		}
	case <-ctx.Done():
		return false
	}
}

// probePort intenta un TCP connect a ip:port con el timeout dado.
// Retorna true si el host está vivo:
//   - Conexión exitosa (puerto abierto)
//   - Connection refused / RST (puerto cerrado, pero host activo)
//
// Retorna false si hay timeout, "no route to host", "network unreachable", etc.
func probePort(ctx context.Context, ip string, port int, timeout time.Duration, dialer proxy.ContextDialer) bool {
	addr := net.JoinHostPort(ip, fmt.Sprintf("%d", port))
	var d proxy.ContextDialer
	if dialer != nil {
		d = dialer
	} else {
		d = &net.Dialer{Timeout: timeout}
	}

	for retries := 0; retries < 3; retries++ {
		if ctx.Err() != nil {
			return false
		}

		// Apply the timeout to the context just in case the proxy dialer relies on it
		dialCtx, cancel := context.WithTimeout(ctx, timeout)
		
		// Proteger el dialer con un semáforo global para evitar crashear el kernel
		select {
		case globalDialSem <- struct{}{}:
		case <-ctx.Done():
			cancel()
			return false
		}
		
		conn, err := d.DialContext(dialCtx, "tcp", addr)
		
		<-globalDialSem
		cancel()
		
		if err == nil {
			if tcpConn, ok := conn.(*net.TCPConn); ok {
				_ = tcpConn.SetLinger(0)
			}
			_ = conn.Close()
			return true // Conexión exitosa → host vivo, puerto abierto
		}

		errStr := err.Error()
		// Graceful Degradation: si el OS se queda sin buffers, pausar y reintentar
		if strings.Contains(errStr, "WSAENOBUFS") || strings.Contains(errStr, "too many open files") || strings.Contains(errStr, "socket: no buffer space") || strings.Contains(errStr, "10055") {
			time.Sleep(50 * time.Millisecond)
			continue
		}

		// Analizar el error: RST / Connection Refused confirman que el host existe
		if strings.Contains(errStr, "connection refused") ||
			strings.Contains(errStr, "refused") ||
			strings.Contains(errStr, "reset") {
			return true // Host vivo, puerto cerrado
		}

		return false
	}
	return false
}

// ──────────────────────────────────────────────
// Utilidades de red
// ──────────────────────────────────────────────

// generateIPs genera todas las IPs válidas (excluyendo red y broadcast) de un rango CIDR.
// Emite las IPs a un canal para mantener un consumo de memoria constante O(1).
func generateIPs(ctx context.Context, ipnet *net.IPNet) <-chan string {
	out := make(chan string, 100)
	
	go func() {
		defer close(out)
		ones, bits := ipnet.Mask.Size()
		hostBits := bits - ones

		for ip := cloneIP(ipnet.IP.Mask(ipnet.Mask)); ipnet.Contains(ip); incrementIP(ip) {
			if ctx.Err() != nil {
				return
			}
			
			// Saltar dirección de red y broadcast en redes > /30
			if hostBits > 1 {
				hostPart := ip[len(ip)-1]
				if hostPart == 0 || hostPart == 255 {
					continue
				}
			}
			
			select {
			case out <- ip.String():
			case <-ctx.Done():
				return
			}
		}
	}()
	
	return out
}

func cloneIP(ip net.IP) net.IP {
	clone := make(net.IP, len(ip))
	copy(clone, ip)
	return clone
}

func incrementIP(ip net.IP) {
	for i := len(ip) - 1; i >= 0; i-- {
		ip[i]++
		if ip[i] != 0 {
			break
		}
	}
}
