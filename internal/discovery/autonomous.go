package discovery

import (
	"context"
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/raptor-recon/raptor/internal/proxy"
	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
	"os"
	"runtime"
)

// AutoDiscover realiza un mapeo autónomo de la red interna (Shadow IT Hunt)
// 1. Target Cero: Obtiene interfaces locales e infiere subredes (soporte para VPNs /32).
// 2. Smart Sweep: Barrido heurístico de RFC1918 (Clases A, B, C) probando .1, .100 y .254.
func AutoDiscover(ctx context.Context, probePorts []int, workers int, timeout time.Duration, dialer proxy.ContextDialer, statusChan chan<- string) (<-chan string, error) {
	if len(probePorts) == 0 {
		probePorts = []int{80, 443, 445} // Puertos heurísticos por defecto
	}

	// Canal donde enviaremos todas las IPs de las Zonas Vivas
	candidateIPs := make(chan string, 10000)

	go func() {
		defer close(candidateIPs)

		// 1. Obtener contexto local (Interfaces y VPNs)
		localCIDRs := getLocalNetworks()
		
		// Inyectar Rutas Activas del OS (OS Routing Table)
		osRoutes := getOSRoutes()
		for _, r := range osRoutes {
			// Prevenir duplicados de forma sencilla
			found := false
			for _, l := range localCIDRs {
				if l == r {
					found = true
					break
				}
			}
			if !found {
				localCIDRs = append(localCIDRs, r)
			}
		}

		// Map para evitar escanear la misma red /24 varias veces
		seen24 := make(map[string]bool)
		var mu sync.Mutex

		// Enviar redes locales directamente (Prioridad 0)
		for _, cidr := range localCIDRs {
			_, ipnet, err := net.ParseCIDR(cidr)
			if err != nil {
				continue
			}

			// Marcar los /24 correspondientes como vistos
			ones, _ := ipnet.Mask.Size()
			if ones <= 24 {
				// Si es más grande que un /24, no marcamos todo, solo lo inyectamos.
				// El smart sweep saltará las partes que ya descubrimos si las metemos en seen24,
				// pero por simplicidad solo marcamos si es exactamente un /24
				if ones == 24 {
					mu.Lock()
					seen24[ipnet.String()] = true
					mu.Unlock()
				}
			}

			// Generar IPs para la red local y enviarlas como candidatas
			ipChan := generateIPs(ctx, ipnet)
			for ip := range ipChan {
				select {
				case candidateIPs <- ip:
				case <-ctx.Done():
					return
				}
			}
		}

		// 2. Definir bloques RFC 1918 para el Smart Sweep
		var rfc1918 []string
		
		// isAdmin asume que lo copiaste de main o tienes acceso a algo similar,
		// como isAdmin no está en discovery, mejor importamos `os` y `runtime` si es necesario o usamos una variable
		// Pero para hacerlo fácil, podemos simplemente ver si tenemos permisos de Raw Socket (ICMP)
		// ya que intentamos crear un conn raw en el inicio. O simplemente importamos una utilidad.
		// Para no meter un ciclo de dependencias o romper, usaré una lógica de "si ICMP falló globalmente".
		// Wait, `isAdmin()` is in `main.go`, we can't easily call it from here unless we pass it.
		// The easiest way is to look at whether ICMP actually works (e.g. check `os.Geteuid() == 0` for linux, but windows is harder).
		// Let's implement a simple check here or pass a flag.
		// Actually, I can use a local function `isAdminPrivileged()`
		rfc1918 = []string{
			"192.168.0.0/16",
			"172.16.0.0/12",
			"10.0.0.0/8",
		}

		// Canal de subredes /24 a evaluar
		subnets24 := make(chan string, 10000)

		// Generador de /24s
		go func() {
			defer close(subnets24)
			
			// Primero las locales y de VPN (Rápidas)
			for _, netBlock := range localCIDRs {
				_, ipnet, _ := net.ParseCIDR(netBlock)
				generate24s(ctx, ipnet, subnets24)
			}
			for _, netBlock := range osRoutes {
				_, ipnet, _ := net.ParseCIDR(netBlock)
				generate24s(ctx, ipnet, subnets24)
			}

			// Luego el barrido extenso si hay privilegios
			if isAdminPrivileged() {
				for _, block := range rfc1918 {
					_, ipnet, _ := net.ParseCIDR(block)
					generate24s(ctx, ipnet, subnets24)
				}
			}
		}()

		// Worker pool para Smart Sweep heurístico
		var wg sync.WaitGroup
		sweepWorkers := workers
		if sweepWorkers > 500 {
			sweepWorkers = 500 // Limitar concurrencia del sweep para no saturar routers
		}

		for i := 0; i < sweepWorkers; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				for cidr24 := range subnets24 {
					if ctx.Err() != nil {
						return
					}

					mu.Lock()
					if seen24[cidr24] {
						mu.Unlock()
						continue
					}
					seen24[cidr24] = true
					mu.Unlock()

					// Realizar prueba heurística (.1, .100, .254) con timeout adaptativo
					aliveHeuristicIPs := checkHeuristic24(ctx, cidr24, probePorts, timeout, dialer)
					if len(aliveHeuristicIPs) > 0 {
						// Doble check heurístico para evadir gateways ruidosos / VPNs que interceptan todo
						dense := confirmDensity(ctx, cidr24, probePorts, timeout, dialer)
						
						if dense {
							// ¡Zona Viva confirmada! Generar todas las IPs de este /24 y enviarlas
							_, net24, _ := net.ParseCIDR(cidr24)
							ipChan := generateIPs(ctx, net24)
							for ip := range ipChan {
								select {
								case candidateIPs <- ip:
								case <-ctx.Done():
									return
								}
							}
						} else {
							// Falso positivo de red densa (ej. Gateway interceptando).
							// NO inyectar el /24 completo, solo los hosts que respondieron inicialmente.
							for _, ip := range aliveHeuristicIPs {
								select {
								case candidateIPs <- ip:
								case <-ctx.Done():
									return
								}
							}
						}
					}
				}
			}()
		}
		wg.Wait()
	}()

	// 3. Filtrar las IPs candidatas (Worker Pool de escaneo profundo) para confirmar que están vivas.
	// launchSweep probará todas las IPs de las zonas vivas para confirmar cuáles existen realmente.
	return launchSweep(ctx, candidateIPs, probePorts, workers, timeout, dialer, statusChan), nil
}

// getLocalNetworks extrae las subredes de las interfaces.
// Si detecta un /32 o interfaz Point-to-Point (VPN), infiere el bloque RFC1918.
func getLocalNetworks() []string {
	var networks []string
	ifaces, err := net.Interfaces()
	if err != nil {
		return networks
	}

	for _, i := range ifaces {
		if i.Flags&net.FlagUp == 0 || i.Flags&net.FlagLoopback != 0 {
			continue // Ignorar loopback y caídas
		}

		addrs, err := i.Addrs()
		if err != nil {
			continue
		}

		for _, addr := range addrs {
			ip, ipnet, err := net.ParseCIDR(addr.String())
			if err != nil || ip.To4() == nil {
				continue // Solo IPv4
			}

			ones, _ := ipnet.Mask.Size()

			// Lógica de VPN: Si es un /32 o PtP
			if ones == 32 || i.Flags&net.FlagPointToPoint != 0 {
				inferred := inferRFC1918Block(ip)
				if inferred != "" {
					networks = append(networks, inferred)
				}
			} else {
				networks = append(networks, ipnet.String())
			}
		}
	}
	return networks
}

// inferRFC1918Block adivina la red madre de una IP de VPN /32
func inferRFC1918Block(ip net.IP) string {
	ip4 := ip.To4()
	if ip4 == nil {
		return ""
	}

	// Si es 10.x.x.x -> 10.0.0.0/8
	if ip4[0] == 10 {
		return "10.0.0.0/8"
	}
	// Si es 172.16-31.x.x -> 172.16.0.0/12
	if ip4[0] == 172 && ip4[1] >= 16 && ip4[1] <= 31 {
		return "172.16.0.0/12"
	}
	// Si es 192.168.x.x -> 192.168.0.0/16
	if ip4[0] == 192 && ip4[1] == 168 {
		return "192.168.0.0/16"
	}
	return ""
}

// generate24s itera sobre un bloque grande y emite subredes /24
func generate24s(ctx context.Context, ipnet *net.IPNet, out chan<- string) {
	ones, _ := ipnet.Mask.Size()
	if ones >= 24 {
		out <- ipnet.String()
		return
	}

	ip := cloneIP(ipnet.IP.Mask(ipnet.Mask))
	for ipnet.Contains(ip) {
		select {
		case out <- fmt.Sprintf("%d.%d.%d.0/24", ip[0], ip[1], ip[2]):
		case <-ctx.Done():
			return
		}

		// Incrementar al siguiente /24
		ip[2]++
		if ip[2] == 0 {
			ip[1]++
			if ip[1] == 0 {
				ip[0]++
			}
		}
	}
}

// checkHeuristic24 prueba .1, .100 y .254. Retorna las IPs que respondieron (hasta 3).
func checkHeuristic24(ctx context.Context, cidr24 string, ports []int, timeout time.Duration, dialer proxy.ContextDialer) []string {
	_, ipnet, err := net.ParseCIDR(cidr24)
	if err != nil {
		return nil
	}

	ip := ipnet.IP.To4()
	if ip == nil {
		return nil
	}

	targets := []string{
		fmt.Sprintf("%d.%d.%d.1", ip[0], ip[1], ip[2]),
		fmt.Sprintf("%d.%d.%d.100", ip[0], ip[1], ip[2]),
		fmt.Sprintf("%d.%d.%d.254", ip[0], ip[1], ip[2]),
	}

	aliveChan := make(chan string, len(targets))
	var wg sync.WaitGroup

	for _, t := range targets {
		wg.Add(1)
		go func(targetIP string) {
			defer wg.Done()
			if ctx.Err() != nil {
				return
			}
			
			// 1. Fail-Safe ICMP Ping
			// If it's a local network, enforce ARP instead of ICMP
			if isLocalIP(targetIP) {
				aliveARP, supported := checkARP(targetIP)
				if supported && aliveARP {
					aliveChan <- targetIP
					return
				}
			} else {
				aliveICMP, errICMP := icmpPing(ctx, targetIP, timeout)
				if errICMP != nil {
					// No privileges for raw sockets, fail silently and continue to TCP
				} else if aliveICMP {
					aliveChan <- targetIP
					return
				}
			}

			// 2. Fallback a TCP
			heuristicPorts := ports
			if len(heuristicPorts) > 10 {
				// Enterprise fallback: SSH, HTTP, HTTPS, RPC, NetBIOS, SMB, MSSQL, RDP, Alt HTTP/S
				heuristicPorts = []int{22, 80, 135, 139, 443, 445, 1433, 3389, 8080, 8443} 
			}
			if probeHost(ctx, targetIP, heuristicPorts, timeout, dialer) {
				aliveChan <- targetIP
				return
			}
		}(t)
	}

	wg.Wait()
	close(aliveChan)

	var alive []string
	for ip := range aliveChan {
		alive = append(alive, ip)
	}
	return alive
}

// confirmDensity hace un "doble check" probando 3 IPs aleatorias dentro de la subred /24.
// Si al menos 1 de esas IPs aleatorias responde, asumimos que es una red real y densamente poblada.
// Si ninguna responde, asumimos que el heurístico inicial fue un falso positivo 
// causado por un gateway ruidoso o un firewall interceptando tráfico.
func confirmDensity(ctx context.Context, cidr24 string, ports []int, timeout time.Duration, dialer proxy.ContextDialer) bool {
	_, ipnet, err := net.ParseCIDR(cidr24)
	if err != nil {
		return false
	}
	ip := ipnet.IP.To4()
	if ip == nil {
		return false
	}

	// Seleccionar 3 IPs aleatorias entre .2 y .253 (excluyendo .1, .100, .254)
	var targets []string
	for len(targets) < 3 {
		oct := time.Now().UnixNano() % 252 + 2 // 2 to 253
		if oct == 100 {
			continue // Excluir la .100 que ya se usa en la prueba inicial
		}
		
		candidate := fmt.Sprintf("%d.%d.%d.%d", ip[0], ip[1], ip[2], oct)
		
		// Evitar duplicados simples
		duplicate := false
		for _, t := range targets {
			if t == candidate {
				duplicate = true
				break
			}
		}
		if !duplicate {
			targets = append(targets, candidate)
		}
	}

	aliveChan := make(chan bool, len(targets))
	var wg sync.WaitGroup

	hostCtx, cancel := context.WithCancel(ctx)
	defer cancel()

	for _, t := range targets {
		wg.Add(1)
		go func(targetIP string) {
			defer wg.Done()
			if hostCtx.Err() != nil {
				return
			}
			
			// 1. Fail-Safe ICMP / ARP
			if isLocalIP(targetIP) {
				aliveARP, supported := checkARP(targetIP)
				if supported && aliveARP {
					select { case aliveChan <- true: default: }
					cancel()
					return
				}
			} else {
				aliveICMP, errICMP := icmpPing(hostCtx, targetIP, timeout)
				if errICMP == nil && aliveICMP {
					select { case aliveChan <- true: default: }
					cancel()
					return
				}
			}

			// 2. Fallback a TCP
			heuristicPorts := ports
			if len(heuristicPorts) > 10 {
				heuristicPorts = []int{22, 80, 135, 139, 443, 445, 1433, 3389, 8080, 8443} 
			}
			if probeHost(hostCtx, targetIP, heuristicPorts, timeout, dialer) {
				select { case aliveChan <- true: default: }
				cancel()
				return
			}
		}(t)
	}

	go func() {
		wg.Wait()
		close(aliveChan)
	}()

	for res := range aliveChan {
		if res {
			return true // Al menos una respondió -> Red viva y poblada
		}
	}

	return false // Falso positivo -> No expandir el /24
}

// icmpPing intenta enviar un ICMP Echo Request. Retorna (vivo, error).
// Si hay error (ej. permisos), se asume que no se pudo probar.
func icmpPing(ctx context.Context, ip string, timeout time.Duration) (bool, error) {
	c, err := icmp.ListenPacket("ip4:icmp", "0.0.0.0")
	if err != nil {
		return false, err
	}
	defer c.Close()

	wm := icmp.Message{
		Type: ipv4.ICMPTypeEcho, Code: 0,
		Body: &icmp.Echo{
			ID: os.Getpid() & 0xffff, Seq: 1,
			Data: []byte("RAPTOR"),
		},
	}
	wb, err := wm.Marshal(nil)
	if err != nil {
		return false, err
	}
	dst, err := net.ResolveIPAddr("ip4", ip)
	if err != nil {
		return false, err
	}

	if _, err := c.WriteTo(wb, dst); err != nil {
		return false, err
	}

	err = c.SetReadDeadline(time.Now().Add(timeout))
	if err != nil {
		return false, err
	}

	rb := make([]byte, 1500)
	for {
		if ctx.Err() != nil {
			return false, nil
		}
		n, peer, err := c.ReadFrom(rb)
		if err != nil {
			return false, nil // Timeout o EOF
		}
		if peer.String() == ip {
			rm, err := icmp.ParseMessage(ipv4.ICMPTypeEchoReply.Protocol(), rb[:n])
			if err == nil && rm.Type == ipv4.ICMPTypeEchoReply {
				return true, nil
			}
		}
	}
}

// isAdminPrivileged revisa de forma local si tenemos permisos de Raw Sockets (Root/Admin)
func isAdminPrivileged() bool {
	if runtime.GOOS == "windows" {
		f, err := os.Open("\\\\.\\PHYSICALDRIVE0")
		if err != nil {
			return false
		}
		_ = f.Close()
		return true
	}
	return os.Geteuid() == 0
}
