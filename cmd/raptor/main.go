// Raptor Recon — binario standalone de ASM y auditoría táctica.
// Cero dependencias de binarios externos.
package main

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net"
	"net/url"
	"os"
	"os/signal"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/raptor-recon/raptor/internal/baselining"
	"github.com/raptor-recon/raptor/internal/discovery"
	"github.com/raptor-recon/raptor/internal/enrichment"
	"github.com/raptor-recon/raptor/internal/fingerprint"
	"github.com/raptor-recon/raptor/internal/pivot"
	"github.com/raptor-recon/raptor/internal/proxy"
	"github.com/raptor-recon/raptor/internal/reporter"
	"github.com/raptor-recon/raptor/internal/risk"
	"github.com/raptor-recon/raptor/internal/rules"
	"github.com/raptor-recon/raptor/internal/scanner"
	"github.com/raptor-recon/raptor/internal/stealth"
	"github.com/raptor-recon/raptor/internal/system"

	"github.com/charmbracelet/bubbles/progress"
	"github.com/charmbracelet/lipgloss"
	"github.com/charmbracelet/lipgloss/table"
	"github.com/muesli/termenv"
)

const version = "1.0.0"

var ansiRegex = regexp.MustCompile(`\x1b\[[0-9;]*[a-zA-Z]`)

func stripANSI(str string) string {
	return ansiRegex.ReplaceAllString(str, "")
}

const banner = `
 ██████╗  █████╗ ██████╗ ████████╗ ██████╗ ██████╗
 ██╔══██╗██╔══██╗██╔══██╗╚══██╔══╝██╔═══██╗██╔══██╗
 ██████╔╝███████║██████╔╝   ██║   ██║   ██║██████╔╝
 ██╔══██╗██╔══██║██╔═══╝    ██║   ██║   ██║██╔══██╗
 ██║  ██║██║  ██║██║        ██║   ╚██████╔╝██║  ██║
 ╚═╝  ╚═╝╚═╝  ╚═╝╚═╝        ╚═╝    ╚═════╝ ╚═╝  ╚═╝
 ██████╗ ███████╗ ██████╗ ██████╗ ███╗   ██╗
 ██╔══██╗██╔════╝██╔════╝██╔═══██╗████╗  ██║
 ██████╔╝█████╗  ██║     ██║   ██║██╔██╗ ██║
 ██╔══██╗██╔══╝  ██║     ██║   ██║██║╚██╗██║
 ██║  ██║███████╗╚██████╗╚██████╔╝██║ ╚████║
 ╚═╝  ╚═╝╚══════╝ ╚═════╝ ╚═════╝ ╚═╝  ╚═══╝  v` + version + `
 ASM · Attack Surface Management
`

// ──────────────────────────────────────────────
// CLI flags
// ──────────────────────────────────────────────

var (
	flagTarget   = flag.String("target", "", "IP, CIDR o Dominio a escanear, e.g. 192.168.1.0/24 o example.com")
	flagDomain   = flag.String("domain", "", "Alias de target")
	flagPorts    = flag.String("ports", "common", "Puertos: 'common', 'top100', 'all', '-p-', o lista (e.g. 22,80)")
	flagWorkers  = flag.Int("workers", 500, "Goroutines concurrentes (ignorados si se usa --profile)")
	flagRate     = flag.Int("rate", 2000, "Conexiones por segundo (ignorados si se usa --profile)")
	flagForceRate = flag.Int("force-rate", 0, "Forzar un rate limit absoluto, desactiva AIMD Auto-Scaling")
	flagThrottle = flag.Int("throttle", 0, "Pausa (ms) entre cada conexión para evitar DoS (Default 0. Modo auto = 50ms)")
	flagTimeout  = flag.Duration("timeout", 500*time.Millisecond, "Timeout por conexión TCP (ignorados si se usa --profile)")
	flagProfile  = flag.String("profile", "", "Perfil de escaneo: 'stealth', 'balanced', 'aggressive'")
	flagSafe     = flag.Bool("safe", false, "Safe Mode (Evitar Fuzzing, WAF triggers o peticiones intrusivas)")
	flagBanners  = flag.Bool("banners", false, "Intentar capturar banners de servicios")
	flagL7       = flag.Bool("l7", false, "Activar L7 Template Engine (Handshakes Activos)")
	flagL7Allow  = flag.String("l7-allow", "", "Lista de IDs L7 permitidos separados por coma (Modo Manual). Vacío = Todos.")
	flagOS       = flag.Bool("os", false, "Activar OS Fingerprinting (Heurístico / Raw)")
	flagFuzz     = flag.Bool("fuzz", false, "Activar Web Fuzzing / Tech Detection")
	flagGhost    = flag.Bool("ghost", false, "Ghost Mode: IP shuffling + jitter temporal + rotación de User-Agents")
	flagFrag     = flag.String("frag", "off", "DPI Evasion: off, low, medium, high, auto")
	flagAuto     = flag.Bool("auto", false, "Descubrimiento Autónomo (Shadow IT Hunt)")
	flagRulesDir = flag.String("rules", "rules", "Directorio de archivos YAML de reglas")
	flagOutput   = flag.String("output", "raptor_results.json", "Archivo de salida JSON")
	flagHTML     = flag.String("html", "raptor_report.html", "Archivo de salida HTML")
	flagSarif    = flag.String("sarif", "", "Archivo de salida SARIF v2.1.0 (ej. raptor.sarif)")
	flagStateFile = flag.String("state-file", "raptor_state.json", "Archivo para guardar/leer el Baseline (Snapshot)")
	flagVerbose  = flag.Bool("v", false, "Verbose: mostrar todos los puertos escaneados")
	flagQuiet    = flag.Bool("quiet", false, "Quiet: ocultar logs de progreso, mostrar solo findings")
	flagNoColor  = flag.Bool("no-color", false, "Desactivar colores en la terminal")
	flagProxy    = flag.String("proxies", "", "Proxy (ej. socks5://127.0.0.1:9050 o http://user:pass@ip:port)")
	
	// Proxy Pivot Detection flags
	flagProxyPivot  = flag.Bool("proxy-pivot", false, "Activar Proxy Pivot Detection manual")
	flagPivotSubnet = flag.Bool("pivot-subnet", false, "Escanear subred /24 del proxy detectado")
	flagPivotTarget = flag.String("pivot-target", "", "Rango CIDR explícito para escanear vía proxy")
	flagPivotPorts  = flag.String("pivot-ports", "", "Puertos a escanear vía proxy (vacío = default)")
	
	// Lifecycle
	flagUpdate      = flag.Bool("update", false, "Actualizar Raptor Recon a la última versión disponible (GitHub Releases)")
)

// ──────────────────────────────────────────────
// Punto de entrada
// ──────────────────────────────────────────────

func main() {
	flag.Usage = usage
	
	// Configurar límite de memoria automático (Soft Memory Limit) GC Tuning
	system.EnableAutoMemoryLimit()
	
	// Configurar Logging Persistente a Archivo
	logFile, err := os.OpenFile("raptor.log", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0600)
	if err == nil {
		log.SetOutput(logFile)
		log.SetFlags(log.Ldate | log.Ltime | log.Lshortfile)
		log.Println("--- Iniciando nueva ejecución de Raptor Recon ---")
	} else {
		log.Printf("WARN: No se pudo abrir raptor.log para escritura: %v", err)
	}
	
	// Arquitectura Híbrida: CLI o TUI interactiva
	if len(os.Args) > 1 {
		flag.Parse()
	} else {
		runInteractiveTUI()
	}

	if *flagNoColor {
		lipgloss.SetColorProfile(termenv.Ascii)
	}

	if *flagUpdate {
		fmt.Println(lipgloss.NewStyle().Foreground(cBrand).Bold(true).Render(banner))
		err := system.CheckAndUpdate(version)
		if err != nil {
			fmt.Println(styleError.Render("✖ Error de actualización: ") + err.Error())
			os.Exit(1)
		}
		os.Exit(0)
	}

	if !*flagQuiet {
		fmt.Println(lipgloss.NewStyle().Foreground(cBrand).Bold(true).Render(banner))
		if !system.HasAdminPrivileges() {
			fmt.Println(styleWarning.Render("⚠ WARN: Ejecución sin privilegios de Administrador/Root."))
			fmt.Println(styleDim.Render("  - ICMP Raw Sockets desactivados por el Sistema Operativo."))
			fmt.Println(styleDim.Render("  - Se usará ARP nativo (Red Local) y Top 10 TCP Fallback (Redes Remotas)."))
			fmt.Println(styleDim.Render("  - Para máxima velocidad y visibilidad 100%, ejecuta como Administrador.\n"))
		}
	}

	if *flagTarget == "" && *flagDomain == "" && !*flagAuto {
		fmt.Println(styleError.Render("✖ Error: Debes especificar un objetivo con -target, -domain, o habilitar -auto"))
		flag.Usage()
		os.Exit(1)
	}

	target := *flagTarget
	if *flagAuto {
		target = "AUTONOMOUS-ASM"
		if len(os.Args) > 1 {
			// Inteligencia Autónoma (Drop & Go):
			*flagProfile = "balanced"
			*flagBanners = true
			*flagL7 = true
			*flagOS = true
			*flagFuzz = true
			*flagGhost = true
			*flagFrag = "auto"
			if *flagThrottle == 0 {
				*flagThrottle = 50 // Safe throttle para prevenir DoS en modo Auto
			}
			*flagSafe = false // Fuzzing & Tech activados
			*flagHTML = "raptor_report.html"
			if *flagStateFile == "" {
				*flagStateFile = "raptor_state.json"
			}
			if *flagSarif == "" {
				*flagSarif = "raptor_sarif.json"
			}
			if *flagPorts == "common" {
				*flagPorts = "top100"
			}
			if !*flagQuiet {
				if system.HasAdminPrivileges() {
					fmt.Println(styleInfo.Render("🔥") + " Modo Autónomo: Privilegios de Administrador detectados. Activando Fingerprinting con Raw Sockets.")
				} else {
					fmt.Println(styleWarning.Render("⚠️") + " Modo Autónomo: Permisos estándar. Activando Motor de Deducción Heurística (L7/L4).")
				}
				fmt.Println(styleInfo.Render("ℹ") + " Perfil Balanced, OS, L7, Fuzzing, Ghost, Baselining y Reportes activados.")
			}
			// Protección contra Congestión: Límites estrictos para no tumbar la interfaz
			*flagWorkers = 500
			*flagRate = 2000
			*flagTimeout = 500 * time.Millisecond
		}
	} else if *flagDomain != "" {
		target = *flagDomain
	}

	// Contexto cancelable (Ctrl+C limpio)
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()

	// Cargar reglas
	rulesDir := *flagRulesDir
	if _, err := os.Stat(rulesDir); os.IsNotExist(err) {
		if execPath, err := os.Executable(); err == nil {
			execDir := filepath.Dir(execPath)
			altPath := filepath.Join(execDir, "..", "rules")
			if _, err := os.Stat(altPath); err == nil {
				rulesDir = altPath
			} else {
				altPath = filepath.Join(execDir, "rules")
				if _, err := os.Stat(altPath); err == nil {
					rulesDir = altPath
				}
			}
		}
	}
	ruleSet, loadErrs := rules.LoadDir(rulesDir)
	for _, e := range loadErrs {
		if !*flagQuiet {
			fmt.Println(styleWarning.Render("⚠ WARN: ") + styleDim.Render(e.Error()))
		}
	}
	if !*flagQuiet {
		fmt.Println(styleSuccess.Render("✓") + fmt.Sprintf(" %d reglas cargadas desde %q", len(ruleSet.Rules), *flagRulesDir))
	}

	// Cargar templates L7
	l7Dir := filepath.Join(rulesDir, "l7")
	l7Templates, l7Err := rules.LoadL7Templates(l7Dir)
	if l7Err != nil && !*flagQuiet {
		fmt.Println(styleWarning.Render("⚠ WARN: ") + styleDim.Render("No se pudieron cargar templates L7: "+l7Err.Error()))
	}
	l7Map := make(map[int][]rules.L7Template)
	for _, tmpl := range l7Templates {
		l7Map[tmpl.Port] = append(l7Map[tmpl.Port], tmpl)
	}
	if len(l7Templates) > 0 && !*flagQuiet {
		fmt.Println(styleSuccess.Render("✓") + fmt.Sprintf(" %d templates L7 cargados desde %q", len(l7Templates), l7Dir))
	}

	// Resolver puertos
	ports := resolvePorts(*flagPorts)

	// Micro-timeouts para Full-Port
	if len(ports) > 5000 && *flagTimeout > 400*time.Millisecond {
		*flagTimeout = 400 * time.Millisecond
		if !*flagQuiet {
			fmt.Println(styleWarning.Render(fmt.Sprintf("[-] Full-Port detectado: Timeout ajustado a %s para evitar saturación.", *flagTimeout)))
		}
	}

	// Aplicar Perfiles si están definidos
	if *flagProfile != "" {
		switch strings.ToLower(*flagProfile) {
		case "stealth":
			*flagWorkers = 50
			*flagRate = 100
			*flagTimeout = 2 * time.Second
			*flagGhost = true
		case "balanced":
			*flagWorkers = 500
			*flagRate = 2000
			*flagTimeout = 500 * time.Millisecond
		case "aggressive":
			*flagWorkers = 2000
			*flagRate = 0
			*flagTimeout = 200 * time.Millisecond
		case "auto":
			// Heuristics para Auto Profile
			if system.HasAdminPrivileges() {
				// Internal/Admin context -> go Aggressive but safe limit
				*flagWorkers = 1000
				*flagRate = 5000
				*flagTimeout = 300 * time.Millisecond
			} else if *flagTarget != "" && !strings.HasPrefix(*flagTarget, "192.168.") && !strings.HasPrefix(*flagTarget, "10.") && !strings.HasPrefix(*flagTarget, "172.") {
				// External Target -> balanced to avoid blocking
				*flagWorkers = 250
				*flagRate = 1000
				*flagTimeout = 1 * time.Second
			} else {
				// Default Internal Context
				*flagWorkers = 500
				*flagRate = 2000
				*flagTimeout = 500 * time.Millisecond
			}
			if !*flagQuiet {
				fmt.Println(styleInfo.Render("ℹ") + fmt.Sprintf(" Profile Auto heurístico ajustado: %d workers, %d rate, %s timeout", *flagWorkers, *flagRate, *flagTimeout))
			}
		default:
			if !*flagQuiet {
				fmt.Println(styleWarning.Render("⚠ WARN: Perfil desconocido. Usando valores custom o balanced."))
			}
		}
	}

	// Safe Mode Override
	if *flagSafe {
		*flagBanners = false // Forzar desactivación de interacción L7
		if !*flagQuiet {
			fmt.Println(styleInfo.Render("ℹ") + styleSuccess.Render(" SAFE MODE ACTIVADO: ") + "Fuzzing, Banners y Safe-Checks deshabilitados. Solo escaneo pasivo TCP SYN.")
		}
	}

	// Construir configuración del engine
	cfg := scanner.Config{
		Workers:     *flagWorkers,
		Timeout:     *flagTimeout,
		RateLimit:   *flagRate,
		GrabBanners: *flagBanners,
		Jitter:      *flagGhost,
		SafeMode:    *flagSafe,
		FragProfile: stealth.FragmentProfile(*flagFrag),
		ForceRate:   *flagForceRate,
		Throttle:    *flagThrottle,
		L7Templates: l7Map,
		// L7 Port-Triggered Execution Policy:
		// En modo autónomo TODOS los templates se disparan (si coincide el puerto).
		// En modo manual/TUI, AllowedL7IDs se usa para filtrar los templates autorizados.
		IsAutoMode:   *flagAuto, // Seteado por --auto o por la TUI cuando elige modo "auto"
		AllowedL7IDs: parseAllowedL7(*flagL7Allow),
	}

	var pDialer proxy.ContextDialer
	if *flagProxy != "" {
		pDialer, err = proxy.NewDialer(*flagProxy, cfg.Timeout)
		if err != nil {
			fmt.Println(styleError.Render("✖ Error con el proxy configurado: ") + err.Error())
			os.Exit(1)
		}
		
		// PRE-FLIGHT CHECK: Verify the proxy is alive before starting the scan
		u, uerr := url.Parse(*flagProxy)
		if uerr == nil {
			proxyHost := u.Host
			if !strings.Contains(proxyHost, ":") {
				if u.Scheme == "https" { proxyHost += ":443" } else if u.Scheme == "http" { proxyHost += ":80" } else if u.Scheme == "socks5" { proxyHost += ":1080" }
			}
			if !*flagQuiet {
				fmt.Println(styleInfo.Render("▶") + fmt.Sprintf(" Verificando conectividad con el proxy: %s", proxyHost))
			}
			pc, perr := net.DialTimeout("tcp", proxyHost, 5*time.Second)
			if perr != nil {
				fmt.Println(styleError.Render("✖ ERROR FATAL: El proxy no responde o está inalcanzable. Abortando escaneo."))
				os.Exit(1)
			}
			_ = pc.Close()
		}

		cfg.Dialer = pDialer
	}

	engine := scanner.NewEngine(ctx, cfg)

	// Ghost Mode: mostrar estado de las tácticas de evasión
	if *flagGhost && !*flagQuiet {
		fmt.Println(styleGhost.Render("\n👻 Ghost Mode ACTIVADO:"))
		fmt.Println("    " + styleSuccess.Render("✓") + " IP Shuffling (orden aleatorio de targets)")
		fmt.Println("    " + styleSuccess.Render("✓") + " Jitter temporal (5-50ms entre probes)")
		fmt.Println("    " + styleSuccess.Render("✓") + " Rotación de User-Agents (8 identidades)")
		if *flagFrag != "off" && *flagFrag != "" {
			fmt.Println("    " + styleSuccess.Render("✓") + fmt.Sprintf(" Evasión DPI: Payload Fragmentation (Perfil: %s)", *flagFrag))
		}
		fmt.Println()
	}

	if !*flagQuiet {
		fmt.Println(styleInfo.Render("ℹ") + fmt.Sprintf(" Escaneando %d puertos con %d workers @ %d conn/s", len(ports), cfg.Workers, cfg.RateLimit))
	}

	// 1. Discovery (DNS + Ping Sweep)
	// 'target' is already defined above, no need to redeclare it here
	if *flagTarget != "" && !*flagAuto {
		target = *flagTarget
	} else if *flagDomain != "" && !*flagAuto {
		target = *flagDomain
	}

	// Discovery agresivo: con timeout corto (200ms) para máxima velocidad de detección.
	discoveryTimeout := 200 * time.Millisecond
	
	// Limitar Discovery para evitar ineficiencias matemáticas en Full-Port Scan (-p-)
	var discoveryPorts []int
	if len(ports) > 100 {
		discoveryPorts = top100Ports()
	} else {
		for _, p := range ports {
			if p.Protocol == "tcp" {
				discoveryPorts = append(discoveryPorts, p.Port)
			}
		}
	}
	if len(discoveryPorts) == 0 {
		// Fallback si el usuario solo pidió UDP
		discoveryPorts = []int{80, 443}
	}

	if *flagProxy != "" && !*flagQuiet {
		fmt.Println(styleWarning.Render(fmt.Sprintf("⚠  Enrutando todo el tráfico vía Proxy: %s", *flagProxy)))
	}

	var liveIPsChan <-chan string
	statusChan := make(chan string, 1000)
	// 'err' was already declared around line 145, just assign to it.

	if *flagAuto {
		if !*flagQuiet {
			fmt.Println(styleInfo.Render("▶") + fmt.Sprintf(" Iniciando Shadow IT Hunt (Mapeo VPN / RFC1918) timeout %s...", discoveryTimeout))
		}
		liveIPsChan, err = discovery.AutoDiscover(ctx, discoveryPorts, *flagWorkers, discoveryTimeout, pDialer, statusChan)
	} else {
		if !*flagQuiet {
			fmt.Println(styleInfo.Render("▶") + fmt.Sprintf(" Iniciando descubrimiento agresivo (%d puertos/host, timeout %s) para %s...", len(discoveryPorts), discoveryTimeout, target))
		}
		liveIPsChan, err = discovery.Discover(ctx, target, discoveryPorts, *flagWorkers, discoveryTimeout, pDialer, statusChan)
	}
	
	if err != nil {
		fmt.Println(styleError.Render("✖ Error en descubrimiento: ") + err.Error())
		os.Exit(1)
	}

	// Consumir el canal de IPs vivas y el status ghost
	var liveIPs []string
	for {
		select {
		case ip, ok := <-liveIPsChan:
			if !ok {
				liveIPsChan = nil
			} else {
				liveIPs = append(liveIPs, ip)
				if !*flagQuiet {
					// Muestra rápidamente la IP que se acaba de encontrar y aumenta el contador, en la misma línea
					fmt.Printf("\r\033[K  [*] Evaluando: %s | Activos: %s", styleSuccess.Render(ip), styleSuccess.Render(fmt.Sprintf("%d", len(liveIPs))))
				}
			}
		case ip, ok := <-statusChan:
			if !ok {
				statusChan = nil
				continue
			}
			if !*flagQuiet {
				// Muestra el fantasma en gris tenue, en la misma línea
				fmt.Printf("\r\033[K  [*] Evaluando: %s | Activos: %s", styleDim.Render(ip), styleSuccess.Render(fmt.Sprintf("%d", len(liveIPs))))
			}
		}
		if liveIPsChan == nil {
			break
		}
	}
	if !*flagQuiet {
		fmt.Printf("\r\033[K") // Limpiar la línea al terminar
	}

	if len(liveIPs) == 0 {
		if !*flagQuiet {
			fmt.Println(styleWarning.Render("[-] No se encontraron hosts activos en el descubrimiento (Ping Sweep)."))
		}
		return
	}

	if !*flagQuiet {
		fmt.Println(styleSuccess.Render("✓") + fmt.Sprintf(" Hosts activos detectados: %d", len(liveIPs)))
	}

	hostMap := make(map[string]*reporter.HostSummary)
	var validLiveIPs []string

	for _, ip := range liveIPs {
		if *flagVerbose {
			fmt.Printf("    Host activo: %s\n", ip)
		}
		
		// PRE-SCAN: WAF / TARPIT DETECTOR
		if scanner.CheckWAF(ctx, ip, 800*time.Millisecond, pDialer) {
			if !*flagQuiet {
				fmt.Println(styleWarning.Render("⚠") + fmt.Sprintf(" Host %s ignorado: Detectado como [WAF/Tarpit] (Puertos aleatorios abiertos)", ip))
			}
			hostMap[ip] = &reporter.HostSummary{
				IP: ip, 
				OS: "Desconocido [WAF/Tarpit]",
			}
			continue
		}
		
		validLiveIPs = append(validLiveIPs, ip)
		// Asegurar que los validos aparezcan en el hostMap
		hostMap[ip] = &reporter.HostSummary{IP: ip}
	}
	liveIPs = validLiveIPs

	// Crear canal de IPs vivas para el generador de targets
	liveIPsInput := make(chan string, len(liveIPs))
	for _, ip := range liveIPs {
		liveIPsInput <- ip
	}
	close(liveIPsInput)

	totalTargets := len(liveIPs) * len(ports)
	if !*flagQuiet {
		fmt.Println(styleInfo.Render("▶") + fmt.Sprintf(" Generando %d targets de escaneo...", totalTargets))
	}
	targets := scanner.GenerateTargetsFromIPs(liveIPsInput, ports, cfg.Workers*4, *flagGhost)

	// Escanear y recolectar resultados
	flushCallback := func(currentFindings []rules.Finding, currentResults []scanner.Result) {
		tmpHostMap := make(map[string]*reporter.HostSummary)
		for _, ip := range liveIPs {
			tmpHostMap[ip] = &reporter.HostSummary{IP: ip}
		}
		for _, p := range currentResults {
			if _, ok := tmpHostMap[p.Host]; !ok {
				tmpHostMap[p.Host] = &reporter.HostSummary{IP: p.Host}
			}
			tmpHostMap[p.Host].Ports = append(tmpHostMap[p.Host].Ports, reporter.PortSummary{Result: p})
		}
		for _, f := range currentFindings {
			if _, ok := tmpHostMap[f.Host]; !ok {
				tmpHostMap[f.Host] = &reporter.HostSummary{IP: f.Host}
			}
			if f.RuleID == "TLS-DOMAINS-DISCOVERED" {
				tmpHostMap[f.Host].TLSDomains = append(tmpHostMap[f.Host].TLSDomains, strings.Split(f.Description, ",")...)
			} else {
				tmpHostMap[f.Host].StaticFindings = append(tmpHostMap[f.Host].StaticFindings, f)
			}
		}
		var summaries []reporter.HostSummary
		for _, s := range tmpHostMap {
			summaries = append(summaries, *s)
		}
		
		subnetMap := make(map[string]*reporter.SubnetSummary)
		for _, hs := range summaries {
			ip := net.ParseIP(hs.IP).To4()
			if ip == nil { continue }
			cidr := fmt.Sprintf("%d.%d.%d.0/24", ip[0], ip[1], ip[2])
			if _, ok := subnetMap[cidr]; !ok {
				subnetMap[cidr] = &reporter.SubnetSummary{CIDR: cidr}
			}
			subnetMap[cidr].Hosts = append(subnetMap[cidr].Hosts, hs)
		}
		
		var subnets []reporter.SubnetSummary
		for _, s := range subnetMap {
			subnets = append(subnets, *s)
		}
		
		if *flagOutput != "" {
			_ = saveJSON(*flagOutput, subnets)
		}
		if *flagSarif != "" {
			_ = reporter.ExportToSARIF(summaries, *flagSarif, version, nil)
		}
	}

	// Crear L7Dispatcher con la política correcta (Auto vs Manual).
	// En modo --auto: todos los templates autorizados si coincide el puerto.
	// En modo manual/TUI: solo los IDs en cfg.AllowedL7IDs (doble validación).
	l7Dispatcher := scanner.NewL7Dispatcher(cfg.L7Templates, cfg.IsAutoMode, cfg.AllowedL7IDs)

	allFindings, openResults := runScan(ctx, engine, ruleSet, targets, totalTargets, flushCallback, pDialer, l7Dispatcher)
	if !*flagQuiet {
		fmt.Println()
	}

	// Agrupar resultados por Host y procesar módulos 1 y 6
	// hostMap ya fue creado durante el WAF Detection

	// Agrupar puertos
	for _, p := range openResults {
		if _, ok := hostMap[p.Host]; !ok {
			hostMap[p.Host] = &reporter.HostSummary{IP: p.Host}
		}
		hostMap[p.Host].Ports = append(hostMap[p.Host].Ports, reporter.PortSummary{Result: p})
	}

	// Agrupar hallazgos estáticos
	for _, f := range allFindings {
		if _, ok := hostMap[f.Host]; !ok {
			hostMap[f.Host] = &reporter.HostSummary{IP: f.Host}
		}
		if f.RuleID == "TLS-DOMAINS-DISCOVERED" {
			hostMap[f.Host].TLSDomains = append(hostMap[f.Host].TLSDomains, strings.Split(f.Description, ",")...)
		} else {
			hostMap[f.Host].StaticFindings = append(hostMap[f.Host].StaticFindings, f)
		}
	}

	// ──────────────────────────────────────────────
	// Fase de Proxy Pivot (Deferred execution)
	// ──────────────────────────────────────────────
	pivotCfg := pivot.Config{
		Mode: pivot.PivotModeDisabled,
	}
	if *flagAuto {
		pivotCfg.Mode = pivot.PivotModeAuto
		pivotCfg.Levels.SameIP = true
		pivotCfg.Levels.Subnet = true
		pivotCfg.Levels.Target = *flagPivotTarget
	} else if *flagProxyPivot {
		pivotCfg.Mode = pivot.PivotModeManual
		pivotCfg.Levels.SameIP = true
		pivotCfg.Levels.Subnet = *flagPivotSubnet
		pivotCfg.Levels.Target = *flagPivotTarget
	}

	var pivotSummary []reporter.PivotSummaryEntry
	isCancelled := ctx.Err() != nil

	if pivotCfg.Mode != pivot.PivotModeDisabled && !isCancelled {
		if *flagPivotPorts != "" {
			var parsedPorts []int
			for _, p := range resolvePorts(*flagPivotPorts) {
				if p.Protocol == "tcp" {
					parsedPorts = append(parsedPorts, p.Port)
				}
			}
			pivotCfg.PivotPorts = parsedPorts
		}
		pivotCfg.ProxyPorts = pivot.DefaultProxyPorts
		pivotCfg.Workers = 50
		pivotCfg.Timeout = cfg.Timeout

		pivotSummary = runPivotPhase(ctx, hostMap, pivotCfg, l7Dispatcher)
	}

	if isCancelled && !*flagQuiet {
		fmt.Println(styleWarning.Render("\n[!] Escaneo interrumpido por el usuario (Ctrl+C). Generando reporte parcial rápidamente..."))
	}

	var hostSummaries []reporter.HostSummary
	for ip, summary := range hostMap {
		// En caso de presionar Ctrl+C de nuevo durante el guardado rápido, salir inmediatamente
		if isCancelled && ctx.Err() != nil {
			// Actually we can't easily trap double Ctrl+C without extra logic, but we skip slow things.
		}

		// WAF/TARPIT Circuit Breaker
		if len(summary.Ports) > 150 {
			if *flagVerbose {
				fmt.Println(styleWarning.Render("⚠") + fmt.Sprintf(" Host %s superó el umbral de 150 puertos abiertos. Etiquetado como [WAF/Tarpit]", ip))
			}
			summary.OS = "Desconocido [WAF/Tarpit]"
			// Skip everything else for this honeypot/tarpit
			hostSummaries = append(hostSummaries, *summary)
			continue
		}

		if *flagVerbose && !isCancelled {
			fmt.Println(styleInfo.Render("ℹ") + fmt.Sprintf(" Analizando Hostname, OS y CVEs para el host %s...", ip))
		}
		
		// DNS PTR Lookup (Reverse DNS)
		dnsCtx, cancelDNS := context.WithTimeout(ctx, 2*time.Second)
		names, err := net.DefaultResolver.LookupAddr(dnsCtx, ip)
		cancelDNS()
		if err == nil && len(names) > 0 {
			summary.Hostname = strings.TrimSuffix(names[0], ".")
			if *flagVerbose {
				fmt.Println(styleSuccess.Render("✓") + fmt.Sprintf(" Hostname resuelto: %s", summary.Hostname))
			}
		}

		// Módulo 1: OS Fingerprinting
		var rawPorts []scanner.Result
		for _, ps := range summary.Ports {
			rawPorts = append(rawPorts, ps.Result)
		}
		if isCancelled {
			summary.OS = "Desconocido (Interrumpido)"
		} else {
			if *flagOS {
				summary.OS = fingerprint.DetectOS(ip, rawPorts)
			} else {
				summary.OS = "Desconocido"
			}
			
			// Módulo 7: L2 ARP Fingerprinting
			mac, err := fingerprint.GetLocalMAC(ip)
			if err == nil && mac != "" {
				summary.MACAddress = mac
				summary.Vendor = fingerprint.LookupVendor(mac)
			}
		}
		
		// Fallback OS detection if ICMP raw sockets failed
		if summary.OS == "Desconocido" && summary.Vendor != "" {
			v := strings.ToLower(summary.Vendor)
			if strings.Contains(v, "apple") {
				summary.OS = "macOS/iOS"
			} else if strings.Contains(v, "vmware") || strings.Contains(v, "virtualbox") || strings.Contains(v, "qemu") || strings.Contains(v, "parallels") {
				summary.OS = "Virtual Appliance / VM"
			} else if strings.Contains(v, "samsung") || strings.Contains(v, "huawei") || strings.Contains(v, "zte") || strings.Contains(v, "motorola") || strings.Contains(v, "xiaomi") {
				summary.OS = "Embedded OS / Android"
			} else if strings.Contains(v, "cisco") || strings.Contains(v, "juniper") || strings.Contains(v, "aruba") || strings.Contains(v, "ubiquiti") || strings.Contains(v, "fortinet") {
				summary.OS = "Network Appliance OS"
			} else if strings.Contains(v, "raspberry") {
				summary.OS = "Raspberry Pi OS"
			} else if strings.Contains(v, "intel") || strings.Contains(v, "realtek") || strings.Contains(v, "qualcomm") || strings.Contains(v, "broadcom") || strings.Contains(v, "dell") || strings.Contains(v, "hp") || strings.Contains(v, "lenovo") || strings.Contains(v, "asus") || strings.Contains(v, "chongqing") || strings.Contains(v, "msi") || strings.Contains(v, "gigabyte") || strings.Contains(v, "tp-link") || strings.Contains(v, "d-link") || strings.Contains(v, "netgear") {
				summary.OS = "PC / Workstation (Desconocido)"
			} else {
				summary.OS = "IoT / Custom OS"
			}
		}
		
		// Módulo 6: CVE Enrichment
		for i, p := range summary.Ports {
			if len(p.Banner) > 0 {
				cves := enrichment.LookupCVEs(p.Banner)
				summary.Ports[i].CVEs = cves
			}
		}
		
		// Módulo 8: Risk Scoring & Attack Paths (CTEM Fase 2)
		risk.AnalyzeHost(summary)

		hostSummaries = append(hostSummaries, *summary)
	}

	// Agrupar por Subred (/24)
	subnetMap := make(map[string]*reporter.SubnetSummary)
	for _, hs := range hostSummaries {
		ip := net.ParseIP(hs.IP).To4()
		if ip == nil {
			continue // Ignorar IPs inválidas
		}
		cidr := fmt.Sprintf("%d.%d.%d.0/24", ip[0], ip[1], ip[2])
		if _, ok := subnetMap[cidr]; !ok {
			subnetMap[cidr] = &reporter.SubnetSummary{
				CIDR:  cidr,
				Hosts: []reporter.HostSummary{},
			}
		}
		subnetMap[cidr].Hosts = append(subnetMap[cidr].Hosts, hs)
	}

	var subnets []reporter.SubnetSummary
	for _, s := range subnetMap {
		subnets = append(subnets, *s)
	}

	// Guardar JSON
	if err := saveJSON(*flagOutput, subnets); err != nil {
		log.Printf("WARN: no se pudo guardar JSON: %v", err)
	}

	// Integración de Baselining (Fase 2)
	var deltaB64 string
	if *flagStateFile != "" {
		if !*flagQuiet {
			fmt.Println(styleInfo.Render("▶") + " Calculando Deltas de infraestructura con Snapshot anterior...")
		}
		
		oldState, err := baselining.LoadState(*flagStateFile)
		if err != nil {
			log.Printf("WARN: no se pudo leer el state previo: %v", err)
		}
		
		// Construir el newState desde los resultados actuales
		newState := &baselining.StateSnapshot{
			Timestamp: time.Now().UTC(),
			Hosts:     make(map[string]baselining.HostState),
		}
		for _, hs := range hostSummaries {
			var openPorts []int
			for _, p := range hs.Ports {
				openPorts = append(openPorts, p.Port)
			}
			newState.Hosts[hs.IP] = baselining.HostState{OpenPorts: openPorts}
		}
		
		delta := baselining.ComputeDelta(oldState, newState)
		
		// Serializar Delta a Base64 para el reporte HTML
		if deltaJSON, err := json.Marshal(delta); err == nil {
			deltaB64 = base64.StdEncoding.EncodeToString(deltaJSON)
		}
		
		// Guardar el nuevo Snapshot
		if err := baselining.SaveState(*flagStateFile, newState); err != nil {
			log.Printf("WARN: no se pudo guardar el nuevo state: %v", err)
		}
	}

	// Guardar HTML
	if *flagHTML != "" {
		cleanPath := filepath.Clean(*flagHTML)
		f, err := os.Create(cleanPath)
		if err != nil {
			log.Printf("WARN: no se pudo crear archivo HTML: %v", err)
		} else {
			if err := reporter.WriteHTMLReport(f, target, version, subnets, deltaB64, pivotSummary); err != nil {
				log.Printf("WARN: no se pudo guardar HTML: %v", err)
			}
			if cerr := f.Close(); cerr != nil {
				log.Printf("WARN: error al cerrar archivo HTML: %v", cerr)
			}
		}
	}

	// Guardar SARIF
	if *flagSarif != "" {
		if err := reporter.ExportToSARIF(hostSummaries, *flagSarif, version, pivotSummary); err != nil {
			log.Printf("WARN: no se pudo guardar SARIF: %v", err)
		}
	}

	// Resumen final
	scanned, open, elapsed := engine.Stats.Snapshot()

	// Crear tabla de resumen
	t := table.New().
		Border(lipgloss.RoundedBorder()).
		BorderStyle(lipgloss.NewStyle().Foreground(cBrand)).
		Headers("Métrica", "Valor").
		StyleFunc(func(row, col int) lipgloss.Style {
			switch {
			case row == 0:
				return lipgloss.NewStyle().Foreground(cWhite).Bold(true).Padding(0, 1)
			case col == 0:
				return lipgloss.NewStyle().Foreground(cCyan).Padding(0, 1)
			default:
				return lipgloss.NewStyle().Foreground(cWhite).Padding(0, 1)
			}
		}).
		Row("⏱  Tiempo", elapsed.Round(time.Millisecond).String()).
		Row("🔍 Escaneados", fmt.Sprintf("%d", scanned)).
		Row("🔓 Abiertos", fmt.Sprintf("%d", open)).
		Row("🚨 Findings", fmt.Sprintf("%d", len(allFindings))).
		Row("📄 JSON Report", *flagOutput)

	if *flagHTML != "" {
		t.Row("🌐 HTML Report", *flagHTML)
	}
	if *flagSarif != "" {
		t.Row("🛡️  SARIF Report", *flagSarif)
	}

	summaryStr := fmt.Sprintf("\n%s\n\n%s\n", styleTitle.Render(" RESUMEN EJECUTIVO "), t.Render())
	fmt.Println(summaryStr)
}

// ──────────────────────────────────────────────
// Helpers
// ──────────────────────────────────────────────

func parseAllowedL7(val string) []string {
	if val == "" {
		return []string{}
	}
	parts := strings.Split(val, ",")
	var cleaned []string
	for _, p := range parts {
		if t := strings.TrimSpace(p); t != "" {
			cleaned = append(cleaned, t)
		}
	}
	return cleaned
}

func runPivotPhase(ctx context.Context, hostMap map[string]*reporter.HostSummary, cfg pivot.Config, l7Dispatcher *scanner.L7Dispatcher) []reporter.PivotSummaryEntry {
	var candidates []pivot.Candidate
	for ip, hs := range hostMap {
		for _, p := range hs.Ports {
			if pivot.IsProxyPort(p.Port, cfg) {
				candidates = append(candidates, pivot.Candidate{
					Host: ip,
					Port: p.Port,
				})
			}
		}
	}

	if len(candidates) == 0 {
		return nil
	}

	if !*flagQuiet {
		fmt.Println(styleInfo.Render("▶") + fmt.Sprintf(" Iniciando Proxy Pivot Detection en %d proxies detectados...", len(candidates)))
	}

	var summaries []reporter.PivotSummaryEntry
	var pivotWg sync.WaitGroup
	var mu sync.Mutex

	var completedProxies int32
	totalProxies := int32(len(candidates)) // #nosec G115 -- La cantidad de candidatos proxy será pequeña

	ticker := time.NewTicker(200 * time.Millisecond)
	defer ticker.Stop()

	go func() {
		for range ticker.C {
			if !*flagQuiet {
				c := atomic.LoadInt32(&completedProxies)
				fmt.Printf("\r\033[K%s Evaluando Proxies y Pivotando [%d/%d]...", styleWarning.Render("↻"), c, totalProxies)
			}
		}
	}()

	for _, cand := range candidates {
		pivotWg.Add(1)
		go func(c pivot.Candidate) {
			defer pivotWg.Done()
			defer atomic.AddInt32(&completedProxies, 1)
			
			// Extraer TODOS los puertos directos conocidos de TODOS los hosts
			directHostMap := make(map[string][]int)
			if mu.TryLock() { mu.Unlock() } // Just a reminder that hostMap is safe here since we are after wait
			for ip, summary := range hostMap {
				for _, p := range summary.Ports {
					directHostMap[ip] = append(directHostMap[ip], p.Port)
				}
			}

			res, err := pivot.CheckAndPivot(ctx, c, directHostMap, cfg)
			if err != nil || res == nil {
				return // proxy no funcional o fallback
			}

			if !*flagQuiet {
				findingsCount := len(res.AllFindings())
				if findingsCount > 0 {
					// Blank the line so the \n leaves it clean, and ticker reprints underneath
					fmt.Printf("\r\033[K  %s 🔀 Pivot via %s:%d (%s) → %s puertos expuestos (PIVOT-ONLY)\n", 
						styleWarning.Render("►"), c.Host, c.Port, res.Proxy.ProxyType, styleSevCritical.Render(fmt.Sprintf("%d", findingsCount)))
					
					// Print the actual exposed ports
					for _, f := range res.AllFindings() {
						sevStr := severityIcon(f.Severity) + " " + styleSevCritical.Render(string(f.Severity))
						fmt.Printf("\r\033[K      ↳ %s %s:%d [%s] %s\n", sevStr, stripANSI(f.Host), f.Port, styleDim.Render(stripANSI(f.Service)), styleDim.Render("vía proxy "+stripANSI(res.Proxy.ProxyType)))
					}
				}
			}

			// Opcional: L7 sobre findings L1 usando DispatchWithContext
			var finalFindings []reporter.PivotFindingEntry
			for _, f := range res.AllFindings() {
				// Ejecutar L7 si está activado globalmente
				if *flagL7 {
					dialer, errD := proxy.NewDialer(fmt.Sprintf("%s://%s:%d", res.Proxy.ProxyType, res.Proxy.Host, res.Proxy.Port), cfg.Timeout)
					if errD == nil {
						pCtx := scanner.PivotContext{
							IsPivot:   true,
							ProxyHost: res.Proxy.Host,
							ProxyPort: res.Proxy.Port,
							ProxyType: res.Proxy.ProxyType,
						}
						// Disparar L7 a través del túnel pivot
						l7Findings := l7Dispatcher.DispatchWithContext(f.Host, f.Port, f.Service, cfg.Timeout, dialer, pCtx)
						for _, l7f := range l7Findings {
							finalFindings = append(finalFindings, reporter.PivotFindingEntry{
								Host:        l7f.Host,
								Port:        l7f.Port,
								Protocol:    l7f.Service,
								Severity:    l7f.Severity,
								RuleID:      l7f.RuleID,
								RuleName:    l7f.RuleName,
								Description: l7f.Description,
								Context:     l7f.Context,
								ProxyHost:   res.Proxy.Host,
								ProxyPort:   res.Proxy.Port,
								ProxyType:   res.Proxy.ProxyType,
								Visibility:  "pivot-only", // Por definición L7 via pivot va al servicio interno
							})
						}
					}
				}
				
				finalFindings = append(finalFindings, reporter.PivotFindingEntry{
					Host:        f.Host,
					Port:        f.Port,
					Protocol:    f.Service,
					Severity:    f.Severity,
					RuleID:      f.RuleID,
					RuleName:    f.RuleName,
					Description: f.Description,
					Context:     f.Context,
					ProxyHost:   f.ProxyHost,
					ProxyPort:   f.ProxyPort,
					ProxyType:   res.Proxy.ProxyType,
					Visibility:  f.Visibility,
				})
				
				// Actualizar el HostSummary global para que salgan en HTML section de host también
				mu.Lock()
				if hs, ok := hostMap[f.Host]; ok {
					hs.PivotFindings = append(hs.PivotFindings, finalFindings[len(finalFindings)-1])
				} else {
					// Si es un host en subred/rango que no estaba en el discovery
					hs = &reporter.HostSummary{IP: f.Host}
					hs.PivotFindings = append(hs.PivotFindings, finalFindings[len(finalFindings)-1])
					hostMap[f.Host] = hs
				}
				mu.Unlock()
			}

			if len(finalFindings) > 0 {
				mu.Lock()
				summaries = append(summaries, reporter.PivotSummaryEntry{
					ProxyHost: res.Proxy.Host,
					ProxyPort: res.Proxy.Port,
					ProxyType: res.Proxy.ProxyType,
					Findings:  finalFindings,
				})
				mu.Unlock()
			}
		}(cand)
	}
	pivotWg.Wait()
	if !*flagQuiet {
		fmt.Printf("\r\033[K") // Limpiar barra final
	}
	return summaries
}

func runScan(ctx context.Context, engine *scanner.Engine, ruleSet *rules.RuleSet, targets <-chan scanner.Target, totalTargets int, flushCallback func([]rules.Finding, []scanner.Result), pDialer proxy.ContextDialer, l7Dispatcher *scanner.L7Dispatcher) ([]rules.Finding, []scanner.Result) {

	var openResults []scanner.Result
	var allFindings []rules.Finding
	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()

	// Progreso
	prog := progress.New(progress.WithDefaultGradient())
	
	// Auto-Save ticker
	flushTicker := time.NewTicker(30 * time.Second)
	defer flushTicker.Stop()

	results := engine.Scan(ctx, targets)

	// Canal para recibir hallazgos asíncronos de enriquecimiento (Fases 3, 4, 5)
	asyncFindingsChan := make(chan rules.Finding, 1000)
	asyncStatusUrlChan := make(chan string, 100) // Canal para live URL status
	var asyncWg sync.WaitGroup
	var asyncCount int32
	asyncSem := make(chan struct{}, 100) // Semáforo para limitar a 100 hilos de Fuzzing concurrentes

	resultsOpen := true
	asyncOpen := true
	var currentFuzzURL string
	var currentScanTarget string

	for resultsOpen || asyncOpen {
		select {
		case r, ok := <-results:
			if !ok {
				results = nil // Deshabilitar este case
				resultsOpen = false
				// Ahora que el escaneo de puertos terminó, esperamos a las tareas asíncronas
				go func() {
					asyncWg.Wait()
					close(asyncFindingsChan)
				}()
				continue
			}
			
			currentScanTarget = fmt.Sprintf("%s:%d", r.Host, r.Port)
			
			if r.Open {
				openResults = append(openResults, r)
				svc := scanner.GuessService(r.Port, []byte(r.Banner))
				t := rules.ScanTarget{
					Host:    r.Host,
					Port:    r.Port,
					Service: svc,
					Banner:  r.Banner,
				}
				fs := rules.Evaluate(ruleSet, t)
				allFindings = append(allFindings, fs...)

				// Fases 3, 4, 5 (Safe-Checks, Web Fuzzing, TLS)
				// Integración concurrente gobernada.
				if !engine.Config().SafeMode { // No lanzar en Safe Mode
					asyncWg.Add(1)
					atomic.AddInt32(&asyncCount, 1)
					go func(host string, port int, service string, protocol string, isTLS bool, dialer proxy.ContextDialer) {
						asyncSem <- struct{}{} // Adquirir token de concurrencia
						defer func() { <-asyncSem }() // Liberar token
						
						defer asyncWg.Done()
						defer atomic.AddInt32(&asyncCount, -1)
						var asyncFindings []rules.Finding
						timeout := 3 * time.Second // Regla #1: Timeouts implacables

						// Fase 3: TLS (con proxy propagado)
						if isTLS || port == 443 || port == 8443 {
							asyncFindings = append(asyncFindings, enrichment.CheckTLS(host, port, timeout, dialer)...)
						}

						// Fase 4: Web Fuzzing & Tech (con proxy propagado al http.Transport)
						if *flagFuzz {
							if strings.HasPrefix(service, "http") || port == 80 || port == 443 || port == 8080 || port == 8443 {
								asyncFindings = append(asyncFindings, enrichment.CheckWebFingerprint(host, port, isTLS || port == 443 || port == 8443, timeout, ruleSet.Rules, asyncStatusUrlChan, *flagProxy)...)
							}
						}

						// Fase 5: Protocol Safe-Checks (con proxy propagado)
						if port == 445 {
							asyncFindings = append(asyncFindings, enrichment.CheckSMB(host, port, timeout, dialer)...)
						}
						if port == 21 {
							asyncFindings = append(asyncFindings, enrichment.CheckFTPAnonymous(host, port, timeout, dialer)...)
						}
						if port == 3389 {
							asyncFindings = append(asyncFindings, enrichment.CheckRDP_NLA(host, port, timeout, dialer)...)
						}

						// Fase 6: L7 Port-Triggered Execution
						// El Dispatcher aplica doble validación: puerto coincide + autorización de modo.
						// En Modo Auto: todos los templates autorizados para este puerto.
						// En Modo Manual: solo los IDs en AllowedL7IDs del usuario.
						if *flagL7 {
							asyncFindings = append(asyncFindings, l7Dispatcher.Dispatch(host, port, protocol, timeout, dialer)...)
						}

						// Enviar al canal
						for _, f := range asyncFindings {
							asyncFindingsChan <- f
						}
					}(r.Host, r.Port, svc, r.Protocol, strings.Contains(svc, "https") || strings.Contains(svc, "ssl"), pDialer)
				}

				for _, f := range fs {
					sevStr := string(f.Severity)
					switch f.Severity {
					case rules.SeverityCritical:
						sevStr = styleSevCritical.Render(sevStr)
					case rules.SeverityHigh:
						sevStr = styleSevHigh.Render(sevStr)
					case rules.SeverityMedium:
						sevStr = styleSevMedium.Render(sevStr)
					case rules.SeverityLow:
						sevStr = styleSevLow.Render(sevStr)
					default:
						sevStr = styleSevInfo.Render(sevStr)
					}
					confStr := ""
					if f.Confidence == "confirmed" {
						confStr = styleConfConfirmed.Render("[🎯 CONFIRMED] ")
					} else if f.Confidence == "high" {
						confStr = styleConfHigh.Render("[⚠️ HIGH CONF] ")
					}

					fmt.Printf("\r\033[K  %s %s  %-8s  %s%s:%d  (%s)\n",
						styleWarning.Render("►"), severityIcon(f.Severity), sevStr, confStr, stripANSI(f.Host), f.Port, styleDim.Render(stripANSI(f.RuleName)))
				}
				if *flagVerbose {
					fmt.Printf("\r\033[K  %s %s:%d  [%s]\n", styleSuccess.Render("🔓 OPEN"), stripANSI(r.Host), r.Port, styleDim.Render(stripANSI(svc)))
				}
			}
		case f, ok := <-asyncFindingsChan:
			if !ok {
				asyncFindingsChan = nil // Deshabilitar este case
				asyncOpen = false
				continue
			}
			allFindings = append(allFindings, f)
			if !*flagQuiet {
				sevStr := string(f.Severity)
				switch f.Severity {
				case rules.SeverityCritical:
					sevStr = styleSevCritical.Render(sevStr)
				case rules.SeverityHigh:
					sevStr = styleSevHigh.Render(sevStr)
				case rules.SeverityMedium:
					sevStr = styleSevMedium.Render(sevStr)
				case rules.SeverityLow:
					sevStr = styleSevLow.Render(sevStr)
				default:
					sevStr = styleSevInfo.Render(sevStr)
				}
				confStr := ""
				if f.Confidence == "confirmed" {
					confStr = styleConfConfirmed.Render("[🎯 CONFIRMED] ")
				} else if f.Confidence == "high" {
					confStr = styleConfHigh.Render("[⚠️ HIGH CONF] ")
				}

				fmt.Printf("\r\033[K  %s %s  %-8s  %s%s:%d  (%s)\n",
					styleWarning.Render("►"), severityIcon(f.Severity), sevStr, confStr, stripANSI(f.Host), f.Port, styleDim.Render(stripANSI(f.RuleName)))
			}
		case urlStatus := <-asyncStatusUrlChan:
			currentFuzzURL = urlStatus
		case <-ticker.C:
			if !*flagQuiet {
				scanned, open, _ := engine.Stats.Snapshot()
				ratio := float64(scanned) / float64(totalTargets)
				if ratio > 1.0 {
					ratio = 1.0
				}
				
				if !resultsOpen {
					pending := atomic.LoadInt32(&asyncCount)
					if pending > 0 {
						title := fmt.Sprintf("⏳ ENRICHMENT [%d Tareas Restantes]", pending)
						displayUrl := currentFuzzURL
						if displayUrl != "" {
							if len(displayUrl) > 40 {
								displayUrl = "..." + displayUrl[len(displayUrl)-37:]
							}
							title += " → Fuzzing: " + displayUrl
						}
						// Animation frames based on time
						frames := []string{"⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"}
						frame := frames[(time.Now().UnixNano()/100000000)%int64(len(frames))]
						
						fmt.Printf("\r\033[K  %s %s %s", styleWarning.Render(frame), styleSevMedium.Render("MODULO ACTIVO:"), styleDim.Render(title))
					}
				} else {
					title := "TCP SYN Scanning"
					if currentScanTarget != "" {
						title += fmt.Sprintf(" → %s", currentScanTarget)
					}
					fmt.Printf("\r\033[K%s %s %s [%d/%d]",
						prog.ViewAs(ratio), styleDim.Render(title), styleSuccess.Render(fmt.Sprintf("(%d open)", open)), scanned, totalTargets)
				}
			}
		case <-flushTicker.C:
			if flushCallback != nil {
				flushCallback(allFindings, openResults)
			}
		case <-ctx.Done():
			// En caso de cancelación, no esperamos a las asíncronas y salimos rápido
			return allFindings, openResults
		}
	}
	return allFindings, openResults
}

func severityIcon(s rules.Severity) string {
	switch s {
	case rules.SeverityCritical:
		return styleSevCritical.Render("💀 CRIT")
	case rules.SeverityHigh:
		return styleSevHigh.Render("☣️  HIGH")
	case rules.SeverityMedium:
		return styleSevMedium.Render("⚡ MED ")
	case rules.SeverityLow:
		return styleSevLow.Render("ℹ️  LOW ")
	default:
		return styleSevInfo.Render("🔍 INFO")
	}
}

// JSONReport es la estructura de salida del reporte.
type JSONReport struct {
	Meta    JSONMeta                 `json:"meta"`
	Subnets []reporter.SubnetSummary `json:"subnets"`
}

type JSONMeta struct {
	Version   string    `json:"version"`
	Timestamp time.Time `json:"timestamp"`
	Target    string    `json:"target"`
}

func saveJSON(path string, subnets []reporter.SubnetSummary) error {
	cleanPath := filepath.Clean(path)
	tmpPath := filepath.Clean(cleanPath + ".tmp")
	f, err := os.Create(tmpPath) // #nosec G304 -- User supplied output path via CLI
	if err != nil {
		return err
	}

	target := *flagTarget
	if target == "" {
		target = *flagDomain
	}
	if *flagAuto {
		target = "AUTONOMOUS-ASM"
	}

	report := JSONReport{
		Meta:    JSONMeta{Version: version, Timestamp: time.Now().UTC(), Target: target},
		Subnets: subnets,
	}
	dataBytes, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		_ = f.Close()
		return err
	}
	
	_, err = f.Write(dataBytes)
	if closeErr := f.Close(); closeErr != nil && err == nil {
		err = closeErr
	}
	
	if err != nil {
		return err
	}
	
	return os.Rename(tmpPath, cleanPath)
}

func resolvePorts(spec string) []scanner.Target {
	var targets []scanner.Target
	switch strings.ToLower(spec) {
	case "common":
		for _, p := range scanner.CommonPorts {
			targets = append(targets, scanner.Target{Port: p, Protocol: "tcp"})
		}
		// Inyectar puertos UDP críticos por defecto
		targets = append(targets, scanner.Target{Port: 53, Protocol: "udp"})
		targets = append(targets, scanner.Target{Port: 161, Protocol: "udp"})
		targets = append(targets, scanner.Target{Port: 123, Protocol: "udp"})
		return targets
	case "top100":
		for _, p := range top100Ports() {
			targets = append(targets, scanner.Target{Port: p, Protocol: "tcp"})
		}
		return targets
	case "all", "-p-":
		for i := 1; i <= 65535; i++ {
			targets = append(targets, scanner.Target{Port: i, Protocol: "tcp"})
		}
		return targets
	default:
		for _, p := range strings.Split(spec, ",") {
			p = strings.TrimSpace(p)
			protocol := "tcp"
			if strings.HasSuffix(strings.ToLower(p), "/udp") {
				protocol = "udp"
				p = strings.TrimSuffix(strings.ToLower(p), "/udp")
			} else if strings.HasSuffix(strings.ToLower(p), "/tcp") {
				protocol = "tcp"
				p = strings.TrimSuffix(strings.ToLower(p), "/tcp")
			}
			var n int
			_, _ = fmt.Sscanf(p, "%d", &n)
			if n > 0 && n <= 65535 {
				targets = append(targets, scanner.Target{Port: n, Protocol: protocol})
			}
		}
		if len(targets) == 0 {
			log.Fatal("Lista de puertos vacía o inválida")
		}
		return targets
	}
}

func top100Ports() []int {
	return []int{
		1, 3, 7, 9, 13, 17, 19, 21, 22, 23, 25, 37, 42, 53, 70, 79, 80, 88, 110,
		111, 113, 119, 135, 139, 143, 161, 179, 194, 389, 443, 445, 465, 514, 515,
		543, 544, 548, 587, 631, 636, 993, 995, 1080, 1194, 1433, 1521, 1723, 1900,
		2049, 2082, 2083, 2086, 2087, 2095, 2096, 2181, 3128, 3306, 3389, 4443, 4444,
		5432, 5900, 5984, 6379, 6443, 7001, 7443, 8000, 8080, 8081, 8082, 8083,
		8090, 8118, 8443, 8888, 9000, 9090, 9200, 9300, 10000, 11211, 27017, 27018,
		27019, 28017, 50000, 50070, 50075, 54321, 61616,
	}
}
func usage() {
	fmt.Fprintf(os.Stderr, "Uso: raptor [flags]\n\n")
	flag.PrintDefaults()
	fmt.Fprintf(os.Stderr, `
Ejemplos:
  raptor --target 192.168.1.0/24
  raptor --target 192.168.1.0/24 --ports 80,443 --workers 100
  raptor --target 172.16.0.0/12 --ports top100 --rules ./my-rules --output report.json
`)
	fmt.Println()
}


