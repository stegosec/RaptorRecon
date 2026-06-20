package main

import (
	"fmt"
	"log"
	"os"
	"strings"

	"github.com/charmbracelet/huh"
	"github.com/charmbracelet/lipgloss"
)

// ──────────────────────────────────────────────
// Asistente Interactivo (TUI)
// ──────────────────────────────────────────────

func runInteractiveTUI() {
	var (
		mode      string
		target    string
		ports     string
		profile   string
		ghost     bool
		banners   bool
		safeMode  bool
		proxyURL  string
		htmlOut   string
		modules   []string
		fragProf  string
	)

	form := huh.NewForm(
		huh.NewGroup(
			huh.NewSelect[string]().
				Title("Modo de Operación").
				Options(
					huh.NewOption("Auditoría Dirigida (Target Manual)", "manual"),
					huh.NewOption("Descubrimiento Autónomo (Shadow IT Hunt)", "auto"),
				).
				Value(&mode),
		),
		huh.NewGroup(
			huh.NewInput().
				Title("¿Cuál es el objetivo (IP/CIDR/Dominio)?").
				Value(&target).
				Validate(func(s string) error {
					if strings.TrimSpace(s) == "" {
						return fmt.Errorf("el objetivo no puede estar vacío en modo manual")
					}
					return nil
				}),
		).WithHideFunc(func() bool {
			return mode == "auto"
		}),
		huh.NewGroup(
			huh.NewSelect[string]().
				Title("Perfil de Puertos").
				Options(
					huh.NewOption("Top 100 (Rápido y Sigiloso)", "common"),
					huh.NewOption("Comunes + IoT UDP", "common,53/udp,161/udp"),
					huh.NewOption("Full-Port 65535 (Profundo)", "all"),
				).
				Value(&ports),
		),
		huh.NewGroup(
			huh.NewSelect[string]().
				Title("Perfil de Red (Rate Limit & Workers)").
				Options(
					huh.NewOption("Balanced (Equilibrado, default)", "balanced"),
					huh.NewOption("Aggressive (Rápido, ruidoso)", "aggressive"),
					huh.NewOption("Stealth (Lento, evasivo)", "stealth"),
				).
				Value(&profile),
			huh.NewMultiSelect[string]().
				Title("Módulos Adicionales (Usa Espacio para seleccionar)").
				Options(
					huh.NewOption("Activar L7 Template Engine (Handshakes Activos)", "l7"),
					huh.NewOption("Activar OS Fingerprinting (Heurístico / Raw)", "os"),
					huh.NewOption("Activar Web Fuzzing / Tech Detection", "fuzz"),
					huh.NewOption("Exportar Reporte HTML (Dashboard CISO)", "html"),
					huh.NewOption("Exportar Reporte SARIF (SIEM/DevSecOps)", "sarif"),
					huh.NewOption("Detectar cambios respecto al escaneo anterior (CTEM)", "baseline"),
					huh.NewOption("Activar Proxy Pivot Detection (Exposición oculta tras proxy)", "pivot"),
				).
				Value(&modules),
			huh.NewSelect[string]().
				Title("Evasión DPI (Payload Fragmentation)").
				Options(
					huh.NewOption("Off (Sin evasión)", "off"),
					huh.NewOption("Low (64-byte chunks, no delay)", "low"),
					huh.NewOption("Medium (8-byte chunks, 5-15ms delay)", "medium"),
					huh.NewOption("High (1-byte TLS, 10-50ms delay)", "high"),
					huh.NewOption("Auto (Depende del protocolo detectado)", "auto"),
				).
				Value(&fragProf),
		).WithHideFunc(func() bool {
			return mode == "auto"
		}),
		huh.NewGroup(
			huh.NewInput().
				Title("Proxy (SOCKS5/HTTP) - Opcional").
				Placeholder("socks5://127.0.0.1:9050").
				Value(&proxyURL),
			huh.NewInput().
				Title("Nombre del reporte HTML de salida").
				Value(&htmlOut).
				Placeholder("raptor_report.html"),
		),
	).WithTheme(stegosecTheme())

	err := form.Run()
	if err != nil {
		if err == huh.ErrUserAborted {
			fmt.Println("\n[!] Asistente cancelado por el usuario.")
			os.Exit(0)
		}
		log.Fatalf("Error en el asistente interactivo: %v", err)
	}

	if htmlOut == "" {
		htmlOut = "raptor_report.html"
	}

	var l7Enabled, osEnabled, fuzzEnabled, exportHtml, sarif, baseline, pivotEnabled bool
	for _, mod := range modules {
		switch mod {
		case "l7":
			l7Enabled = true
		case "os":
			osEnabled = true
		case "fuzz":
			fuzzEnabled = true
		case "html":
			exportHtml = true
		case "sarif":
			sarif = true
		case "baseline":
			baseline = true
		case "pivot":
			pivotEnabled = true
		}
	}

	// Mapear respuestas a las flags globales de forma transparente
	if mode == "auto" {
		*flagAuto = true
	} else {
		*flagTarget = target
	}
	*flagPorts = ports
	*flagGhost = ghost
	*flagBanners = banners
	*flagProxy = proxyURL
	*flagHTML = htmlOut
	*flagProfile = profile
	*flagFrag = fragProf
	*flagSafe = safeMode
	*flagL7 = l7Enabled
	*flagOS = osEnabled
	*flagFuzz = fuzzEnabled
	
	if pivotEnabled {
		*flagProxyPivot = true
		*flagPivotSubnet = true // En modo TUI interactivo habilitamos escaneo de subred por defecto si activa pivot
	}

	if !exportHtml {
		*flagHTML = ""
	}

	if sarif {
		*flagSarif = "raptor_sarif.json"
	}
	if baseline {
		*flagStateFile = "raptor_state.json"
	}

	// La lógica de asignación de Workers/RateLimit/Timeout ya se maneja en main.go 
	// en base a *flagProfile, así que no es necesario reasignarlos manualmente aquí.
}

func stegosecTheme() *huh.Theme {
	t := huh.ThemeBase()
	
	orange := lipgloss.Color("#FF6600") // Neon Orange
	navy := lipgloss.Color("#0F172A") // Deep Slate
	white := lipgloss.Color("#FFFFFF")
	gray := lipgloss.Color("#475569")

	t.Focused.Base = t.Focused.Base.BorderForeground(orange)
	t.Focused.Title = t.Focused.Title.Foreground(orange).Bold(true)
	t.Focused.TextInput.Cursor = t.Focused.TextInput.Cursor.Foreground(orange)
	t.Focused.TextInput.Prompt = t.Focused.TextInput.Prompt.Foreground(orange)
	
	t.Focused.SelectedOption = t.Focused.SelectedOption.Foreground(white).Background(navy).Bold(true)
	t.Focused.UnselectedOption = t.Focused.UnselectedOption.Foreground(gray)
	t.Focused.SelectSelector = t.Focused.SelectSelector.Foreground(orange)
	
	t.Focused.Description = t.Focused.Description.Foreground(gray)
	t.Focused.NextIndicator = t.Focused.NextIndicator.Foreground(orange)
	
	t.Focused.FocusedButton = t.Focused.FocusedButton.Foreground(white).Background(orange).Bold(true)
	t.Focused.BlurredButton = t.Focused.BlurredButton.Foreground(gray)

	t.Blurred = t.Focused
	t.Blurred.Base = t.Blurred.Base.BorderStyle(lipgloss.HiddenBorder())

	return t
}
