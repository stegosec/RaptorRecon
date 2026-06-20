package main

import "github.com/charmbracelet/lipgloss"

// ──────────────────────────────────────────────
// Estilos CLI — StegoSec Branding
// ──────────────────────────────────────────────

var (
	cBrand  = lipgloss.Color("#0EA5E9") // Professional Cyber Blue (Sky)
	cNavy   = lipgloss.Color("#0F172A") // Deep Slate
	cWhite  = lipgloss.Color("#FFFFFF")
	cRed    = lipgloss.Color("#EF4444") // Standard Red
	cYellow = lipgloss.Color("#FACC15") // Electric Yellow (Medium)
	cCyan   = lipgloss.Color("#22D3EE") // Cyan (Low)
	cGray   = lipgloss.Color("#64748B") // Slate Gray
	cGreen  = lipgloss.Color("#10B981") // Emerald Green (Success)

	styleSuccess = lipgloss.NewStyle().Foreground(cGreen).Bold(true)
	styleWarning = lipgloss.NewStyle().Foreground(cYellow).Bold(true)
	styleError   = lipgloss.NewStyle().Foreground(cRed).Bold(true)
	styleInfo    = lipgloss.NewStyle().Foreground(cCyan).Bold(true)
	styleGhost   = lipgloss.NewStyle().Foreground(lipgloss.Color("#8B5CF6")).Bold(true)
	styleDim     = lipgloss.NewStyle().Foreground(cGray)

	stylePanel = lipgloss.NewStyle().
			Border(lipgloss.RoundedBorder()).
			BorderForeground(cBrand).
			Padding(1, 2)

	styleTitle = lipgloss.NewStyle().
			Background(cBrand).
			Foreground(cNavy).
			Padding(0, 1).
			Bold(true)

	styleSevCritical = lipgloss.NewStyle().Foreground(cRed).Bold(true)
	styleSevHigh     = lipgloss.NewStyle().Foreground(lipgloss.Color("#F97316")).Bold(true) // Orange for High
	styleSevMedium   = lipgloss.NewStyle().Foreground(cYellow).Bold(true)
	styleSevLow      = lipgloss.NewStyle().Foreground(cCyan).Bold(true)
	styleSevInfo     = lipgloss.NewStyle().Foreground(cGray).Bold(true)

	styleConfConfirmed = lipgloss.NewStyle().Foreground(cGreen).Bold(true)
	styleConfHigh      = lipgloss.NewStyle().Foreground(lipgloss.Color("#F97316")).Bold(true)
)
