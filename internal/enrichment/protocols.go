package enrichment

import (
	"bytes"
	"context"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/raptor-recon/raptor/internal/proxy"
	"github.com/raptor-recon/raptor/internal/rules"
)

// dialWithProxy devuelve una conexión TCP usando el proxy configurado si está disponible,
// o un net.Dialer directo en caso contrario. Centraliza la lógica de dialing para todos los checks.
func dialWithProxy(ctx context.Context, addr string, timeout time.Duration, dialer proxy.ContextDialer) (net.Conn, error) {
	var d proxy.ContextDialer
	if dialer != nil {
		d = dialer
	} else {
		d = &net.Dialer{Timeout: timeout}
	}
	dialCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	return d.DialContext(dialCtx, "tcp", addr)
}

// CheckSMB evalúa el soporte de SMBv1 en el puerto 445 mediante un Negotiation Request nativo.
// Acepta un proxy.ContextDialer opcional para enrutar el tráfico a través de un proxy configurado.
func CheckSMB(host string, port int, timeout time.Duration, dialer proxy.ContextDialer) []rules.Finding {
	var findings []rules.Finding
	addr := fmt.Sprintf("%s:%d", host, port)

	conn, err := dialWithProxy(context.Background(), addr, timeout, dialer)
	if err != nil {
		return findings // Fallo de conexión o timeout (Degradación silenciosa)
	}
	defer conn.Close()

	// Timeout de lectura/escritura implacable
	_ = conn.SetDeadline(time.Now().Add(timeout))

	// SMB Negotiate Protocol Request Packet (Pidiendo dialecto NT LM 0.12 - SMBv1)
	// Este es un payload crudo estándar para listar dialectos soportados.
	smbNegotiate := []byte{
		0x00, 0x00, 0x00, 0x2f, 0xff, 0x53, 0x4d, 0x42, // NetBIOS Session Service + SMB Header
		0x72, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x22, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x0c, 0x00, 0x02, 0x4e, 0x54, 0x20, 0x4c, // "NT LM 0.12"
		0x4d, 0x20, 0x30, 0x2e, 0x31, 0x32, 0x00,
	}

	_, err = conn.Write(smbNegotiate)
	if err != nil {
		return findings
	}

	reply := make([]byte, 1024)
	n, err := conn.Read(reply)
	if err != nil || n < 4 {
		return findings
	}

	// Comprobar la respuesta de la negociación
	// Si el servidor acepta el dialecto 0 (NT LM 0.12), significa que SMBv1 está activo.
	// Buscamos la firma SMB (0xff, 'S', 'M', 'B') y la respuesta del dialecto.
	if bytes.Contains(reply[:n], []byte{0xff, 'S', 'M', 'B'}) {
		// La respuesta a negotiate protocol es el comando 0x72.
		// En SMBv1, el index del dialecto aceptado está en offset 35-36.
		if n >= 37 && reply[35] != 0xff && reply[36] != 0xff {
			evidence := fmt.Sprintf("%x", reply[:n])
			if len(evidence) > 500 {
				evidence = evidence[:500] + "..."
			}
			findings = append(findings, rules.Finding{
				Host:        host,
				Port:        port,
				RuleID:      "PROTO-SMBV1-ENABLED",
				RuleName:    "Protocolo SMBv1 Habilitado",
				Severity:    rules.SeverityCritical,
				Confidence:  "confirmed",
				Description: "El servidor soporta SMBv1 (NT LM 0.12). Este protocolo es obsoleto y altamente vulnerable a exploits de ejecución remota de código (ej. EternalBlue) que facilitan el movimiento lateral del ransomware.",
				Remediation: "Deshabilitar SMBv1 en todos los sistemas. En Windows, usar PowerShell: Disable-WindowsOptionalFeature -Online -FeatureName smb1protocol",
				Mitre:       []string{"T1021.002 - Remote Services: SMB/Windows Admin Shares"},
				SLA:         "24 horas",
				Evidence:    "Raw Negotiation Response (Hex):\n" + evidence,
			})
		}
	}

	return findings
}

// CheckFTPAnonymous intenta un login anónimo pasivo en el puerto 21.
// Acepta un proxy.ContextDialer opcional para enrutar el tráfico a través de un proxy configurado.
func CheckFTPAnonymous(host string, port int, timeout time.Duration, dialer proxy.ContextDialer) []rules.Finding {
	var findings []rules.Finding
	addr := fmt.Sprintf("%s:%d", host, port)

	conn, err := dialWithProxy(context.Background(), addr, timeout, dialer)
	if err != nil {
		return findings
	}
	defer conn.Close()

	_ = conn.SetDeadline(time.Now().Add(timeout))

	buf := make([]byte, 1024)
	// Leer banner inicial
	_, err = conn.Read(buf)
	if err != nil {
		return findings
	}

	// Enviar USER anonymous
	_, err = conn.Write([]byte("USER anonymous\r\n"))
	if err != nil {
		return findings
	}

	n, err := conn.Read(buf)
	if err != nil {
		return findings
	}
	resp := string(buf[:n])

	if strings.Contains(resp, "331") {
		// Enviar PASS anonymous
		_, err = conn.Write([]byte("PASS anonymous\r\n"))
		if err != nil {
			return findings
		}

		n, err = conn.Read(buf)
		if err != nil {
			return findings
		}
		resp = string(buf[:n])

		// 230 User logged in
		if strings.Contains(resp, "230") {
			evidence := resp
			if len(evidence) > 500 {
				evidence = evidence[:500] + "..."
			}
			findings = append(findings, rules.Finding{
				Host:        host,
				Port:        port,
				RuleID:      "PROTO-FTP-ANONYMOUS",
				RuleName:    "FTP Acceso Anónimo Permitido",
				Severity:    rules.SeverityHigh,
				Confidence:  "confirmed",
				Description: "El servidor FTP permite iniciar sesión como 'anonymous' sin contraseña, exponiendo archivos internos y pudiendo servir como repositorio de malware.",
				Remediation: "Deshabilitar la cuenta 'anonymous' en la configuración del servidor FTP (ej. anonymous_enable=NO en vsftpd.conf).",
				Mitre:       []string{"T1078 - Valid Accounts"},
				SLA:         "7 días",
				Evidence:    "FTP Dialog:\nUSER anonymous\nPASS anonymous\n" + evidence,
			})
		}
	}

	return findings
}

// CheckRDP_NLA valida si el servidor RDP requiere NLA (Network Level Authentication).
// Acepta un proxy.ContextDialer opcional para enrutar el tráfico a través de un proxy configurado.
func CheckRDP_NLA(host string, port int, timeout time.Duration, dialer proxy.ContextDialer) []rules.Finding {
	var findings []rules.Finding
	addr := fmt.Sprintf("%s:%d", host, port)

	conn, err := dialWithProxy(context.Background(), addr, timeout, dialer)
	if err != nil {
		return findings
	}
	defer conn.Close()

	_ = conn.SetDeadline(time.Now().Add(timeout))

	// X.224 Connection Request PDU
	// Pidiendo routing token y soporte para protocolos de seguridad
	rdpReq := []byte{
		0x03, 0x00, 0x00, 0x13, // TPKT Header
		0x0e,                   // X.224 length
		0xe0,                   // CR (Connection Request)
		0x00, 0x00,             // Destination reference
		0x00, 0x00,             // Source reference
		0x00,                   // Class
		0x01, 0x00, 0x08, 0x00, // RDP Neg Req (routingToken / info)
		0x0b, 0x00, 0x00, 0x00, // Requested protocols: SSL, HYBRID, HYBRID_EX
	}

	_, err = conn.Write(rdpReq)
	if err != nil {
		return findings
	}

	reply := make([]byte, 1024)
	n, err := conn.Read(reply)
	if err != nil || n < 19 {
		return findings
	}

	// Parsear la respuesta RDP Negotiation Response (0x02)
	// Asegurar que inicie con TPKT (0x03) para evitar falsos positivos con otros protocolos.
	// Si el flag de protocolos soportados no incluye 0x02 (NLA / CredSSP) o 0x08 (HYBRID_EX),
	// significa que permite fallback a RDP Security Layer (Altamente vulnerable a MitM).
	if reply[0] == 0x03 && reply[11] == 0x02 {
		selectedProtocol := uint32(reply[15]) | uint32(reply[16])<<8 | uint32(reply[17])<<16 | uint32(reply[18])<<24

		// 0x00000000 = Standard RDP Security (vulnerable)
		// 0x00000001 = TLS 1.0 (obsolete)
		if selectedProtocol == 0 || selectedProtocol == 1 {
			evidence := fmt.Sprintf("%x", reply[:n])
			if len(evidence) > 500 {
				evidence = evidence[:500] + "..."
			}
			findings = append(findings, rules.Finding{
				Host:        host,
				Port:        port,
				RuleID:      "PROTO-RDP-NO-NLA",
				RuleName:    "RDP sin Network Level Authentication (NLA)",
				Severity:    rules.SeverityHigh,
				Confidence:  "confirmed",
				Description: "El servidor RDP permite fallback a Standard RDP Security Layer (sin NLA). Un atacante podría interceptar la conexión (MitM) o explotar vulnerabilidades pre-autenticación como BlueKeep (CVE-2019-0708).",
				Remediation: "Habilitar 'Require computers to use Network Level Authentication' en las propiedades del sistema Windows.",
				Mitre:       []string{"T1021.001 - Remote Services: Remote Desktop Protocol"},
				SLA:         "48 horas",
				Evidence:    "Raw Negotiation Response (Hex):\n" + evidence,
			})
		}
	}

	return findings
}
