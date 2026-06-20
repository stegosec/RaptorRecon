# 🦅 Raptor Recon - Advanced Attack Surface Management

![Release](https://img.shields.io/github/v/release/stegosec/RaptorRecon?style=for-the-badge&color=00f0ff)
![Go Version](https://img.shields.io/badge/Go-1.22+-00ADD8?style=for-the-badge&logo=go)
![Build Status](https://img.shields.io/github/actions/workflow/status/stegosec/RaptorRecon/release.yml?style=for-the-badge)

**Raptor Recon** es el framework definitivo de escaneo de red y Attack Surface Management (ASM) construido para operaciones ofensivas de **StegoSec**. Diseñado para el caos del mundo real, Raptor combina la velocidad de la concurrencia nativa de Go con tácticas avanzadas de evasión, *Pivoting* asíncrono y heurística de Capa 7.

Opera bajo el paradigma *Living Off the Land (LotL)*: **100% estático, Zero CGO, sin dependencias de Nmap o libpcap.** Simplemente haz *Drop & Go*.

---

## 🖥️ Interfaz TUI Interactiva (Terminal User Interface)

Olvídate de la fatiga de la línea de comandos. Si ejecutas `./raptor` sin parámetros, entrarás a un entorno inmersivo desarrollado con **BubbleTea** y **Lipgloss**.

- **Configuración Visual:** Define targets (IPs, CIDRs, Dominios), ajusta el control de congestión y habilita perfiles tácticos con tu teclado.
- **Control Modular:** Activa módulos ofensivos (L7, Fuzzing, OS Fingerprinting, Ghost Mode) individualmente mediante *checkboxes* visuales.
- **Dashboard Asíncrono en Vivo:** Observa el progreso con barras de carga *anti-parpadeo*, validaciones de estado en red y recolección de vulnerabilidades renderizadas en tiempo real.

---

## ⚔️ Arquitectura de Módulos Ofensivos

Raptor no es solo un port scanner; es un ecosistema de reconocimiento estructurado en fases:

### 1. Descubrimiento y Red (AIMD Engine)
- **ICMP/ARP Raw Sockets:** Descubrimiento ultra rápido a nivel de kernel para mapear subredes y evitar enviar ruido a IPs muertas.
- **AIMD Congestion Control:** Raptor monitorea el estrés de la red. Si detecta caídas de paquetes, reduce su velocidad a la mitad. Si la red es estable, acelera agresivamente (*Additive Increase, Multiplicative Decrease*).
- **Safe Throttle (`--throttle`):** Control manual de latencia fijos en milisegundos diseñado específicamente para no derribar controladores industriales (SCADA/OT) vulnerables a ataques volumétricos.

### 2. Motor de Evasión (Ghost Mode)
Diseñado para operar bajo la mirada de Firewalls de Próxima Generación (NGFW) y sistemas NIDS.
- **Ghost Mode (`--ghost`):** Activa *IP Shuffling* (randomización de la cola de IPs para evadir bloqueos por umbral), *Temporal Jitter* (retrasos asimétricos aleatorios entre conexiones de 5-50ms) y rotación dinámica de 8 perfiles de User-Agents.
- **DPI Evasion (`--frag`):** Fragmenta intencionalmente los payloads TCP a nivel de socket para romper las firmas de los sistemas Deep Packet Inspection (DPI). Soporta perfiles `low`, `medium`, `high` y `auto`.

### 3. Port-Triggered L7 Engine & Heurística
No disparamos payloads a ciegas. La interacción L7 solo ocurre si el puerto responde a la firma correspondiente.
- **L7 Templates (`--l7`):** Motor de reglas en YAML (compatible con expresiones regulares y condicionales lógicas) que ejecuta *Handshakes activos* para detectar vulnerabilidades (Ej. CVEs o credenciales default). 
  - *OpSec:* Protegido en memoria con un límite estricto de 1MB por regla y 4KB de lectura máxima del socket para blindar la herramienta contra **Zip-Bombs y Tarpits** enemigos.
- **Web Fuzzing & Tech (`--fuzz`):** Descubrimiento asíncrono de rutas ocultas (Dirbusting) y *fingerprinting* de tecnologías web directamente desde las cabeceras HTTP.
- **OS Fingerprinting (`--os`):** Deducción heurística del Sistema Operativo basado en firmas TTL y respuesta de los paquetes TCP SYN/ACK.

### 4. Automatización de Pivoting y SSRF
Raptor no se detiene en el perímetro, lo penetra.
- **Proxy Pivot (`--proxy-pivot`):** Si encuentra proxies abiertos (HTTP/SOCKS5), valida vulnerabilidades SSRF obligando al proxy a conectarse a su propio `127.0.0.1` (bypass de ACLs). Automáticamente **enruta todo el escáner L4/L7** a través de ese túnel para descubrir subredes internas (`--pivot-subnet`, `--pivot-target`).

### 5. DevSecOps & Reportes Multi-Formato
- **Baseline (Atomic Save):** Usa `--state-file` para congelar una *Snapshot* de la red actual. En ejecuciones futuras, Raptor calculará el **Delta**, reportando exclusivamente qué puertos nuevos se abrieron, qué servicios cayeron y qué nuevas alertas surgieron respecto a tu escaneo anterior.
- **Salida SARIF (`--sarif`):** Integración nativa con GitHub Advanced Security y sistemas SIEM corporativos.
- **Reportes HTML (`--html`):** Dashboard analítico estático e interactivo, fuertemente sanitizado contra *Stored XSS* provocado por banners maliciosos capturados.

---

## 📦 Instalación y Ejecución (Drop & Go)

Raptor Recon está pre-compilado estáticamente para los principales sistemas operativos. No necesitas instalar Go, entornos virtuales, ni librerías en el sistema (Zero CGO). Solo descarga y ejecuta.

### Windows
Descarga el ejecutable `raptor-windows-amd64.exe` desde la sección de **Releases** y ejecútalo directamente desde PowerShell o CMD.
```powershell
.\raptor-windows-amd64.exe
```
> **Nota de Privilegios:** Ejecuta la terminal como **Administrador** para que Raptor pueda crear *Raw Sockets* y evadir restricciones del SO.

### Linux
Descarga el binario para tu arquitectura, dale permisos de ejecución y lánzalo.
```bash
wget https://github.com/stegosec/RaptorRecon/releases/latest/download/raptor-linux-amd64
chmod +x raptor-linux-amd64
sudo ./raptor-linux-amd64
```
> **Nota de Privilegios:** Usar `sudo` (Root) es fuertemente recomendado para maximizar la velocidad de la fase de descubrimiento (Ping Sweep vía Raw Sockets).

### macOS (Darwin)
Para Apple Silicon (M1/M2/M3) descarga el binario `arm64`. Para procesadores Intel, el `amd64`. Retira la cuarentena de Apple y ejecuta:
```bash
chmod +x raptor-darwin-arm64
xattr -d com.apple.quarantine raptor-darwin-arm64
sudo ./raptor-darwin-arm64
```

---

## 📖 Filosofía Operativa (Zero Flags)

Raptor Recon fue diseñado para la simplicidad extrema en medio del caos. Olvídate de los manuales complejos y combinaciones infinitas de flags; toda la potencia táctica de Raptor se orquesta de dos únicas formas:

### 1. Interfaz Gráfica TUI (Operaciones Asistidas)
La experiencia principal. Lanza la herramienta sin argumentos y el asistente visual te guiará para configurar los targets, encender la evasión y arrancar el motor, mostrándote todo el escrutinio en tiempo real a través del Dashboard.
```bash
./raptor
```

### 2. Shadow IT Hunt (Modo Autónomo)
Ideal para integraciones, despliegues ciegos o inventarios rápidos. Usa únicamente la bandera `--auto`. Raptor encenderá todos sus perfiles heurísticos (L7, Fuzzing, Ghost) y activará de forma nativa un acelerador de seguridad (`throttle` inteligente) para operar silencioso sin derribar servicios críticos. Él toma todas las decisiones operativas por ti.
```bash
./raptor --auto -target 10.0.0.0/24
```
