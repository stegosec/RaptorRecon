# 🚀 Raptor Recon v1.0.0 - (MVP Release)

Raptor Recon v1.0.0 ya está aquí. Esta versión marca la graduación del escáner a su estado de **Producto Mínimo Viable (MVP)** operativo. Es una herramienta 100% estática (Zero CGO), lista para escenarios de *Red Teaming* y *Attack Surface Management* en entornos hostiles.

## 🔥 Novedades Principales

- **TUI Interactiva (Bubbletea):** Lanzamiento de la interfaz visual. Ejecuta `./raptor` sin banderas para un asistente guiado de escaneo, selección visual de perfiles y dashboard anti-parpadeo.
- **Port-Triggered L7 Engine:** Módulo de heurística y ejecución de templates YAML. Solo envía payloads a puertos verificados. Incluye límite de memoria nativo (Anti YAML-Bomb de 1MB) y lectura blindada (Anti Zip-Bomb de 4KB).
- **Auto-Throttle & AIMD:** Nuevo control de congestión. El flag `--auto` ahora inyecta inteligentemente `--throttle 50` para evitar saturar infraestructuras críticas industriales (SCADA/OT) previniendo DoS volumétrico.
- **Evasión (Ghost Mode):** Aleatoriedad temporal (*Jitter*), *IP Shuffling*, rotación de User-Agents y evasión DPI vía fragmentación de paquetes (`--frag`).
- **Proxy Pivot Automation:** Capacidad para enrutar todo el escáner (L4 y L7) a través de proxies vulnerables, validando SSRF a localhost antes del pivoting.
- **Reportes Multi-Formato & Sanitizados:** Salida simultánea en JSON, HTML (Sanitizado contra Stored XSS derivado de banners) y SARIF v2.1.0 (Integración CI/CD).

## 🛠️ Descarga y Uso Rápido (Drop & Go)

Raptor no necesita dependencias. Descarga el binario correspondiente a tu sistema operativo (Linux, Windows o macOS), dale permisos de ejecución y lánzalo.

### Linux / macOS
```bash
chmod +x raptor-linux-amd64
sudo ./raptor-linux-amd64  # Privilegios root son opcionales pero recomendados para Raw Sockets (máxima velocidad)
```

### Windows
```powershell
.\raptor-windows-amd64.exe
```

## ⚔️ Filosofía "Zero Flags" (Inicio Rápido)

Raptor no requiere que te aprendas manuales extensos. Descarga el ejecutable para tu plataforma y arranca de una de estas dos formas:

**1. Interfaz Gráfica de Consola (Operación Asistida):**
La TUI (Terminal User Interface) te guiará visualmente para configurar targets, evadir DPI y levantar el motor asíncrono.
```bash
./raptor
```

**2. Shadow IT Hunt (Modo Autónomo):**
Perfecto para scripts y operaciones ciegas. Raptor habilitará solo todas sus rutinas ofensivas y activará un límite de seguridad en la red para operar silenciosamente sin derribar servidores.
```bash
./raptor --auto -target 10.0.0.0/24
```

---
*Para ver la documentación técnica completa del motor, consulta el README del repositorio.*
