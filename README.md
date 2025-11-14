```
 _   _ __   __ __  __
| \ | |\ \ / / \ \/ /
|  \| | \ V /   \  / 
| |\  |  | |    /  \ 
|_| \_|  |_|   /_/\_\
```

# NYX Scanner - Professional Network Reconnaissance Framework

[![License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![Python](https://img.shields.io/badge/python-3.6+-green.svg)](https://www.python.org/)
[![Dependencies](https://img.shields.io/badge/dependencies-zero-brightgreen.svg)](requirements.txt)

> High-performance network scanning and service detection framework built with Python standard library only.

[English](#english) | [Español](#español)

---

## English

### Overview

NYX Scanner is a professional-grade network reconnaissance tool designed for security professionals and penetration testers. Built entirely with Python's standard library, it requires zero external dependencies while delivering enterprise-level performance and accuracy.

### Key Features

- **Zero Dependencies**: Works with Python 3.6+ standard library only
- **Dual Interface**: Command-line and web-based interfaces
- **High Performance**: Multi-threaded scanning with stealth mode
- **Service Detection**: Identifies services and versions on open ports
- **OS Fingerprinting**: TTL-based operating system detection
- **Multiple Export Formats**: Text, JSON, and grepable output
- **Pre-scan Checks**: Validates target reachability before scanning
- **Professional Output**: Clean, color-coded terminal output

### Installation

**Option 1: Quick Install (Recommended)**

```bash
git clone https://github.com/DiegoPerrusquia/nyx-framework.git
cd nyx-framework
chmod +x install.sh
./install.sh
```

This will install `nyx` as a global command. After installation, simply use:

```bash
nyx scan 192.168.1.1
nyx web
```

**Option 2: Manual Usage**

```bash
git clone https://github.com/DiegoPerrusquia/nyx-framework.git
cd nyx-framework
python3 nyx_standalone.py --help
```

**Requirements:**
- Python 3.6 or higher
- No external packages needed

### Quick Start

#### Command Line Interface

**Basic scan:**
```bash
nyx scan 192.168.1.1
```

**Scan with service detection:**
```bash
nyx scan 192.168.1.1 -s
```

**Scan specific ports:**
```bash
nyx scan 192.168.1.1 -p "22,80,443,8080"
```

**Scan port ranges:**
```bash
nyx scan 192.168.1.1 -p "1-1000"
```

**Fast scan (top 20 ports):**
```bash
nyx scan 192.168.1.1 -p top-20
```

**Full scan with all features:**
```bash
nyx scan target.com -p top-1000 -s -t 200 -oN output.txt
```

#### Web Interface

**Start web server:**
```bash
nyx web
```

Then open your browser at `http://127.0.0.1:8080`

### Command Line Options

```
Scan Command:
  scan TARGET              Target IP address or hostname
  
  -p, --ports RANGE       Port specification:
                          - top-20, top-100, top-1000
                          - Ranges: "1-1000"
                          - Lists: "22,80,443"
                          - Mixed: "22,80,1000-2000"
                          (default: top-100)
  
  -s, --services          Enable service detection
  -t, --threads NUM       Number of threads (default: 75)
  --timeout SEC           Socket timeout in seconds (default: 3)
  -oN, --output-normal FILE    Save results in normal text format
  -oG, --output-grepable FILE  Save results in grepable format
  -oJ, --output-json FILE      Save results in JSON format
  -v, --verbose           Increase verbosity
  --silent                Suppress banner and progress
  --no-pre-scan           Skip connectivity check

Web Command:
  web                     Start web interface
  --host HOST             Bind address (default: 127.0.0.1)
  --port PORT             Bind port (default: 8080)
```

### Usage Examples

**Scan a web server:**
```bash
nyx scan example.com -p web -s
```

**Scan with custom threads:**
```bash
nyx scan 192.168.1.1 -p top-1000 -t 300
```

**Export to JSON:**
```bash
nyx scan 192.168.1.1 -s -oJ scan_results.json
```

**Grepable output (compatible with parsing tools):**
```bash
nyx scan 192.168.1.1 -s -oG scan.grep
```

**Normal text output:**
```bash
nyx scan 192.168.1.1 -s -oN scan.txt
```

**Silent mode (no banner or progress):**
```bash
nyx scan 192.168.1.1 --silent -oN results.txt
```

### Output Formats

#### Text Format
Standard human-readable output with color coding and detailed information.

#### JSON Format
Structured data format suitable for automation and integration:
```json
{
  "target": "192.168.1.1",
  "ip": "192.168.1.1",
  "open_ports": [22, 80, 443],
  "os_info": {
    "os_family": "Linux",
    "confidence": 85
  },
  "services": {
    "identified": [
      {
        "port": 22,
        "service": "ssh",
        "product": "OpenSSH",
        "version": "8.2"
      }
    ]
  }
}
```

#### Grepable Format
Compatible with command-line parsing tools:
```
Host: 192.168.1.1	Ports: 22,80,443
22/open/tcp//ssh//OpenSSH 8.2
80/open/tcp//http//nginx 1.18.0
443/open/tcp//https//nginx 1.18.0
```

### Architecture

```
nyx-framework/
├── nyx_standalone.py      # Main application (CLI + Web)
├── core/
│   ├── scanner.py         # Advanced scanning engine
│   ├── evasion.py         # Evasion techniques
│   └── logger.py          # Logging system
├── modules/
│   ├── port_scanner.py    # Port scanning module
│   └── service_detection.py # Service detection
├── utils/
│   ├── banner.py          # ASCII banner display
│   ├── validator.py       # Input validation
│   └── target_parser.py   # Target parsing
├── web/
│   └── templates/
│       └── scan_compact.html # Web interface
└── data/
    └── nmap_services.json # Service signatures database
```

### Security Features

- **Input Validation**: Sanitizes all user inputs
- **CSRF Protection**: Token-based protection for web interface
- **Rate Limiting**: Prevents abuse of web API
- **XSS Prevention**: HTML escaping on all outputs
- **Stealth Mode**: Configurable scan timing and randomization

### Performance

- **Multi-threaded**: Concurrent port scanning (default: 75 threads)
- **Optimized Timeouts**: Smart timeout management
- **Pre-scan Checks**: Validates connectivity before full scan
- **Efficient Memory**: Low memory footprint
- **Fast Execution**: Typical scan completes in seconds

### OS Detection

NYX Scanner uses TTL-based fingerprinting to identify target operating systems:

| TTL Range | Operating System |
|-----------|-----------------|
| 60-64     | Linux/Unix      |
| 120-128   | Windows         |
| 250-255   | Network Device  |

### Service Detection

The scanner identifies services using multiple techniques:
- Banner grabbing
- Service-specific probes
- Version fingerprinting
- Signature matching against 1000+ service patterns

### Legal Disclaimer

This tool is provided for educational and authorized security testing purposes only. Users must comply with all applicable laws and regulations. Unauthorized scanning of networks and systems is illegal.

**Only scan systems you own or have explicit permission to test.**

### Contributing

Contributions are welcome! Please follow these guidelines:
1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Test thoroughly
5. Submit a pull request

### License

This project is licensed under the MIT License. See [LICENSE](LICENSE) file for details.

### Support

For issues, questions, or contributions:
- Open an issue on GitHub
- Submit a pull request
- Contact: diegoe.perrusquia@gmail.com

### Acknowledgments

- Developed by Diego Perrusquía
- Inspired by Nmap and similar reconnaissance tools
- Built for the information security community
- Designed with performance and simplicity in mind

---

## Español

### Descripción General

NYX Scanner es una herramienta de reconocimiento de redes de nivel profesional diseñada para profesionales de seguridad y pentesters. Construida completamente con la biblioteca estándar de Python, no requiere dependencias externas mientras ofrece rendimiento y precisión de nivel empresarial.

### Características Principales

- **Cero Dependencias**: Funciona solo con la biblioteca estándar de Python 3.6+
- **Interfaz Dual**: Interfaces de línea de comandos y web
- **Alto Rendimiento**: Escaneo multi-hilo con modo sigiloso
- **Detección de Servicios**: Identifica servicios y versiones en puertos abiertos
- **Fingerprinting de SO**: Detección de sistema operativo basada en TTL
- **Múltiples Formatos de Exportación**: Texto, JSON y formato grepable
- **Verificación Pre-escaneo**: Valida accesibilidad del objetivo antes de escanear
- **Salida Profesional**: Salida de terminal limpia y codificada por colores

### Instalación

**Opción 1: Instalación Rápida (Recomendada)**

```bash
git clone https://github.com/DiegoPerrusquia/nyx-framework.git
cd nyx-framework
chmod +x install.sh
./install.sh
```

Esto instalará `nyx` como comando global. Después de la instalación, simplemente usa:

```bash
nyx scan 192.168.1.1
nyx web
```

**Opción 2: Uso Manual**

```bash
git clone https://github.com/DiegoPerrusquia/nyx-framework.git
cd nyx-framework
python3 nyx_standalone.py --help
```

**Requisitos:**
- Python 3.6 o superior
- No se necesitan paquetes externos

### Inicio Rápido

#### Interfaz de Línea de Comandos

**Escaneo básico:**
```bash
nyx scan 192.168.1.1
```

**Escaneo con detección de servicios:**
```bash
nyx scan 192.168.1.1 -s
```

**Escanear puertos específicos:**
```bash
nyx scan 192.168.1.1 -p "22,80,443,8080"
```

**Escanear rangos de puertos:**
```bash
nyx scan 192.168.1.1 -p "1-1000"
```

**Escaneo rápido (top 20 puertos):**
```bash
nyx scan 192.168.1.1 -p top-20
```

**Escaneo completo con todas las características:**
```bash
nyx scan target.com -p top-1000 -s -t 200 -oN salida.txt
```

#### Interfaz Web

**Iniciar servidor web:**
```bash
nyx web
```

Luego abre tu navegador en `http://127.0.0.1:8080`

### Opciones de Línea de Comandos

```
Comando Scan:
  scan TARGET              Dirección IP o hostname objetivo
  
  -p, --ports RANGE       Especificación de puertos:
                          - top-20, top-100, top-1000
                          - Rangos: "1-1000"
                          - Listas: "22,80,443"
                          - Mixto: "22,80,1000-2000"
                          (por defecto: top-100)
  
  -s, --services          Habilitar detección de servicios
  -t, --threads NUM       Número de hilos (por defecto: 75)
  --timeout SEC           Timeout de socket en segundos (por defecto: 3)
  -oN, --output-normal FILE    Guardar resultados en formato texto normal
  -oG, --output-grepable FILE  Guardar resultados en formato grepable
  -oJ, --output-json FILE      Guardar resultados en formato JSON
  -v, --verbose           Aumentar verbosidad
  --silent                Suprimir banner y progreso
  --no-pre-scan           Omitir verificación de conectividad

Comando Web:
  web                     Iniciar interfaz web
  --host HOST             Dirección de enlace (por defecto: 127.0.0.1)
  --port PORT             Puerto de enlace (por defecto: 8080)
```

### Ejemplos de Uso

**Escanear un servidor web:**
```bash
nyx scan example.com -p web -s
```

**Escanear con hilos personalizados:**
```bash
nyx scan 192.168.1.1 -p top-1000 -t 300
```

**Exportar a JSON:**
```bash
nyx scan 192.168.1.1 -s -oJ resultados.json
```

**Salida grepable (compatible con herramientas de parsing):**
```bash
nyx scan 192.168.1.1 -s -oG scan.grep
```

**Salida de texto normal:**
```bash
nyx scan 192.168.1.1 -s -oN scan.txt
```

**Modo silencioso (sin banner ni progreso):**
```bash
nyx scan 192.168.1.1 --silent -oN resultados.txt
```

### Formatos de Salida

#### Formato Texto
Salida estándar legible por humanos con codificación de colores e información detallada.

#### Formato JSON
Formato de datos estructurado adecuado para automatización e integración:
```json
{
  "target": "192.168.1.1",
  "ip": "192.168.1.1",
  "open_ports": [22, 80, 443],
  "os_info": {
    "os_family": "Linux",
    "confidence": 85
  },
  "services": {
    "identified": [
      {
        "port": 22,
        "service": "ssh",
        "product": "OpenSSH",
        "version": "8.2"
      }
    ]
  }
}
```

#### Formato Grepable
Compatible con herramientas de parsing de línea de comandos:
```
Host: 192.168.1.1	Ports: 22,80,443
22/open/tcp//ssh//OpenSSH 8.2
80/open/tcp//http//nginx 1.18.0
443/open/tcp//https//nginx 1.18.0
```

### Arquitectura

```
nyx-framework/
├── nyx_standalone.py      # Aplicación principal (CLI + Web)
├── core/
│   ├── scanner.py         # Motor de escaneo avanzado
│   ├── evasion.py         # Técnicas de evasión
│   └── logger.py          # Sistema de logging
├── modules/
│   ├── port_scanner.py    # Módulo de escaneo de puertos
│   └── service_detection.py # Detección de servicios
├── utils/
│   ├── banner.py          # Visualización de banner ASCII
│   ├── validator.py       # Validación de entrada
│   └── target_parser.py   # Parsing de objetivos
├── web/
│   └── templates/
│       └── scan_compact.html # Interfaz web
└── data/
    └── nmap_services.json # Base de datos de firmas de servicios
```

### Características de Seguridad

- **Validación de Entrada**: Sanitiza todas las entradas de usuario
- **Protección CSRF**: Protección basada en tokens para interfaz web
- **Limitación de Tasa**: Previene abuso de la API web
- **Prevención XSS**: Escapado de HTML en todas las salidas
- **Modo Sigiloso**: Temporización y aleatorización de escaneo configurable

### Rendimiento

- **Multi-hilo**: Escaneo de puertos concurrente (por defecto: 75 hilos)
- **Timeouts Optimizados**: Gestión inteligente de timeouts
- **Verificaciones Pre-escaneo**: Valida conectividad antes del escaneo completo
- **Memoria Eficiente**: Huella de memoria baja
- **Ejecución Rápida**: Escaneo típico completa en segundos

### Detección de SO

NYX Scanner utiliza fingerprinting basado en TTL para identificar sistemas operativos objetivo:

| Rango TTL | Sistema Operativo |
|-----------|------------------|
| 60-64     | Linux/Unix       |
| 120-128   | Windows          |
| 250-255   | Dispositivo de Red |

### Detección de Servicios

El escáner identifica servicios usando múltiples técnicas:
- Banner grabbing
- Sondeos específicos de servicio
- Fingerprinting de versión
- Coincidencia de firmas contra 1000+ patrones de servicio

### Descargo de Responsabilidad Legal

Esta herramienta se proporciona solo para fines educativos y pruebas de seguridad autorizadas. Los usuarios deben cumplir con todas las leyes y regulaciones aplicables. El escaneo no autorizado de redes y sistemas es ilegal.

**Solo escanee sistemas que posea o tenga permiso explícito para probar.**

### Contribuir

¡Las contribuciones son bienvenidas! Por favor siga estas pautas:
1. Fork el repositorio
2. Cree una rama de características
3. Haga sus cambios
4. Pruebe exhaustivamente
5. Envíe un pull request

### Licencia

Este proyecto está licenciado bajo la Licencia MIT. Consulte el archivo [LICENSE](LICENSE) para más detalles.

### Soporte

Para problemas, preguntas o contribuciones:
- Abra un issue en GitHub
- Envíe un pull request
- Contacto: diegoe.perrusquia@gmail.com

### Agradecimientos

- Desarrollado por Diego Perrusquía
- Inspirado por Nmap y herramientas similares de reconocimiento
- Construido para la comunidad de seguridad de la información
- Diseñado con rendimiento y simplicidad en mente

---


**NYX Scanner** - Professional Network Reconnaissance Framework | Developed by Diego Perrusquía | MIT License | 2025
