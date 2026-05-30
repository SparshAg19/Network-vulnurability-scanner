# Python Network Vulnerability Scanner

A professional CLI network vulnerability scanner built with Python. It scans TCP ports, enriches open services with Nmap version detection, performs lightweight banner grabbing, checks potential CVEs through the NVD API, and exports polished HTML and JSON reports.

> This tool is intended only for authorized security testing.

## Features

- Configurable TCP port range scanning
- Threaded scanner for fast default scans
- Optional asyncio scanner with `--async-scan`
- Nmap service and version detection using `python-nmap`
- Basic banner grabbing for common text-based services
- NVD CVE 2.0 API lookup with optional `NVD_API_KEY`
- CVSS severity filtering
- Responsive dark-theme HTML report
- Optional JSON report export
- Optional bounded scan history file
- Rich terminal progress bars, tables, and colored statuses
- Rotating logs written to `logs/scanner.log`
- Windows and Linux friendly

## Project Structure

```text
network_scanner/
|-- main.py
|-- scanner/
|   |-- __init__.py
|   |-- port_scanner.py
|   |-- banner_grabber.py
|   |-- cve_lookup.py
|   |-- report_generator.py
|   `-- utils.py
|-- reports/
|-- logs/
|-- templates/
|   `-- report_template.html
|-- requirements.txt
|-- SECURITY.md
`-- README.md
```

## Setup

Install Python 3.10 or newer, then install dependencies:

```bash
cd network_scanner
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

On Windows PowerShell:

```powershell
cd network_scanner
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
```

Install the Nmap binary separately so `python-nmap` can call it:

- Windows: download from <https://nmap.org/download.html>
- Debian/Ubuntu: `sudo apt install nmap`
- Fedora: `sudo dnf install nmap`
- macOS: `brew install nmap`

## NVD API Key

The scanner works without an API key, but NVD rate limits unauthenticated requests. For better reliability, request an API key from NVD and set it as an environment variable.

This product uses data from the NVD API but is not endorsed or certified by the NVD.

Linux/macOS:

```bash
export NVD_API_KEY="your-api-key"
```

Windows PowerShell:

```powershell
$env:NVD_API_KEY="your-api-key"
```

Do not hardcode API keys into source files or commit them to Git.

## Usage

Basic scan:

```bash
python main.py -t 192.168.1.1 -p 1-1000
```

Custom report paths:

```bash
python main.py -t scanme.nmap.org -p 20-1000 -o reports/scanme.html --json reports/scanme.json
```

Fast local scan without CVE lookup:

```bash
python main.py -t 127.0.0.1 -p 1-5000 --threads 200 --timeout 0.5 --no-cve
```

OS detection and severity filtering:

```bash
python main.py -t 192.168.1.10 -p 1-2000 --os-detect --min-severity HIGH --history -v
```

Async scan mode:

```bash
python main.py -t example.com -p 80,443,8000-8100 --async-scan
```

## CLI Arguments

| Argument | Description |
| --- | --- |
| `-t`, `--target` | Target IPv4 address or domain name |
| `-p`, `--ports` | Port expression such as `22,80,443` or `1-1000` |
| `-o`, `--output` | HTML report output path inside the project directory |
| `--json` | Optional JSON report path inside the project directory |
| `--threads` | Maximum TCP scan worker threads, 1-512 |
| `--timeout` | Socket timeout in seconds, 0.1-30 |
| `--async-scan` | Use asyncio instead of threaded scanning |
| `--min-severity` | Minimum CVE severity: `LOW`, `MEDIUM`, `HIGH`, `CRITICAL` |
| `--no-cve` | Skip NVD CVE lookup |
| `--max-cves` | Maximum CVEs per service query, 1-20 |
| `--os-detect` | Attempt Nmap OS detection |
| `--history` | Append a compact entry to `reports/scan_history.json` |
| `-v`, `--verbose` | Enable verbose terminal and log output |

## Security Hardening

- Target input must be a bare IPv4 address or hostname, not a URL.
- Port expressions are validated and bounded.
- Thread count, timeout, and CVE result limits are range-checked.
- HTML and JSON outputs are restricted to this project directory.
- Service banners and API responses are sanitized before terminal, log, JSON, or HTML output.
- HTML reports use Jinja autoescaping and a restrictive Content Security Policy.
- Nmap arguments are fixed by the application, and scan targets are resolved before Nmap is called.
- Logs and generated reports are ignored by Git by default.

## Mock Terminal Output

```text
Authorized Use Only
This tool is intended only for authorized security testing.

Scanning TCP ports  1000/1000 0:00:05
Open ports: [22, 80, 443]

Port  Service  Product  Version  Banner
22    ssh      OpenSSH  8.9      SSH-2.0-OpenSSH_8.9
80    http     nginx    1.24.0   HTTP/1.1 200 OK
443   https    nginx    1.24.0   -

HTML report saved: reports/scan_report.html
JSON report saved: reports/scan_report.json
```

## How CVE Matching Works

The scanner builds a keyword from Nmap service detection fields such as product and version, then queries the NVD CVE 2.0 API. This is useful for triage, but it is not a substitute for manual validation. Version banners can be missing, altered, backported, or intentionally misleading.

## Logs and Reports

- Logs: `logs/scanner.log`
- Default HTML report: `reports/scan_report.html`
- Optional JSON export: pass `--json reports/name.json`
- Optional history: pass `--history`

Generated reports and logs may contain internal hostnames, service banners, and vulnerability details, so they are ignored by Git by default.

## Security and Ethics

Only scan systems you own or have explicit written permission to test. Unauthorized scanning can violate laws, contracts, and acceptable-use policies. The CVE results are potential matches and should be validated before reporting risk.

## Troubleshooting

If service detection is missing, verify that the Nmap binary is installed and available on `PATH`.

If NVD lookups are slow, set `NVD_API_KEY` or use `--no-cve` for offline demonstrations.

If OS detection fails, run with appropriate privileges or omit `--os-detect`.
