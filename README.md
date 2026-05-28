# Python Network Vulnerability Scanner

A professional, portfolio-ready CLI network vulnerability scanner built with Python. It scans TCP ports, enriches open services with Nmap version detection, performs lightweight banner grabbing, checks potential CVEs through the NVD API, and exports polished HTML and JSON reports.

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
- Optional scan history file
- Rich terminal progress bars, tables, and colored statuses
- Rotating logs written to `logs/scanner.log`
- Windows and Linux friendly

## Project Structure

```text
network_scanner/
├── main.py
├── scanner/
│   ├── __init__.py
│   ├── port_scanner.py
│   ├── banner_grabber.py
│   ├── cve_lookup.py
│   ├── report_generator.py
│   └── utils.py
├── reports/
├── logs/
├── templates/
│   └── report_template.html
├── requirements.txt
└── README.md
```

## Setup

Install Python 3.10 or newer, then install the Python dependencies:

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
| `-t`, `--target` | Target IP address or domain name |
| `-p`, `--ports` | Port expression such as `22,80,443` or `1-1000` |
| `-o`, `--output` | HTML report output path |
| `--json` | Optional JSON report path |
| `--threads` | Maximum TCP scan worker threads |
| `--timeout` | Socket timeout in seconds |
| `--async-scan` | Use asyncio instead of threaded scanning |
| `--min-severity` | Minimum CVE severity: `LOW`, `MEDIUM`, `HIGH`, `CRITICAL` |
| `--no-cve` | Skip NVD CVE lookup |
| `--max-cves` | Maximum CVEs per service query |
| `--os-detect` | Attempt Nmap OS detection |
| `--history` | Append a compact entry to `reports/scan_history.json` |
| `-v`, `--verbose` | Enable verbose terminal and log output |

## Mock Terminal Output

```text
╭─ Authorized Use Only ─────────────────────────────╮
│ This tool is intended only for authorized security testing. │
╰───────────────────────────────────────────────────╯

Scanning TCP ports  ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━ 1000/1000 0:00:05
Open ports: [22, 80, 443]

                      Open Ports and Services
┏━━━━━━┳━━━━━━━━━┳━━━━━━━━━━━━┳━━━━━━━━━┳━━━━━━━━━━━━━━━━━━━━━━┓
┃ Port ┃ Service ┃ Product    ┃ Version ┃ Banner               ┃
┡━━━━━━╇━━━━━━━━━╇━━━━━━━━━━━━╇━━━━━━━━━╇━━━━━━━━━━━━━━━━━━━━━━┩
│ 22   │ ssh     │ OpenSSH    │ 8.9     │ SSH-2.0-OpenSSH_8.9  │
│ 80   │ http    │ nginx      │ 1.24.0  │ HTTP/1.1 200 OK      │
│ 443  │ https   │ nginx      │ 1.24.0  │ -                    │
└──────┴─────────┴────────────┴─────────┴──────────────────────┘

HTML report saved: reports/scan_report.html
JSON report saved: reports/scan_report.json
```

## Mock HTML Report

The generated report includes a dark dashboard layout with:

- Target and scan timestamp
- Count cards for scanned ports, open ports, and CVE matches
- Open port and service table
- Optional OS detection result
- Vulnerability table with severity badges
- Links to NVD CVE detail pages

## How CVE Matching Works

The scanner builds a keyword from Nmap service detection fields such as product and version, then queries the NVD CVE 2.0 API. This is useful for triage, but it is not a substitute for manual validation. Version banners can be missing, altered, backported, or intentionally misleading.

## Logs and Reports

- Logs: `logs/scanner.log`
- Default HTML report: `reports/scan_report.html`
- Optional JSON export: pass `--json reports/name.json`
- Optional history: pass `--history`

## Security and Ethics

Only scan systems you own or have explicit written permission to test. Unauthorized scanning can violate laws, contracts, and acceptable-use policies. The CVE results are potential matches and should be validated before reporting risk.

## Troubleshooting

If service detection is missing, verify that the Nmap binary is installed and available on `PATH`.

If NVD lookups are slow, set `NVD_API_KEY` or use `--no-cve` for offline demonstrations.

If OS detection fails, run with appropriate privileges or omit `--os-detect`.
