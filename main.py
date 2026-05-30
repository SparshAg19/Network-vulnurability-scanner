"""Command-line entry point for the Network Vulnerability Scanner."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from rich.console import Console
from rich.markup import escape
from rich.panel import Panel
from rich.progress import BarColumn, Progress, SpinnerColumn, TextColumn, TimeElapsedColumn
from rich.table import Table

from scanner.banner_grabber import ServiceDetector
from scanner.cve_lookup import CVELookup
from scanner.port_scanner import PortScanner
from scanner.report_generator import ReportGenerator
from scanner.utils import (
    DEFAULT_SEVERITIES,
    bounded_float,
    bounded_int,
    build_scan_metadata,
    parse_port_range,
    safe_output_path,
    save_history,
    save_json_report,
    sanitize_text,
    setup_logging,
    severity_meets_threshold,
    validate_target,
)


WARNING_TEXT = "This tool is intended only for authorized security testing."
NVD_NOTICE = "This product uses data from the NVD API but is not endorsed or certified by the NVD."


def terminal_text(value: object, max_length: int = 300) -> str:
    """Sanitize and escape untrusted values before rendering with Rich markup."""
    return escape(sanitize_text(value, max_length))


def build_parser() -> argparse.ArgumentParser:
    """Build and return the CLI argument parser."""
    parser = argparse.ArgumentParser(
        description="Professional Python CLI Network Vulnerability Scanner",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument(
        "-t",
        "--target",
        required=True,
        help="Target IP address or domain name to scan.",
    )
    parser.add_argument(
        "-p",
        "--ports",
        default="1-1000",
        help="Port range, comma list, or both. Example: 22,80,443,8000-8100.",
    )
    parser.add_argument(
        "-o",
        "--output",
        default="reports/scan_report.html",
        help="Path for the generated HTML report.",
    )
    parser.add_argument(
        "--json",
        dest="json_output",
        default=None,
        help="Optional path for a JSON export.",
    )
    parser.add_argument(
        "--threads",
        type=int,
        default=100,
        help="Maximum worker threads for TCP scanning. Allowed range: 1-512.",
    )
    parser.add_argument(
        "--timeout",
        type=float,
        default=1.0,
        help="Socket timeout in seconds. Allowed range: 0.1-30.",
    )
    parser.add_argument(
        "--async-scan",
        action="store_true",
        help="Use asyncio TCP scanning instead of the threaded scanner.",
    )
    parser.add_argument(
        "--min-severity",
        choices=DEFAULT_SEVERITIES,
        default="LOW",
        help="Minimum CVSS severity to keep in the report.",
    )
    parser.add_argument(
        "--no-cve",
        action="store_true",
        help="Skip NVD CVE lookup. Useful for offline scans and quick demos.",
    )
    parser.add_argument(
        "--max-cves",
        type=int,
        default=5,
        help="Maximum CVEs to keep per detected service. Allowed range: 1-20.",
    )
    parser.add_argument(
        "--os-detect",
        action="store_true",
        help="Ask Nmap to attempt OS detection. This may require elevated privileges.",
    )
    parser.add_argument(
        "--history",
        action="store_true",
        help="Append a compact scan summary to reports/scan_history.json.",
    )
    parser.add_argument(
        "-v",
        "--verbose",
        action="store_true",
        help="Enable verbose terminal and log output.",
    )
    return parser


def print_warning(console: Console) -> None:
    """Print the authorized-use warning banner."""
    console.print(
        Panel.fit(
            WARNING_TEXT,
            title="[bold yellow]Authorized Use Only[/bold yellow]",
            border_style="yellow",
        )
    )


def render_open_ports_table(console: Console, services: list[dict]) -> None:
    """Render the open port and service table."""
    table = Table(title="Open Ports and Services", show_lines=False)
    table.add_column("Port", style="cyan", no_wrap=True)
    table.add_column("Service", style="green")
    table.add_column("Product")
    table.add_column("Version")
    table.add_column("Banner", overflow="fold")

    if not services:
        table.add_row("-", "No open TCP ports found", "-", "-", "-")
    else:
        for service in services:
            table.add_row(
                terminal_text(service.get("port", ""), 16),
                terminal_text(service.get("service") or "unknown", 80),
                terminal_text(service.get("product") or "-", 120),
                terminal_text(service.get("version") or "-", 80),
                terminal_text(service.get("banner") or "-", 200),
            )
    console.print(table)


def render_vulnerability_table(console: Console, vulnerabilities: list[dict]) -> None:
    """Render a compact vulnerabilities table."""
    table = Table(title="Potential Vulnerabilities", show_lines=False)
    table.add_column("Port", style="cyan", no_wrap=True)
    table.add_column("CVE", style="magenta", no_wrap=True)
    table.add_column("Severity", no_wrap=True)
    table.add_column("CVSS", justify="right", no_wrap=True)
    table.add_column("Description", overflow="fold")

    if not vulnerabilities:
        table.add_row("-", "None", "-", "-", "No CVEs matched the configured threshold.")
    else:
        for vuln in vulnerabilities:
            severity = vuln.get("severity", "UNKNOWN")
            color = {
                "CRITICAL": "bold red",
                "HIGH": "red",
                "MEDIUM": "yellow",
                "LOW": "green",
            }.get(severity, "white")
            table.add_row(
                terminal_text(vuln.get("port", ""), 16),
                terminal_text(vuln.get("id", ""), 40),
                f"[{color}]{terminal_text(severity, 16)}[/{color}]",
                terminal_text(vuln.get("cvss_score", "N/A"), 16),
                terminal_text(vuln.get("description", ""), 160),
            )
    console.print(table)


def main() -> int:
    """Run the scanner from CLI arguments."""
    parser = build_parser()
    args = parser.parse_args()

    base_dir = Path(__file__).resolve().parent
    logger = setup_logging(base_dir / "logs", verbose=args.verbose)
    console = Console()

    print_warning(console)

    try:
        args.threads = bounded_int("--threads", args.threads, 1, 512)
        args.timeout = bounded_float("--timeout", args.timeout, 0.1, 30.0)
        args.max_cves = bounded_int("--max-cves", args.max_cves, 1, 20)
        target_ip = validate_target(args.target)
        target_display = sanitize_text(args.target, 253)
        ports = parse_port_range(args.ports)
        output_path = safe_output_path(
            args.output,
            base_dir=base_dir,
            default_subdir="reports",
            allowed_suffixes=(".html", ".htm"),
        )
        json_path = (
            safe_output_path(
                args.json_output,
                base_dir=base_dir,
                default_subdir="reports",
                allowed_suffixes=(".json",),
            )
            if args.json_output
            else None
        )
    except (OSError, ValueError) as exc:
        logger.error("Invalid input: %s", sanitize_text(exc, 300))
        console.print(f"[bold red]Input error:[/bold red] {terminal_text(exc, 300)}")
        return 2

    metadata = build_scan_metadata(target_display, target_ip, args.ports)
    logger.info("Starting scan for %s (%s) on %s", target_display, target_ip, sanitize_text(args.ports, 120))

    scanner = PortScanner(
        target=target_ip,
        ports=ports,
        timeout=args.timeout,
        max_threads=args.threads,
        logger=logger,
    )

    open_ports: list[int] = []
    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(),
        TextColumn("{task.completed}/{task.total}"),
        TimeElapsedColumn(),
        console=console,
    ) as progress:
        scan_task = progress.add_task("Scanning TCP ports", total=len(ports))

        def advance(_: int, __: bool) -> None:
            progress.advance(scan_task)

        open_ports = scanner.scan(progress_callback=advance, async_mode=args.async_scan)

    console.print(f"[bold green]Open ports:[/bold green] {terminal_text(open_ports or 'none', 300)}")

    detector = ServiceDetector(
        target=target_ip,
        open_ports=open_ports,
        timeout=max(args.timeout, 2.0),
        logger=logger,
    )
    services, os_info = detector.detect(os_detect=args.os_detect)
    render_open_ports_table(console, services)

    vulnerabilities: list[dict] = []
    if args.no_cve:
        console.print("[yellow]CVE lookup skipped by --no-cve.[/yellow]")
    elif services:
        lookup = CVELookup(logger=logger)
        with console.status("[bold cyan]Querying NVD for potential CVEs...[/bold cyan]"):
            vulnerabilities = lookup.lookup_for_services(
                services=services,
                max_results=args.max_cves,
                min_severity=args.min_severity,
            )
        vulnerabilities = [
            vuln
            for vuln in vulnerabilities
            if severity_meets_threshold(vuln.get("severity", "UNKNOWN"), args.min_severity)
        ]
    render_vulnerability_table(console, vulnerabilities)

    report_data = {
        "metadata": metadata,
        "target": target_display,
        "target_ip": target_ip,
        "ports_scanned": len(ports),
        "open_ports": open_ports,
        "services": services,
        "os_info": os_info,
        "vulnerabilities": vulnerabilities,
        "severity_filter": args.min_severity,
        "authorized_warning": WARNING_TEXT,
        "nvd_notice": NVD_NOTICE,
    }

    generator = ReportGenerator(
        template_dir=base_dir / "templates",
        logger=logger,
    )
    try:
        html_path = generator.generate_html_report(report_data, output_path)
    except OSError as exc:
        logger.error("Could not write HTML report: %s", exc.__class__.__name__)
        console.print("[bold red]Report error:[/bold red] Could not write the HTML report. Check output directory permissions.")
        return 1
    except Exception as exc:  # noqa: BLE001 - keep CLI failures controlled and user-friendly
        logger.error("Could not generate HTML report: %s", sanitize_text(exc, 200))
        console.print("[bold red]Report error:[/bold red] Could not generate the HTML report.")
        return 1
    console.print(f"[bold green]HTML report saved:[/bold green] {terminal_text(html_path, 300)}")

    if json_path:
        try:
            save_json_report(report_data, json_path)
        except OSError as exc:
            logger.error("Could not write JSON report: %s", exc.__class__.__name__)
            console.print("[bold red]Report error:[/bold red] Could not write the JSON report. Check output directory permissions.")
            return 1
        console.print(f"[bold green]JSON report saved:[/bold green] {terminal_text(json_path, 300)}")

    if args.history:
        history_path = base_dir / "reports" / "scan_history.json"
        try:
            save_history(report_data, history_path)
        except OSError as exc:
            logger.error("Could not update scan history: %s", exc.__class__.__name__)
            console.print("[bold yellow]History warning:[/bold yellow] Could not update scan history.")
        else:
            console.print(f"[bold green]History updated:[/bold green] {terminal_text(history_path, 300)}")

    logger.info(
        "Scan completed for %s. Open ports=%s, vulnerabilities=%s",
        target_display,
        len(open_ports),
        len(vulnerabilities),
    )
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except KeyboardInterrupt:
        Console().print("\n[bold yellow]Scan interrupted by user.[/bold yellow]")
        sys.exit(130)
