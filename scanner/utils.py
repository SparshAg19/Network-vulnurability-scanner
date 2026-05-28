"""Shared helpers for CLI input, logging, reports, and severity handling."""

from __future__ import annotations

import json
import logging
import socket
from datetime import datetime, timezone
from logging.handlers import RotatingFileHandler
from pathlib import Path
from typing import Iterable

DEFAULT_SEVERITIES = ["LOW", "MEDIUM", "HIGH", "CRITICAL"]
SEVERITY_ORDER = {
    "UNKNOWN": 0,
    "LOW": 1,
    "MEDIUM": 2,
    "HIGH": 3,
    "CRITICAL": 4,
}


def parse_port_range(port_expression: str) -> list[int]:
    """Parse ports like '22,80,443,8000-8100' into a sorted integer list."""
    if not port_expression:
        raise ValueError("Port range cannot be empty.")

    ports: set[int] = set()
    for part in port_expression.split(","):
        token = part.strip()
        if not token:
            continue
        if "-" in token:
            start_text, end_text = token.split("-", 1)
            start, end = int(start_text), int(end_text)
            if start > end:
                raise ValueError(f"Invalid port range '{token}'.")
            ports.update(range(start, end + 1))
        else:
            ports.add(int(token))

    invalid = [port for port in ports if port < 1 or port > 65535]
    if invalid:
        raise ValueError("Ports must be between 1 and 65535.")
    if not ports:
        raise ValueError("No valid ports were provided.")
    return sorted(ports)


def validate_target(target: str) -> str:
    """Resolve a target IP/domain and return the IP address used for scanning."""
    if not target or not target.strip():
        raise ValueError("Target cannot be empty.")
    try:
        return socket.gethostbyname(target.strip())
    except socket.gaierror as exc:
        raise ValueError(f"Could not resolve target '{target}'.") from exc


def ensure_directory(path: str | Path) -> Path:
    """Create a directory if it does not already exist."""
    directory = Path(path)
    directory.mkdir(parents=True, exist_ok=True)
    return directory


def setup_logging(log_dir: str | Path, verbose: bool = False) -> logging.Logger:
    """Configure rotating file and console logging."""
    directory = ensure_directory(log_dir)
    logger = logging.getLogger("network_scanner")
    logger.setLevel(logging.DEBUG if verbose else logging.INFO)
    logger.handlers.clear()
    logger.propagate = False

    formatter = logging.Formatter(
        "%(asctime)s | %(levelname)s | %(name)s | %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )

    file_handler = RotatingFileHandler(
        directory / "scanner.log",
        maxBytes=1_000_000,
        backupCount=3,
        encoding="utf-8",
    )
    file_handler.setLevel(logging.DEBUG)
    file_handler.setFormatter(formatter)
    logger.addHandler(file_handler)

    stream_handler = logging.StreamHandler()
    stream_handler.setLevel(logging.DEBUG if verbose else logging.WARNING)
    stream_handler.setFormatter(formatter)
    logger.addHandler(stream_handler)
    return logger


def utc_now_iso() -> str:
    """Return the current UTC timestamp in ISO 8601 format."""
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def build_scan_metadata(target: str, target_ip: str, port_expression: str) -> dict:
    """Build common metadata included in every report."""
    return {
        "target": target,
        "target_ip": target_ip,
        "port_expression": port_expression,
        "scan_timestamp": utc_now_iso(),
        "scanner": "Python Network Vulnerability Scanner",
    }


def severity_meets_threshold(severity: str, threshold: str) -> bool:
    """Return True when severity is at or above the configured threshold."""
    current = SEVERITY_ORDER.get(str(severity).upper(), 0)
    minimum = SEVERITY_ORDER.get(str(threshold).upper(), 1)
    return current >= minimum


def save_json_report(report_data: dict, path: str | Path) -> Path:
    """Save full report data as formatted JSON."""
    output = Path(path)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(report_data, indent=2, default=str), encoding="utf-8")
    return output


def save_history(report_data: dict, path: str | Path) -> Path:
    """Append a compact scan summary to a JSON history file."""
    output = Path(path)
    output.parent.mkdir(parents=True, exist_ok=True)
    history = load_json_list(output)
    history.append(
        {
            "timestamp": report_data.get("metadata", {}).get("scan_timestamp"),
            "target": report_data.get("target"),
            "target_ip": report_data.get("target_ip"),
            "ports_scanned": report_data.get("ports_scanned"),
            "open_ports": report_data.get("open_ports", []),
            "vulnerability_count": len(report_data.get("vulnerabilities", [])),
        }
    )
    output.write_text(json.dumps(history, indent=2), encoding="utf-8")
    return output


def load_json_list(path: str | Path) -> list[dict]:
    """Load a JSON list from disk, returning an empty list on missing/invalid files."""
    input_path = Path(path)
    if not input_path.exists():
        return []
    try:
        data = json.loads(input_path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError):
        return []
    return data if isinstance(data, list) else []


def comma_join(values: Iterable[object]) -> str:
    """Join values for display in reports."""
    return ", ".join(str(value) for value in values)
