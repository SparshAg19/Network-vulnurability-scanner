"""Shared helpers for CLI input, logging, reports, and severity handling."""

from __future__ import annotations

import json
import logging
import os
import re
import socket
import tempfile
from ipaddress import ip_address
from datetime import datetime, timezone
from logging.handlers import RotatingFileHandler
from pathlib import Path
from typing import Iterable, Sequence

DEFAULT_SEVERITIES = ["LOW", "MEDIUM", "HIGH", "CRITICAL"]
SEVERITY_ORDER = {
    "UNKNOWN": 0,
    "LOW": 1,
    "MEDIUM": 2,
    "HIGH": 3,
    "CRITICAL": 4,
}
MAX_PORT_EXPRESSION_LENGTH = 4096
MAX_HOST_LENGTH = 253
MAX_HISTORY_ENTRIES = 100
MAX_HISTORY_BYTES = 5_000_000
WINDOWS_RESERVED_NAMES = {
    "CON",
    "PRN",
    "AUX",
    "NUL",
    *(f"COM{index}" for index in range(1, 10)),
    *(f"LPT{index}" for index in range(1, 10)),
}
CONTROL_CHAR_PATTERN = re.compile(r"[\x00-\x1f\x7f-\x9f]")
HOST_LABEL_PATTERN = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?$")


def sanitize_text(value: object, max_length: int = 1000) -> str:
    """Return a printable, bounded string safe for logs, terminals, and reports."""
    text = "" if value is None else str(value)
    text = CONTROL_CHAR_PATTERN.sub(" ", text)
    text = " ".join(text.split())
    if len(text) > max_length:
        return f"{text[: max_length - 3]}..."
    return text


def parse_port_range(
    port_expression: str,
    max_ports: int = 65_535,
) -> list[int]:
    """Parse ports like '22,80,443,8000-8100' into a sorted integer list."""
    if not port_expression:
        raise ValueError("Port range cannot be empty.")
    if len(port_expression) > MAX_PORT_EXPRESSION_LENGTH:
        raise ValueError("Port expression is too long.")

    ports: set[int] = set()
    for part in port_expression.split(","):
        token = part.strip()
        if not token:
            continue
        if "-" in token:
            start_text, end_text = token.split("-", 1)
            if not start_text.isdigit() or not end_text.isdigit():
                raise ValueError(f"Invalid port range '{sanitize_text(token, 80)}'.")
            start, end = int(start_text), int(end_text)
            if start > end:
                raise ValueError(f"Invalid port range '{sanitize_text(token, 80)}'.")
            ports.update(range(start, end + 1))
        else:
            if not token.isdigit():
                raise ValueError(f"Invalid port '{sanitize_text(token, 80)}'.")
            ports.add(int(token))

    invalid = [port for port in ports if port < 1 or port > 65535]
    if invalid:
        raise ValueError("Ports must be between 1 and 65535.")
    if not ports:
        raise ValueError("No valid ports were provided.")
    if len(ports) > max_ports:
        raise ValueError(f"Port selection exceeds the maximum of {max_ports} ports.")
    return sorted(ports)


def validate_target(target: str) -> str:
    """Resolve a target IP/domain and return the IP address used for scanning."""
    candidate = sanitize_text(target, MAX_HOST_LENGTH + 20).strip().rstrip(".")
    if not candidate:
        raise ValueError("Target cannot be empty.")
    if len(candidate) > MAX_HOST_LENGTH:
        raise ValueError("Target is too long.")
    if "://" in candidate or "/" in candidate or "\\" in candidate or "@" in candidate:
        raise ValueError("Target must be a bare IP address or domain name, not a URL.")

    try:
        parsed_ip = ip_address(candidate)
    except ValueError:
        parsed_ip = None

    if parsed_ip is not None:
        if parsed_ip.version != 4:
            raise ValueError("Only IPv4 targets are supported by this scanner.")
        return str(parsed_ip)

    ascii_host = _to_ascii_hostname(candidate)
    _validate_hostname(ascii_host)

    try:
        return socket.gethostbyname(ascii_host)
    except socket.gaierror as exc:
        raise ValueError(f"Could not resolve target '{sanitize_text(candidate, 80)}'.") from exc


def _to_ascii_hostname(hostname: str) -> str:
    """Convert internationalized domain input to DNS-safe ASCII."""
    try:
        return hostname.encode("idna").decode("ascii")
    except UnicodeError as exc:
        raise ValueError("Target hostname is not valid IDNA.") from exc


def _validate_hostname(hostname: str) -> None:
    """Validate a DNS hostname without accepting URL/path syntax."""
    if len(hostname) > MAX_HOST_LENGTH:
        raise ValueError("Target hostname is too long.")
    labels = hostname.split(".")
    if any(not label for label in labels):
        raise ValueError("Target hostname contains an empty label.")
    if not all(HOST_LABEL_PATTERN.match(label) for label in labels):
        raise ValueError("Target hostname contains invalid characters.")


def ensure_directory(path: str | Path, mode: int = 0o700) -> Path:
    """Create a directory if it does not already exist."""
    directory = Path(path)
    directory.mkdir(parents=True, exist_ok=True, mode=mode)
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

    stream_handler = logging.StreamHandler()
    stream_handler.setLevel(logging.DEBUG if verbose else logging.WARNING)
    stream_handler.setFormatter(formatter)
    logger.addHandler(stream_handler)

    try:
        file_handler = RotatingFileHandler(
            directory / "scanner.log",
            maxBytes=1_000_000,
            backupCount=3,
            encoding="utf-8",
        )
        file_handler.setLevel(logging.DEBUG)
        file_handler.setFormatter(formatter)
        logger.addHandler(file_handler)
    except OSError as exc:
        logger.addHandler(logging.NullHandler())
        logger.debug("File logging unavailable: %s", sanitize_text(exc, 200))
        logger.warning("File logging is unavailable; continuing with console logging only.")
    return logger


def bounded_int(name: str, value: int, minimum: int, maximum: int) -> int:
    """Validate an integer CLI option within an inclusive range."""
    if value < minimum or value > maximum:
        raise ValueError(f"{name} must be between {minimum} and {maximum}.")
    return value


def bounded_float(name: str, value: float, minimum: float, maximum: float) -> float:
    """Validate a float CLI option within an inclusive range."""
    if value < minimum or value > maximum:
        raise ValueError(f"{name} must be between {minimum} and {maximum}.")
    return value


def safe_output_path(
    requested_path: str | Path,
    base_dir: str | Path,
    default_subdir: str,
    allowed_suffixes: Sequence[str],
) -> Path:
    """Resolve an output path while preventing path traversal and unsafe writes."""
    base = Path(base_dir).resolve()
    requested = Path(requested_path)
    if requested.is_absolute():
        candidate = requested
    elif requested.parent == Path("."):
        candidate = base / default_subdir / requested
    else:
        candidate = base / requested
    resolved = candidate.resolve()

    try:
        resolved.relative_to(base)
    except ValueError as exc:
        raise ValueError("Output paths must stay inside the project directory.") from exc

    suffixes = {suffix.lower() for suffix in allowed_suffixes}
    if resolved.suffix.lower() not in suffixes:
        allowed = ", ".join(sorted(suffixes))
        raise ValueError(f"Output file must use one of these extensions: {allowed}.")
    if _is_reserved_windows_name(resolved.name):
        raise ValueError("Output file name is reserved by Windows.")

    try:
        resolved.parent.relative_to(base)
    except ValueError as exc:
        raise ValueError("Output directory must stay inside the project directory.") from exc
    ensure_directory(resolved.parent)
    return resolved


def _is_reserved_windows_name(filename: str) -> bool:
    """Return True for Windows device names such as CON or NUL."""
    stem = filename.split(".", 1)[0].upper()
    return stem in WINDOWS_RESERVED_NAMES


def utc_now_iso() -> str:
    """Return the current UTC timestamp in ISO 8601 format."""
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def build_scan_metadata(target: str, target_ip: str, port_expression: str) -> dict:
    """Build common metadata included in every report."""
    return {
        "target": sanitize_text(target, 253),
        "target_ip": sanitize_text(target_ip, 64),
        "port_expression": sanitize_text(port_expression, 120),
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
    write_text_atomic(output, json.dumps(report_data, indent=2, default=str))
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
    history = history[-MAX_HISTORY_ENTRIES:]
    write_text_atomic(output, json.dumps(history, indent=2))
    return output


def load_json_list(path: str | Path) -> list[dict]:
    """Load a JSON list from disk, returning an empty list on missing/invalid files."""
    input_path = Path(path)
    if not input_path.exists():
        return []
    try:
        if input_path.stat().st_size > MAX_HISTORY_BYTES:
            return []
        data = json.loads(input_path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError):
        return []
    return data if isinstance(data, list) else []


def comma_join(values: Iterable[object]) -> str:
    """Join values for display in reports."""
    return ", ".join(str(value) for value in values)


def write_text_atomic(path: str | Path, content: str) -> Path:
    """Write text through a sibling temporary file and atomically replace target."""
    output = Path(path)
    output.parent.mkdir(parents=True, exist_ok=True)
    temporary_name = ""
    try:
        with tempfile.NamedTemporaryFile(
            "w",
            encoding="utf-8",
            dir=output.parent,
            prefix=f".{output.name}.",
            suffix=".tmp",
            delete=False,
        ) as temporary:
            temporary.write(content)
            temporary_name = temporary.name
        os.replace(temporary_name, output)
    finally:
        if temporary_name and Path(temporary_name).exists():
            Path(temporary_name).unlink(missing_ok=True)
    return output
