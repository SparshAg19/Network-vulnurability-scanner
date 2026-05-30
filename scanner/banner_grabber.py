"""Service detection and lightweight banner grabbing."""

from __future__ import annotations

import logging
import socket
from typing import Iterable

from scanner.utils import sanitize_text

try:
    import nmap
except ImportError:  # pragma: no cover - depends on optional runtime install
    nmap = None


class ServiceDetector:
    """Detect service names, versions, banners, and optional OS hints."""

    def __init__(
        self,
        target: str,
        open_ports: Iterable[int],
        timeout: float = 2.0,
        logger: logging.Logger | None = None,
    ) -> None:
        self.target = target
        self.open_ports = self._valid_ports(open_ports)
        self.timeout = min(max(0.5, timeout), 30.0)
        self.logger = logger or logging.getLogger(__name__)

    def detect(self, os_detect: bool = False) -> tuple[list[dict], dict]:
        """Return service records and optional OS detection details."""
        nmap_services, os_info = self._detect_with_nmap(os_detect=os_detect)
        services: list[dict] = []

        for port in self.open_ports:
            detected = nmap_services.get(port, {})
            banner = self.grab_banner(port)
            fallback_name = self._service_name_from_port(port)

            service = {
                "port": port,
                "protocol": "tcp",
                "state": "open",
                "service": sanitize_text(detected.get("service") or fallback_name or "unknown", 80),
                "product": sanitize_text(detected.get("product", ""), 120),
                "version": sanitize_text(detected.get("version", ""), 80),
                "extrainfo": sanitize_text(detected.get("extrainfo", ""), 200),
                "cpe": detected.get("cpe", []),
                "banner": sanitize_text(banner or detected.get("banner", ""), 300),
                "source": sanitize_text(detected.get("source", "socket"), 24),
            }
            services.append(service)

        return services, os_info

    def grab_banner(self, port: int) -> str:
        """Attempt to read a short application banner from an open port."""
        probes = self._probes_for_port(port)
        chunks: list[bytes] = []

        try:
            with socket.create_connection((self.target, port), timeout=self.timeout) as sock:
                sock.settimeout(self.timeout)
                for probe in probes:
                    if probe:
                        sock.sendall(probe)
                    try:
                        chunk = sock.recv(1024)
                    except socket.timeout:
                        continue
                    if chunk:
                        chunks.append(chunk)
                        break
        except OSError as exc:
            self.logger.debug("Banner grab failed for %s:%s: %s", self.target, port, exc)

        if not chunks:
            return ""
        banner = b" ".join(chunks).decode("utf-8", errors="replace")
        return sanitize_text(banner, 300)

    def _detect_with_nmap(self, os_detect: bool = False) -> tuple[dict[int, dict], dict]:
        """Run Nmap service detection when python-nmap and Nmap are installed."""
        if not self.open_ports:
            return {}, {}
        if nmap is None:
            self.logger.warning("python-nmap is not installed; skipping Nmap detection.")
            return {}, {}

        services: dict[int, dict] = {}
        os_info: dict = {}
        ports = ",".join(str(port) for port in self.open_ports)
        arguments = "-sV --version-light"
        if os_detect:
            arguments = f"{arguments} -O --osscan-guess"

        try:
            scanner = nmap.PortScanner()
            scanner.scan(hosts=self.target, ports=ports, arguments=arguments)
            host = self.target
            if host not in scanner.all_hosts() and scanner.all_hosts():
                host = scanner.all_hosts()[0]

            tcp_data = scanner[host].get("tcp", {}) if host in scanner.all_hosts() else {}
            for port, details in tcp_data.items():
                script_data = details.get("script", {})
                if not isinstance(script_data, dict):
                    script_data = {}
                cpe_data = details.get("cpe", [])
                if isinstance(cpe_data, str):
                    cpe_data = [cpe_data]
                services[int(port)] = {
                    "service": sanitize_text(details.get("name", ""), 80),
                    "product": sanitize_text(details.get("product", ""), 120),
                    "version": sanitize_text(details.get("version", ""), 80),
                    "extrainfo": sanitize_text(details.get("extrainfo", ""), 200),
                    "cpe": [sanitize_text(cpe, 200) for cpe in cpe_data[:10]],
                    "banner": sanitize_text(script_data.get("banner", ""), 300),
                    "source": "nmap",
                }

            if os_detect and host in scanner.all_hosts():
                os_matches = scanner[host].get("osmatch", [])
                if os_matches:
                    best = os_matches[0]
                    os_info = {
                        "name": sanitize_text(best.get("name", "Unknown"), 120),
                        "accuracy": sanitize_text(best.get("accuracy", "0"), 8),
                    }
        except Exception as exc:  # noqa: BLE001 - nmap raises several runtime-specific errors
            self.logger.warning("Nmap detection failed. Ensure Nmap is installed and available on PATH.")
            self.logger.debug("Nmap detection detail: %s", sanitize_text(exc, 300))

        return services, os_info

    @staticmethod
    def _service_name_from_port(port: int) -> str:
        """Return a best-effort IANA service name for a TCP port."""
        try:
            return socket.getservbyport(port, "tcp")
        except OSError:
            return ""

    @staticmethod
    def _valid_ports(ports: Iterable[int]) -> list[int]:
        """Return sorted TCP ports, ignoring malformed values defensively."""
        valid: set[int] = set()
        for port in ports:
            try:
                candidate = int(port)
            except (TypeError, ValueError):
                continue
            if 1 <= candidate <= 65535:
                valid.add(candidate)
        return sorted(valid)

    @staticmethod
    def _probes_for_port(port: int) -> list[bytes]:
        """Return a small, safe probe list for common text protocols."""
        if port in {80, 8080, 8000, 8008, 8888}:
            return [b"HEAD / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n"]
        if port in {443, 8443}:
            return [b""]
        return [b"\r\n", b""]
