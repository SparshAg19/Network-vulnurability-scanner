"""Service detection and lightweight banner grabbing."""

from __future__ import annotations

import logging
import socket
from typing import Iterable

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
        self.open_ports = sorted(set(open_ports))
        self.timeout = max(0.5, timeout)
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
                "service": detected.get("service") or fallback_name or "unknown",
                "product": detected.get("product", ""),
                "version": detected.get("version", ""),
                "extrainfo": detected.get("extrainfo", ""),
                "cpe": detected.get("cpe", []),
                "banner": banner or detected.get("banner", ""),
                "source": detected.get("source", "socket"),
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
        return " ".join(banner.split())[:300]

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
                services[int(port)] = {
                    "service": details.get("name", ""),
                    "product": details.get("product", ""),
                    "version": details.get("version", ""),
                    "extrainfo": details.get("extrainfo", ""),
                    "cpe": details.get("cpe", []),
                    "banner": details.get("script", {}).get("banner", ""),
                    "source": "nmap",
                }

            if os_detect and host in scanner.all_hosts():
                os_matches = scanner[host].get("osmatch", [])
                if os_matches:
                    best = os_matches[0]
                    os_info = {
                        "name": best.get("name", "Unknown"),
                        "accuracy": best.get("accuracy", "0"),
                    }
        except Exception as exc:  # noqa: BLE001 - nmap raises several runtime-specific errors
            self.logger.warning("Nmap detection failed: %s", exc)

        return services, os_info

    @staticmethod
    def _service_name_from_port(port: int) -> str:
        """Return a best-effort IANA service name for a TCP port."""
        try:
            return socket.getservbyport(port, "tcp")
        except OSError:
            return ""

    @staticmethod
    def _probes_for_port(port: int) -> list[bytes]:
        """Return a small, safe probe list for common text protocols."""
        if port in {80, 8080, 8000, 8008, 8888}:
            return [b"HEAD / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n"]
        if port in {443, 8443}:
            return [b""]
        return [b"\r\n", b""]
