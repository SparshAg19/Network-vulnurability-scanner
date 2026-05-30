
from __future__ import annotations

import asyncio
import logging
import socket
import threading
from queue import Empty, Queue
from typing import Callable, Iterable

ProgressCallback = Callable[[int, bool], None]


class PortScanner:
    """Scan TCP ports using either worker threads or asyncio."""

    def __init__(
        self,
        target: str,
        ports: Iterable[int],
        timeout: float = 1.0,
        max_threads: int = 100,
        logger: logging.Logger | None = None,
    ) -> None:
        self.target = target
        self.ports = self._valid_ports(ports)
        self.timeout = min(max(0.1, timeout), 30.0)
        self.max_threads = min(max(1, max_threads), 512)
        self.logger = logger or logging.getLogger(__name__)

    def scan(
        self,
        progress_callback: ProgressCallback | None = None,
        async_mode: bool = False,
    ) -> list[int]:
        """Return sorted open TCP ports for the configured target."""
        if not self.ports:
            return []
        if async_mode:
            return asyncio.run(self._scan_async(progress_callback))
        return self._scan_threaded(progress_callback)

    def _scan_port(self, port: int) -> bool:
        """Return True when a TCP connect succeeds."""
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.settimeout(self.timeout)
                result = sock.connect_ex((self.target, port))
                return result == 0
        except OSError as exc:
            self.logger.debug("Socket error on %s:%s: %s", self.target, port, exc)
            return False

    def _scan_threaded(self, progress_callback: ProgressCallback | None) -> list[int]:
        """Scan ports with a small pool of worker threads."""
        queue: Queue[int] = Queue()
        open_ports: list[int] = []
        lock = threading.Lock()

        for port in self.ports:
            queue.put(port)

        def worker() -> None:
            while True:
                try:
                    port = queue.get_nowait()
                except Empty:
                    return

                is_open = self._scan_port(port)
                if is_open:
                    with lock:
                        open_ports.append(port)
                    self.logger.info("Open port found: %s/tcp", port)

                if progress_callback:
                    progress_callback(port, is_open)
                queue.task_done()

        thread_count = min(self.max_threads, len(self.ports))
        threads = [
            threading.Thread(target=worker, name=f"port-worker-{idx}", daemon=True)
            for idx in range(thread_count)
        ]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()

        return sorted(open_ports)

    @staticmethod
    def _valid_ports(ports: Iterable[int]) -> list[int]:
        """Return sorted unique TCP ports, ignoring malformed values defensively."""
        valid: set[int] = set()
        for port in ports:
            try:
                candidate = int(port)
            except (TypeError, ValueError):
                continue
            if 1 <= candidate <= 65535:
                valid.add(candidate)
        return sorted(valid)

    async def _scan_async(self, progress_callback: ProgressCallback | None) -> list[int]:
        """Scan ports using asyncio connections and a bounded semaphore."""
        semaphore = asyncio.Semaphore(self.max_threads)
        open_ports: list[int] = []

        async def check(port: int) -> None:
            is_open = False
            async with semaphore:
                try:
                    connect = asyncio.open_connection(self.target, port)
                    reader, writer = await asyncio.wait_for(connect, timeout=self.timeout)
                    writer.close()
                    await writer.wait_closed()
                    is_open = True
                    open_ports.append(port)
                    self.logger.info("Open port found: %s/tcp", port)
                except (asyncio.TimeoutError, OSError):
                    is_open = False
                finally:
                    if progress_callback:
                        progress_callback(port, is_open)

        await asyncio.gather(*(check(port) for port in self.ports))
        return sorted(open_ports)
