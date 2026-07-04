"""Dynamic decoy port server with banner spoofing and live port hopping.

Manages a set of listener threads — one per decoy port — and
optionally rotates one port at configurable intervals to simulate
a dynamic network environment.
"""

from __future__ import annotations

import asyncio
import queue
import random
import socket
import threading
import time
from datetime import datetime, timezone
from typing import Dict, List, Optional, Set, Tuple

from .banner_spoofer import choose_banner
from .firewall import block_ip
from .logger import get_logger
from .models import EventSeverity, SecurityEvent, ShadowNetConfig


logger = get_logger()


class _PortListener:
    """Internal helper that runs a single decoy listener on one port."""

    def __init__(
        self,
        port: int,
        config: ShadowNetConfig,
        event_queue: "queue.Queue[SecurityEvent]",
        geo_cache: Dict[str, str],
        geo_queue: "asyncio.Queue[str]",
        blocked_ips: Set[str],
    ) -> None:
        self.port = port
        self.config = config
        self.event_queue = event_queue
        self.geo_cache = geo_cache
        self.geo_queue = geo_queue
        self.blocked_ips = blocked_ips

        self._stop = threading.Event()
        self._thread: Optional[threading.Thread] = None
        self._server: Optional[socket.socket] = None

    @property
    def is_alive(self) -> bool:
        return self._thread is not None and self._thread.is_alive()

    def start(self) -> None:
        if self.is_alive:
            return
        self._stop.clear()
        self._thread = threading.Thread(
            target=self._run,
            daemon=True,
            name=f"decoy-{self.port}",
        )
        self._thread.start()

    def stop(self, timeout: float = 2.0) -> None:
        self._stop.set()
        self._close_socket()
        if self._thread and self._thread.is_alive():
            self._thread.join(timeout=timeout)
        self._thread = None

    def _close_socket(self) -> None:
        if self._server is not None:
            try:
                self._server.close()
            except OSError:
                pass
            self._server = None

    def _now(self) -> str:
        return datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")

    def _enqueue_event(
        self,
        source_ip: str,
        location: str,
        targeted: str,
        action: str,
        severity: EventSeverity,
    ) -> None:
        self.event_queue.put(
            SecurityEvent(
                timestamp=self._now(),
                source_ip=source_ip,
                location=location,
                targeted=targeted,
                action=action,
                severity=severity,
            )
        )

    def _run(self) -> None:
        host = "0.0.0.0"
        try:
            server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            server.bind((host, self.port))
            server.listen(200)
            server.settimeout(self.config.socket_accept_timeout)
            self._server = server
        except OSError as exc:
            self._enqueue_event(
                source_ip="-",
                location="-",
                targeted=f"tcp/{self.port}",
                action=f"listener bind failed: {exc}",
                severity=EventSeverity.CRITICAL,
            )
            logger.error("Failed to bind decoy port %d: %s", self.port, exc)
            return

        logger.info("Decoy listener started on tcp/%d", self.port)

        while not self._stop.is_set():
            try:
                try:
                    conn, addr = server.accept()
                except socket.timeout:
                    continue
                except OSError:
                    break

                self._handle_connection(conn, addr)

            except Exception as exc:
                logger.error("Listener error on port %d: %s", self.port, exc)
                continue

        self._close_socket()

    def _handle_connection(
        self,
        conn: socket.socket,
        addr: Tuple[str, int],
    ) -> None:
        attacker_ip = addr[0]
        targeted = f"tcp/{self.port}"

        banner = choose_banner(self.port, self.config)
        try:
            conn.settimeout(self.config.client_spin_limit)
            conn.sendall(banner)
        except OSError:
            pass
        finally:
            try:
                conn.close()
            except OSError:
                pass

        action_taken = f"spoofed banner sent ({len(banner)} bytes); connection dropped"

        if attacker_ip not in self.blocked_ips:
            self.blocked_ips.add(attacker_ip)
            threading.Thread(
                target=self._mitigate_and_report,
                args=(attacker_ip, targeted),
                daemon=True,
            ).start()
        else:
            self._enqueue_event(
                source_ip=attacker_ip,
                location=self.geo_cache.get(attacker_ip, "Resolving..."),
                targeted=targeted,
                action=action_taken,
                severity=EventSeverity.WARN,
            )

        if attacker_ip not in self.geo_cache:
            self.geo_cache[attacker_ip] = "Resolving..."
            try:
                loop = asyncio.get_event_loop()
                if loop.is_running():
                    loop.call_soon_threadsafe(
                        lambda: self.geo_queue.put_nowait(attacker_ip)
                    )
                else:
                    loop = asyncio.new_event_loop()
                    loop.run_until_complete(self.geo_queue.put(attacker_ip))
                    loop.close()
            except RuntimeError:
                logger.debug("No running event loop for geo dispatch")

    def _mitigate_and_report(self, ip: str, targeted: str) -> None:
        ok, detail = block_ip(ip, self.config.firewall_rule_prefix)
        severity = EventSeverity.CRITICAL if ok else EventSeverity.WARN
        self._enqueue_event(
            source_ip=ip,
            location=self.geo_cache.get(ip, "Resolving..."),
            targeted=targeted,
            action=f"{'BLOCKED' if ok else 'BLOCK FAILED'}: {detail}",
            severity=severity,
        )


class DecoyServerManager:
    """Manages a collection of decoy port listeners with optional rotation."""

    def __init__(
        self,
        config: ShadowNetConfig,
        event_queue: "queue.Queue[SecurityEvent]",
        geo_cache: Dict[str, str],
        geo_queue: "asyncio.Queue[str]",
        blocked_ips: Set[str],
    ) -> None:
        self._config = config
        self._event_queue = event_queue
        self._geo_cache = geo_cache
        self._geo_queue = geo_queue
        self._blocked_ips = blocked_ips

        self._lock = threading.Lock()
        self._listeners: Dict[int, _PortListener] = {}
        self._rotation_thread: Optional[threading.Thread] = None
        self._stop = threading.Event()

    @property
    def active_ports(self) -> List[int]:
        with self._lock:
            return sorted(self._listeners.keys())

    def start(self, console: Optional["rich.console.Console"] = None) -> None:
        """Create and start all decoy listeners."""
        with self._lock:
            for port in self._config.decoy_ports:
                listener = _PortListener(
                    port=port,
                    config=self._config,
                    event_queue=self._event_queue,
                    geo_cache=self._geo_cache,
                    geo_queue=self._geo_queue,
                    blocked_ips=self._blocked_ips,
                )
                listener.start()
                self._listeners[port] = listener

        if self._config.rotation_minutes > 0:
            self._rotation_thread = threading.Thread(
                target=self._rotation_loop,
                daemon=True,
                name="port-rotator",
            )
            self._rotation_thread.start()

        msg = f"Decoy servers active on {len(self._listeners)} port(s): {self.active_ports}"
        logger.info(msg)
        if console:
            console.log(f"[green][ShadowNet] {msg}[/green]")

    def stop(self, timeout: float = 3.0) -> None:
        """Gracefully stop all listeners and the rotation thread."""
        self._stop.set()
        with self._lock:
            for port, listener in list(self._listeners.items()):
                listener.stop(timeout=min(timeout, 1.0))
            self._listeners.clear()
        logger.info("All decoy listeners stopped")

    def _rotate_one_port(self) -> bool:
        """Replace one random active port with a new random port.

        Returns True if a rotation occurred, False otherwise.
        """
        pool = list(self._config.decoy_ports)
        with self._lock:
            if len(pool) < 2:
                return False
            inactive = [p for p in pool if p not in self._listeners]
            if not inactive:
                return False
            to_replace = random.choice(list(self._listeners.keys()))
            new_port = random.choice(inactive)

            old_listener = self._listeners.pop(to_replace, None)
            if old_listener:
                old_listener.stop(timeout=1.0)

            new_listener = _PortListener(
                port=new_port,
                config=self._config,
                event_queue=self._event_queue,
                geo_cache=self._geo_cache,
                geo_queue=self._geo_queue,
                blocked_ips=self._blocked_ips,
            )
            new_listener.start()
            self._listeners[new_port] = new_listener

        logger.info("Rotated decoy port %d -> %d", to_replace, new_port)
        return True

    def _rotation_loop(self) -> None:
        interval = self._config.rotation_minutes * 60
        while not self._stop.is_set():
            if self._stop.wait(timeout=interval):
                break
            if not self._stop.is_set():
                self._rotate_one_port()
