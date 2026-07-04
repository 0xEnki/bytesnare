"""ShadowNet — main orchestrator.

Initialises all subsystems, wires them together via queues and
caches, and manages graceful shutdown on SIGINT / SIGTERM.
"""

from __future__ import annotations

import asyncio
import os
import signal
import sys
import threading
from typing import Any, Dict, List, Set

from rich.console import Console

from .config import load_config
from .dashboard import dashboard_loop
from .decoy_server import DecoyServerManager
from .geo import geo_fill_worker
from .honeyfile_monitor import start_honeyfile_monitor
from .logger import get_logger, setup_logger
from .models import EventSeverity, SecurityEvent, ShadowNetConfig


logger = get_logger()


async def _geo_dispatch_loop(
    geo_cache: Dict[str, str],
    geo_queue: "asyncio.Queue[str]",
) -> None:
    """Poll geo_cache for unresolved IPs and enqueue them for lookup.

    This bridging loop is needed because the (thread-based) decoy
    listeners may not always be able to schedule into the async loop.
    """
    seen: Set[str] = set()
    while True:
        try:
            unresolved = [
                ip
                for ip, loc in geo_cache.items()
                if loc == "Resolving..." and ip not in seen
            ]
            for ip in unresolved:
                seen.add(ip)
                await geo_queue.put(ip)
        except Exception as exc:
            logger.debug("Geo dispatch iteration error: %s", exc)
        await asyncio.sleep(0.5)


async def main_async(config: ShadowNetConfig, console: Console) -> None:
    """Asynchronous entry point: initialise and run all subsystems."""

    import queue as _queue

    event_queue: "queue.Queue[SecurityEvent]" = _queue.Queue()
    geo_cache: Dict[str, str] = {}
    geo_queue: "asyncio.Queue[str]" = asyncio.Queue()
    blocked_ips: Set[str] = set()
    stop_ui = threading.Event()

    decoy_manager = DecoyServerManager(
        config=config,
        event_queue=event_queue,
        geo_cache=geo_cache,
        geo_queue=geo_queue,
        blocked_ips=blocked_ips,
    )

    ui_thread = threading.Thread(
        target=dashboard_loop,
        args=(
            console,
            event_queue,
            stop_ui,
            lambda: decoy_manager.active_ports,
        ),
        daemon=True,
    )
    ui_thread.start()

    geo_task = asyncio.create_task(
        geo_fill_worker(geo_cache, geo_queue, config.geo_api_url)
    )
    dispatch_task = asyncio.create_task(_geo_dispatch_loop(geo_cache, geo_queue))

    observer = None
    if config.honeyfiles_enabled:
        observer = start_honeyfile_monitor(
            config.honeyfiles, event_queue, console
        )

    decoy_manager.start(console)

    console.log(
        "[bold green]ShadowNet fully operational — press Ctrl+C to stop[/bold green]"
    )

    shutdown_event = asyncio.Event()

    def _signal_handler() -> None:
        console.log("[bold yellow]Shutdown signal received, draining...[/bold yellow]")
        shutdown_event.set()

    loop = asyncio.get_running_loop()
    for sig in (signal.SIGINT, signal.SIGTERM):
        try:
            loop.add_signal_handler(sig, _signal_handler)
        except NotImplementedError:
            pass

    try:
        await shutdown_event.wait()
    except asyncio.CancelledError:
        pass

    console.log("[bold yellow]Initiating graceful shutdown...[/bold yellow]")

    stop_ui.set()
    decoy_manager.stop(timeout=3.0)
    if observer:
        observer.stop()
        observer.join(timeout=2.0)

    geo_task.cancel()
    dispatch_task.cancel()
    for t in (geo_task, dispatch_task):
        try:
            await t
        except (asyncio.CancelledError, Exception):
            pass

    console.log("[bold green]ShadowNet shutdown complete.[/bold green]")


def main() -> None:
    """Synchronous entry point called by ``python -m shadownet``."""

    if sys.platform.startswith("win"):
        try:
            asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())
        except Exception:
            pass

    console = Console()

    try:
        config = load_config()
    except Exception as exc:
        console.log(f"[bold red]Failed to load configuration: {exc}[/bold red]")
        sys.exit(1)

    try:
        setup_logger(
            log_path=config.log_file,
            level=config.log_level,
        )
    except Exception as exc:
        console.log(f"[bold red]Failed to set up logger: {exc}[/bold red]")
        sys.exit(1)

    asyncio.run(main_async(config, console))
