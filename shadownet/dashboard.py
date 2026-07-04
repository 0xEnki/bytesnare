"""Premium SOC-style terminal dashboard using the Rich library.

Renders a live-updating layout with:
- ASCII art banner
- Alert table (timestamp, source IP, location, targeted asset, action)
- Real-time stats footer
"""

from __future__ import annotations

import queue
import threading
from datetime import datetime, timezone
from typing import Dict, List, Optional, Set

from rich import box
from rich.console import Console, Group
from rich.layout import Layout
from rich.live import Live
from rich.panel import Panel
from rich.style import Style
from rich.table import Table
from rich.text import Text

from .logger import get_logger
from .models import EventSeverity, SecurityEvent


logger = get_logger()


_BANNER = r"""

 ╔══════════════════════════════════════════════════════════════╗
 ║   ███████╗██╗  ██╗ █████╗ ██████╗  ██████╗ ██╗    ██╗        ║
 ║   ██╔════╝██║  ██║██╔══██╗██╔══██╗██╔═══██╗██║    ██║        ║
 ║   ███████╗███████║███████║██║  ██║██║   ██║██║ █╗ ██║        ║
 ║   ╚════██║██╔══██║██╔══██║██║  ██║██║   ██║██║███╗██║        ║
 ║   ███████║██║  ██║██║  ██║██████╔╝╚██████╔╝╚███╔███╔╝        ║
 ║   ╚══════╝╚═╝  ╚═╝╚═╝  ╚═╝╚═════╝  ╚═════╝  ╚══╝╚══╝         ║
 ║                                                              ║
 ║            Dynamic Honeypot ·  Active Defense                ║
 ║            Developer        .  Enki                          ║
 ║         Live SOC Dashboard  ·  Threat Mitigation             ║
 ╚══════════════════════════════════════════════════════════════╝
"""


def _build_stats_table(
    total_events: int,
    blocked_count: int,
    active_ports: List[int],
    geo_cache_size: int,
) -> Table:
    """Small informational table shown above the alert list."""
    table = Table(
        box=box.ROUNDED,
        show_header=False,
        expand=True,
        style="bright_blue",
    )
    table.add_column("Metric", style="bold cyan", width=16)
    table.add_column("Value", style="white")

    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    table.add_row("System Time", now)
    table.add_row("Total Events", str(total_events))
    table.add_row("Blocked IPs", f"[bold red]{blocked_count}[/bold red]")
    table.add_row("Active Ports", f"[bold green]{', '.join(map(str, active_ports))}[/bold green]")
    table.add_row("Geo Cache", f"{geo_cache_size} entries")
    return table


def _build_alert_table(events: List[SecurityEvent]) -> Table:
    """Build a colour-coded alert table from the event list.

    The most recent 50 events are shown, newest first.
    """
    table = Table(
        title="[bold magenta]Live Threat Alerts[/bold magenta]",
        box=box.ROUNDED,
        show_lines=False,
        header_style="bold magenta",
        title_style="bold magenta",
        expand=True,
    )
    table.add_column("Timestamp", style="dim", width=22, no_wrap=True)
    table.add_column("Source IP", style="bold", width=18, no_wrap=True)
    table.add_column("Location", style="cyan", width=28, no_wrap=True)
    table.add_column("Targeted Asset/Port", style="yellow", width=24, no_wrap=True)
    table.add_column("Action Taken", style="white", min_width=20)

    for ev in reversed(events[-50:]):
        if ev.severity == EventSeverity.CRITICAL:
            style = "bold red"
        elif ev.severity == EventSeverity.WARN:
            style = "bold yellow"
        else:
            style = "white"
        table.add_row(
            ev.timestamp,
            ev.source_ip,
            ev.location,
            ev.targeted,
            f"[{style}]{ev.action}[/{style}]",
        )

    return table


def dashboard_loop(
    console: Console,
    event_queue: "queue.Queue[SecurityEvent]",
    stop_event: threading.Event,
    active_ports_fn: "callable[[], List[int]]",
) -> None:
    """Run the live Rich dashboard in a dedicated thread.

    Parameters
    ----------
    console:
        Rich Console tied to stdout.
    event_queue:
        Thread-safe queue from which SecurityEvents are consumed.
    stop_event:
        Set to signal graceful shutdown.
    active_ports_fn:
        Callback returning the list of currently active decoy ports.
    """
    events: List[SecurityEvent] = []
    blocked_ips: Set[str] = set()

    def _render() -> Layout:
        layout = Layout()
        layout.split_column(
            Layout(name="header", size=14),
            Layout(name="stats", size=5),
            Layout(name="alerts"),
        )

        layout["header"].update(
            Panel(
                _BANNER.strip("\n"),
                border_style="bright_blue",
                padding=(0, 2),
                title="[bold blue]ShadowNet SOC Dashboard[/bold blue]",
                subtitle="[dim]Active Defense Engine v2.0[/dim]",
            )
        )

        stats_table = _build_stats_table(
            total_events=len(events),
            blocked_count=len(blocked_ips),
            active_ports=active_ports_fn(),
            geo_cache_size=0,
        )
        layout["stats"].update(
            Panel(stats_table, border_style="cyan", padding=(0, 1))
        )

        alert_table = _build_alert_table(events)
        layout["alerts"].update(
            Panel(alert_table, border_style="magenta", padding=(0, 1))
        )

        return layout

    with Live(
        _render(),
        console=console,
        refresh_per_second=8,
        screen=True,
    ) as live:
        while not stop_event.is_set():
            try:
                ev = event_queue.get(timeout=0.25)
                events.append(ev)
                if ev.severity == EventSeverity.CRITICAL and ev.action.startswith("BLOCKED"):
                    blocked_ips.add(ev.source_ip)
                live.update(_render())
            except queue.Empty:
                continue
            except Exception:
                continue
