"""Honeyfile monitoring via watchdog.

Watches configured bait files for read, modify, delete, and move
attempts and emits SecurityEvents for the dashboard.
"""

from __future__ import annotations

import os
import threading
from pathlib import Path
from typing import Dict, List, Optional, Set

from watchdog.events import FileSystemEvent, FileSystemEventHandler
from watchdog.observers import Observer

from .logger import get_logger
from .models import EventSeverity, SecurityEvent


logger = get_logger()


class HoneyfileEventHandler(FileSystemEventHandler):
    """Watchdog event handler that produces SecurityEvents for honeyfiles."""

    def __init__(
        self,
        watched: Set[str],
        event_queue: "queue.Queue[SecurityEvent]",
        source_ip: str = "HOST",
        location_label: str = "Local Host",
    ) -> None:
        super().__init__()
        self._watched = watched
        self._queue = event_queue
        self._source_ip = source_ip
        self._location = location_label

    def _emit(self, path: str, action: str) -> None:
        self._queue.put(
            SecurityEvent(
                timestamp=self._now(),
                source_ip=self._source_ip,
                location=self._location,
                targeted=path,
                action=action,
                severity=EventSeverity.CRITICAL,
            )
        )
        logger.info("Honeyfile event: %s -> %s", path, action)

    @staticmethod
    def _now() -> str:
        from datetime import datetime, timezone
        return datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")

    def on_modified(self, event: FileSystemEvent) -> None:
        if event.is_directory:
            return
        path = os.path.abspath(event.src_path)
        if path in self._watched:
            self._emit(path, "MODIFY attempt")

    def on_deleted(self, event: FileSystemEvent) -> None:
        if event.is_directory:
            return
        path = os.path.abspath(event.src_path)
        if path in self._watched:
            self._emit(path, "DELETE attempt")

    def on_moved(self, event: FileSystemEvent) -> None:
        if event.is_directory:
            return
        dest = os.path.abspath(event.dest_path) if event.dest_path else ""
        src = os.path.abspath(event.src_path)
        if dest in self._watched:
            self._emit(dest, "MOVE (overwrite) attempt")
        elif src in self._watched:
            self._emit(src, "MOVE (rename away) attempt")

    def on_created(self, event: FileSystemEvent) -> None:
        if event.is_directory:
            return
        path = os.path.abspath(event.src_path)
        if path in self._watched:
            self._emit(path, "CREATE (overwrite) attempt")


def ensure_honeyfiles(paths: List[str]) -> None:
    """Create honeyfile placeholder files if they do not exist."""
    placeholder = "# ShadowNet honeyfile - do not modify\n"
    for p in paths:
        ap = os.path.abspath(p)
        parent = os.path.dirname(ap)
        if parent and not os.path.exists(parent):
            os.makedirs(parent, exist_ok=True)
        if not os.path.exists(ap):
            with open(ap, "w", encoding="utf-8") as f:
                f.write(placeholder)
            logger.info("Created honeyfile placeholder: %s", ap)


def start_honeyfile_monitor(
    honeyfiles: List[str],
    event_queue: "queue.Queue[SecurityEvent]",
    console: Optional["rich.console.Console"] = None,
) -> Observer:
    """Start a watchdog observer that monitors honeyfile paths.

    Parameters
    ----------
    honeyfiles:
        List of file paths to watch.
    event_queue:
        Queue to which SecurityEvents will be written.
    console:
        Optional Rich console for startup log messages.

    Returns
    -------
    The started (and already running) Observer instance.
    """
    ensure_honeyfiles(honeyfiles)
    watched = {os.path.abspath(p) for p in honeyfiles}

    handler = HoneyfileEventHandler(
        watched=watched,
        event_queue=event_queue,
    )

    observer = Observer()
    observer.schedule(handler, path=".", recursive=True)
    observer.start()

    msg = f"Honeyfile monitoring active for {len(honeyfiles)} asset(s): {honeyfiles}"
    logger.info(msg)
    if console:
        console.log(f"[cyan][ShadowNet] {msg}[/cyan]")

    return observer
