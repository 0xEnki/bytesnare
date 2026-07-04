"""
ShadowNet — Dynamic Honeypot with Active Defense.

A local-only active defense toolkit that operates decoy ports with
banner spoofing, monitors honeyfiles, and automatically blocks
attackers at the host firewall.
"""

from __future__ import annotations

from .entrypoint import main
from .models import EventSeverity, SecurityEvent, ShadowNetConfig

__all__ = [
    "main",
    "EventSeverity",
    "SecurityEvent",
    "ShadowNetConfig",
]

__version__ = "2.0.0"
