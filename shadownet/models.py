"""ShadowNet data models and enumerations."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, List, Optional, Set


class EventSeverity(str, Enum):
    """Severity classification for security events."""

    INFO = "INFO"
    WARN = "WARN"
    CRITICAL = "CRITICAL"
    DEBUG = "DEBUG"


@dataclass(frozen=True)
class SecurityEvent:
    """An immutable security event record emitted by any ShadowNet sensor."""

    timestamp: str
    source_ip: str
    location: str
    targeted: str
    action: str
    severity: EventSeverity


@dataclass
class AttackerRecord:
    """Tracks state for a single attacker IP across the system."""

    ip: str
    first_seen: str
    last_seen: str
    hit_count: int = 0
    blocked: bool = False
    location: str = "Resolving..."
    targeted_ports: Set[int] = field(default_factory=set)


@dataclass
class ShadowNetConfig:
    """Merged configuration from YAML and environment overrides."""

    decoy_ports: List[int] = field(default_factory=lambda: [22, 80, 445, 8080])
    rotation_minutes: int = 10
    banner_rotation_seconds: float = 2.0
    honeyfiles: List[str] = field(
        default_factory=lambda: ["credentials.db", "network_config.json"]
    )
    honeyfiles_enabled: bool = True
    geo_api_url: str = "https://ipinfo.io/{ip}/json"
    geo_timeout_seconds: float = 4.5
    firewall_rule_prefix: str = "ShadowNet_Block_"
    log_file: str = "logs/shadownet.log"
    log_level: str = "INFO"
    socket_accept_timeout: float = 1.0
    client_spin_limit: float = 3.0
    custom_banners: Dict[int, List[str]] = field(default_factory=dict)
