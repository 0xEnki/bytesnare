"""Configuration management — loads YAML with environment overrides."""

from __future__ import annotations

import os
import json
from pathlib import Path
from typing import Any, Dict, List, Optional

import yaml

from .models import ShadowNetConfig


_ENV_PREFIX = "SHADOWNET_"


def _resolve_path(base_dir: Path, path_str: str) -> str:
    """Resolve a potentially relative path against the project root."""
    p = Path(path_str)
    if p.is_absolute():
        return str(p)
    return str(base_dir / p)


def load_config(path: Optional[str] = None) -> ShadowNetConfig:
    """Load configuration from YAML file, merged with environment overrides.

    Resolution order (lowest to highest priority):
        1. Defaults in ShadowNetConfig
        2. Values from YAML file
        3. Environment variables with SHADOWNET_ prefix (JSON-decoded)
    """
    base_dir = Path.cwd()

    config = ShadowNetConfig()

    if path is None:
        candidates = [
            base_dir / "config.yaml",
            base_dir / "config.yml",
            base_dir / "shadownet" / "config.yaml",
        ]
        resolved_path: Optional[Path] = None
        for c in candidates:
            if c.exists():
                resolved_path = c
                break
        if resolved_path is None:
            try:
                import importlib.resources as pkg_resources
                from . import DEFAULT_CONFIG
                default = pkg_resources.files("shadownet").joinpath("config.yaml")
                if default.exists():
                    resolved_path = default
            except (ImportError, TypeError, AttributeError):
                pass
    else:
        resolved_path = Path(path)

    if resolved_path and resolved_path.exists():
        with open(resolved_path, "r", encoding="utf-8") as f:
            raw: Dict[str, Any] = yaml.safe_load(f) or {}

        general = raw.get("general", {})
        ports_cfg = raw.get("decoy_ports", {})
        honey_cfg = raw.get("honeyfiles", {})
        geo_cfg = raw.get("geo", {})
        log_cfg = raw.get("logging", {})

        if isinstance(ports_cfg.get("ports"), list):
            config.decoy_ports = [int(p) for p in ports_cfg["ports"]]
        if isinstance(general.get("rotation_minutes"), (int, float)):
            config.rotation_minutes = int(general["rotation_minutes"])
        if isinstance(ports_cfg.get("banners"), dict):
            raw_banners: Dict[str, Any] = ports_cfg["banners"]
            config.custom_banners = {
                int(k): v if isinstance(v, list) else [v]
                for k, v in raw_banners.items()
            }
        if isinstance(honey_cfg.get("enabled"), bool):
            config.honeyfiles_enabled = honey_cfg["enabled"]
        if isinstance(honey_cfg.get("paths"), list):
            config.honeyfiles = [
                _resolve_path(base_dir, p) for p in honey_cfg["paths"]
            ]
        if isinstance(geo_cfg.get("api_url"), str):
            config.geo_api_url = geo_cfg["api_url"]
        if isinstance(geo_cfg.get("timeout_seconds"), (int, float)):
            config.geo_timeout_seconds = float(geo_cfg["timeout_seconds"])
        if isinstance(general.get("firewall_rule_prefix"), str):
            config.firewall_rule_prefix = general["firewall_rule_prefix"]
        if isinstance(log_cfg.get("file"), str):
            config.log_file = _resolve_path(base_dir, log_cfg["file"])
        if isinstance(log_cfg.get("level"), str):
            config.log_level = log_cfg["level"].upper()

    for key, val in os.environ.items():
        if not key.startswith(_ENV_PREFIX):
            continue
        stripped = key[len(_ENV_PREFIX) :].lower()
        try:
            parsed: Any = json.loads(val)
        except (json.JSONDecodeError, TypeError):
            parsed = val

        if stripped == "decoy_ports" and isinstance(parsed, list):
            config.decoy_ports = [int(p) for p in parsed]
        elif stripped == "rotation_minutes":
            config.rotation_minutes = int(parsed)
        elif stripped == "honeyfiles" and isinstance(parsed, list):
            config.honeyfiles = parsed
        elif stripped == "honeyfiles_enabled":
            config.honeyfiles_enabled = bool(parsed)
        elif stripped == "geo_api_url":
            config.geo_api_url = str(parsed)
        elif stripped == "log_level":
            config.log_level = str(parsed).upper()
        elif stripped == "log_file":
            config.log_file = str(parsed)

    return config
