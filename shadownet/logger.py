"""Centralised logging — rotating file handler with structured formatting."""

from __future__ import annotations

import logging
import sys
from logging.handlers import RotatingFileHandler
from pathlib import Path
from typing import Optional


_LOG_FORMAT = "%(asctime)s - [%(levelname)s] - %(message)s"
_DATE_FORMAT = "%Y-%m-%d %H:%M:%S"


def setup_logger(
    log_path: str = "logs/shadownet.log",
    level: str = "INFO",
    max_bytes: int = 10 * 1024 * 1024,
    backup_count: int = 5,
    quiet_console: bool = True,
) -> logging.Logger:
    """Configure and return the root ShadowNet logger.

    Parameters
    ----------
    log_path:
        Path to the rotating log file.
    level:
        Logging level string (DEBUG, INFO, WARNING, etc.).
    max_bytes:
        Maximum size per log file before rotation.
    backup_count:
        Number of rotated backups to keep.
    quiet_console:
        If True, suppresses console propagation to avoid duplicating
        output with the Rich dashboard.
    """
    logger = logging.getLogger("shadownet")
    logger.setLevel(getattr(logging, level.upper(), logging.INFO))

    for handler in logger.handlers[:]:
        logger.removeHandler(handler)

    log_dir = Path(log_path).parent
    log_dir.mkdir(parents=True, exist_ok=True)

    file_handler = RotatingFileHandler(
        log_path,
        maxBytes=max_bytes,
        backupCount=backup_count,
        encoding="utf-8",
    )
    file_handler.setFormatter(logging.Formatter(_LOG_FORMAT, datefmt=_DATE_FORMAT))
    logger.addHandler(file_handler)

    if not quiet_console:
        console_handler = logging.StreamHandler(sys.stderr)
        console_handler.setFormatter(logging.Formatter(_LOG_FORMAT, datefmt=_DATE_FORMAT))
        logger.addHandler(console_handler)

    logger.info("ShadowNet logger initialised (file=%s, level=%s)", log_path, level)

    return logger


def get_logger() -> logging.Logger:
    """Retrieve the pre-configured ShadowNet logger."""
    return logging.getLogger("shadownet")
