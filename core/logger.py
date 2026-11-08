from __future__ import annotations

import logging
import os
from logging.handlers import RotatingFileHandler
from pathlib import Path

from core.config import PROJECT_ROOT

LOGS_DIR = PROJECT_ROOT / "logs"
LOGS_DIR.mkdir(parents=True, exist_ok=True)
LOG_FILE = LOGS_DIR / "dhcp_analyzer.log"

_CONFIGURED = False


def setup_logger(name: str = "dhcp_analyzer", level: int = logging.INFO) -> logging.Logger:
    """Configure structured rotating file logger and console output.

    Spec chapter 5 & 19.1: error classification, operational log retention.
    """
    global _CONFIGURED
    logger = logging.getLogger(name)
    logger.setLevel(level)

    if not _CONFIGURED:
        formatter = logging.Formatter(
            fmt="%(asctime)s [%(levelname)s] [%(name)s] %(message)s",
            datefmt="%Y-%m-%d %H:%M:%S",
        )

        # File handler (10MB per file, keep 5 backups)
        file_handler = RotatingFileHandler(
            filename=str(LOG_FILE),
            maxBytes=10 * 1024 * 1024,
            backupCount=5,
            encoding="utf-8",
        )
        file_handler.setFormatter(formatter)
        file_handler.setLevel(level)
        logger.addHandler(file_handler)

        # Console handler
        console_handler = logging.StreamHandler()
        console_handler.setFormatter(formatter)
        console_handler.setLevel(level)
        logger.addHandler(console_handler)

        _CONFIGURED = True

    return logger
