"""
WinSecure Structured Logging Subsystem
"""
import logging
import os
import sys
from datetime import datetime, timezone
from typing import Optional
from winsecure.utils.security import sanitize_text


class SanitizingFormatter(logging.Formatter):
    """Custom logging formatter that strips sensitive secrets and tokens."""
    def format(self, record: logging.LogRecord) -> str:
        original = super().format(record)
        return sanitize_text(original)


def setup_logger(
    name: str = "winsecure",
    log_level: int = logging.INFO,
    log_file: Optional[str] = None,
) -> logging.Logger:
    """Configures and returns a structured logger for WinSecure."""
    logger = logging.getLogger(name)
    logger.setLevel(log_level)
    logger.handlers.clear()

    # Console handler with clean formatting
    console_handler = logging.StreamHandler(sys.stderr)
    console_handler.setLevel(log_level)
    console_format = SanitizingFormatter(
        "[%(levelname)s] %(message)s"
    )
    console_handler.setFormatter(console_format)
    logger.addHandler(console_handler)

    # Optional file handler with timestamps
    if log_file:
        os.makedirs(os.path.dirname(os.path.abspath(log_file)), exist_ok=True)
        file_handler = logging.FileHandler(log_file, encoding="utf-8")
        file_handler.setLevel(logging.DEBUG)
        file_format = SanitizingFormatter(
            "%(asctime)s [%(levelname)s] [%(name)s:%(lineno)d] %(message)s"
        )
        file_handler.setFormatter(file_format)
        logger.addHandler(file_handler)

    return logger
