"""Project-wide logging configuration.

Library code must not write to stdout/stderr directly: use ``get_logger`` and
emit records. CLI entrypoints opt in to output by calling
``configure_logging``; the default level is ``INFO`` and the message format is
kept bare so existing CLI output stays unchanged.
"""

import logging
import os
import sys
from typing import Optional, TextIO

_ROOT = "blastradius"
_DEFAULT_FORMAT = "%(message)s"


class _DynamicStdoutHandler(logging.StreamHandler):
    """Follow ``sys.stdout`` so test capture and redirection keep working."""

    def __init__(self) -> None:
        super().__init__(sys.stdout)

    def emit(self, record: logging.LogRecord) -> None:
        self.stream = sys.stdout
        super().emit(record)


def get_logger(name: str) -> logging.Logger:
    """Return a logger under the ``blastradius`` namespace."""
    if name == _ROOT or name.startswith(f"{_ROOT}."):
        return logging.getLogger(name)
    return logging.getLogger(f"{_ROOT}.{name}")


def configure_logging(
    level: Optional[str] = None,
    stream: Optional[TextIO] = None,
) -> None:
    """Attach one fresh stdout handler to the ``blastradius`` logger.

    Re-binding on every call keeps the handler pointed at the current
    ``sys.stdout`` (important under pytest capture) and avoids duplicate
    output. ``level`` falls back to ``BLASTRADIUS_LOG_LEVEL`` and then
    ``INFO``.
    """
    logger = logging.getLogger(_ROOT)
    level_name = (level or os.getenv("BLASTRADIUS_LOG_LEVEL") or "INFO").upper()
    logger.setLevel(getattr(logging, level_name, logging.INFO))
    for existing in list(logger.handlers):
        logger.removeHandler(existing)
        existing.close()
    handler: logging.Handler = (
        logging.StreamHandler(stream) if stream is not None else _DynamicStdoutHandler()
    )
    handler.setFormatter(logging.Formatter(_DEFAULT_FORMAT))
    logger.addHandler(handler)
    logger.propagate = False
