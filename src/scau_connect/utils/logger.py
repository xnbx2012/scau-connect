"""Structured logging via structlog.

All modules should use ``get_logger(__name__)`` to obtain a bound logger.
Debug mode toggles between ``console`` (colourised, human-readable) and
``json`` (machine-readable, production-friendly) renderers.
"""

from __future__ import annotations

import logging
import sys

import structlog

_LOG_LEVEL_MAP: dict[str, int] = {
    "debug": logging.DEBUG,
    "info": logging.INFO,
    "warning": logging.WARNING,
    "error": logging.ERROR,
    "critical": logging.CRITICAL,
}

_configured = False


def _configure_structlog(*, debug: bool = False) -> None:
    """(Re-)configure structlog and stdlib logging.

    Parameters
    ----------
    debug : bool
        If ``True``, use a colourised console renderer with tracebacks.
        Otherwise use a key-value renderer suitable for piping / JSON.
    """
    global _configured
    if _configured:
        return

    log_level = logging.DEBUG if debug else logging.INFO

    renderer: list[structlog.types.Processor]
    if debug:
        renderer = [
            structlog.dev.ConsoleRenderer(colors=True),
        ]
    else:
        renderer = [
            structlog.dev.ConsoleRenderer(colors=False),
        ]

    structlog.configure(
        processors=[
            structlog.contextvars.merge_contextvars,
            structlog.stdlib.filter_by_level,
            structlog.stdlib.add_logger_name,
            structlog.stdlib.add_log_level,
            structlog.stdlib.PositionalArgumentsFormatter(),
            structlog.processors.TimeStamper(fmt="iso"),
            structlog.processors.StackInfoRenderer(),
            structlog.processors.format_exc_info,
            structlog.processors.UnicodeDecoder(),
            *renderer,
        ],
        wrapper_class=structlog.stdlib.BoundLogger,
        context_class=dict,
        logger_factory=structlog.stdlib.LoggerFactory(),
        cache_logger_on_first_use=True,
    )

    # Also configure stdlib logging so third-party libraries show up.
    logging.root.setLevel(log_level)
    # Ensure a StreamHandler exists so stdlib logs are visible.
    if not logging.root.handlers:
        logging.root.addHandler(logging.StreamHandler(sys.stderr))

    _configured = True


def get_logger(name: str, *, debug: bool = False) -> structlog.stdlib.BoundLogger:
    """Return a configured structlog logger bound to *name*.

    Parameters
    ----------
    name : str
        Typically ``__name__`` of the calling module.
    debug : bool
        Enable debug-level output on first call.

    Returns
    -------
    structlog.stdlib.BoundLogger
    """
    _configure_structlog(debug=debug)
    return structlog.get_logger(name)


def reset_configuration() -> None:
    """Reset the structlog configuration (useful in tests)."""
    global _configured
    _configured = False
    structlog.reset_defaults()
