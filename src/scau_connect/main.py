"""Application entry point for scau-connect.

This module is a placeholder skeleton. The real ``main`` coroutine is
implemented in :mod:`scau_connect.cli` (the Typer CLI). See Agent-2 for the
full connection orchestration.
"""

from __future__ import annotations

from scau_connect.cli import app


def main() -> None:
    """Console script entry point.

    Delegates to the Typer application defined in :mod:`scau_connect.cli`.
    """
    app()


if __name__ == "__main__":
    main()
