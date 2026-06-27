"""Module entry point: ``python -m scau_connect``.

Delegates to the Typer CLI defined in :mod:`scau_connect.cli`.
"""

from scau_connect.cli import main


if __name__ == "__main__":
    main()
