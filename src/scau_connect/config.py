"""Application configuration for scau-connect.

Loads settings from defaults, environment variables (``SCAU_*``), and (in a
later phase) from a persisted JSON session file.

Example environment variables::

    SCAU_SERVER=vpn.scau.edu.cn
    SCAU_USERNAME=your_student_id
    SCAU_PASSWORD=your_password
    SCAU_DEBUG=1

All values are **optional**; sensible defaults are provided so the library can
be imported and inspected without any environment setup.
"""

from __future__ import annotations

import json
import os
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any


@dataclass
class Config:
    """Central configuration dataclass for scau-connect.

    Attributes
    ----------
    server : str
        VPN gateway hostname (``vpn.scau.edu.cn``).
    port : int
        HTTPS port for the aTrust server (default 443).
    protocol : str
        Tunnel protocol name (``atrust``).
    auth_type : str
        Authentication backend (``cas`` / ``ldap``).
    login_domain : str
        CAS login domain / realm (``CAS``).
    username : str | None
        Student / staff ID. ``None`` means "use Selenium browser".
    password : str | None
        Password. ``None`` means "use Selenium browser".
    http_proxy_port : int
        Local HTTP(S) CONNECT proxy port.
    socks5_proxy_port : int
        Local SOCKS5 proxy port.
    enable_http_proxy : bool
        Start the HTTP proxy on launch.
    enable_socks5_proxy : bool
        Start the SOCKS5 proxy on launch.
    session_file : str
        Path (relative or absolute) to the persisted session JSON.
    auto_reconnect : bool
        Automatically re-establish the tunnel if it drops.
    debug : bool
        Enable verbose structlog output.
    skip_ssl_verify : bool
        Disable TLS certificate verification (useful behind corporate proxies).
    headless_browser : bool
        Run Selenium Chrome in headless mode when browser-based login is needed.
    browser : str
        Browser driver name (``chrome`` / ``firefox``).
    """

    # --- Connection / protocol ---
    server: str = "vpn.scau.edu.cn"
    port: int = 443
    protocol: str = "atrust"

    # --- Authentication ---
    auth_type: str = "cas"
    login_domain: str = "CAS"
    username: str | None = None
    password: str | None = None

    # --- Local proxy ---
    http_proxy_port: int = 1081
    http_proxy_host: str = "0.0.0.0"
    socks5_proxy_port: int = 1080
    socks5_proxy_host: str = "0.0.0.0"
    enable_http_proxy: bool = True
    enable_socks5_proxy: bool = True

    # --- Session persistence ---
    session_file: str = ".session.json"
    auto_reconnect: bool = True

    # --- Developer options ---
    debug: bool = False
    skip_ssl_verify: bool = True
    headless_browser: bool = True
    browser: str = "chrome"

    # --- Internal state (not serialised by default) ---
    _extra: dict[str, Any] = field(default_factory=dict, repr=False)

    # ------------------------------------------------------------------
    # Class factories
    # ------------------------------------------------------------------

    @classmethod
    def from_env(cls) -> Config:
        """Construct a :class:`Config` from environment variables.

        Environment variable mapping (all optional):

        ===========================  =====================================
        Env var                     Config attribute
        ===========================  =====================================
        ``SCAU_SERVER``              ``server``
        ``SCAU_PORT``                ``port`` (int)
        ``SCAU_PROTOCOL``            ``protocol``
        ``SCAU_AUTH_TYPE``           ``auth_type``
        ``SCAU_LOGIN_DOMAIN``        ``login_domain``
        ``SCAU_USERNAME``            ``username``
        ``SCAU_PASSWORD``            ``password``
        ``SCAU_HTTP_PROXY_PORT``     ``http_proxy_port`` (int)
        ``SCAU_HTTP_PROXY_HOST``     ``http_proxy_host``
        ``SCAU_SOCKS5_PROXY_PORT``  ``socks5_proxy_port`` (int)
        ``SCAU_SOCKS5_PROXY_HOST``  ``socks5_proxy_host``
        ``SCAU_ENABLE_HTTP_PROXY``   ``enable_http_proxy`` (bool, 0/1/true/false)
        ``SCAU_ENABLE_SOCKS5_PROXY`` ``enable_socks5_proxy`` (bool, 0/1/true/false)
        ``SCAU_SESSION_FILE``        ``session_file``
        ``SCAU_AUTO_RECONNECT``      ``auto_reconnect`` (bool, 0/1/true/false)
        ``SCAU_DEBUG``               ``debug`` (bool, 0/1/true/false)
        ``SCAU_SKIP_SSL_VERIFY``     ``skip_ssl_verify`` (bool, 0/1/true/false)
        ``SCAU_HEADLESS_BROWSER``    ``headless_browser`` (bool, 0/1/true/false)
        ``SCAU_BROWSER``             ``browser``
        ===========================  =====================================

        Returns
        -------
        Config
            Populated configuration instance.
        """
        raw = {
            "server": os.getenv("SCAU_SERVER"),
            "port": _env_int("SCAU_PORT"),
            "protocol": os.getenv("SCAU_PROTOCOL"),
            "auth_type": os.getenv("SCAU_AUTH_TYPE"),
            "login_domain": os.getenv("SCAU_LOGIN_DOMAIN"),
            "username": os.getenv("SCAU_USERNAME"),
            "password": os.getenv("SCAU_PASSWORD"),
            "http_proxy_port": _env_int("SCAU_HTTP_PROXY_PORT"),
            "http_proxy_host": os.getenv("SCAU_HTTP_PROXY_HOST"),
            "socks5_proxy_port": _env_int("SCAU_SOCKS5_PROXY_PORT"),
            "socks5_proxy_host": os.getenv("SCAU_SOCKS5_PROXY_HOST"),
            "enable_http_proxy": _env_bool("SCAU_ENABLE_HTTP_PROXY"),
            "enable_socks5_proxy": _env_bool("SCAU_ENABLE_SOCKS5_PROXY"),
            "session_file": os.getenv("SCAU_SESSION_FILE"),
            "auto_reconnect": _env_bool("SCAU_AUTO_RECONNECT"),
            "debug": _env_bool("SCAU_DEBUG"),
            "skip_ssl_verify": _env_bool("SCAU_SKIP_SSL_VERIFY"),
            "headless_browser": _env_bool("SCAU_HEADLESS_BROWSER"),
            "browser": os.getenv("SCAU_BROWSER"),
        }
        # Drop None values so dataclass defaults are preserved
        kwargs = {k: v for k, v in raw.items() if v is not None}
        return cls(**kwargs)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> Config:
        """Construct a :class:`Config` from a plain dict (e.g. loaded from JSON).

        Parameters
        ----------
        data : dict[str, Any]
            Dictionary matching the fields of :class:`Config`.

        Returns
        -------
        Config
        """
        # Separate known fields from unknown extras.
        # ``_extra`` is a known (private) field, so it is part of ``core``;
        # anything else lands in the extras catch-all.
        known = {f.name for f in cls.__dataclass_fields__.values()}
        extras = {k: v for k, v in data.items() if k not in known}
        core = {k: v for k, v in data.items() if k in known}
        # Merge any unknown extras into the ``_extra`` bucket, then drop the
        # explicit ``_extra`` key so we never pass it twice.
        if "_extra" in core:
            merged = dict(core.pop("_extra"))
            merged.update(extras)
            extras = merged
        return cls(**core, _extra=extras) if extras else cls(**core)

    # ------------------------------------------------------------------
    # Serialisation
    # ------------------------------------------------------------------

    def to_dict(self) -> dict[str, Any]:
        """Return a plain ``dict`` representation suitable for JSON serialisation.

        Private fields (those starting with ``_``) and ``_extra`` are omitted.
        """
        return asdict(self)

    def save(self, path: str | Path | None = None) -> None:
        """Persist the config to a JSON file.

        Parameters
        ----------
        path : str | Path | None
            File path. Defaults to ``self.session_file``.
        """
        target = Path(path or self.session_file)
        target.write_text(json.dumps(self.to_dict(), indent=2, ensure_ascii=False), encoding="utf-8")

    @classmethod
    def load(cls, path: str | Path) -> Config:
        """Load a config from a JSON file.

        Parameters
        ----------
        path : str | Path
            Path to the JSON file.

        Returns
        -------
        Config
        """
        data = json.loads(Path(path).read_text(encoding="utf-8"))
        return cls.from_dict(data)


# ---------------------------------------------------------------------------
# Helper utilities (module-private)
# ---------------------------------------------------------------------------

_TRUE_VALUES = {"1", "true", "yes", "on"}


def _env_bool(name: str) -> bool | None:
    """Parse a boolean environment variable.

    Returns ``None`` if the variable is unset so that dataclass defaults are
    preserved.
    """
    raw = os.getenv(name)
    if raw is None:
        return None
    return raw.lower() in _TRUE_VALUES


def _env_int(name: str) -> int | None:
    """Parse an integer environment variable.

    Returns ``None`` if the variable is unset so that dataclass defaults are
    preserved.
    """
    raw = os.getenv(name)
    if raw is None:
        return None
    try:
        return int(raw)
    except ValueError:
        return None
