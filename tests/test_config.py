"""Tests for :mod:`scau_connect.config`.

These run as plain pytest functions (no async). Environment variables are
patched via :class:`monkeypatch` so the global environment is never mutated.
"""

from __future__ import annotations

import os

from scau_connect.config import Config


# ---------------------------------------------------------------------------
# Defaults
# ---------------------------------------------------------------------------

def test_defaults_server_port_protocol() -> None:
    cfg = Config()
    assert cfg.server == "vpn.scau.edu.cn"
    assert cfg.port == 443
    assert cfg.protocol == "atrust"


def test_defaults_auth() -> None:
    cfg = Config()
    assert cfg.auth_type == "cas"
    assert cfg.login_domain == "CAS"
    assert cfg.username is None
    assert cfg.password is None


def test_defaults_proxy() -> None:
    cfg = Config()
    assert cfg.http_proxy_port == 1081
    assert cfg.socks5_proxy_port == 1080
    assert cfg.enable_http_proxy is True
    assert cfg.enable_socks5_proxy is True


def test_defaults_session_and_flags() -> None:
    cfg = Config()
    assert cfg.session_file == ".session.json"
    assert cfg.auto_reconnect is True
    assert cfg.debug is False
    assert cfg.skip_ssl_verify is True
    assert cfg.headless_browser is True
    assert cfg.browser == "chrome"


# ---------------------------------------------------------------------------
# from_env
# ---------------------------------------------------------------------------

def test_from_env_full(monkeypatch: object) -> None:
    mp = monkeypatch  # type: ignore[assignment]
    env = {
        "SCAU_SERVER": "example.scau.edu.cn",
        "SCAU_PORT": "8443",
        "SCAU_USERNAME": "student001",
        "SCAU_PASSWORD": "s3cret",
        "SCAU_HTTP_PROXY_PORT": "2081",
        "SCAU_SOCKS5_PROXY_PORT": "2080",
        "SCAU_DEBUG": "1",
        "SCAU_SKIP_SSL_VERIFY": "false",
        "SCAU_HEADLESS_BROWSER": "0",
        "SCAU_AUTO_RECONNECT": "false",
        "SCAU_BROWSER": "firefox",
        "SCAU_AUTH_TYPE": "ldap",
        "SCAU_LOGIN_DOMAIN": "LDAP",
    }
    for k in list(os.environ.keys()):
        if k.startswith("SCAU_"):
            mp.delenv(k, raising=False)
    for k, v in env.items():
        mp.setenv(k, v)

    cfg = Config.from_env()
    assert cfg.server == "example.scau.edu.cn"
    assert cfg.port == 8443
    assert cfg.username == "student001"
    assert cfg.password == "s3cret"
    assert cfg.http_proxy_port == 2081
    assert cfg.socks5_proxy_port == 2080
    assert cfg.debug is True
    assert cfg.skip_ssl_verify is False
    assert cfg.headless_browser is False
    assert cfg.auto_reconnect is False
    assert cfg.browser == "firefox"
    assert cfg.auth_type == "ldap"
    assert cfg.login_domain == "LDAP"


def test_from_env_empty_falls_back_to_defaults(monkeypatch: object) -> None:
    mp = monkeypatch  # type: ignore[assignment]
    for k in list(os.environ.keys()):
        if k.startswith("SCAU_"):
            mp.delenv(k, raising=False)

    cfg = Config.from_env()
    assert cfg.server == "vpn.scau.edu.cn"
    assert cfg.username is None
    assert cfg.debug is False
    assert cfg.port == 443


def test_from_env_bool_truthy_variants(monkeypatch: object) -> None:
    mp = monkeypatch  # type: ignore[assignment]
    for k in list(os.environ.keys()):
        if k.startswith("SCAU_"):
            mp.delenv(k, raising=False)
    for v in ("1", "true", "True", "YES", "on"):
        mp.setenv("SCAU_DEBUG", v)
        assert Config.from_env().debug is True, f"value {v!r} should be truthy"
    for v in ("0", "false", "no", "off", ""):
        mp.setenv("SCAU_DEBUG", v)
        assert Config.from_env().debug is False, f"value {v!r} should be falsy"


def test_from_env_invalid_int_falls_back_to_default(monkeypatch: object) -> None:
    mp = monkeypatch  # type: ignore[assignment]
    for k in list(os.environ.keys()):
        if k.startswith("SCAU_"):
            mp.delenv(k, raising=False)
    mp.setenv("SCAU_PORT", "not-a-number")
    cfg = Config.from_env()
    assert cfg.port == 443  # default preserved


# ---------------------------------------------------------------------------
# (de)serialisation
# ---------------------------------------------------------------------------

def test_to_dict_from_dict_roundtrip() -> None:
    cfg = Config(server="vpn.example.cn", username="u", http_proxy_port=2000)
    d = cfg.to_dict()
    assert d["server"] == "vpn.example.cn"
    assert d["username"] == "u"
    assert d["http_proxy_port"] == 2000
    cfg2 = Config.from_dict(d)
    assert cfg2.server == "vpn.example.cn"
    assert cfg2.username == "u"
    assert cfg2.http_proxy_port == 2000


def test_from_dict_ignores_unknown_keys() -> None:
    cfg = Config.from_dict({"server": "x", "unknown_field": 123})
    assert cfg.server == "x"
