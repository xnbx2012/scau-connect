"""Authenticated session state for aTrust.

Holds all material obtained during a successful CAS login and the subsequent
aTrust handshake. Instances can be serialised to / from JSON so that the session
is persisted across program invocations.
"""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass, field
from typing import Any

__all__ = ["Session", "AuthInfo", "ClientResource"]


# ---------------------------------------------------------------------------
# Supporting data classes
# ---------------------------------------------------------------------------


@dataclass
class AuthInfo:
    """Static authentication configuration from the aTrust server.

    Extracted from the ``authConfig`` response body (``data`` → firstAuth,
    defaultDomain, domains, authServerInfoList, pubKey, etc.).
    """

    first_auth: list[str] = field(default_factory=list)
    default_domain: str = ""
    domains: list[str] = field(default_factory=list)
    auth_server_info_list: list[dict[str, Any]] = field(default_factory=list)
    pub_key: str = ""
    pub_key_exp: str = ""
    csrf_token: str = ""
    guid: str = ""
    anti_replay_rand: str = ""
    client_verify_code: str = ""
    portal_protocol_key: str = ""
    raw: dict[str, Any] = field(default_factory=dict)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> AuthInfo:
        security = data.get("security", {})
        return cls(
            first_auth=data.get("firstAuth", []),
            default_domain=data.get("defaultDomain", ""),
            domains=data.get("domains", []),
            auth_server_info_list=data.get("authServerInfoList", []),
            pub_key=data.get("pubKey", ""),
            pub_key_exp=data.get("pubKeyExp", ""),
            csrf_token=security.get("csrfToken", ""),
            guid=data.get("guid", ""),
            anti_replay_rand=data.get("antiReplayRand", ""),
            client_verify_code=data.get("clientVerifyCode", ""),
            portal_protocol_key=data.get("portalProtocolKey", ""),
            raw=data,
        )


@dataclass
class ClientResource:
    """Network resource data returned after a successful login.

    Includes the assigned virtual IP address, DNS servers, gateway, and routing
    information used to configure the L3 tunnel.
    """

    ip: str = ""
    dns: list[str] = field(default_factory=list)
    gateway: str = ""
    routes: list[str] = field(default_factory=list)
    mtu: int = 1500
    raw: dict[str, Any] = field(default_factory=dict)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> ClientResource:
        # The actual resource structure is inside "resourceType" in the response.
        raise NotImplementedError("ClientResource.from_dict() 待解析 clientResource 响应后实现。")

    def to_dict(self) -> dict[str, Any]:
        return {
            "ip": self.ip,
            "dns": self.dns,
            "gateway": self.gateway,
            "routes": self.routes,
            "mtu": self.mtu,
            "raw": self.raw,
        }


# ---------------------------------------------------------------------------
# Main session class
# ---------------------------------------------------------------------------


@dataclass
class Session:
    """Complete authenticated aTrust session.

    Attributes
    ----------
    base_url : str
        aTrust gateway base URL, e.g. ``https://vpn.scau.edu.cn``.
    username : str | None
        Authenticated account (e.g. student ID).
    display_name : str | None
        Display name returned by ``onlineInfo``.
    rid : str | None
        aTrust session/realm identifier (from authConfig or cookies).
    csrf_token : str
        ``x-csrf-token`` value extracted from ``authConfig`` → ``data.security.csrfToken``.
    cookies : dict[str, str]
        All cookies captured from the browser and subsequent API calls.
        Key cookies include ``sid``, ``sid.sig``, ``sid-legacy``, ``sid-legacy.sig``,
        ``CASTGC``, ``session``, ``online``.
    auth_info : AuthInfo | None
        Full ``authConfig`` response (includes RSA pubKey for password encryption).
    is_online : bool
        ``True`` once ``onlineInfo`` has confirmed the session is active.
    client_ip : str | None
        Source IP assigned by the VPN (from ``onlineInfo``).
    auth_info_raw : dict[str, Any]
        Unstructured storage for any additional fields discovered later.

    Notes
    -----
    **Cookie lifecycle:**

    * ``sid`` / ``sid.sig`` / ``sid-legacy`` / ``sid-legacy.sig`` are refreshed by
      every request to ``authConfig`` and ``authCheck``.
    * ``CASTGC`` is set by the ``/passport/v1/auth/cas`` callback after the CAS
      login.
    * ``online`` transitions from ``0`` → ``1`` after a successful ``ticketExchange``.

    The session file (default ``.session.json``) stores these cookies in plain text.
    **Encryption at rest is not yet implemented** — keep the file permissions tight.
    """

    # --- Identity ---
    base_url: str = "https://vpn.scau.edu.cn"
    username: str | None = None
    display_name: str | None = None

    # --- CSRF / tokens ---
    rid: str | None = None
    csrf_token: str = ""

    # --- Cookie jar ---
    cookies: dict[str, str] = field(default_factory=dict)

    # --- Auth configuration (from authConfig) ---
    auth_info: AuthInfo | None = None
    pub_key: str = ""
    pub_key_exp: str = ""

    # --- Session state ---
    is_online: bool = False
    client_ip: str | None = None
    auth_info_raw: dict[str, Any] = field(default_factory=dict)

    # --- Extra / unknown fields ---
    extra: dict[str, Any] = field(default_factory=dict)

    # ------------------------------------------------------------------
    # Serialisation
    # ------------------------------------------------------------------

    def to_dict(self) -> dict[str, Any]:
        """Return a JSON-serialisable dict representation of this session.

        ``auth_info`` objects are flattened into top-level keys.
        ``extra`` values with a ``to_dict()`` method are serialised first.
        """
        extra_serializable = {}
        for k, v in self.extra.items():
            if hasattr(v, "to_dict"):
                extra_serializable[k] = v.to_dict()
            else:
                extra_serializable[k] = v
        result = {
            "base_url": self.base_url,
            "username": self.username,
            "display_name": self.display_name,
            "rid": self.rid,
            "csrf_token": self.csrf_token,
            "cookies": self.cookies,
            "pub_key": self.pub_key,
            "pub_key_exp": self.pub_key_exp,
            "is_online": self.is_online,
            "client_ip": self.client_ip,
            "auth_info_raw": self.auth_info_raw,
            "extra": extra_serializable,
        }
        return result

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "Session":
        """Reconstruct a :class:`Session` from a plain dict (e.g. loaded from JSON)."""
        auth_info_raw = data.pop("auth_info_raw", {})
        auth_info = AuthInfo.from_dict(auth_info_raw) if auth_info_raw else None
        extra = data.pop("extra", {})
        return cls(
            auth_info=auth_info,
            auth_info_raw=auth_info_raw,
            extra=extra,
            **{
                k: v
                for k, v in data.items()
                if k
                not in {
                    "auth_info",
                    "auth_info_raw",
                    "extra",
                }
            },
        )

    def save(self, path: str | None = None) -> None:
        """Persist the session to a JSON file.

        Parameters
        ----------
        path : str | None
            File path. If ``None``, defaults to ``.session.json`` in the cwd.
        """
        target = path or ".session.json"
        with open(target, "w", encoding="utf-8") as fh:
            json.dump(self.to_dict(), fh, indent=2, ensure_ascii=False)

    @classmethod
    def load(cls, path: str) -> "Session":
        """Load a session from a JSON file.

        Parameters
        ----------
        path : str
            Path to the JSON file.

        Returns
        -------
        Session
        """
        with open(path, encoding="utf-8") as fh:
            return cls.from_dict(json.load(fh))

    # ------------------------------------------------------------------
    # Validity predicate
    # ------------------------------------------------------------------

    def is_valid(self) -> bool:
        """Return ``True`` if this session has enough state to attempt a reconnect.

        A session is considered valid when:
        * ``csrf_token`` is non-empty.
        * ``sid`` cookie is present.
        * ``CASTGC`` cookie is present.
        """
        return bool(
            self.csrf_token
            and self.cookies.get("sid")
            and self.cookies.get("CASTGC")
        )

    # ------------------------------------------------------------------
    # Cookie helpers
    # ------------------------------------------------------------------

    def set_cookie(self, name: str, value: str) -> None:
        """Set a single cookie in the jar."""
        self.cookies[name] = value

    def get_cookie(self, name: str) -> str | None:
        """Return the value of a cookie, or ``None``."""
        return self.cookies.get(name)

    def sid_ticket(self) -> str | None:
        """Return the current ``sid`` value (used as a ticket identifier).

        This is the opaque session token returned by the server in the ``sid``
        cookie after the first ``authConfig`` call.
        """
        return self.cookies.get("sid")

    def sid_legacy(self) -> str | None:
        """Return the legacy ``sid-legacy`` value, if present."""
        return self.cookies.get("sid-legacy")
