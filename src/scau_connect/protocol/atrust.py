"""aTrust protocol implementation for SCAU.

Implements the SCAU-specific aTrust SSO handshake based on HAR traffic capture.

Authentication sequence (per HAR real traffic):
1. GET /passport/v1/public/authConfig  -- receive csrf_token + sid cookie
2. Selenium login (CASAuthenticator)     -- obtain CAS ticket via browser
3. GET /passport/v1/auth/cas?ticket=   -- exchange CAS ticket, receive CASTGC cookie
4. GET /passport/v1/auth/authCheck       -- receive sidTicket + updated sid
5. POST /passport/v1/public/ticketExchange -- finalise session
6. GET /passport/v1/user/onlineInfo     -- confirm isOnline=true
7. POST /controller/v1/user/clientResource -- pull resource data (apps, routes, DNS, etc.)
"""

from __future__ import annotations

import asyncio
import json
import uuid
from typing import TYPE_CHECKING

import structlog

from scau_connect.protocol.auth.cas import CASAuthenticator
from scau_connect.protocol.base import AuthenticationError, ProtocolBase, TunnelError
from scau_connect.session import AuthInfo, ClientResource, Session
from scau_connect.utils.http_client import ATrustHTTPClient

logger = structlog.get_logger(__name__)

if TYPE_CHECKING:
    from scau_connect.config import Config


__all__ = ["ATrustProtocol", "AuthenticationError", "TunnelError"]


# Standard request parameters appended to most aTrust API calls.
_API_QUERY = "clientType=SDPBrowserClient&platform=Windows&lang=zh-CN"


class ATrustProtocol(ProtocolBase):
    """SCAU aTrust SSO protocol handler.

    Coordinates the full authentication lifecycle:
    - Selenium-based CAS login
    - Ticket exchange with the aTrust gateway
    - Session polling via onlineInfo
    """

    def __init__(self, config: Config, session: Session | None = None) -> None:
        super().__init__(config, session)
        self._http: ATrustHTTPClient | None = None

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _make_http(self, session: Session | None = None) -> ATrustHTTPClient:
        """Return an ATrustHTTPClient wired to the given (or stored) session."""
        sess = session or self.session
        cookies = sess.cookies if sess else {}
        csrf = sess.csrf_token if sess else ""
        base = f"https://{self.config.server}"
        return ATrustHTTPClient(
            base,
            cookies=cookies,
            csrf_token=csrf,
            skip_ssl_verify=self.config.skip_ssl_verify,
        )

    def _new_trace_id(self) -> str:
        return uuid.uuid4().hex[:8]

    def _build_auth_query(self, extra: str = "") -> str:
        parts = [_API_QUERY]
        if extra:
            parts.append(extra)
        return "&".join(parts)

    # ------------------------------------------------------------------
    # Step 1 - authConfig
    # ------------------------------------------------------------------

    async def _fetch_auth_config(self) -> tuple[AuthInfo, dict]:
        """GET /passport/v1/public/authConfig.

        Returns AuthInfo parsed from response data and the raw response dict.
        Raises AuthenticationError on non-zero code.
        """
        http = self._make_http()
        path = "/passport/v1/public/authConfig?" + self._build_auth_query("needTicket=1")
        resp = await http.request("GET", path)

        data = resp.json()
        code = data.get("code", 0)
        if code != 0:
            raise AuthenticationError(
                f"authConfig failed: code={code} msg={data.get('message', '')}"
            )

        auth_data = data.get("data", {})
        auth_info = AuthInfo.from_dict(auth_data)

        # Extract csrf_token from security section.
        security = auth_data.get("security", {})
        csrf = security.get("csrfToken", "")
        if not csrf:
            csrf = auth_data.get("csrfToken", "")

        return auth_info, data

    # ------------------------------------------------------------------
    # Step 2.5 - authConfig?mod=1 (post-CAS registration)
    # ------------------------------------------------------------------

    async def _fetch_auth_config_mod(
        self, http: ATrustHTTPClient | None = None
    ) -> tuple[AuthInfo, dict]:
        """GET /passport/v1/public/authConfig?mod=1&needTicket=1.

        After CAS login, the portal JS re-fetches authConfig with mod=1 to
        register the CAS session with the gateway and obtain a new csrf_token.
        Uses the provided http client (with cookies already set).
        """
        _http = http if http is not None else self._make_http(self.session)
        path = "/passport/v1/public/authConfig?" + self._build_auth_query("mod=1&needTicket=1")
        resp = await _http.request("GET", path)

        data = resp.json()
        code = data.get("code", 0)
        if code != 0:
            raise AuthenticationError(
                f"authConfig?mod=1 failed: code={code} msg={data.get('message', '')}"
            )

        auth_data = data.get("data", {})
        auth_info = AuthInfo.from_dict(auth_data)

        # Update session cookies from the mod=1 response.
        if self.session is not None:
            for name, val in _http.cookies.items():
                self.session.cookies[name] = val

        return auth_info, data

    # ------------------------------------------------------------------
    # Step 3 - submit CAS ticket to /auth/cas
    # ------------------------------------------------------------------

    async def _submit_cas_ticket(self, ticket: str, http: ATrustHTTPClient) -> dict:
        """GET /passport/v1/auth/cas?ticket=...

        Uses follow_redirects=False to capture the Location header which
        carries the portal ticket.
        """
        path = "/passport/v1/auth/cas?ticket=" + ticket
        resp = await http.request("GET", path, follow_redirects=False)

        location = resp.headers.get("location", "")
        if not location:
            try:
                body = resp.json()
                location = body.get("data", {}).get("redirectUrl", "")
            except Exception:
                pass

        return {"location": location}

    # ------------------------------------------------------------------
    # Step 4 - authCheck
    # ------------------------------------------------------------------

    async def _auth_check(self, http: ATrustHTTPClient) -> tuple[str, dict]:
        """GET /passport/v1/auth/authCheck.

        Returns (sid_ticket, response_body).
        Raises AuthenticationError on failure.
        """
        path = "/passport/v1/auth/authCheck?" + self._build_auth_query()
        resp = await http.request("GET", path)

        data = resp.json()
        code = data.get("code", 0)
        if code != 0:
            raise AuthenticationError(
                f"authCheck failed: code={code} msg={data.get('message', '')}"
            )
        sid_ticket = data.get("data", {}).get("sidTicket", "")
        return sid_ticket, data

    # ------------------------------------------------------------------
    # Step 5 - ticketExchange
    # ------------------------------------------------------------------

    async def _ticket_exchange(
        self, sid_ticket: str, http: ATrustHTTPClient
    ) -> dict:
        """POST /passport/v1/public/ticketExchange.

        Sends sidTicket as form-urlencoded body.
        """
        path = "/passport/v1/public/ticketExchange?" + self._build_auth_query()
        body = "sidTicket=" + sid_ticket
        resp = await http.request(
            "POST", path, content=body.encode(), follow_redirects=False
        )
        try:
            return resp.json()
        except Exception:
            return {}

    # ------------------------------------------------------------------
    # Step 6 - onlineInfo
    # ------------------------------------------------------------------

    async def _online_info(self, http: ATrustHTTPClient) -> dict:
        """GET /passport/v1/user/onlineInfo.

        A successful login shows ``data.isOnline = True``.
        """
        path = "/passport/v1/user/onlineInfo?" + self._build_auth_query()
        resp = await http.request("GET", path)
        return resp.json()

    # ------------------------------------------------------------------
    # Step 7 - clientResource
    # ------------------------------------------------------------------

    async def _client_resource(self, http: ATrustHTTPClient) -> dict:
        """POST /controller/v1/user/clientResource.

        Sends a JSON body requesting appList and resourceType.
        Uses the portal session (online=1 cookie) - NOT the CAS ticket session.
        """
        path = "/controller/v1/user/clientResource?" + self._build_auth_query()
        payload = json.dumps({
            "resourceType": {
                "appList": {},
                "featureCenter": {},
                "sdpPolicy": {},
                "favoriteAppList": {},
                "uemSpace": {
                    "params": {
                        "action": "login",
                    }
                },
            }
        }).encode()
        # Portal session requires referer from the portal page
        headers = {
            "Content-Type": "application/json",
            "Referer": "https://vpn.scau.edu.cn/portal/service_center.html",
        }
        resp = await http.request(
            "POST", path, content=payload, headers=headers
        )
        try:
            return resp.json()
        except Exception:
            return {}

    # ------------------------------------------------------------------
    # Public API - ProtocolBase
    # ------------------------------------------------------------------

    async def authenticate(self) -> Session:
        """Full SCAU aTrust login sequence.

        Exact HAR-verified sequence:
        1. GET /passport/v1/public/authConfig  -- get csrf_token + initial sid
        2. Selenium browser: navigate to casLogin + fill credentials
        3. Browser JS: portal/shortcut.html loads + auto-runs auth chain
        4. GET /passport/v1/public/authConfig?mod=1  -- register CAS login (uses csrf+sid from step 1)
        5. GET /passport/v1/auth/authCheck        -- get sidTicket
        6. POST /passport/v1/public/ticketExchange -- finalise session
        7. GET /passport/v1/user/onlineInfo       -- confirm isOnline=true
        8. POST /controller/v1/user/clientResource -- pull resources
        """
        # Step 1 - authConfig (csrf_token + initial sid cookie).
        auth_info, auth_raw = await self._fetch_auth_config()
        csrf = auth_info.csrf_token

        http = self._make_http()
        session = Session(
            base_url=f"https://{self.config.server}",
            username=self.config.username or "",
            csrf_token=csrf,
            cookies=dict(http.cookies),
            auth_info=auth_info,
            auth_info_raw=auth_raw,
        )

        # Step 2 - Selenium CAS login.
        # The browser completes the full SSO chain, including the portal page JS
        # that drives authConfig?mod=1, authCheck, and ticketExchange. At this
        # point the browser cookie jar should already be in the online=1 state.
        cas_auth = CASAuthenticator(self.config)
        cas_session = await cas_auth.login()

        # Merge browser cookies (sid, sid.sig, CASTGC, online, etc.).
        http.update_cookies_from_dict(cas_session.cookies)
        for name, val in cas_session.cookies.items():
            session.cookies[name] = val

        # Step 3 - onlineInfo: verify the browser-established session directly.
        # Retry briefly: the browser has just performed CAS login + portal handshake
        # and the gateway may take a second to register the session as online.
        online_data: dict = {}
        for _attempt in range(5):
            online_data = await self._online_info(http)
            online_code = online_data.get("code", 0)
            if online_code == 0:
                break
            await asyncio.sleep(1.0)
        else:
            online_code = online_data.get("code", 0)
        if online_code == 0:
            session.is_online = True
            session.display_name = online_data.get("data", {}).get("displayName", "")
            session.client_ip = online_data.get("data", {}).get("clientIp", "")
            session.extra["online_data"] = online_data
        elif online_code == 1000101:
            raise AuthenticationError(
                f"Session expired: {online_data.get('message', 're-login required')}"
            )
        else:
            raise AuthenticationError(
                f"onlineInfo failed: code={online_code} msg={online_data.get('message', '')}"
            )

        # Step 8 - clientResource.
        # The controller/v1/user/clientResource API requires:
        # - Full browser cookies (sid, online, etc.) with proper domain scoping
        # - Fresh csrf_token from authConfig?mod=1 (after CAS login)
        from scau_connect.utils.http_client import ATrustHTTPClient

        # Fetch fresh csrf_token via authConfig?mod=1
        auth_info2, _ = await self._fetch_auth_config_mod(http)
        fresh_csrf = auth_info2.csrf_token

        # Build a new HTTP client with full browser cookies
        # (sid, online, sdp_user_token, etc.) + fresh csrf
        portal_cookies = {k: v for k, v in session.cookies.items()
                        if k not in ("CASTGC_-_vpn.scau.edu.cn",
                                     "session_-_vpn.scau.edu.cn",
                                     "locale_-_vpn.scau.edu.cn")}
        portal_http = ATrustHTTPClient(
            f"https://{self.config.server}",
            cookies=portal_cookies,
            csrf_token=fresh_csrf,
            skip_ssl_verify=self.config.skip_ssl_verify,
        )

        resource_data = await self._client_resource(portal_http)
        session.extra["resource_data"] = resource_data

        app_data = (
            resource_data.get("data", {})
            .get("appList", {})
            .get("data", {})
            .get("appInfo", [])
        )
        session.extra["app_list"] = app_data

        client_ip = online_data.get("data", {}).get("clientIp", "")
        resource = ClientResource(
            ip=client_ip,
            dns=[],
            gateway="",
            routes=[],
            mtu=1500,
            raw=resource_data,
        )
        session.extra["client_resource"] = resource

        self.session = session
        await cas_auth.logout(session)
        return session

    async def establish_tunnel(self, session: Session) -> None:
        """Establish L3 tunnel (Phase 2)."""
        raise NotImplementedError(
            "establish_tunnel() is Phase 2 (L3 tunnel). "
            "Web proxy mode is available now via ATrustHTTPClient."
        )

    async def refresh_session(self, session: Session) -> Session:
        """Refresh the tunnel session with a complete new browser-based authentication.

        The aTrust node requires ``online=1`` AND a freshly issued ``sid``.
        A simple CAS re-login (which only returns ``sid`` without ``online=1``) is
        insufficient.  This method calls ``authenticate()`` — the full browser flow
        including ``portal/shortcut.html`` — to obtain a session with ``CASTGC``,
        ``sid``, and ``online=1`` all set.  The new session's cookies are merged
        into the live session, preserving non-authentication state.

        Requires ``config.username`` and ``config.password`` to be set.

        Raises
        ------
        AuthenticationError
            If ``CASTGC`` is missing or the browser auth fails.
        """
        if not self.config.username or not self.config.password:
            raise AuthenticationError(
                "refresh_session requires config.username and config.password. "
                "Start the CLI with --username/--password (or set SCAU_USERNAME/SCAU_PASSWORD) "
                "to enable tunnel SID refresh."
            )

        logger.debug("tcp_tunnel_full_reauth")

        # Full authenticate() runs the complete browser flow (CAS login + shortcut.html),
        # giving us CASTGC + sid + online=1 in one shot.
        new_session = await self.authenticate()

        new_sid = new_session.cookies.get("sid", "")
        new_online = new_session.is_online
        if not new_sid:
            raise AuthenticationError(
                "refresh_session: authenticate() returned no sid cookie. "
                "The browser session may have expired — a full re-login is required."
            )

        # Merge: update the live session with freshly authenticated cookies,
        # preserving any non-auth state (e.g. username, extra fields).
        session.cookies.clear()
        session.cookies.update(new_session.cookies)
        session.csrf_token = new_session.csrf_token
        session.is_online = new_online
        session.client_ip = new_session.client_ip

        logger.info(
            "tcp_tunnel_session_refreshed",
            new_sid=new_sid[:30],
            online=new_online,
        )
        return session

    async def close(self) -> None:
        """Close HTTP client."""
        if self._http:
            await self._http.close()
        self.session = None
        self._http = None
