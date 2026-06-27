"""Background session keep-alive and auto-reconnect for the local proxy.

The aTrust web-proxy session expires after some minutes of inactivity.  When it
does, every proxied request gets a 302 redirect to the aTrust portal instead of
the real upstream content (which manifests to clients as a 502).

This module runs a background task that:

1. Periodically calls ``/passport/v1/user/onlineInfo`` to keep the session warm
   and detect expiry.
2. When the session is reported expired (code ``1000101``) or the call fails,
   triggers a full re-authentication using the stored ``Config`` credentials and
   pushes the refreshed cookies into the :class:`WebProxyDialer`.

Usage::

    manager = SessionManager(config, session, dialer)
    await manager.start()      # starts the keep-alive loop
    ...
    await manager.stop()       # cancels the loop
"""

from __future__ import annotations

import asyncio
from typing import TYPE_CHECKING

import structlog

from scau_connect.protocol.atrust import ATrustProtocol, AuthenticationError

if TYPE_CHECKING:
    from scau_connect.config import Config
    from scau_connect.proxy.web_proxy_dialer import WebProxyDialer
    from scau_connect.session import Session

logger = structlog.get_logger(__name__)

# How often to ping onlineInfo to keep the session alive.
# aTrust sessions are observed to expire within a couple of minutes of total
# inactivity, so a sub-minute interval is safe and cheap (one GET per tick).
_KEEPALIVE_INTERVAL_SECONDS = 45  # seconds


class SessionManager:
    """Keeps an aTrust session warm and re-authenticates on expiry.

    Parameters
    ----------
    config : Config
        Configuration (server, username, password, ...). Used for re-auth.
    session : Session
        The current authenticated session. Updated in place on refresh.
    dialer : WebProxyDialer
        The dialer whose cookies must be kept in sync.
    keepalive_interval : float
        Seconds between onlineInfo pings.
    """

    def __init__(
        self,
        config: Config,
        session: Session,
        dialer: WebProxyDialer,
        *,
        keepalive_interval: float = _KEEPALIVE_INTERVAL_SECONDS,
    ) -> None:
        self._config = config
        self._session = session
        self._dialer = dialer
        self._keepalive_interval = keepalive_interval
        self._task: asyncio.Task | None = None
        self._stop = asyncio.Event()

    async def start(self) -> None:
        if self._task is not None:
            return
        self._stop.clear()
        # Send an immediate keep-alive ping so the session is confirmed alive
        # (and any refreshed cookies are picked up) before we serve traffic.
        try:
            alive = await self._check_alive()
            logger.info("session_manager_initial_check", alive=alive)
            if not alive:
                logger.warning("session_expired_at_startup_reauthenticating")
                await self._reauthenticate()
        except Exception as exc:
            logger.warning("session_manager_initial_check_error", error=str(exc))
        self._task = asyncio.create_task(self._run(), name="session-keepalive")
        logger.info("session_manager_started", interval=self._keepalive_interval)

    async def stop(self) -> None:
        self._stop.set()
        if self._task is not None:
            self._task.cancel()
            try:
                await self._task
            except (asyncio.CancelledError, Exception):
                pass
            self._task = None
        logger.info("session_manager_stopped")

    async def _run(self) -> None:
        """Main keep-alive loop."""
        while not self._stop.is_set():
            try:
                await asyncio.wait_for(
                    self._stop.wait(), timeout=self._keepalive_interval
                )
                return  # stop signalled
            except asyncio.TimeoutError:
                pass  # interval elapsed, run a keep-alive tick

            try:
                alive = await self._check_alive()
                if alive:
                    logger.debug("session_keepalive_ok")
                else:
                    logger.warning("session_expired_reauthenticating")
                    await self._reauthenticate()
            except Exception as exc:
                logger.warning("session_keepalive_error", error=str(exc))

    async def _check_alive(self) -> bool:
        """Ping onlineInfo; return True if the session is still online."""
        protocol = ATrustProtocol(self._config, session=self._session)
        http = protocol._make_http(self._session)
        try:
            data = await http.request(
                "GET",
                "/passport/v1/user/onlineInfo?clientType=SDPBrowserClient&platform=Windows&lang=zh-CN",
            )
            payload = data.json()
            code = payload.get("code", 0)
            if code == 0:
                # Refresh display/ip and any cookie updates from the response.
                online = payload.get("data", {})
                self._session.is_online = bool(online.get("isOnline", True))
                self._session.display_name = online.get("displayName", self._session.display_name)
                self._session.client_ip = online.get("clientIp", self._session.client_ip)
                # Merge any new cookies set by the server.
                if http.cookies:
                    changed = False
                    for name, val in http.cookies.items():
                        if self._session.cookies.get(name) != val:
                            self._session.cookies[name] = val
                            changed = True
                    if changed:
                        self._dialer.update_cookies(self._session.cookies)
                return True
            # code 1000101 == session expired
            return False
        finally:
            await http.close()

    async def _reauthenticate(self) -> bool:
        """Full re-authentication. Updates session + dialer cookies. Returns success."""
        protocol = ATrustProtocol(self._config)
        try:
            new_session = await protocol.authenticate()
            # Copy refreshed state into the live session object.
            self._session.cookies.clear()
            self._session.cookies.update(new_session.cookies)
            self._session.csrf_token = new_session.csrf_token
            self._session.is_online = new_session.is_online
            self._session.client_ip = new_session.client_ip
            self._session.display_name = new_session.display_name
            # Push to dialer and persist.
            self._dialer.update_cookies(self._session.cookies)
            try:
                self._session.save(self._config.session_file)
            except Exception as exc:
                logger.warning("session_save_failed", error=str(exc))
            logger.info(
                "session_reauthenticated",
                username=self._session.username,
            )
            return True
        except (AuthenticationError, Exception) as exc:
            logger.error("session_reauth_failed", error=str(exc))
            return False
        finally:
            await protocol.close()
