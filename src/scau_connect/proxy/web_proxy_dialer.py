"""Web-proxy dialer for Phase 1 (no L3 tunnel required).

The aTrust web proxy is a transparent reverse proxy accessed via HTTPS:
- Connect to  ``{host-replaced-dots}-s.vpn.scau.edu.cn:443``  (TLS)
- Send HTTP/1.1 request with  ``Host: {host-replaced-dots}-s.vpn.scau.edu.cn``
- Cookie headers carry the aTrust session cookies
- The proxy transparently forwards the request to the real target host
"""

from __future__ import annotations

import asyncio
import socket
import ssl
from typing import TYPE_CHECKING

import structlog

from scau_connect.protocol.tunnel.dialer import Dialer, DialerError

if TYPE_CHECKING:
    from scau_connect.session import Session

logger = structlog.get_logger(__name__)

_PROXY_PORT = 443


def _atrust_proxy_host(host: str) -> str:
    """Map a real hostname to its aTrust web-proxy alias.

    e.g.  ``www.baidu.com`` -> ``www-baidu-com-s.vpn.scau.edu.cn``
    """
    safe = host.replace(".", "-")
    return f"{safe}-s.vpn.scau.edu.cn"


class _ProxyWriter:
    """StreamWriter that injects Cookie header into the first HTTP request sent."""

    def __init__(self, sock: ssl.SSLSocket, cookie_header: str) -> None:
        self._sock = sock
        self._cookie_header = cookie_header
        self._closed = False

    def write(self, data: bytes) -> None:
        if self._closed:
            return
        if not self._cookie_header:
            self._sendall(data)
            return

        self._sendall(data)

    def _sendall(self, data: bytes) -> None:
        try:
            self._sock.sendall(data)
        except OSError:
            self._closed = True

    async def drain(self) -> None:
        pass

    def close(self) -> None:
        self._closed = True
        try:
            self._sock.close()
        except OSError:
            pass

    async def wait_closed(self) -> None:
        pass

    def get_extra_info(self, name: str, default=None):
        if name == "peername":
            try:
                return self._sock.getpeername()
            except OSError:
                return default
        return default


class _ProxyReader:
    """StreamReader over a raw SSL socket."""

    def __init__(self, sock: ssl.SSLSocket, loop: asyncio.AbstractEventLoop) -> None:
        self._sock = sock
        self._loop = loop

    async def read(self, n: int = 65536) -> bytes:
        try:
            return await self._loop.run_in_executor(None, self._sock.recv, n)
        except OSError:
            return b""

    async def readline(self) -> bytes:
        return await self._loop.run_in_executor(None, self._readline_sync)

    def _readline_sync(self) -> bytes:
        buf = b""
        while True:
            try:
                ch = self._sock.recv(1)
                if not ch:
                    return buf
                buf += ch
                if ch == b"\n":
                    return buf
            except OSError:
                return buf


class WebProxyDialer(Dialer):
    """Dialer that routes TCP connections through the aTrust web proxy.

    For a target ``(host, port)`` it connects to
    ``{host-replaced-dots}-s.vpn.scau.edu.cn:443`` over TLS and sends the
    raw HTTP request. The Cookie header must be included in the request by
    the caller (it is NOT auto-injected).

    Usage::

        dialer = WebProxyDialer(session)
        reader, writer = await dialer.dial("www.baidu.com", 80)
        # The Cookie header must be set by the caller.
        writer.write(b"GET / HTTP/1.1\\r\\nHost: www-baidu-com-s.vpn.scau.edu.cn\\r\\nCookie: ...\\r\\n\\r\\n")
    """

    def __init__(self, session: Session) -> None:
        self._session = session
        self._cookies = "; ".join(
            f"{name}={value}" for name, value in session.cookies.items()
        )
        self._closed = False
        self._loop: asyncio.AbstractEventLoop | None = None
        self._conns: dict[tuple[str, int], tuple[_ProxyReader, _ProxyWriter]] = {}

    @property
    def cookie_header(self) -> str:
        """The full Cookie header value for this session."""
        return self._cookies

    def update_cookies(self, cookies: dict[str, str]) -> None:
        """Replace the cookie header (e.g. after a session refresh / re-auth)."""
        self._cookies = "; ".join(f"{name}={value}" for name, value in cookies.items())
        # Invalidate cached connections since they may carry stale cookies.
        for _reader, writer in self._conns.values():
            writer.close()
        self._conns.clear()
        logger.debug("web_proxy_dialer_cookies_updated", cookies=len(cookies))

    async def dial(
        self, host: str, port: int
    ) -> tuple[_ProxyReader, _ProxyWriter]:
        if self._closed:
            raise DialerError("WebProxyDialer is closed")

        if self._loop is None:
            self._loop = asyncio.get_running_loop()

        key = (host, port)
        if key in self._conns:
            cached = self._conns[key]
            if not cached[1]._closed:
                logger.debug("proxy_dial_cache_hit", host=host, port=port)
                return cached
            del self._conns[key]

        proxy_host = _atrust_proxy_host(host)
        logger.debug(
            "proxy_dial_connecting",
            host=host, port=port, proxy_host=proxy_host,
        )

        ssl_ctx = ssl.create_default_context()
        ssl_ctx.check_hostname = False
        ssl_ctx.verify_mode = ssl.CERT_NONE

        try:
            sock: ssl.SSLSocket = await asyncio.wait_for(
                self._loop.run_in_executor(
                    None, self._connect_raw, proxy_host, ssl_ctx
                ),
                timeout=15,
            )
        except (OSError, ssl.SSLError) as exc:
            raise DialerError(
                f"Failed to connect to proxy {proxy_host}:{_PROXY_PORT}: {exc}"
            ) from exc

        reader = _ProxyReader(sock, self._loop)
        writer = _ProxyWriter(sock, self._cookies)
        self._conns[key] = (reader, writer)
        logger.debug(
            "proxy_dial_connected",
            host=host, port=port, proxy_host=proxy_host,
        )
        return reader, writer

    @staticmethod
    def _connect_raw(proxy_host: str, ssl_ctx: ssl.SSLContext) -> ssl.SSLSocket:
        raw = socket.create_connection((proxy_host, _PROXY_PORT), timeout=10)
        return ssl_ctx.wrap_socket(raw, server_hostname=proxy_host)

    async def close(self) -> None:
        self._closed = True
        for _reader, writer in self._conns.values():
            writer.close()
        self._conns.clear()
        logger.info("web_proxy_dialer_closed")
