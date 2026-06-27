"""SOCKS5 proxy server (RFC 1928) — EXPERIMENTAL.

⚠️ The aTrust web proxy only speaks HTTP, not raw TCP. This SOCKS5 server
therefore only supports HTTP traffic to port 80: it reads the first HTTP
request from the client, rewrites the ``Host`` header to the aTrust
``<host>-s.vpn.scau.edu.cn`` alias, injects the session cookies, and forwards
to the proxy. HTTPS / non-HTTP / port-≠-80 traffic cannot work through this
implementation.

Clients connect and issue CONNECT commands. The proxy dials through the
WebProxyDialer which connects to the aTrust web-proxy domain.
"""

from __future__ import annotations

import asyncio
import socket
import struct
from typing import TYPE_CHECKING

import structlog

from scau_connect.proxy.base import ProxyBase
from scau_connect.proxy.web_proxy_dialer import WebProxyDialer, _atrust_proxy_host

if TYPE_CHECKING:
    from scau_connect.protocol.tunnel.dialer import Dialer

logger = structlog.get_logger(__name__)

SOCKS5_VER = 0x05
AUTH_NONE = 0x00
AUTH_GSSAPI = 0x01
AUTH_PASSWORD = 0x02
AUTH_NO_ACCEPTABLE = 0xFF
CMD_CONNECT = 0x01
CMD_BIND = 0x02
CMD_UDP_ASSOCIATE = 0x03
ATYP_IPV4 = 0x01
ATYP_DOMAIN = 0x03
ATYP_IPV6 = 0x04
REP_SUCCESS = 0x00
REP_GENERAL_FAILURE = 0x01
REP_COMMAND_NOT_SUPPORTED = 0x07
REP_ADDRESS_TYPE_NOT_SUPPORTED = 0x08


class Socks5Proxy(ProxyBase):
    def __init__(
        self,
        dialer: WebProxyDialer,
        listen_host: str = "0.0.0.0",
        listen_port: int = 1080,
        *,
        username: str | None = None,
        password: str | None = None,
    ) -> None:
        super().__init__(dialer, listen_host, listen_port)
        self.username = username
        self.password = password
        self._server: asyncio.Server | None = None

    async def start(self) -> None:
        self._server = await asyncio.start_server(self._handle_client, self.listen_host, self.listen_port)
        host, port = self._server.sockets[0].getsockname()
        logger.info("socks5_proxy_started", host=host, port=port)

    async def stop(self) -> None:
        if self._server:
            self._server.close()
            await self._server.wait_closed()
            self._server = None
            logger.info("socks5_proxy_stopped")

    @property
    def is_running(self) -> bool:
        return self._server is not None

    async def _handle_client(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        try:
            greeting = await reader.read(2)
            if len(greeting) < 2:
                return
            ver, nmethods = struct.unpack("!BB", greeting)
            if ver != SOCKS5_VER:
                return
            methods = await reader.read(nmethods)
            method = self._select_auth_method(methods)
            writer.write(struct.pack("!BB", SOCKS5_VER, method))
            await writer.drain()
            if method == AUTH_NO_ACCEPTABLE:
                return
            if method == AUTH_PASSWORD and not await self._auth_password(reader, writer):
                return

            request = await reader.read(4)
            if len(request) < 4:
                return
            ver, cmd, _, atyp = struct.unpack("!BBBB", request)
            if cmd != CMD_CONNECT:
                await self._send_reply(writer, REP_COMMAND_NOT_SUPPORTED, atyp)
                return

            if atyp == ATYP_IPV4:
                host = socket.inet_ntoa(await reader.read(4))
            elif atyp == ATYP_DOMAIN:
                domain_len = struct.unpack("!B", await reader.read(1))[0]
                host = (await reader.read(domain_len)).decode()
            elif atyp == ATYP_IPV6:
                host = socket.inet_ntop(socket.AF_INET6, await reader.read(16))
            else:
                await self._send_reply(writer, REP_ADDRESS_TYPE_NOT_SUPPORTED, atyp)
                return
            port = struct.unpack("!H", await reader.read(2))[0]

            logger.debug("socks5_connect", host=host, port=port)
            upstream_reader, upstream_writer = await self.dialer.dial(host, port)
            await self._send_reply(writer, REP_SUCCESS, ATYP_IPV4)
            writer.write(struct.pack("!I", 0) + struct.pack("!H", 0))
            await writer.drain()

            # Read first client request, rewrite Host/Cookie for aTrust proxy, send upstream.
            first_req = await reader.read(65536)
            if first_req:
                proxy_host = _atrust_proxy_host(host)
                req = first_req.decode("utf-8", errors="replace")
                # Replace Host header with proxy host and inject cookies.
                lines = req.split("\r\n")
                out = []
                has_host = False
                for line in lines:
                    if line.lower().startswith("host:"):
                        out.append(f"Host: {proxy_host}")
                        has_host = True
                    elif line:
                        out.append(line)
                if not has_host:
                    out.insert(1, f"Host: {proxy_host}")
                out.insert(2, f"Cookie: {self.dialer.cookie_header}")
                rewritten = "\r\n".join(out).encode() + b"\r\n\r\n"
                upstream_writer.write(rewritten)
                await upstream_writer.drain()

            await asyncio.gather(
                self._pipe(reader, upstream_writer),
                self._pipe(upstream_reader, writer),
            )
        except Exception as exc:
            logger.debug("socks5_client_error", error=str(exc))

    def _select_auth_method(self, methods: bytes) -> int:
        method_list = list(methods)
        if AUTH_PASSWORD in method_list and self.username and self.password:
            return AUTH_PASSWORD
        if AUTH_NONE in method_list:
            return AUTH_NONE
        return AUTH_NO_ACCEPTABLE

    async def _auth_password(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> bool:
        try:
            ulen = struct.unpack("!B", await reader.read(1))[0]
            username = (await reader.read(ulen)).decode(errors="replace")
            plen = struct.unpack("!B", await reader.read(1))[0]
            password = (await reader.read(plen)).decode(errors="replace")
            ok = username == (self.username or "") and password == (self.password or "")
            writer.write(struct.pack("!BB", SOCKS5_VER, 0x00 if ok else 0x01))
            await writer.drain()
            return ok
        except Exception:
            return False

    async def _send_reply(self, writer: asyncio.StreamWriter, rep: int, atyp: int) -> None:
        writer.write(struct.pack("!BBBB", SOCKS5_VER, rep, 0x00, atyp))
        await writer.drain()

    @staticmethod
    async def _pipe(reader, writer) -> None:
        try:
            while True:
                chunk = await reader.read(65536)
                if not chunk:
                    break
                writer.write(chunk)
                await writer.drain()
        except Exception:
            pass
