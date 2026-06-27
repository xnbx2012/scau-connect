"""HTTP/HTTPS CONNECT proxy server.

Clients connect to this local port and issue HTTP requests. The server
forwards traffic through the authenticated aTrust session via the aTrust web
proxy.  HTTPS CONNECT is handled by local TLS termination (MITM) so tools like
``curl --proxy http://<proxy-host>:1081 -k https://scau.edu.cn`` can work without a
separate aTrust desktop client.
"""

from __future__ import annotations

import asyncio
import ipaddress
import re
import socket
import ssl
import struct
import threading
from urllib.parse import urlparse

import structlog

from scau_connect.protocol.tunnel.dialer import Dialer as TunnelDialer
from scau_connect.protocol.tunnel.tcp_tunnel_dialer import TCPTunnelDialer
from scau_connect.proxy.base import ProxyBase
from scau_connect.proxy.certificates import CertificateAuthority
from scau_connect.proxy.web_proxy_dialer import WebProxyDialer, _atrust_proxy_host

logger = structlog.get_logger(__name__)


class HTTPProxy(ProxyBase):
    """HTTP proxy that routes traffic through the aTrust web proxy or TCP tunnel.

    For domain targets (e.g. www.scau.edu.cn): uses WebProxyDialer via the aTrust
    HTTP reverse proxy (web proxy mode).

    For raw IP targets (e.g. 222.201.229.3): uses TCPTunnelDialer via the aTrust
    L3 TCP tunnel. This requires the target IP to be in a known IP resource range.
    """

    def __init__(
        self,
        dialer: WebProxyDialer,
        listen_host: str = "0.0.0.0",
        listen_port: int = 1081,
        *,
        mitm_ca_dir: str = ".proxy-ca",
        enable_https_mitm: bool = True,
        tcp_tunnel_dialer: TCPTunnelDialer | None = None,
    ) -> None:
        super().__init__(dialer, listen_host, listen_port)
        self._ca = CertificateAuthority(mitm_ca_dir)
        self._enable_https_mitm = enable_https_mitm
        self._sock: socket.socket | None = None
        self._thread: threading.Thread | None = None
        self._stop = threading.Event()
        self._tcp_tunnel_dialer = tcp_tunnel_dialer

    async def start(self) -> None:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind((self.listen_host, self.listen_port))
        sock.listen(100)
        sock.settimeout(1.0)
        self._sock = sock
        self._stop.clear()
        self._thread = threading.Thread(target=self._serve_forever, daemon=True)
        self._thread.start()
        self._running = True
        logger.info("http_proxy_started", host=self.listen_host, port=self.listen_port)

    async def stop(self) -> None:
        self._stop.set()
        if self._sock is not None:
            try:
                self._sock.close()
            except OSError:
                pass
            self._sock = None
        if self._thread is not None:
            self._thread.join(timeout=2)
            self._thread = None
        self._running = False
        logger.info("http_proxy_stopped")

    @property
    def is_running(self) -> bool:
        return self._running

    def _serve_forever(self) -> None:
        assert self._sock is not None
        while not self._stop.is_set():
            try:
                client, addr = self._sock.accept()
                client.settimeout(30)
            except socket.timeout:
                continue
            except OSError:
                break
            threading.Thread(target=self._handle_socket, args=(client,), daemon=True).start()

    def _handle_socket(self, client: socket.socket) -> None:
        try:
            self._handle_socket_inner(client)
        except Exception as exc:
            logger.debug("client_handler_error", error=str(exc))
        finally:
            try:
                client.close()
            except OSError:
                pass

    def _handle_socket_inner(self, client: socket.socket) -> None:
        line = self._readline(client)
        if not line:
            return
        decoded = line.decode("utf-8", errors="replace").strip()
        if not decoded:
            return
        parts = decoded.split()
        if len(parts) < 2:
            return
        method, target = parts[0], parts[1]
        http_version = parts[2] if len(parts) > 2 else "HTTP/1.1"

        headers = self._read_headers(client)
        host, port = self._parse_host_header(headers)
        if not host:
            host = target.split("/")[0].split(":")[0]
            host = host.replace("http://", "").replace("https://", "")

        # Strip port from host for IP detection
        host_clean = host.split(":")[0]

        # Detect if this is a raw IP target that needs the TCP tunnel
        is_raw_ip = self._is_raw_ip_target(host_clean)
        if is_raw_ip and method == "CONNECT" and self._tcp_tunnel_dialer is not None:
            # CONNECT on raw IP: route through TCP tunnel
            self._handle_connect_tunnel(client, host_clean, port)
            return
        elif is_raw_ip and self._tcp_tunnel_dialer is not None:
            # HTTP request on raw IP: route through TCP tunnel
            body = b""
            cl = self._parse_content_length(headers)
            if cl > 0:
                body = self._read_exact(client, cl)
            response = self._forward_via_tunnel(host_clean, port, method, target, http_version, headers, body)
            if response:
                client.sendall(response)
            return

        if method == "CONNECT":
            self._handle_connect(client, host, port)
            return

        body = b""
        cl = self._parse_content_length(headers)
        if cl > 0:
            body = self._read_exact(client, cl)
        response = self._sync_forward(host, port, method, target, http_version, headers, body)
        if response:
            client.sendall(response)

    def _handle_connect(self, client: socket.socket, host: str, port: int) -> None:
        logger.debug("http_proxy_connect", host=host, port=port)
        if not self._enable_https_mitm:
            client.sendall(b"HTTP/1.1 501 Not Implemented\r\n\r\n")
            return
        client.sendall(b"HTTP/1.1 200 Connection Established\r\n\r\n")
        cert_path, key_path = self._ca.ensure_leaf(host)
        ssl_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ssl_ctx.load_cert_chain(certfile=str(cert_path), keyfile=str(key_path))
        try:
            with ssl_ctx.wrap_socket(client, server_side=True) as tls_sock:
                tls_sock.settimeout(30)
                self._serve_tls_http(tls_sock, host, port)
        except Exception as exc:
            logger.debug("mitm_session_error", host=host, error=str(exc))

    def _serve_tls_http(self, tls_sock: ssl.SSLSocket, host: str, port: int) -> None:
        while True:
            line = self._readline(tls_sock)
            if not line:
                return
            if line in (b"\r\n", b"\n"):
                continue
            decoded = line.decode("utf-8", errors="replace").strip()
            parts = decoded.split()
            if len(parts) < 2:
                return
            method, target = parts[0], parts[1]
            http_version = parts[2] if len(parts) > 2 else "HTTP/1.1"
            headers = self._read_headers(tls_sock)
            body = b""
            cl = self._parse_content_length(headers)
            if cl > 0:
                body = self._read_exact(tls_sock, cl)

            # Route raw IP targets through TCP tunnel
            if self._is_raw_ip_target(host) and self._tcp_tunnel_dialer is not None:
                response = self._forward_via_tunnel(host, port, method, target, http_version, headers, body)
                if response:
                    tls_sock.sendall(response)
                return

            response = self._sync_forward(host, port, method, target, http_version, headers, body)
            if response:
                tls_sock.sendall(response)

    def _sync_forward(
        self,
        host: str,
        port: int,
        method: str,
        target: str,
        http_version: str,
        headers: bytes,
        body: bytes,
    ) -> bytes:
        logger.debug(
            "sync_forward_start",
            host=host,
            proxy_host=_atrust_proxy_host(host),
            dialer_cookies=self.dialer.cookie_header[:50],
        )
        try:
            proxy_host = _atrust_proxy_host(host)
            ssl_ctx = ssl.create_default_context()
            ssl_ctx.check_hostname = False
            ssl_ctx.verify_mode = ssl.CERT_NONE
            raw = socket.create_connection((proxy_host, 443), timeout=15)
            with ssl_ctx.wrap_socket(raw, server_hostname=proxy_host) as upstream:
                new_headers = self._replace_host_header(headers, proxy_host)
                cookie_header = f"Cookie: {self.dialer.cookie_header}\r\n".encode()
                path = target
                if target.startswith("http://") or target.startswith("https://"):
                    parsed = urlparse(target)
                    path = parsed.path + ("?" + parsed.query if parsed.query else "")
                connection_header = b"Connection: close\r\n"
                request = (
                    f"{method} {path} {http_version}\r\n".encode()
                    + new_headers
                    + cookie_header
                    + connection_header
                    + b"\r\n"
                )
                if body:
                    request += body
                upstream.sendall(request)

                # Read full response. Since we send Connection: close, the
                # upstream will close the connection after the response.
                # For chunked responses, we need to fully decode to know size.
                response = b""
                while True:
                    chunk = upstream.recv(65536)
                    if not chunk:
                        break
                    response += chunk
                    if len(response) > 50_000_000:
                        break

                # Detect expired-session 302: aTrust web proxy returns 302 when the
                # session cookie is invalid or expired, redirecting to the portal.
                # Only 302 + aTrust page indicates session expiry.
                # 404 with aTrust body means the target is not accessible (separate issue).
                header_end = response.find(b"\r\n\r\n")
                if header_end > 0:
                    resp_head = response[:header_end]
                    resp_body = response[header_end + 4:]
                    status_line = resp_head.split(b"\r\n")[0]
                    body_text = resp_body[:2000].decode("utf-8", errors="replace")
                    is_atrust_page = "aTrust" in body_text or "sf-webproxy" in body_text

                    logger.debug(
                        "web_proxy_raw_response",
                        host=host,
                        proxy_host=proxy_host,
                        status=status_line.decode(errors="replace"),
                        is_atrust=is_atrust_page,
                        body_preview=body_text[:200],
                    )

                    # Only 302 + aTrust page = session expired
                    if status_line.startswith(b"HTTP/1.1 302") and is_atrust_page:
                        logger.warning(
                            "atrust_session_expired",
                            host=host,
                            note="aTrust returned 302 — session may be expired.",
                        )
                        return (
                            b"HTTP/1.1 502 Bad Gateway\r\n"
                            b"Content-Type: text/plain; charset=utf-8\r\n"
                            b"Connection: close\r\n"
                            b"\r\n"
                            b"502 aTrust session expired. "
                            b"Please run 'uv run scau-connect login' again to re-authenticate.\n"
                        )

                    # aTrust's own 502 page: it accepted the request but could not
                    # reach the upstream. This typically happens for raw IP targets or
                    # internal hosts that are only reachable via the L3 tunnel (not the
                    # HTTP web proxy). Surface a clear message instead of the raw HTML.
                    if status_line.startswith(b"HTTP/1.1 502") and is_atrust_page:
                        logger.warning(
                            "atrust_upstream_unreachable",
                            host=host,
                            note="aTrust web proxy could not reach the upstream target.",
                        )
                        return (
                            b"HTTP/1.1 502 Bad Gateway\r\n"
                            b"Content-Type: text/plain; charset=utf-8\r\n"
                            b"Connection: close\r\n"
                            b"\r\n"
                            b"502 aTrust web proxy cannot reach '" + host.encode()
                            + b"'.\r\n"
                            b"This usually means the target is a raw IP or internal host\r\n"
                            b"that is only reachable through the L3 tunnel (full VPN), not\r\n"
                            b"the HTTP web proxy. Domain-based HTTP sites (e.g. www.scau.edu.cn)\r\n"
                            b"work; raw IPs / internal addresses require L3 tunnel support\r\n"
                            b"(not yet implemented).\r\n"
                        )

                return response

        except Exception as exc:
            logger.warning("proxy_forward_error", host=host, error=str(exc))
            return (
                b"HTTP/1.1 502 Bad Gateway\r\n"
                b"Content-Type: text/plain; charset=utf-8\r\n"
                b"Connection: close\r\n"
                b"\r\n"
                b"502 Proxy error: "
                + str(exc).encode("utf-8", errors="replace")
                + b"\n"
            )

    # -------------------------------------------------------------------------
    # TCP tunnel helpers
    # -------------------------------------------------------------------------

    @staticmethod
    def _is_raw_ip_target(host: str) -> bool:
        """Check if host is a raw IP address (needs TCP tunnel, not web proxy)."""
        try:
            ipaddress.IPv4Address(host)
            return True
        except ValueError:
            return False

    def _handle_connect_tunnel(self, client: socket.socket, host: str, port: int) -> None:
        """Handle HTTPS CONNECT on a raw IP target via TCP tunnel."""
        logger.debug("tunnel_connect", host=host, port=port)

        # Check if we have a tunnel dialer and the IP is in our resource ranges
        if self._tcp_tunnel_dialer is None:
            client.sendall(b"HTTP/1.1 502 TCP Tunnel Not Available\r\n\r\n")
            return

        # Return 200 so the client starts TLS negotiation
        client.sendall(b"HTTP/1.1 200 Connection Established\r\n\r\n")

        # Now pipe the TLS connection through the TCP tunnel
        # We don't do MITM for raw IP targets - just raw passthrough
        try:
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            try:
                loop.run_until_complete(
                    self._pipe_tunnel(client, host, port)
                )
            finally:
                loop.close()
        except Exception as exc:
            logger.debug("tunnel_connect_error", host=host, error=str(exc))

    async def _pipe_tunnel(self, client: socket.socket, host: str, port: int) -> None:
        """Bridge a client socket to the TCP tunnel using async I/O."""
        if self._tcp_tunnel_dialer is None:
            return

        loop = asyncio.get_running_loop()

        try:
            # Dial the tunnel
            tunnel_reader, tunnel_writer = await self._tcp_tunnel_dialer.dial(host, port)

            async def client_to_tunnel():
                """Read HTTP request from client and forward through tunnel."""
                try:
                    buf = bytearray()
                    while True:
                        chunk = await loop.run_in_executor(None, client.recv, 65536)
                        if not chunk:
                            break
                        buf.extend(chunk)
                        # Send as we get data
                        tunnel_writer.write(bytes(buf))
                        await tunnel_writer.drain()
                        buf.clear()
                        # For HTTP with Connection: close, one request is enough
                        break
                except (OSError, ConnectionResetError, BrokenPipeError):
                    pass
                finally:
                    tunnel_writer.close()

            async def tunnel_to_client():
                """Read tunnel responses and forward to client."""
                try:
                    while True:
                        chunk = await tunnel_reader.read(65536)
                        if not chunk:
                            break
                        # _TunnelReader already strips frame headers
                        await loop.run_in_executor(
                            None, client.sendall, chunk
                        )
                except (OSError, ConnectionResetError, BrokenPipeError):
                    pass
                finally:
                    tunnel_writer.close()

            # Run both directions concurrently
            await asyncio.gather(client_to_tunnel(), tunnel_to_client(), return_exceptions=True)
        except Exception as exc:
            logger.debug("tunnel_pipe_error", host=host, error=str(exc))

    def _forward_via_tunnel(
        self,
        host: str,
        port: int,
        method: str,
        target: str,
        http_version: str,
        headers: bytes,
        body: bytes,
    ) -> bytes:
        """Forward an HTTP request through the TCP tunnel (sync wrapper)."""
        if self._tcp_tunnel_dialer is None:
            return (
                b"HTTP/1.1 502 TCP Tunnel Not Available\r\n"
                b"Content-Type: text/plain\r\n"
                b"Connection: close\r\n\r\n"
                b"TCP tunnel dialer not configured.\n"
            )

        # Build the HTTP request
        # For the tunnel, target is the absolute path (or full URL)
        path = target
        if target.startswith("http://") or target.startswith("https://"):
            parsed = urlparse(target)
            path = parsed.path + ("?" + parsed.query if parsed.query else "")

        # Rebuild request
        new_headers = self._replace_host_header(headers, host)
        cookie_header = f"Cookie: {self.dialer.cookie_header}\r\n".encode()
        connection_header = b"Connection: close\r\n"
        request = (
            f"{method} {path} {http_version}\r\n".encode()
            + new_headers
            + cookie_header
            + connection_header
            + b"\r\n"
        )
        if body:
            request += body

        # Run async dial in a new event loop
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        try:
            tunnel_reader, tunnel_writer = loop.run_until_complete(
                self._tcp_tunnel_dialer.dial(host, port)
            )

            # Send request through tunnel
            tunnel_writer.write(request)
            loop.run_until_complete(tunnel_writer.drain())

            # Read response - _TunnelReader strips frame headers
            response = b""
            while True:
                try:
                    chunk = loop.run_until_complete(
                        asyncio.wait_for(tunnel_reader.read(65536), timeout=15)
                    )
                except asyncio.TimeoutError:
                    break
                if not chunk:
                    break
                response += chunk
                if len(response) > 50_000_000:
                    break

            tunnel_writer.close()
            return response if response else (
                b"HTTP/1.1 502 Empty response from tunnel\r\n"
                b"Content-Type: text/plain\r\n"
                b"Connection: close\r\n\r\n"
                b"502 Empty response from TCP tunnel.\n"
            )
        except asyncio.TimeoutError:
            return (
                b"HTTP/1.1 504 Gateway Timeout\r\n"
                b"Content-Type: text/plain\r\n"
                b"Connection: close\r\n\r\n"
                b"504 Tunnel request timed out.\n"
            )
        except Exception as exc:
            logger.warning("tunnel_forward_error", host=host, error=str(exc))
            return (
                b"HTTP/1.1 502 Bad Gateway\r\n"
                b"Content-Type: text/plain\r\n"
                b"Connection: close\r\n\r\n"
                b"502 Tunnel error: "
                + str(exc).encode("utf-8", errors="replace")
                + b"\n"
            )
        finally:
            loop.close()

    @staticmethod
    def _readline(sock: socket.socket | ssl.SSLSocket) -> bytes:
        buf = bytearray()
        while True:
            ch = sock.recv(1)
            if not ch:
                return bytes(buf)
            buf.extend(ch)
            if ch == b"\n":
                return bytes(buf)

    def _read_headers(self, sock: socket.socket | ssl.SSLSocket) -> bytes:
        headers = b""
        while True:
            line = self._readline(sock)
            if line in (b"\r\n", b"\n", b""):
                return headers
            headers += line

    @staticmethod
    def _read_exact(sock: socket.socket | ssl.SSLSocket, n: int) -> bytes:
        chunks = []
        remaining = n
        while remaining > 0:
            chunk = sock.recv(remaining)
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        return b"".join(chunks)

    @staticmethod
    def _parse_host_header(headers: bytes) -> tuple[str, int]:
        for line in headers.split(b"\r\n"):
            if line.lower().startswith(b"host:"):
                host_port = line.split(b":", 1)[1].strip().decode("utf-8", errors="replace")
                if ":" in host_port:
                    h, p = host_port.rsplit(":", 1)
                    try:
                        return h, int(p)
                    except ValueError:
                        return h, 80
                return host_port, 80
        return "", 80

    @staticmethod
    def _replace_host_header(headers: bytes, new_host: str) -> bytes:
        lines = headers.split(b"\r\n")
        result = []
        replaced = False
        for line in lines:
            if line.lower().startswith(b"host:"):
                result.append(b"Host: " + new_host.encode())
                replaced = True
            elif line and not line.lower().startswith(b"cookie:") and not line.lower().startswith(b"connection:") and not line.lower().startswith(b"proxy-connection:"):
                result.append(line)
        if not replaced:
            result.insert(0, b"Host: " + new_host.encode())
        return b"\r\n".join(result) + b"\r\n"

    @staticmethod
    def _parse_content_length(headers: bytes) -> int:
        for line in headers.split(b"\r\n"):
            if line.lower().startswith(b"content-length:"):
                try:
                    return int(line.split(b":", 1)[1].strip())
                except ValueError:
                    return 0
        return 0
