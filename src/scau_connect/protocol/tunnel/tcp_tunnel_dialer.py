"""TCP Tunnel dialer for aTrust L3 tunnel.

This implements the connection-oriented TCP tunnel protocol used by aTrust to
reach internal/IP-address targets that the web proxy cannot handle.

Wire protocol (from zju-connect client/atrust/tcptunnel.go):
1. TLS connect to node:441
2. Init frame:  [0x05, 0x01, 0x81, 0x53, 0x03] + len(2BE) + authJSON
3. Dest frame:  [0x05, 0x01, 0x01, 0x01] + 4-byte IP + 2-byte port
4. Server responds with init ACK [0x05,0x81] (2 bytes), then
   [0x53,0x00,len(2BE),data] protocol response with "OK" or error JSON.
5. After OK, the steady-state byte stream uses:
   - [0x01, 0x00, len(2BE), data]  -- application data frames
   - [0x01, 0x01, 0x00, 0x00]      -- close message
   - [0x53, 0x00, len(2BE), data]   -- protocol response (skip)
   - [0x05, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]
     -- data/ACK frame with FIXED 10-byte header; all remaining socket
        bytes are the application payload (live capture confirmed).

The authJSON contains:
  sid, appId, url, deviceId, connectionId, procHash, userName,
  destAddr, env (process info), xRequestSig (HMAC-SHA256)

appId / nodeGroupId come from clientResource IP resource ranges.
"""

from __future__ import annotations

import asyncio
import contextlib
from collections.abc import Callable
from dataclasses import dataclass, field
import hashlib
import ipaddress
import json
import os
import socket
import ssl
import struct
import time
from typing import TYPE_CHECKING

import structlog

from scau_connect.protocol.tunnel.crypto import (
    TunnelCrypto,
    calc_x_request_sig,
    generate_device_id,
    generate_sign_key,
)
from scau_connect.protocol.tunnel.dialer import Dialer, DialerError

if TYPE_CHECKING:
    from scau_connect.session import Session

logger = structlog.get_logger(__name__)

# Default aTrust node port for TCP tunnel
_TUNNEL_PORT = 441


# ---------------------------------------------------------------------------
# TCP Tunnel wire protocol constants
# ---------------------------------------------------------------------------

# Init frame prefix: [version, 0x01, 0x81, 0x53, 0x03]
_INIT_PREFIX = bytes([0x05, 0x01, 0x81, 0x53, 0x03])

# Dest frame prefix: [version, 0x01, 0x01, 0x01]
_DEST_PREFIX = bytes([0x05, 0x01, 0x01, 0x01])

# Dest response: [0x00, len(2BE)] + JSON body (server error or message)
_DEST_ERR_PREFIX = bytes([0x00])

# Protocol response: [0x53, 0x00, len(2BE), data] - contains "OK" or error
_PROTO_RESP_PREFIX = bytes([0x53, 0x00])

# Data frame prefix: [0x01, 0x00]
_DATA_PREFIX = bytes([0x01, 0x00])


# ---------------------------------------------------------------------------
# Socket helpers
# ---------------------------------------------------------------------------

def _recv_exact(sock: ssl.SSLSocket, n: int) -> bytes:
    """Receive exactly n bytes from a socket.  Raises OSError on timeout/EOF."""
    buf = b""
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise OSError("socket closed during _recv_exact")
        buf += chunk
    return buf


# Sentinel returned by _read_tcp_frame when the SCAU ``0x05`` data/ACK frame
# header has been consumed and the connection must now switch to RAW byte
# passthrough (the server streams the application payload with no further
# framing). Distinct from a bytes payload and from ``None`` (skip-and-loop).
_RAW_PASSTHROUGH = object()


# ---------------------------------------------------------------------------
# Shared steady-state frame reader
# ---------------------------------------------------------------------------

def _read_tcp_frame(sock: ssl.SSLSocket) -> bytes | None:
    """Read one frame from the steady-state TCP tunnel byte stream.

    Frame layout (from live capture + zju-connect tcptunnel.go):
      [0x01, 0x00, len(2BE), data]  -- application data frame
      [0x01, 0x01, 0x30, 0x30]       -- close message (server->client; return b"")
      [0x53, 0x00, len(2BE), data]   -- protocol response (skip, return None)
      [0x05, cmd, 0x00, 0x01, 0x00*5] -- SCAU data/ACK frame: FIXED 10-byte header,
                                        NO length field. After the header the
                                        server streams the raw application payload
                                        with no further framing (diverges from
                                        zju-connect's Go model). Returns the
                                        _RAW_PASSTHROUGH sentinel so the caller
                                        switches to raw recv() until upstream EOF.

    Returns:
      Raw application bytes for [0x01,0x00] data frames,
      b"" for close frames,
      None to signal the caller should loop and read the next frame,
      _RAW_PASSTHROUGH to signal the caller should switch to raw passthrough.

    Raises:
      OSError: on socket errors during recv.
    """
    # Read 2-byte frame type prefix
    prefix = _recv_exact(sock, 2)

    if prefix == _DATA_PREFIX:
        # Application data frame: [0x01, 0x00, len(2BE), data]
        len_bytes = _recv_exact(sock, 2)
        frame_len = struct.unpack_from(">H", len_bytes, 0)[0]
        if frame_len == 0:
            return b""
        payload = _recv_exact(sock, frame_len)
        return payload

    elif prefix == bytes([0x01, 0x01]):
        # Close message from server: [0x01, 0x01, 0x30, 0x30] ("00" = close).
        # Per zju-connect tcptunnel.go, only 0x30 0x30 triggers EOF; any other
        # trailing 2 bytes are NOT a close and we must keep reading.
        check = _recv_exact(sock, 2)
        if check == b"\x30\x30":
            return b""
        return None  # not a close — loop and read the next frame

    elif prefix == _PROTO_RESP_PREFIX:
        # Protocol response: [0x53, 0x00, len(2BE), data] -- skip and continue
        len_bytes = _recv_exact(sock, 2)
        frame_len = struct.unpack_from(">H", len_bytes, 0)[0]
        if frame_len > 0:
            _recv_exact(sock, frame_len)
        return None  # Signal caller to loop

    elif prefix[0:1] == bytes([0x05]):
        # SCAU data/ACK frame: FIXED 10-byte header, NO embedded length field.
        # Live capture (HTTP/1.1 400 response):
        #   [05 00 00 01 00 00 00 00 00 00] + raw HTTP bytes (immediately, no
        #   [0x01,0x00,len] wrapper — SCAU diverges from zju-connect's Go model).
        # Consume the 8 remaining header bytes, then signal the caller to switch
        # to raw byte passthrough for the rest of this response. The caller
        # (TunnelReader) keeps issuing recv() until the upstream closes (the
        # proxy sends Connection: close), so there is no length cap or timeout.
        header_rest = _recv_exact(sock, 8)  # 2 (prefix) + 8 = 10 bytes total
        logger.debug(
            "tcp_tunnel_data_frame",
            prefix=prefix.hex(),
            header_rest=header_rest.hex(),
        )
        return _RAW_PASSTHROUGH

    else:
        logger.warning("tcp_tunnel_unknown_frame", prefix=prefix.hex())
        return prefix


# ---------------------------------------------------------------------------
# IP resource range matching
# ---------------------------------------------------------------------------


def _ip_to_int(ip_str: str) -> int:
    """Convert dotted-quad IP string to 32-bit integer."""
    parts = ip_str.strip().split(".")
    return (int(parts[0]) << 24) | (int(parts[1]) << 16) | (int(parts[2]) << 8) | int(parts[3])


def _parse_ip_range(ip_str: str) -> tuple[int, int] | None:
    """Parse an IP/CIDR/range string into (start_int, end_int) tuple.

    Handles:
      "222.201.229.3"       -> single IP
      "222.201.229.0/24"   -> CIDR range
      "10.0.0.0-10.0.0.255" -> explicit range
    Returns None if parsing fails.
    """
    ip_str = ip_str.strip()
    if "/" in ip_str:
        try:
            net = ipaddress.IPv4Network(ip_str, strict=False)
            start_int = int(net.network_address)
            end_int = int(net.broadcast_address)
            return start_int, end_int
        except ValueError:
            return None
    if "-" in ip_str:
        try:
            start_str, end_str = ip_str.split("-", 1)
            start_int = _ip_to_int(start_str.strip())
            end_int = _ip_to_int(end_str.strip())
            if start_int > end_int:
                start_int, end_int = end_int, start_int
            return start_int, end_int
        except (ValueError, IndexError):
            return None
    try:
        start_int = _ip_to_int(ip_str)
        return start_int, start_int
    except (ValueError, IndexError):
        return None


def _ip_in_range(ip: str, ip_str: str) -> bool:
    """Check if an IP address is within an IP/CIDR/range string."""
    net = _parse_ip_range(ip_str)
    if net is None:
        return False
    try:
        addr = ipaddress.IPv4Address(ip)
        return addr in net
    except ValueError:
        return False


# ---------------------------------------------------------------------------
# Process info for tunnel auth
# ---------------------------------------------------------------------------

# Process name/path used in the env field of auth JSON.
# zju-connect uses google-chrome-stable; we mimic that.
_PROC_NAME = "google-chrome-stable"
_PROC_PATH = "/usr/bin/google-chrome-stable"
_PROC_HASH = hashlib.sha256(_PROC_PATH.encode()).hexdigest().upper()


def _build_env_field() -> dict:
    """Build the env field for the auth JSON, matching zju-connect's structure."""
    return {
        "application": {
            "runtime": {
                "process": {
                    "name": _PROC_NAME,
                    "digital_signature": "TrustAppClosed",
                    "platform": "Linux",
                    "fingerprint": _PROC_HASH,
                    "description": "TrustAppClosed",
                    "path": _PROC_PATH,
                    "version": "TrustAppClosed",
                    "security_env": "normal",
                },
                "process_trusted": "TRUSTED",
            }
        }
    }


# ---------------------------------------------------------------------------
# Stream reader/writer over raw TCP socket
# ---------------------------------------------------------------------------


class _TunnelReader:
    """Async stream reader over a blocking socket.

    Automatically strips tunnel data frame headers so callers receive raw
    application bytes.  Uses the shared _read_tcp_frame helper.

    After the SCAU ``0x05`` data/ACK header the reader switches to raw
    passthrough mode: subsequent reads return ``sock.recv()`` chunks directly,
    with no length cap and no read timeout, until the upstream closes (the
    proxy sends ``Connection: close`` so recv() returns b"" cleanly).
    """

    def __init__(self, sock: socket.socket, loop: asyncio.AbstractEventLoop) -> None:
        self._sock = sock
        self._loop = loop
        self._raw_mode = False

    async def read(self, n: int = 65536) -> bytes:
        """Read and return raw application bytes (frame header stripped)."""
        return await self._loop.run_in_executor(None, self._read_frame, n)

    def _read_frame(self, max_bytes: int) -> bytes:
        """Read one tunnel frame and return the application payload."""
        try:
            if self._raw_mode:
                # Raw passthrough after the SCAU 0x05 data/ACK header.
                # recv() returns b"" on upstream close -> caller sees EOF.
                return self._sock.recv(max_bytes)
            while True:
                result = _read_tcp_frame(self._sock)
                if result is _RAW_PASSTHROUGH:
                    self._raw_mode = True
                    return self._sock.recv(max_bytes)
                if result is not None:
                    return result
                # None means loop and read the next frame
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


class _TunnelReaderWithBuffer:
    """A tunnel reader that starts with buffered data from an initial read.

    Used when the dest response comes as a data frame instead of "OK".
    Switches to raw passthrough after the SCAU ``0x05`` header, same as
    :class:`_TunnelReader`.
    """

    def __init__(
        self, sock: ssl.SSLSocket, loop: asyncio.AbstractEventLoop, initial: bytes
    ) -> None:
        self._sock = sock
        self._loop = loop
        self._buf = initial
        self._raw_mode = False

    async def read(self, n: int = 65536) -> bytes:
        if self._buf:
            result = self._buf[:n]
            self._buf = self._buf[n:]
            return result
        return await self._loop.run_in_executor(None, self._read_frame, n)

    def _read_frame(self, max_bytes: int) -> bytes:
        """Read one tunnel frame (same logic as _TunnelReader._read_frame)."""
        try:
            if self._raw_mode:
                return self._sock.recv(max_bytes)
            while True:
                result = _read_tcp_frame(self._sock)
                if result is _RAW_PASSTHROUGH:
                    self._raw_mode = True
                    return self._sock.recv(max_bytes)
                if result is not None:
                    return result
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


class _TunnelWriter:
    """Async stream writer that wraps tunnel byte-stream frames."""

    def __init__(self, sock: socket.socket) -> None:
        self._sock = sock
        self._closed = False

    def write(self, data: bytes) -> None:
        if self._closed or not data:
            return
        # Send raw bytes directly — the tunnel server expects the application
        # protocol (HTTP) bytes without any framing wrapper. Framing was
        # incorrectly added based on zju-connect Go, but the SCAU node only
        # uses [0x05...] headers for control/ACK and raw passthrough for data.
        try:
            self._sock.sendall(data)
        except OSError:
            self._closed = True

    async def drain(self) -> None:
        pass  # sendall is synchronous blocking, already flushed

    def close(self) -> None:
        self._closed = True
        try:
            self._sock.shutdown(socket.SHUT_RDWR)
        except OSError:
            pass
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


# ---------------------------------------------------------------------------
# TCP Tunnel Connection
# ---------------------------------------------------------------------------


class TCPTunnelConn:
    """A single TCP tunnel connection to a target (host, port).

    Handles the TLS + handshake + dest setup and exposes an async
    reader/writer pair for the byte stream.
    """

    def __init__(
        self,
        node_host: str,
        node_port: int,
        target_host: str,
        target_port: int,
        auth_json: str,
        sign_key: bytes,
        device_id: str,
        connection_id: str,
        ssl_ctx: ssl.SSLContext,
        timeout: float = 15.0,
    ) -> None:
        self.node_host = node_host
        self.node_port = node_port
        self.target_host = target_host
        self.target_port = target_port
        self.auth_json = auth_json
        self.sign_key = sign_key
        self.device_id = device_id
        self.connection_id = connection_id
        self.ssl_ctx = ssl_ctx
        self.timeout = timeout
        self._sock: socket.socket | None = None
        self._reader: _TunnelReader | None = None
        self._writer: _TunnelWriter | None = None

    async def connect(self) -> tuple[_TunnelReader, _TunnelWriter]:
        """Establish the tunnel connection and return (reader, writer)."""
        loop = asyncio.get_running_loop()

        # Raw TCP connect
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(self.timeout)
        try:
            await loop.run_in_executor(
                None, sock.connect, (self.node_host, self.node_port)
            )
        except OSError as exc:
            sock.close()
            raise DialerError(
                f"TCP tunnel: failed to connect to node {self.node_host}:{self.node_port}: {exc}"
            ) from exc

        # TLS handshake
        try:
            sock = await loop.run_in_executor(
                None,
                lambda: self.ssl_ctx.wrap_socket(sock, server_hostname=self.node_host),
            )
        except ssl.SSLError as exc:
            sock.close()
            raise DialerError(
                f"TCP tunnel: TLS handshake failed with {self.node_host}: {exc}"
            ) from exc

        self._sock = sock

        # Step 1: Send init frame (auth JSON) + dest frame together.
        # Per zju-connect tcptunnel.go: there is NO separate init response read.
        # We send init then dest, and the server replies with a single protocol
        # response frame [0x53, 0x00, len(2BE), data] containing "OK" or an error.
        auth_bytes = self.auth_json.encode("utf-8")
        init_frame = (
            _INIT_PREFIX
            + struct.pack(">H", len(auth_bytes))
            + auth_bytes
        )

        # Build dest frame: [0x05,0x01,0x01,0x01] + 4-byte IP + 2-byte port
        try:
            target_ip_bytes = socket.inet_aton(self.target_host)
        except OSError:
            try:
                resolved = await loop.run_in_executor(
                    None, socket.gethostbyname, self.target_host
                )
                target_ip_bytes = socket.inet_aton(resolved)
            except OSError:
                self._close_sock(sock)
                raise DialerError(
                    f"TCP tunnel: cannot resolve target host {self.target_host}"
                )

        dest_frame = (
            _DEST_PREFIX
            + target_ip_bytes
            + struct.pack(">H", self.target_port)
        )

        # Send both frames
        try:
            sock.sendall(init_frame + dest_frame)
        except OSError as exc:
            self._close_sock(sock)
            raise DialerError(
                f"TCP tunnel: failed to send init/dest frames: {exc}"
            ) from exc

        # Step 2: Read response frames.
        # Server sends: [0x05,0x81] init-ACK (2 bytes), then
        # [0x53,0x00,len(2BE),data] protocol response with "OK" or error JSON.
        leftover = b""

        # Read first 2 bytes - init ACK [0x05, 0x81]
        try:
            init_ack = await loop.run_in_executor(None, _recv_exact, sock, 2)
        except OSError as exc:
            self._close_sock(sock)
            raise DialerError(
                f"TCP tunnel: failed to read init ACK: {exc}"
            ) from exc

        if init_ack == bytes([0x05, 0x81]):
            # Good - init ACK received. Now read protocol response.
            pass
        elif init_ack[0:1] == bytes([0x05]) and len(init_ack) >= 2:
            # Could be a different frame; keep reading
            leftover = init_ack
        else:
            logger.warning("tcp_tunnel_unexpected_init_ack", hdr=init_ack.hex())

        # Read protocol response frame [0x53, 0x00, len(2BE), data]
        if not leftover:
            try:
                resp_hdr = await loop.run_in_executor(None, _recv_exact, sock, 4)
            except OSError as exc:
                self._close_sock(sock)
                raise DialerError(
                    f"TCP tunnel: failed to read protocol response: {exc}"
                ) from exc
        else:
            # We have 2 bytes already; read 2 more to complete the header
            try:
                more = await loop.run_in_executor(None, _recv_exact, sock, 2)
            except OSError as exc:
                self._close_sock(sock)
                raise DialerError(
                    f"TCP tunnel: failed to read protocol response: {exc}"
                ) from exc
            resp_hdr = leftover + more

        if resp_hdr[0:2] == _PROTO_RESP_PREFIX:
            # Protocol response: [0x53, 0x00, len(2BE), data]
            resp_len = struct.unpack(">H", resp_hdr[2:4])[0]
            resp_body = b""
            if resp_len > 0:
                resp_body = await loop.run_in_executor(
                    None, _recv_exact, sock, resp_len
                )
            body_text = resp_body.decode("utf-8", errors="replace")
            if "OK" in body_text:
                vip = ""
                try:
                    vip = json.loads(body_text).get("data", {}).get("vip", "")
                except Exception:
                    pass
                logger.debug(
                    "tcp_tunnel_connected",
                    target=f"{self.target_host}:{self.target_port}",
                    vip=vip,
                )
            else:
                self._close_sock(sock)
                try:
                    err = json.loads(body_text)
                    raise DialerError(
                        f"TCP tunnel rejected: [{err.get('code','')}] {err.get('message','')}"
                    )
                except json.JSONDecodeError:
                    raise DialerError(
                        f"TCP tunnel rejected: {body_text[:200]}"
                    )
        elif resp_hdr[0:2] == _DATA_PREFIX:
            # Data frame immediately - tunnel working
            self._reader = _TunnelReaderWithBuffer(sock, loop, resp_hdr)
            self._writer = _TunnelWriter(sock)
            return self._reader, self._writer
        else:
            logger.warning(
                "tcp_tunnel_unexpected_resp",
                hdr=resp_hdr.hex(),
            )
            self._close_sock(sock)
            raise DialerError(
                f"TCP tunnel: unexpected response header: {resp_hdr.hex()}"
            )

        self._reader = _TunnelReader(sock, loop)
        self._writer = _TunnelWriter(sock)
        return self._reader, self._writer

    def close(self) -> None:
        if self._sock:
            self._close_sock(self._sock)
            self._sock = None

    @staticmethod
    def _close_sock(sock: socket.socket) -> None:
        try:
            sock.shutdown(socket.SHUT_RDWR)
        except OSError:
            pass
        try:
            sock.close()
        except OSError:
            pass


# ---------------------------------------------------------------------------
# IP Resource Database
# ---------------------------------------------------------------------------


@dataclass
class IPResource:
    """A range of internal IP addresses accessible through the tunnel."""

    ip_range: str  # e.g. "222.201.229.0/24"
    port_range: str  # e.g. "1-65535"
    protocol: str  # e.g. "TCP"
    app_id: str
    node_group_id: str
    node_address: str  # e.g. "node-gateway.scau.edu.cn:441"


@dataclass
class IPResourceDB:
    """Database of IP resources from clientResource response.

    Stores IP ranges as (start_int, end_int) tuples for fast integer comparison.
    """

    resources: list[IPResource] = field(default_factory=list)
    # Cache: (start_int, end_int, resource)
    _ranges: list[tuple[int, int, IPResource]] = field(
        default_factory=list, init=False
    )

    def add_resource(self, res: IPResource) -> None:
        self.resources.append(res)
        parsed = _parse_ip_range(res.ip_range)
        if parsed:
            start_int, end_int = parsed
            self._ranges.append((start_int, end_int, res))

    def find_resource(self, ip: str) -> IPResource | None:
        """Find the IP resource that contains the given IP address."""
        try:
            addr_int = _ip_to_int(ip)
        except (ValueError, IndexError):
            return None
        for start_int, end_int, res in self._ranges:
            if start_int <= addr_int <= end_int:
                return res
        return None

    def is_known_internal_ip(self, ip: str) -> bool:
        """Check if an IP address is in any known internal range."""
        return self.find_resource(ip) is not None


# ---------------------------------------------------------------------------
# TCP Tunnel Dialer
# ---------------------------------------------------------------------------


class TCPTunnelDialer(Dialer):
    """Dialer that routes connections through the aTrust TCP tunnel.

    This handles internal IP addresses (like 222.201.229.3) that the web
    proxy cannot reach. It must be configured with IP resources from the
    clientResource response and node addresses.

    The dialer automatically refreshes the session's ``sid`` cookie when the
    tunnel node rejects a dial with "invalid SID" (code 10000004).  Pass an
    ``ATrustProtocol`` instance so it can call ``refresh_session()`` without
    requiring a separate callback.  Alternatively pass ``refresh_callback`` as
    a standalone async callable.

    Usage::

        db = IPResourceDB()
        db.add_resource(IPResource(
            ip_range="222.201.229.0/24",
            port_range="1-65535",
            protocol="TCP",
            app_id="...",
            node_group_id="...",
            node_address="node.scau.edu.cn:441",
        ))
        dialer = TCPTunnelDialer(session, db, protocol=atrust_protocol)
        reader, writer = await dialer.dial("222.201.229.3", 80)
    """

    def __init__(
        self,
        session: Session,
        resource_db: IPResourceDB,
        default_node_host: str | None = None,
        default_node_port: int = _TUNNEL_PORT,
        protocol: "ATrustProtocol | None" = None,
        refresh_callback: Callable[[Session], asyncio.Future[Session]] | None = None,
    ) -> None:
        self._session = session
        self._db = resource_db
        self._default_node_host = default_node_host
        self._default_node_port = default_node_port
        self._closed = False
        self._loop: asyncio.AbstractEventLoop | None = None
        # Per-destination connections (not pooled across destinations)
        self._conns: dict[tuple[str, int], tuple[_TunnelReader, _TunnelWriter]] = {}

        # Session refresh: ATrustProtocol instance and/or async callback.
        # When the tunnel node rejects "invalid SID" (code 10000004) we call
        # refresh_callback(session) -> future -> refreshed session, then retry once.
        self._protocol = protocol
        self._refresh_callback = refresh_callback

        # L3 keepalive: a persistent TLS connection to the node that periodically
        # sends the 0x15 heartbeat frame. This is what aTrust treats as
        # "online user by SID" — without it the node rejects dials with
        # [10000004] after ~1 minute. Started on first dial.
        self._l3_heartbeat_task: asyncio.Task[None] | None = None
        # Signaled once the L3 keepalive tunnel has completed its auth handshake
        # (the node only treats the SID as "online" after this point).
        self._l3_ready: asyncio.Event = asyncio.Event()
        self._loop: asyncio.AbstractEventLoop | None = None
        # Per-destination connections (not pooled across destinations)
        self._conns: dict[tuple[str, int], tuple[_TunnelReader, _TunnelWriter]] = {}

        # Build SSL context once
        self._ssl_ctx = ssl.create_default_context()
        self._ssl_ctx.check_hostname = False
        self._ssl_ctx.verify_mode = ssl.CERT_NONE

        # Tunnel crypto for this dialer instance
        self._crypto = TunnelCrypto()
        # Connect/handshake timeout for L3 keepalive connections (seconds).
        self._timeout = 15.0

    async def _try_dial(
        self, host: str, port: int, resource: IPResource
    ) -> tuple[_TunnelReader, _TunnelWriter]:
        """Attempt one tunnel dial. Returns (reader, writer) or raises."""
        # Build auth JSON from current session cookies
        auth_json = self._build_auth_json(
            dest_host=host,
            dest_port=port,
            app_id=resource.app_id,
            node_group_id=resource.node_group_id,
        )

        node_address = resource.node_address
        if ":" in node_address:
            node_host, node_port_str = node_address.rsplit(":", 1)
            try:
                node_port = int(node_port_str)
            except ValueError:
                node_port = self._default_node_port
        else:
            node_host = node_address
            node_port = self._default_node_port

        conn = TCPTunnelConn(
            node_host=node_host,
            node_port=node_port,
            target_host=host,
            target_port=port,
            auth_json=auth_json,
            sign_key=self._crypto.sign_key_bytes,
            device_id=self._crypto.device_id,
            connection_id=self._crypto.connection_id,
            ssl_ctx=self._ssl_ctx,
        )
        return await conn.connect()

    async def dial(
        self, host: str, port: int
    ) -> tuple[_TunnelReader, _TunnelWriter]:
        """Open a TCP tunnel connection to (host, port) through aTrust.

        On ``invalid SID`` (code 10000004) from the tunnel node, the dialer
        attempts a session refresh (via the registered protocol or callback)
        and retries once before propagating the error.
        """
        if self._closed:
            raise DialerError("TCPTunnelDialer is closed")

        if self._loop is None:
            self._loop = asyncio.get_running_loop()

        key = (host, port)
        if key in self._conns:
            r, w = self._conns[key]
            if not getattr(w, "_closed", False):
                return r, w
            del self._conns[key]

        # Check if this IP is in our known resource ranges
        resource = self._db.find_resource(host)
        if resource is None:
            raise DialerError(
                f"TCPTunnelDialer: {host} is not in any known IP resource range. "
                f"Only internal IPs like 222.201.229.x can be reached via TCP tunnel."
            )

        logger.debug(
            "tcp_tunnel_dial",
            target=f"{host}:{port}",
            node=f"{resource.node_address}",
            app_id=resource.app_id,
            node_group=resource.node_group_id,
        )

        # Ensure the L3 heartbeat keepalive is running. This holds open a
        # persistent TLS connection to the node and sends a 4-byte 0x15 heartbeat
        # every 25s, which is what aTrust treats as "online user by SID". Without
        # it the node rejects dials with [10000004] after ~1 minute of idle time.
        await self._ensure_l3_heartbeat(resource)
        # Wait for the L3 tunnel to finish its auth handshake before dialing —
        # the node only registers the SID as "online" once that completes.
        if self._l3_heartbeat_task is not None:
            with contextlib.suppress(asyncio.TimeoutError):
                await asyncio.wait_for(self._l3_ready.wait(), timeout=5.0)

        try:
            return await self._try_dial(host, port, resource)
        except DialerError as exc:
            if "10000004" not in str(exc) and "invalid SID" not in str(exc).lower():
                raise
            # SID expired — try to refresh and retry once.
            if self._protocol is None and self._refresh_callback is None:
                logger.warning(
                    "tcp_tunnel_invalid_sid_no_refresh",
                    target=f"{host}:{port}",
                    note="No refresh callback registered — SID is expired. "
                         "Configure the dialer with a protocol instance or "
                         "refresh_callback to auto-refresh the session.",
                )
                raise
            logger.info(
                "tcp_tunnel_sid_expired_refresh",
                target=f"{host}:{port}",
            )
            await self._refresh_session()
            return await self._try_dial(host, port, resource)

    def _build_auth_json(
        self,
        dest_host: str,
        dest_port: int,
        app_id: str,
        node_group_id: str,
    ) -> str:
        """Build the auth JSON payload for the tunnel init frame.

        Matches zju-connect's tcptunnel.go DialTCP() message format exactly:
          {"sid":...,"appId":...,"url":"tcp://HOST:PORT","deviceId":...,
           "connectionId":...,"procHash":...,"userName":...,"rcAppliedInfo":0,
           "lang":"en-US","destAddr":"HOST:PORT","env":{...},"xRequestSig":"..."}

        The xRequestSig is HMAC-SHA256(signKey, json_without_sig) and is
        injected into the placeholder before sending.
        """
        sid = self._session.cookies.get("sid", "")
        device_id = self._crypto.device_id
        connection_id = self._crypto.connection_id
        username = self._session.username or ""
        dest_addr = f"{dest_host}:{dest_port}"
        url = f"tcp://{dest_addr}"

        # Build the unsigned message (xRequestSig placeholder empty).
        # Field order must match zju-connect for the signature to validate.
        msg = (
            '{"sid":"' + sid + '"'
            ',"appId":"' + app_id + '"'
            ',"url":"tcp://' + dest_addr + '"'
            ',"deviceId":"' + device_id + '"'
            ',"connectionId":"' + connection_id + '"'
            ',"procHash":"' + _PROC_HASH + '"'
            ',"userName":"' + username + '"'
            ',"rcAppliedInfo":0'
            ',"lang":"en-US"'
            ',"destAddr":"' + dest_addr + '"'
            ',"env":' + json.dumps(_build_env_field(), separators=(",", ":"))
            + ',"xRequestSig":""}'
        )
        msg_bytes = msg.encode("utf-8")

        # Compute signature over the message (with empty sig placeholder),
        # then inject it. zju-connect: msg[:len-3] + '"' + sig + '"}'
        sig = calc_x_request_sig(self._crypto.sign_key_bytes, msg_bytes)
        signed = msg_bytes[:-3] + b'"' + sig.encode("ascii") + b'"}'
        return signed.decode("utf-8")

    async def _refresh_session(self) -> None:
        """Refresh the session's ``sid`` cookie via the registered protocol.

        Called automatically when the tunnel node rejects a dial with "invalid SID".
        Uses ``ATrustProtocol.refresh_session()`` which re-runs CAS authentication
        to obtain a fresh ``sid`` while preserving the existing ``CASTGC``.
        """
        logger.info("tcp_tunnel_sid_expired_refresh")
        await self._protocol.refresh_session(self._session)
        # Restart the L3 heartbeat so it uses the refreshed sid.
        await self._stop_l3_heartbeat()

    # ------------------------------------------------------------------
    # L3 keepalive — persistent tunnel that holds the session "online"
    # ------------------------------------------------------------------

    async def _ensure_l3_heartbeat(self, resource: IPResource) -> None:
        """Start the L3 heartbeat background task if it isn't running.

        aTrust only treats a SID as "online" while at least one L3 tunnel
        connection is open and sending 0x15 heartbeat frames. Without it the
        node rejects every TCP-tunnel dial with [10000004] after ~1 minute.
        We open one persistent TLS connection to the node and heartbeat it
        every 25s for the lifetime of the dialer.
        """
        if self._l3_heartbeat_task is not None and not self._l3_heartbeat_task.done():
            return

        node_address = resource.node_address
        if ":" in node_address:
            node_host, _port = node_address.rsplit(":", 1)
        else:
            node_host = node_address
        node_port = self._default_node_port

        self._l3_ready = asyncio.Event()
        self._l3_heartbeat_task = asyncio.create_task(
            self._l3_heartbeat_loop(node_host, node_port),
            name="l3-heartbeat",
        )

    async def _stop_l3_heartbeat(self) -> None:
        if self._l3_heartbeat_task is not None:
            self._l3_heartbeat_task.cancel()
            with contextlib.suppress(Exception):
                await self._l3_heartbeat_task
            self._l3_heartbeat_task = None

    async def _l3_heartbeat_loop(self, node_host: str, node_port: int) -> None:
        """Open an L3 tunnel to the node and send 0x15 heartbeats every 25s.

        Re-establishes the connection on failure. The connection's only job is
        to be seen by the node as an active online session for our sid — actual
        tunneled traffic goes through the per-dial TCP tunnel.
        """
        while not self._closed:
            sock: socket.socket | None = None
            try:
                sock = await self._l3_connect_and_auth(node_host, node_port)
                logger.info("l3_heartbeat_established", node=f"{node_host}:{node_port}")
                self._l3_ready.set()
                # Reader drain task: consume and discard any frames the server sends
                # (heartbeat responses 0x95, protocol noise 0x53 0x00, etc.) so the
                # recv buffer never fills and stalls the connection.
                drain = asyncio.create_task(self._l3_drain_loop(sock))
                try:
                    while not self._closed:
                        await asyncio.sleep(25)
                        if self._closed:
                            break
                        # 4-byte heartbeat: version, cmdHeartbeatReq, 0x00, 0x00
                        await self._loop.run_in_executor(
                            None, sock.sendall, bytes([0x05, 0x15, 0x00, 0x00])
                        )
                        logger.debug("l3_heartbeat_sent")
                finally:
                    drain.cancel()
                    with contextlib.suppress(Exception):
                        await drain
            except asyncio.CancelledError:
                if sock is not None:
                    TCPTunnelConn._close_sock(sock)
                return
            except Exception as exc:
                logger.warning("l3_heartbeat_lost", error=str(exc))
                # Back off briefly before re-establishing.
                try:
                    await asyncio.sleep(5)
                except asyncio.CancelledError:
                    return

    async def _l3_drain_loop(self, sock: ssl.SSLSocket) -> None:
        """Continuously read and discard frames from the L3 keepalive socket.

        The server sends heartbeat responses (``0x05 0x95 0x00 0x00``) and
        occasional protocol-noise frames; we read them in a blocking fashion so
        the recv buffer never fills and stalls the connection. ``recv`` blocks
        between heartbeats (nothing to read), which is fine.
        """
        try:
            while not self._closed:
                try:
                    chunk = await self._loop.run_in_executor(None, sock.recv, 4096)
                except OSError:
                    return
                if not chunk:
                    return
        except asyncio.CancelledError:
            return

    async def _l3_connect_and_auth(self, node_host: str, node_port: int) -> ssl.SSLSocket:
        """TLS-connect to the node and perform the L3 tunnel auth handshake.

        Returns the authenticated TLS socket.  Raises on failure.
        """
        loop = self._loop or asyncio.get_running_loop()

        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(self._timeout)
        try:
            await loop.run_in_executor(None, sock.connect, (node_host, node_port))
        except OSError as exc:
            sock.close()
            raise DialerError(f"L3 heartbeat: connect failed: {exc}") from exc

        try:
            sock = await loop.run_in_executor(
                None,
                lambda: self._ssl_ctx.wrap_socket(sock, server_hostname=node_host),
            )
        except ssl.SSLError as exc:
            sock.close()
            raise DialerError(f"L3 heartbeat: TLS failed: {exc}") from exc

        # Build L3 auth frame:
        #   [0x05 0x01 0xD0] [0x53 0x00 len:2 json] [0x05 0x04 0x00 addrType 0x00×6]
        # where json = {"sid":"<sid cookie>"}
        sid = self._session.cookies.get("sid", "")
        auth_json = json.dumps({"sid": sid}).encode("utf-8")
        auth_frame = (
            bytes([0x05, 0x01, 0xD0])
            + bytes([0x53, 0x00])
            + struct.pack(">H", len(auth_json))
            + auth_json
            + bytes([0x05, 0x04, 0x00, 0x01])  # addrType 1 = IPv4
            + bytes(6)
        )
        try:
            await loop.run_in_executor(None, sock.sendall, auth_frame)
        except OSError as exc:
            TCPTunnelConn._close_sock(sock)
            raise DialerError(f"L3 heartbeat: send auth failed: {exc}") from exc

        # Read method response [0x05 0xD0] (2 bytes).
        try:
            method_resp = await loop.run_in_executor(None, _recv_exact, sock, 2)
        except OSError as exc:
            TCPTunnelConn._close_sock(sock)
            raise DialerError(f"L3 heartbeat: no method response: {exc}") from exc

        # Read auth response [0x53 status len:2 json] — we don't need its body,
        # just consume it so the connection is cleanly established.
        if method_resp[:1] == bytes([0x53]):
            # The 2 bytes we read were actually the start of the auth response.
            status = method_resp[1:2]
            _ = status
            try:
                len_bytes = await loop.run_in_executor(None, _recv_exact, sock, 2)
            except OSError:
                pass
            else:
                body_len = struct.unpack(">H", len_bytes)[0]
                if body_len:
                    with contextlib.suppress(OSError):
                        await loop.run_in_executor(None, _recv_exact, sock, body_len)
        elif method_resp == bytes([0x05, 0xD0]):
            # Read the auth response header [0x53 status len:2] + body.
            try:
                resp_hdr = await loop.run_in_executor(None, _recv_exact, sock, 4)
                body_len = struct.unpack(">H", resp_hdr[2:4])[0]
                if body_len:
                    with contextlib.suppress(OSError):
                        await loop.run_in_executor(None, _recv_exact, sock, body_len)
            except OSError:
                pass
            # Read VIP response [0x05 ... ] — consume a small fixed chunk.
            with contextlib.suppress(OSError):
                await loop.run_in_executor(None, _recv_exact, sock, 10)

        logger.debug("l3_heartbeat_authed")
        # Reset to blocking mode for the heartbeat loop.
        sock.settimeout(None)
        return sock

    async def close(self) -> None:
        self._closed = True
        await self._stop_l3_heartbeat()
        for key, (reader, writer) in self._conns.items():
            writer.close()
        self._conns.clear()
        logger.info("tcp_tunnel_dialer_closed")
