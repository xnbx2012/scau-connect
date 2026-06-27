"""L3 (IP-layer) tunnel implementation.

This implementation follows the structure of zju-connect's L3 tunnel enough to
support unit tests and future protocol work:
- websocket transport to /sslvpn/clusternap
- packet framing via protocol.tunnel.packet
- keepalive heartbeat loop
- simple dialer bridge for proxy integration

The code intentionally keeps protocol-specific parsing isolated so the transport
layer can be replaced or extended later.
"""

from __future__ import annotations

import asyncio
from dataclasses import dataclass
from typing import Any, Optional
from urllib.parse import urlencode

import websockets

from scau_connect.config import Config
from scau_connect.session import Session
from scau_connect.protocol.tunnel.dialer import Dialer, TunnelDialer
from scau_connect.protocol.tunnel.packet import (
    PacketType,
    TunnelPacket,
    build_heartbeat,
    pack_packet,
    unpack_packet,
)
from scau_connect.protocol.tunnel.crypto import TunnelCrypto


@dataclass
class _TunnelState:
    connected: bool = False
    server_node: str | None = None
    assigned_ip: str | None = None


class L3Tunnel:
    """L3 tunnel manager backed by a websocket transport."""

    def __init__(self, config: Config, session: Session) -> None:
        self.config = config
        self.session = session
        self.crypto = TunnelCrypto()
        self.ws: Any = None
        self._state = _TunnelState()
        self._rx_queue: asyncio.Queue[bytes] = asyncio.Queue()
        self._send_lock = asyncio.Lock()
        self._run_task: asyncio.Task[None] | None = None
        self._keepalive_task: asyncio.Task[None] | None = None
        self._closed = asyncio.Event()
        self._dialer = TunnelDialer(self)

    @property
    def connected(self) -> bool:
        return self._state.connected

    @property
    def server_node(self) -> str | None:
        return self._state.server_node

    @property
    def assigned_ip(self) -> str | None:
        return self._state.assigned_ip

    async def connect(self) -> None:
        """Establish a websocket connection to the aTrust tunnel endpoint."""
        if self.ws is not None:
            return

        query = urlencode({"clientType": "SDPBrowserClient", "platform": "Windows"})
        url = f"wss://{self.config.server}/sslvpn/clusternap?{query}"
        headers = {
            "sid": self.session.tunnel_token or self.session.extra.get("sid", "") or self.session.cookies.get("sid", ""),
            "device-id": self.session.extra.get("device_id", "") or self.session.extra.get("deviceId", ""),
            "rid": self.session.sdp_traceid or self.session.extra.get("rid", ""),
            "x-csrf-token": self.session.csrf_token or "",
        }
        headers = {k: v for k, v in headers.items() if v}

        ssl_context = None
        if self.config.skip_ssl_verify:
            import ssl

            ssl_context = ssl.create_default_context()
            ssl_context.check_hostname = False
            ssl_context.verify_mode = ssl.CERT_NONE

        self.ws = await websockets.connect(url, extra_headers=headers, ssl=ssl_context)
        self._state.connected = True
        self._state.server_node = self.config.server
        self._closed.clear()
        self._run_task = asyncio.create_task(self.run())
        self._keepalive_task = asyncio.create_task(self.keepalive())

    async def disconnect(self) -> None:
        """Close websocket and stop background tasks."""
        self._state.connected = False
        self._closed.set()
        if self._keepalive_task:
            self._keepalive_task.cancel()
        if self._run_task:
            self._run_task.cancel()
        if self.ws is not None:
            await self.ws.close()
            self.ws = None

    async def send_packet(self, data: bytes | TunnelPacket) -> None:
        """Send a packet through the tunnel."""
        if self.ws is None:
            raise RuntimeError("L3 tunnel is not connected")
        payload = pack_packet(data)
        async with self._send_lock:
            await self.ws.send(payload)

    async def recv_packet(self) -> bytes:
        """Receive the next raw packet payload from the tunnel."""
        return await self._rx_queue.get()

    async def keepalive(self) -> None:
        """Periodically send heartbeat packets."""
        try:
            while not self._closed.is_set():
                await asyncio.sleep(25)
                if self.ws is None:
                    continue
                await self.send_packet(build_heartbeat())
        except asyncio.CancelledError:
            return

    async def run(self) -> None:
        """Read packets from websocket and dispatch them into the queue."""
        if self.ws is None:
            return
        try:
            async for message in self.ws:
                if isinstance(message, str):
                    message = message.encode()
                try:
                    pkt = unpack_packet(message)
                except Exception:
                    # Fall back to raw bytes if frame parsing fails
                    await self._rx_queue.put(message)
                    continue

                if pkt.packet_type in (PacketType.DATA_RESPONSE, PacketType.PONG):
                    await self._rx_queue.put(pkt.payload)
                elif pkt.packet_type == PacketType.SECOND_VIP_RESPONSE and pkt.payload:
                    self._state.assigned_ip = pkt.payload.decode(errors="ignore")
                elif pkt.packet_type == PacketType.AUTH_RESPONSE and pkt.payload:
                    # Keep auth responses available for higher layers if needed.
                    await self._rx_queue.put(pkt.payload)
        except asyncio.CancelledError:
            return
        finally:
            self._state.connected = False

    def dialer(self) -> Dialer:
        """Return a dialer bound to this tunnel."""
        return self._dialer

    async def _send_raw(self, data: bytes) -> None:
        if self.ws is None:
            raise RuntimeError("L3 tunnel is not connected")
        async with self._send_lock:
            await self.ws.send(data)
