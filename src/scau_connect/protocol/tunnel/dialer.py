"""Abstract :class:`Dialer` interface and concrete tunnel implementation.

The :class:`Dialer` bridges the proxy layer to the underlying transport.
In phase 1 it is implemented by the web-proxy handler; in phase 2 (Agent-4)
it is implemented by the L3 tunnel so all proxy traffic flows through the
encrypted tunnel.
"""

from __future__ import annotations

import asyncio
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from scau_connect.protocol.tunnel.l3 import L3Tunnel


class DialerError(Exception):
    """Raised when a connection cannot be established through the dialer."""


class Dialer(ABC):
    """Abstract base for stream dialers.

    A dialer is responsible for opening a full-duplex byte stream to a given
    ``(host, port)`` through whatever underlying transport is available
    (web-proxy CONNECT tunnel, L3 tunnel, WebSocket, etc.).

    Implementations must be thread-safe for concurrent use.
    """

    @abstractmethod
    async def dial(self, host: str, port: int) -> tuple[asyncio.StreamReader, asyncio.StreamWriter]:
        """Establish a bidirectional byte stream to ``(host, port)``.

        Returns an asyncio stream pair compatible with ``asyncio.open_connection()``.

        Raises
        ------
        DialerError
            If the connection cannot be established.
        """
        raise NotImplementedError()

    @abstractmethod
    async def close(self) -> None:
        """Release all resources held by the dialer."""
        raise NotImplementedError()


@dataclass
class _TunnelStreamWriter:
    """Minimal writer facade backed by the L3 tunnel send path.

    This satisfies the asyncio writer contract enough for proxy code to write
    response bytes; a full stream multiplexer can replace it later.
    """

    tunnel: "L3Tunnel"
    host: str
    port: int
    _buffer: bytearray = field(default_factory=bytearray)
    _closed: bool = False

    def write(self, data: bytes) -> None:
        if self._closed:
            return
        self._buffer.extend(data)

    async def drain(self) -> None:
        if self._closed or not self._buffer:
            return
        payload = bytes(self._buffer)
        self._buffer.clear()
        await self.tunnel.send_packet(payload)

    def close(self) -> None:
        self._closed = True

    async def wait_closed(self) -> None:
        return None

    def get_extra_info(self, name: str, default=None):
        return default


class TunnelDialer(Dialer):
    """Concrete :class:`Dialer` over an :class:`L3Tunnel` instance.

    The tunnel provides an unreliable datagram-style transport; this dialer
    wraps it in a per-destination reader/writer pair so the proxy layer sees a
    familiar asyncio stream surface. Real flow multiplexing will be wired in
    once the L3 transport is exercised against a live server.
    """

    def __init__(self, tunnel: "L3Tunnel"):
        self._tunnel = tunnel
        self._closed = False
        self._connections: dict[tuple[str, int], tuple[asyncio.StreamReader, _TunnelStreamWriter]] = {}

    async def dial(self, host: str, port: int) -> tuple[asyncio.StreamReader, asyncio.StreamWriter]:
        if self._closed:
            raise DialerError("dialer is closed")
        if not getattr(self._tunnel, "connected", False):
            raise DialerError("L3 tunnel is not connected")

        key = (host, port)
        if key in self._connections:
            return self._connections[key]

        reader = asyncio.StreamReader()
        writer = _TunnelStreamWriter(self._tunnel, host, port)
        pair = (reader, writer)
        self._connections[key] = pair
        return pair

    async def close(self) -> None:
        self._closed = True
        for reader, writer in self._connections.values():
            writer.close()
        self._connections.clear()
