"""Base proxy interface.

Defines the abstract contract for both HTTP CONNECT and SOCKS5 proxies.
"""

from __future__ import annotations

import asyncio
from abc import ABC, abstractmethod
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from scau_connect.protocol.tunnel.dialer import Dialer

import structlog

logger = structlog.get_logger(__name__)


class ProxyBase(ABC):
    """Abstract base class for proxy servers.

    Subclasses must implement the :meth:`start` coroutine which binds a
    listening socket and begins handling connections, and :meth:`stop`
    which tears it down cleanly.
    """

    def __init__(
        self,
        dialer: Dialer,
        listen_host: str = "0.0.0.0",
        listen_port: int = 1080,
    ) -> None:
        """Initialise the proxy.

        Parameters
        ----------
        dialer : Dialer
            :class:`Dialer` used to open outbound streams.
        listen_host : str
            Interface to bind (default: 0.0.0.0, all interfaces).
        listen_port : int
            TCP port to listen on.
        """
        self.dialer = dialer
        self.listen_host = listen_host
        self.listen_port = listen_port
        self._server: asyncio.Server | None = None
        self._running = False

    @abstractmethod
    async def start(self) -> None:
        """Bind the listening socket and start accepting connections.

        After ``start()`` returns, the proxy is ready to handle requests.
        """
        raise NotImplementedError()

    @abstractmethod
    async def stop(self) -> None:
        """Gracefully stop the proxy and close all active connections."""
        raise NotImplementedError()

    @property
    def is_running(self) -> bool:
        """Return ``True`` if the proxy server is currently accepting connections."""
        return self._running
