"""Base protocol interface.

Defines the abstract contract that all aTrust protocol implementations must
satisfy, including authentication and tunnel lifecycle methods.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from scau_connect.config import Config
    from scau_connect.session import Session


class ProtocolBase(ABC):
    """Abstract base class for aTrust protocol handlers.

    Subclasses must implement the auth flow and tunnel establishment logic
    specific to the protocol variant (e.g. aTrust).
    """

    def __init__(self, config: Config, session: Session | None = None) -> None:
        """Initialise the protocol handler.

        Parameters
        ----------
        config : Config
            Application configuration.
        session : Session | None
            Existing session to reuse (e.g. on reconnect).
        """
        self.config = config
        self.session = session

    @abstractmethod
    async def authenticate(self) -> Session:
        """Perform the authentication handshake and return a populated Session.

        Raises
        ------
        AuthenticationError
            If credentials or the CAS ticket exchange fails.
        """
        raise NotImplementedError()

    @abstractmethod
    async def establish_tunnel(self, session: Session) -> None:
        """Establish the encrypted tunnel using the authenticated session.

        Parameters
        ----------
        session : Session
            Valid session obtained from :meth:`authenticate`.

        Raises
        ------
        TunnelError
            If the tunnel cannot be established.
        """
        raise NotImplementedError()

    @abstractmethod
    async def close(self) -> None:
        """Gracefully tear down the tunnel and release resources."""
        raise NotImplementedError()


class AuthenticationError(Exception):
    """Raised when the authentication handshake fails."""


class TunnelError(Exception):
    """Raised when tunnel establishment or I/O fails."""
