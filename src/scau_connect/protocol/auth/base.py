"""Base authenticator interface.

Defines the abstract contract all authentication backends must satisfy.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from scau_connect.config import Config
    from scau_connect.session import Session


class AuthenticationError(Exception):
    """Raised when authentication fails (bad credentials, expired ticket, etc.)."""


class AuthenticatorBase(ABC):
    """Abstract base class for authentication backends.

    Each backend (CAS, LDAP, etc.) must implement :meth:`login` which returns
    a populated :class:`Session` on success.
    """

    def __init__(self, config: Config) -> None:
        self.config = config

    @abstractmethod
    async def login(self) -> Session:
        """Perform authentication and return a populated :class:`Session`.

        Returns
        -------
        Session
            Fully populated session including cookies and CSRF token.

        Raises
        ------
        AuthenticationError
            On any failure.
        """
        raise NotImplementedError()

    @abstractmethod
    async def logout(self, session: Session | None = None) -> None:
        """Invalidate the authenticated session.

        Parameters
        ----------
        session : Session | None
            The session to invalidate. Pass ``None`` to logout without a session
            (e.g. Selenium-only backends that track their own state).
        """
        raise NotImplementedError()
