"""Authentication backends for scau-connect.

Currently provides a CAS implementation; other backends (e.g. LDAP) can be
added later following the same :class:`AuthenticatorBase` contract.
"""

from scau_connect.protocol.auth.base import AuthenticatorBase, AuthenticationError
from scau_connect.protocol.auth.cas import CASAuthenticator

__all__ = [
    "AuthenticatorBase",
    "AuthenticationError",
    "CASAuthenticator",
]
