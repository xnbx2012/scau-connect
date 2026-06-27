"""Protocol layer for aTrust VPN communication.

This package contains protocol implementations for authentication (CAS) and
tunnel establishment (L3 packet, crypto, dialer). Sub-packages:

- :mod:`scau_connect.protocol.auth` -- CAS / other auth backends.
- :mod:`scau_connect.protocol.tunnel` -- L3 tunnel, packet framing, crypto,
  and the :class:`~scau_connect.protocol.tunnel.dialer.Dialer` abstraction.
"""

from scau_connect.protocol.base import ProtocolBase
from scau_connect.protocol.atrust import ATrustProtocol

__all__ = [
    "ProtocolBase",
    "ATrustProtocol",
]
