"""Local HTTP and SOCKS5 proxy servers.

This package provides pluggable proxy back-ends. The HTTP CONNECT proxy and
the SOCKS5 proxy both delegate actual connections to a :class:`Dialer`
registered at startup.
"""

from scau_connect.proxy.base import ProxyBase

__all__ = [
    "ProxyBase",
]
