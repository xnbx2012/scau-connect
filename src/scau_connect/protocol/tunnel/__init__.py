"""Tunnel layer for scau-connect.

Contains the L3 tunnel implementation, packet framing, cryptographic
helpers, and the :class:`Dialer` abstraction that bridges proxies to the
tunnel transport.

Reference: zju-connect/client/atrust/ for the underlying wire protocol.
"""

from scau_connect.protocol.tunnel.dialer import Dialer, DialerError, TunnelDialer
from scau_connect.protocol.tunnel.packet import (
    L3_VERSION,
    CMD_AUTH_REQ,
    CMD_AUTH_RESP,
    CMD_DATA_REQ,
    CMD_DATA_RESP,
    CMD_HEARTBEAT_REQ,
    CMD_HEARTBEAT_RESP,
    CMD_SECOND_VIP_REQ,
    CMD_SECOND_VIP_RESP,
    PacketType,
    TunnelPacket,
    build_auth_request_payload,
    build_heartbeat,
    pack_data_payload,
    pack_meta,
    pack_packet,
    parse_data_payload,
    parse_vip_data,
    unpack_meta,
    unpack_packet,
)
from scau_connect.protocol.tunnel.crypto import (
    TunnelCrypto,
    build_connection_id,
    calc_x_request_sig,
    decrypt_packet,
    derive_session_key,
    encrypt_packet,
    generate_device_id,
    generate_sign_key,
    verify_sign,
)
from scau_connect.protocol.tunnel.l3 import L3Tunnel

from scau_connect.protocol.tunnel.tcp_tunnel_dialer import (
    IPResource,
    IPResourceDB,
    TCPTunnelDialer,
)
from scau_connect.protocol.tunnel.resource_parser import (
    parse_client_resource,
    build_default_ip_resource_db,
)

# Backwards-compatible alias: some callers expect "Packet".
Packet = TunnelPacket

__all__ = [
    # Dialer
    "Dialer",
    "DialerError",
    "TunnelDialer",
    # TCP Tunnel Dialer
    "TCPTunnelDialer",
    "IPResource",
    "IPResourceDB",
    # Resource Parser
    "parse_client_resource",
    "build_default_ip_resource_db",
    # Packet
    "Packet",
    "PacketType",
    "TunnelPacket",
    "L3_VERSION",
    "CMD_AUTH_REQ",
    "CMD_AUTH_RESP",
    "CMD_DATA_REQ",
    "CMD_DATA_RESP",
    "CMD_HEARTBEAT_REQ",
    "CMD_HEARTBEAT_RESP",
    "CMD_SECOND_VIP_REQ",
    "CMD_SECOND_VIP_RESP",
    "pack_packet",
    "unpack_packet",
    "pack_data_payload",
    "parse_data_payload",
    "build_heartbeat",
    "build_auth_request_payload",
    "parse_vip_data",
    "pack_meta",
    "unpack_meta",
    # Crypto
    "generate_sign_key",
    "calc_x_request_sig",
    "verify_sign",
    "encrypt_packet",
    "decrypt_packet",
    "derive_session_key",
    "generate_device_id",
    "build_connection_id",
    "TunnelCrypto",
    # L3
    "L3Tunnel",
]
