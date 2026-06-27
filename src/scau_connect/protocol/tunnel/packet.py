"""L3 Tunnel packet format and framing.

Reference: zju-connect/client/atrust/l3tunnelconn.go

Frame format (L3 protocol, version=0x05):
  - [0]: version byte (0x05)
  - [1]: command byte
  - [2:4]: status(1 byte) + length big-endian(2 bytes)  [for responses with status]
  - [2:4]: length big-endian(2 bytes)                   [for requests]
  - [4:]: payload

Commands:
  0x01  - Auth tunnel handshake
  0x13  - Auth request
  0x93  - Auth response
  0x14  - Data request
  0x94  - Data response
  0x15  - Heartbeat request
  0x95  - Heartbeat response
  0x16  - Second VIP request
  0x96  - Second VIP response

Special frame prefix for tunnel-level handshake:
  0x53 0x00 - Protocol negotiation prefix
"""

from __future__ import annotations

import struct
from dataclasses import dataclass, field
from enum import IntEnum
from typing import Tuple


# L3 protocol constants
L3_VERSION: int = 0x05

# Command bytes
CMD_AUTH_REQ: int = 0x13
CMD_AUTH_RESP: int = 0x93
CMD_DATA_REQ: int = 0x14
CMD_DATA_RESP: int = 0x94
CMD_HEARTBEAT_REQ: int = 0x15
CMD_HEARTBEAT_RESP: int = 0x95
CMD_SECOND_VIP_REQ: int = 0x16
CMD_SECOND_VIP_RESP: int = 0x96

# Tunnel handshake
CMD_TUNNEL_AUTH: int = 0xD0
TUNNEL_PREFIX: bytes = bytes([0x53, 0x00])

# Reserved bytes
RESERVED_2: bytes = bytes([0x00, 0x00])


class PacketType(IntEnum):
    """L3 tunnel packet types."""
    PING = CMD_HEARTBEAT_REQ       # 0x15 - Heartbeat request
    PONG = CMD_HEARTBEAT_RESP      # 0x95 - Heartbeat response
    DATA = CMD_DATA_REQ            # 0x14 - Data request
    DATA_RESPONSE = CMD_DATA_RESP  # 0x94 - Data response
    AUTH_REQUEST = CMD_AUTH_REQ    # 0x13 - Auth request
    AUTH_RESPONSE = CMD_AUTH_RESP  # 0x93 - Auth response
    SECOND_VIP_REQUEST = CMD_SECOND_VIP_REQ  # 0x16
    SECOND_VIP_RESPONSE = CMD_SECOND_VIP_RESP  # 0x96


@dataclass
class TunnelPacket:
    """L3 tunnel packet with header and payload.

    Attributes:
        version: Protocol version (0x05)
        packet_type: Command/packet type byte
        payload: Packet payload data
        status: Status byte (for responses, default 0)
    """
    version: int = L3_VERSION
    packet_type: PacketType = PacketType.PING
    payload: bytes = field(default_factory=bytes)
    status: int = 0  # Only used for response packets

    def __bytes__(self) -> bytes:
        return pack_packet(self)

    @property
    def cmd_byte(self) -> int:
        return int(self.packet_type)


def pack_packet(packet: TunnelPacket | bytes) -> bytes:
    """Pack a TunnelPacket into bytes for wire transmission.

    Format:
      - version (1 byte) + cmd (1 byte) + length (2 bytes BE) + payload

    For packets with status (auth_resp, vip_resp):
      - version (1) + cmd (1) + status (1) + length (2 BE) + payload

    Args:
        packet: TunnelPacket instance or raw bytes

    Returns:
        Wire-format byte string
    """
    if isinstance(packet, bytes):
        return packet

    version = bytes([packet.version])
    cmd = bytes([packet.cmd_byte])

    if packet.packet_type in (PacketType.AUTH_RESPONSE, PacketType.SECOND_VIP_RESPONSE):
        # Response packets include status byte
        status = bytes([packet.status])
        length = struct.pack(">H", len(packet.payload))
        return version + cmd + status + length + packet.payload
    else:
        # Request packets
        length = struct.pack(">H", len(packet.payload))
        return version + cmd + length + packet.payload


def pack_data_payload(token: bytes, packets: list[bytes]) -> bytes:
    """Build a data request payload with token and IP packets.

    Format:
      [version=0x05][cmd=0x14]
      [token_len][token_bytes]
      [0x00][0x00]  # reserved
      [packet_count]
      ([pkt_len_2BE][pkt_data])...

    Args:
        token: Connection token from auth response
        packets: List of raw IP packet bytes

    Returns:
        Full data payload ready to send
    """
    payload_len = 1 + len(token) + 2 + 1  # token_len + token + reserved + count
    for pkt in packets:
        payload_len += 2 + len(pkt)  # len_2BE + data

    result = bytearray(payload_len)
    offset = 0

    # Token length and token
    result[offset] = len(token)
    offset += 1
    result[offset:offset + len(token)] = token
    offset += len(token)

    # Reserved
    result[offset] = 0x00
    result[offset + 1] = 0x00
    offset += 2

    # Packet count
    result[offset] = len(packets)
    offset += 1

    # Each packet: 2-byte length + data
    for pkt in packets:
        struct.pack_into(">H", result, offset, len(pkt))
        offset += 2
        result[offset:offset + len(pkt)] = pkt
        offset += len(pkt)

    return bytes(result)


def parse_data_payload(payload: bytes) -> Tuple[bytes, list[bytes]]:
    """Parse a data response payload.

    Returns:
        Tuple of (token, list of IP packets)
    """
    if len(payload) < 4:
        raise ValueError(f"Payload too short: {len(payload)} bytes")

    token_len = payload[0]
    idx = 1 + token_len

    if len(payload) < idx + 3:
        raise ValueError("Payload token overflow")

    idx += 2  # Skip reserved
    count = payload[idx]
    idx += 1

    token = payload[1:1 + token_len]
    packets = []

    for _ in range(count):
        if idx + 2 > len(payload):
            raise ValueError("Packet length overflow")
        plen = struct.unpack_from(">H", payload, idx)[0]
        idx += 2
        if idx + plen > len(payload):
            raise ValueError("Packet data overflow")
        packets.append(payload[idx:idx + plen])
        idx += plen

    return token, packets


def unpack_packet(data: bytes) -> TunnelPacket:
    """Unpack wire bytes into a TunnelPacket.

    Args:
        data: Raw bytes from wire

    Returns:
        Parsed TunnelPacket

    Raises:
        ValueError: If data is too short or malformed
    """
    if len(data) < 4:
        raise ValueError(f"Frame too short: {len(data)} bytes, need at least 4")

    version = data[0]
    cmd = data[1]

    if cmd == CMD_AUTH_RESP or cmd == CMD_SECOND_VIP_RESP:
        # Response with status
        status = data[2]
        payload_len = struct.unpack_from(">H", data, 3)[0]
        payload = data[5:5 + payload_len] if payload_len > 0 else b""
    else:
        # Standard request/response
        payload_len = struct.unpack_from(">H", data, 2)[0]
        payload = data[4:4 + payload_len] if payload_len > 0 else b""
        status = 0

    try:
        ptype = PacketType(cmd)
    except ValueError:
        # Unknown command, use raw int
        ptype = PacketType(cmd)

    return TunnelPacket(
        version=version,
        packet_type=ptype,
        payload=payload,
        status=status,
    )


def build_heartbeat() -> bytes:
    """Build a heartbeat/keepalive packet.

    Returns:
        Raw bytes for heartbeat request
    """
    return bytes([L3_VERSION, CMD_HEARTBEAT_REQ, 0x00, 0x00])


def build_auth_request_payload(payload: bytes) -> bytes:
    """Wrap auth request data with tunnel-level prefix.

    Used during tunnel handshake (not per-flow auth).

    Format:
      [0x53][0x00][len_2BE][payload]
      Then wrapped with:
      [0x05][0x01][0xD0][tunnel_header][0x05][0x04][addr_type=0x01][...]

    Args:
        payload: JSON auth request body

    Returns:
        Complete wrapped auth request frame
    """
    # Protocol prefix: 0x53 0x00 + length + payload
    prefix = TUNNEL_PREFIX + struct.pack(">H", len(payload)) + payload

    # Outer wrapper
    wrapper = bytes([L3_VERSION, 0x01, CMD_TUNNEL_AUTH])
    addr_info = bytes([0x05, 0x04, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00])

    return wrapper + prefix + addr_info


def parse_vip_data(data: bytes) -> list[bytes]:
    """Parse virtual IP data from auth response.

    Args:
        data: VIP payload bytes

    Returns:
        List of IP address bytes (4 bytes each for IPv4)
    """
    ips = []
    data_len = len(data)

    if data_len == 6:
        # IPv4 only
        ips.append(bytes(data[:4]))
    elif data_len == 18:
        # IPv6 only
        ips.append(bytes(data[:16]))
    elif data_len == 22:
        # Both IPv4 and IPv6
        ips.append(bytes(data[:4]))
        ips.append(bytes(data[4:20]))

    return ips


def pack_meta(src_ip: bytes, dst_ip: bytes, src_port: int, dst_port: int,
              proto: int = 6, atype: int = 4) -> bytes:
    """Pack packet metadata (IP + port + protocol).

    Format:
      [atype(1)][proto(1)][src_ip(4)][dst_ip(4)][src_port(2)][dst_port(2)]

    Args:
        src_ip: Source IP bytes (4 for IPv4)
        dst_ip: Destination IP bytes (4 for IPv4)
        src_port: Source port
        dst_port: Destination port
        proto: Protocol number (6=TCP, 17=UDP, 1=ICMP)
        atype: Address type (4=IPv4, 6=IPv6)

    Returns:
        Encoded meta bytes
    """
    if atype == 4:
        # atype(1) + proto(1) + src_ip(4) + dst_ip(4) + src_port(2) + dst_port(2) = 14
        result = bytearray(14)
        result[0] = atype
        result[1] = proto
        result[2:6] = src_ip[:4]
        result[6:10] = dst_ip[:4]
        struct.pack_into(">H", result, 10, src_port)
        struct.pack_into(">H", result, 12, dst_port)
        return bytes(result)
    else:
        # atype(1) + proto(1) + src_ip(16) + dst_ip(16) + src_port(2) + dst_port(2) = 38
        result = bytearray(38)
        result[0] = atype
        result[1] = proto
        result[2:18] = src_ip[:16]
        result[18:34] = dst_ip[:16]
        struct.pack_into(">H", result, 34, src_port)
        struct.pack_into(">H", result, 36, dst_port)
        return bytes(result)


def unpack_meta(meta_bytes: bytes) -> Tuple[int, int, bytes, bytes, int, int]:
    """Unpack packet metadata bytes.

    Args:
        meta_bytes: Encoded meta bytes

    Returns:
        Tuple of (atype, proto, src_ip, dst_ip, src_port, dst_port)
    """
    if len(meta_bytes) < 2:
        raise ValueError("Meta too short")

    atype = meta_bytes[0]
    proto = meta_bytes[1]
    offset = 2

    if atype == 4:
        if len(meta_bytes) < offset + 8 + 4:
            raise ValueError("Meta IPv4 too short")
        src_ip = bytes(meta_bytes[offset:offset + 4])
        offset += 4
        dst_ip = bytes(meta_bytes[offset:offset + 4])
        offset += 4
    else:
        if len(meta_bytes) < offset + 32 + 4:
            raise ValueError("Meta IPv6 too short")
        src_ip = bytes(meta_bytes[offset:offset + 16])
        offset += 16
        dst_ip = bytes(meta_bytes[offset:offset + 16])
        offset += 16

    src_port = struct.unpack_from(">H", meta_bytes, offset)[0]
    offset += 2
    dst_port = struct.unpack_from(">H", meta_bytes, offset)[0]

    return atype, proto, src_ip, dst_ip, src_port, dst_port
