"""Tests for the L3 tunnel module.

Covers:
- Packet pack/unpack roundtrip (TunnelPacket, PacketType)
- Crypto helpers (HMAC-SHA256 sign key, encrypt/decrypt stub)
- L3Tunnel lifecycle (mockable unit tests, no live server needed)
- TunnelDialer instantiation and interface compliance
"""

from __future__ import annotations

import asyncio
import struct

import pytest

from scau_connect.protocol.tunnel import (
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
from scau_connect.protocol.tunnel.dialer import Dialer, TunnelDialer


# ---------------------------------------------------------------------------
# Packet / framing
# ---------------------------------------------------------------------------

class TestPacketType:
    def test_enum_values(self) -> None:
        assert int(PacketType.PING) == CMD_HEARTBEAT_REQ
        assert int(PacketType.PONG) == CMD_HEARTBEAT_RESP
        assert int(PacketType.DATA) == CMD_DATA_REQ
        assert int(PacketType.DATA_RESPONSE) == CMD_DATA_RESP
        assert int(PacketType.AUTH_REQUEST) == CMD_AUTH_REQ
        assert int(PacketType.AUTH_RESPONSE) == CMD_AUTH_RESP
        assert int(PacketType.SECOND_VIP_REQUEST) == CMD_SECOND_VIP_REQ
        assert int(PacketType.SECOND_VIP_RESPONSE) == CMD_SECOND_VIP_RESP

    def test_l3_version_constant(self) -> None:
        assert L3_VERSION == 0x05


class TestPacketPackUnpack:
    def test_heartbeat_roundtrip(self) -> None:
        raw = build_heartbeat()
        assert raw == bytes([L3_VERSION, CMD_HEARTBEAT_REQ, 0x00, 0x00])
        pkt = unpack_packet(raw)
        assert pkt.version == L3_VERSION
        assert pkt.packet_type == PacketType.PING
        assert pkt.payload == b""

    def test_data_request_roundtrip(self) -> None:
        pkt = TunnelPacket(packet_type=PacketType.DATA, payload=b"\xde\xad\xbe\xef")
        raw = pack_packet(pkt)
        assert raw[0] == L3_VERSION
        assert raw[1] == CMD_DATA_REQ
        length = struct.unpack_from(">H", raw, 2)[0]
        assert length == 4
        assert raw[4:] == b"\xde\xad\xbe\xef"
        unpkt = unpack_packet(raw)
        assert unpkt.payload == b"\xde\xad\xbe\xef"

    def test_auth_response_roundtrip(self) -> None:
        payload = b'{"code":0,"message":"ok"}'
        pkt = TunnelPacket(
            packet_type=PacketType.AUTH_RESPONSE,
            payload=payload,
            status=0,
        )
        raw = pack_packet(pkt)
        # Auth resp has extra status byte
        assert raw[0] == L3_VERSION
        assert raw[1] == CMD_AUTH_RESP
        assert raw[2] == 0  # status
        length = struct.unpack_from(">H", raw, 3)[0]
        assert length == len(payload)
        unpkt = unpack_packet(raw)
        assert unpkt.payload == payload
        assert unpkt.status == 0

    def test_bytes_alias(self) -> None:
        pkt = TunnelPacket(packet_type=PacketType.PING, payload=b"test")
        assert bytes(pkt) == pack_packet(pkt)

    def test_pack_bytes_passthrough(self) -> None:
        raw = b"\x05\x15\x00\x00"
        assert pack_packet(raw) == raw


class TestPackMeta:
    def test_ipv4_meta(self) -> None:
        meta = pack_meta(
            src_ip=b"\x0a\x00\x00\x01",
            dst_ip=b"\xc0\xa8\x00\x64",
            src_port=49152,
            dst_port=443,
            proto=6,
            atype=4,
        )
        assert len(meta) == 14
        assert meta[0] == 4
        assert meta[1] == 6
        assert meta[2:6] == b"\x0a\x00\x00\x01"
        assert meta[6:10] == b"\xc0\xa8\x00\x64"
        assert meta[10:12] == struct.pack(">H", 49152)
        assert meta[12:14] == struct.pack(">H", 443)

    def test_ipv6_meta(self) -> None:
        src = b"\x20\x01\x0d\xb8\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01"
        dst = b"\x20\x01\x0d\xb8\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x02"
        meta = pack_meta(src_ip=src, dst_ip=dst, src_port=12345, dst_port=80, proto=6, atype=6)
        assert len(meta) == 38


class TestUnpackMeta:
    def test_ipv4_roundtrip(self) -> None:
        meta = pack_meta(
            src_ip=b"\x0a\x00\x00\x01",
            dst_ip=b"\xc0\xa8\x00\x64",
            src_port=49152,
            dst_port=443,
            proto=17,
            atype=4,
        )
        atype, proto, src_ip, dst_ip, src_port, dst_port = unpack_meta(meta)
        assert atype == 4
        assert proto == 17
        assert src_ip == b"\x0a\x00\x00\x01"
        assert dst_ip == b"\xc0\xa8\x00\x64"
        assert src_port == 49152
        assert dst_port == 443


class TestDataPayload:
    def test_pack_and_parse(self) -> None:
        token = b"abc123"
        packets = [b"\x45\x00\x00\x1c", b"\xde\xad"]
        payload = pack_data_payload(token, packets)
        parsed_token, parsed_pkts = parse_data_payload(payload)
        assert parsed_token == token
        assert parsed_pkts == packets

    def test_parse_empty(self) -> None:
        token, pkts = parse_data_payload(bytes([len(b"tok"), *b"tok", 0x00, 0x00, 0x00]))
        assert token == b"tok"
        assert pkts == []


class TestVipData:
    def test_ipv4_only(self) -> None:
        data = bytes([10, 0, 0, 1, 0, 0])
        ips = parse_vip_data(data)
        assert len(ips) == 1
        assert ips[0] == bytes([10, 0, 0, 1])

    def test_ipv6_only(self) -> None:
        # parse_vip_data expects exactly 18 bytes for IPv6, returns first 16
        data = bytes([0x20, 0x01, 0x0d, 0xb8]) + b"\x00" * 14
        ips = parse_vip_data(data)
        assert len(ips) == 1
        assert ips[0] == data[:16]

    def test_both_v4_and_v6(self) -> None:
        # parse_vip_data expects exactly 22 bytes: IPv4(4) + IPv6(16) + 2 padding
        v4 = bytes([10, 0, 0, 1])
        v6 = bytes([0x20, 0x01, 0x0d, 0xb8]) + b"\x00" * 12
        data = v4 + v6 + b"\x00\x00"
        ips = parse_vip_data(data)
        assert len(ips) == 2


class TestAuthPayload:
    def test_build_auth_request_payload(self) -> None:
        payload = b'{"sid":"test123"}'
        frame = build_auth_request_payload(payload)
        # Outer wrapper starts with [0x05, 0x01, 0xD0] then inner prefix [0x53, 0x00]
        assert frame[0:3] == bytes([L3_VERSION, 0x01, 0xD0])
        assert frame[3:5] == bytes([0x53, 0x00])
        # Length of payload
        length = struct.unpack_from(">H", frame, 5)[0]
        assert length == len(payload)


# ---------------------------------------------------------------------------
# Crypto
# ---------------------------------------------------------------------------

class TestCryptoHelpers:
    def test_generate_sign_key_length(self) -> None:
        key = generate_sign_key()
        assert len(key) == 64
        assert key.isupper()
        assert all(c in "0123456789ABCDEF" for c in key)

    def test_calc_x_request_sig(self) -> None:
        key = bytes.fromhex(generate_sign_key().lower())
        data = b'{"sid":"test"}'
        sig = calc_x_request_sig(key, data)
        assert len(sig) == 64
        assert sig.isupper()
        # Verify roundtrip
        assert verify_sign(data, sig, key)
        # Wrong data should fail
        assert not verify_sign(b"wrong", sig, key)

    def test_encrypt_decrypt_stub(self) -> None:
        # Current implementation is a pass-through (TLS is used for transport)
        original = b"hello world"
        key = b"0123456789abcdef"
        assert encrypt_packet(original, key) == original
        assert decrypt_packet(original, key) == original

    def test_derive_session_key(self) -> None:
        master = b"masterkey"
        info = b"sessioninfo"
        derived = derive_session_key(master, info)
        assert len(derived) == 32  # SHA-256 output

    def test_generate_device_id(self) -> None:
        did = generate_device_id()
        assert len(did) == 32
        assert did.islower()

    def test_build_connection_id(self) -> None:
        did = "a" * 32
        cid = build_connection_id(did)
        # Format: MD5-hex-UUID "-" timestamp
        parts = cid.split("-")
        assert len(parts) == 2
        assert len(parts[0]) == 32


class TestTunnelCrypto:
    def test_initialisation(self) -> None:
        tc = TunnelCrypto()
        assert len(tc.sign_key_hex) == 64
        assert len(tc.device_id) == 32
        assert "-" in tc.connection_id
        assert tc.sequence == 0

    def test_sign_key_bytes_property(self) -> None:
        tc = TunnelCrypto()
        raw = tc.sign_key_bytes
        assert len(raw) == 32
        assert raw.hex().upper() == tc.sign_key_hex

    def test_next_nonce(self) -> None:
        tc = TunnelCrypto()
        n1 = tc.next_nonce()
        n2 = tc.next_nonce()
        assert len(n1) == 12
        assert len(n2) == 12
        assert n1 != n2
        assert tc.sequence == 2

    def test_encrypt_decrypt_stub(self) -> None:
        tc = TunnelCrypto()
        plaintext = b"secret data"
        assert tc.encrypt(plaintext) == plaintext
        assert tc.decrypt(plaintext) == plaintext

    def test_calc_x_request_sig(self) -> None:
        tc = TunnelCrypto()
        data = b'{"url":"tcp://1.2.3.4:443"}'
        sig = tc.calc_x_request_sig(data)
        assert len(sig) == 64
        assert verify_sign(data, sig, tc.sign_key_bytes)


# ---------------------------------------------------------------------------
# Dialer interface compliance
# ---------------------------------------------------------------------------

class TestTunnelDialer:
    def test_is_dialer_subclass(self) -> None:
        assert issubclass(TunnelDialer, Dialer)

    @pytest.mark.asyncio
    async def test_close(self) -> None:
        td = TunnelDialer(tunnel=object())
        await td.close()
        assert td._closed

    @pytest.mark.asyncio
    async def test_dial_requires_connected_tunnel(self) -> None:
        class FakeTunnel:
            connected = False

        td = TunnelDialer(tunnel=FakeTunnel())
        with pytest.raises(Exception):  # DialerError
            await td.dial("example.com", 443)

    @pytest.mark.asyncio
    async def test_dial_same_host_returns_same_pair(self) -> None:
        class MockTunnel:
            connected = True

        td = TunnelDialer(tunnel=MockTunnel())
        r1, w1 = await td.dial("example.com", 443)
        r2, w2 = await td.dial("example.com", 443)
        assert r1 is r2
        assert w1 is w2


# ---------------------------------------------------------------------------
# L3Tunnel lifecycle (mock only, no network)
# ---------------------------------------------------------------------------

class TestL3Tunnel:
    def test_initial_state(self) -> None:
        from scau_connect.config import Config
        from scau_connect.session import Session

        config = Config(server="vpn.test.cn")
        session = Session()
        tunnel = _make_tunnel(config, session)

        assert tunnel.connected is False
        assert tunnel.server_node is None
        assert tunnel.assigned_ip is None
        assert tunnel.ws is None

    def test_dialer_returns_tunnel_dialer(self) -> None:
        from scau_connect.config import Config
        from scau_connect.session import Session

        tunnel = _make_tunnel(Config(), Session())
        d = tunnel.dialer()
        assert isinstance(d, TunnelDialer)

    @pytest.mark.asyncio
    async def test_stop_when_not_started(self) -> None:
        from scau_connect.config import Config
        from scau_connect.session import Session

        tunnel = _make_tunnel(Config(), Session())
        # disconnect() should not raise even when ws is None
        await tunnel.disconnect()


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_tunnel(config, session) -> "L3Tunnel":
    """Construct an L3Tunnel without starting any network operations."""
    # We import here to avoid circular deps at module level
    from scau_connect.config import Config
    from scau_connect.protocol.tunnel.l3 import L3Tunnel
    from scau_connect.session import Session

    if not isinstance(config, Config):
        config = Config()
    if not isinstance(session, Session):
        session = Session()
    return L3Tunnel(config, session)
