"""Cryptographic utilities for L3 tunnel.

Reference: zju-connect/client/atrust/tcptunnel.go (calcXRequestSig)
           zju-connect/client/atrust/l3tunnelconn.go (signKey usage)

The aTrust protocol uses:
- HMAC-SHA256 for request signing (xRequestSig field)
- TLS for transport encryption (handled by the websocket/tls connection)
- No additional per-packet encryption beyond TLS in the current protocol

The signKey is a 64-character hex string (32 bytes), generated randomly per session.
It's used to sign auth requests with HMAC-SHA256.
"""

from __future__ import annotations

import hashlib
import hmac
import secrets
import struct
from typing import Tuple

# AES-GCM constants
AES_GCM_IV_SIZE = 12  # 96 bits - standard for AES-GCM
AES_GCM_TAG_SIZE = 16  # 128 bits - authentication tag

# ChaCha20-Poly1305 constants
CHACHA_KEY_SIZE = 32
CHACHA_NONCE_SIZE = 12


def generate_sign_key() -> str:
    """Generate a random 64-character hex sign key.

    This is the same as zju-connect's randHex(64).

    Returns:
        64-character uppercase hex string
    """
    return secrets.token_hex(32).upper()


def calc_x_request_sig(sign_key: bytes, data: bytes) -> str:
    """Calculate xRequestSig for auth requests.

    This is HMAC-SHA256 of the request body, hex-encoded uppercase.

    Reference: zju-connect/client/atrust/tcptunnel.go calcXRequestSig()

    Args:
        sign_key: Decoded sign key bytes (32 bytes from hex)
        data: JSON request body bytes

    Returns:
        Uppercase hex signature string
    """
    h = hmac.new(sign_key, data, hashlib.sha256)
    return h.hexdigest().upper()


def verify_sign(data: bytes, sig: str, sign_key: bytes) -> bool:
    """Verify an xRequestSig.

    Args:
        data: Original request body
        sig: Expected signature (uppercase hex)
        sign_key: Decoded sign key bytes

    Returns:
        True if signature is valid
    """
    expected = calc_x_request_sig(sign_key, data)
    return hmac.compare_digest(expected, sig)


def encrypt_packet(data: bytes, key: bytes) -> bytes:
    """Encrypt tunnel data packet.

    TODO: The current zju-connect implementation does NOT use additional
    packet-level encryption - it relies on TLS for transport security.
    However, some versions of the aTrust protocol may use:
    - AES-GCM with a session-derived key, OR
    - ChaCha20-Poly1305

    If encryption is needed, this function should be updated based on
    further reverse engineering of the actual protocol.

    Current implementation: returns data unchanged (TLS encryption is used).

    Args:
        data: Raw packet data
        key: Encryption key bytes

    Returns:
        Encrypted data (currently just returns input)
    """
    # TODO: Reverse engineer actual encryption algorithm if needed.
    # The zju-connect code shows no per-packet encryption beyond TLS.
    # If we discover a specific encryption scheme, implement it here.
    return data


def decrypt_packet(data: bytes, key: bytes) -> bytes:
    """Decrypt tunnel data packet.

    TODO: See encrypt_packet().

    Current implementation: returns data unchanged.

    Args:
        data: Encrypted packet data
        key: Decryption key bytes

    Returns:
        Decrypted data (currently just returns input)
    """
    # TODO: Reverse engineer actual decryption algorithm if needed.
    return data


def derive_session_key(master_key: bytes, session_info: bytes) -> bytes:
    """Derive a session-specific key from master key.

    Uses HKDF-like derivation with SHA-256.

    TODO: This may be needed for per-session or per-connection encryption.
    The actual derivation scheme needs to be reverse engineered.

    Args:
        master_key: Master key bytes
        session_info: Session-specific info (e.g., token, nonce)

    Returns:
        Derived key bytes
    """
    h = hashlib.sha256()
    h.update(master_key)
    h.update(session_info)
    return h.digest()


def generate_device_id() -> str:
    """Generate a random 32-character lowercase hex device ID.

    This matches zju-connect's randHex(32) with lowercase output.

    Returns:
        32-character lowercase hex string
    """
    return secrets.token_hex(16).lower()


def build_connection_id(device_id: str) -> str:
    """Build connection ID from device ID.

    Format: MD5(device_id) + "-" + timestamp_microseconds

    Reference: zju-connect/client/atrust/client.go buildConnectionID()

    Args:
        device_id: 32-character device ID hex string

    Returns:
        Connection ID string
    """
    md5_sum = hashlib.md5(device_id.encode()).hexdigest().upper()
    import time
    timestamp = int(time.time() * 1_000_000)
    return f"{md5_sum}-{timestamp}"


# --- AES-GCM implementation placeholder (for future use) ---

def _aes_gcm_encrypt(plaintext: bytes, key: bytes, nonce: bytes) -> Tuple[bytes, bytes]:
    """AES-GCM encryption (placeholder for future use).

    Args:
        plaintext: Data to encrypt
        key: 16/24/32 byte AES key
        nonce: 12 byte IV/nonce

    Returns:
        Tuple of (ciphertext, tag)
    """
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM

    if len(nonce) != AES_GCM_IV_SIZE:
        raise ValueError(f"Nonce must be {AES_GCM_IV_SIZE} bytes")
    if len(key) not in (16, 24, 32):
        raise ValueError("Key must be 16, 24, or 32 bytes")

    aesgcm = AESGCM(key)
    # AESGCM.encrypt appends the tag to ciphertext
    ciphertext = aesgcm.encrypt(nonce, plaintext, None)
    tag = ciphertext[-AES_GCM_TAG_SIZE:]
    return ciphertext[:-AES_GCM_TAG_SIZE], tag


def _aes_gcm_decrypt(ciphertext: bytes, tag: bytes, key: bytes, nonce: bytes) -> bytes:
    """AES-GCM decryption (placeholder for future use).

    Args:
        ciphertext: Encrypted data (without tag)
        tag: Authentication tag
        key: 16/24/32 byte AES key
        nonce: 12 byte IV/nonce

    Returns:
        Decrypted plaintext

    Raises:
        cryptography.exceptions.InvalidTag: If authentication fails
    """
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM

    if len(nonce) != AES_GCM_IV_SIZE:
        raise ValueError(f"Nonce must be {AES_GCM_IV_SIZE} bytes")

    aesgcm = AESGCM(key)
    return aesgcm.decrypt(nonce, ciphertext + tag, None)


def _chacha20_encrypt(plaintext: bytes, key: bytes, nonce: bytes) -> bytes:
    """ChaCha20-Poly1305 encryption (placeholder for future use).

    Args:
        plaintext: Data to encrypt
        key: 32 byte key
        nonce: 12 byte nonce

    Returns:
        Ciphertext with appended Poly1305 tag
    """
    from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305

    if len(key) != CHACHA_KEY_SIZE:
        raise ValueError(f"Key must be {CHACHA_KEY_SIZE} bytes")
    if len(nonce) != CHACHA_NONCE_SIZE:
        raise ValueError(f"Nonce must be {CHACHA_NONCE_SIZE} bytes")

    chacha = ChaCha20Poly1305(key)
    return chacha.encrypt(nonce, plaintext, None)


def _chacha20_decrypt(ciphertext: bytes, key: bytes, nonce: bytes) -> bytes:
    """ChaCha20-Poly1305 decryption (placeholder for future use).

    Args:
        ciphertext: Encrypted data with appended tag
        key: 32 byte key
        nonce: 12 byte nonce

    Returns:
        Decrypted plaintext
    """
    from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305

    if len(key) != CHACHA_KEY_SIZE:
        raise ValueError(f"Key must be {CHACHA_KEY_SIZE} bytes")
    if len(nonce) != CHACHA_NONCE_SIZE:
        raise ValueError(f"Nonce must be {CHACHA_NONCE_SIZE} bytes")

    chacha = ChaCha20Poly1305(key)
    return chacha.decrypt(nonce, ciphertext, None)


# ---------------------------------------------------------------------------
# Object-oriented wrapper
# ---------------------------------------------------------------------------

class TunnelCrypto:
    """Encryption context for a single tunnel session.

    Object-oriented wrapper around the module-level crypto helpers. Holds the
    sign key, sequence counter, and any session-derived keys for the lifetime
    of a tunnel connection. Actual cipher negotiation will be completed by
    Agent-4 once the aTrust handshake has been fully reverse-engineered.
    """

    def __init__(self) -> None:
        self.sign_key_hex: str = generate_sign_key()
        self.device_id: str = generate_device_id()
        self.connection_id: str = build_connection_id(self.device_id)
        self.sequence: int = 0

    @property
    def sign_key_bytes(self) -> bytes:
        """Decode the hex sign key to raw bytes (32 bytes)."""
        return bytes.fromhex(self.sign_key_hex)

    def calc_x_request_sig(self, data: bytes) -> str:
        """Sign a request body with the session sign key."""
        return calc_x_request_sig(self.sign_key_bytes, data)

    def next_nonce(self) -> bytes:
        """Return the next 12-byte nonce for AEAD operations."""
        nonce = self.sequence.to_bytes(12, "big")
        self.sequence += 1
        return nonce

    def encrypt(self, plaintext: bytes, key: bytes | None = None) -> bytes:
        """Encrypt tunnel payload data.

        Parameters
        ----------
        plaintext : bytes
            Data to encrypt.
        key : bytes | None
            Encryption key. If ``None``, returns plaintext unchanged (TLS is
            used for transport security in the current protocol).

        Returns
        -------
        bytes
            Encrypted data.
        """
        if key is None:
            return encrypt_packet(plaintext, b"")
        return encrypt_packet(plaintext, key)

    def decrypt(self, ciphertext: bytes, key: bytes | None = None) -> bytes:
        """Decrypt tunnel payload data (inverse of :meth:`encrypt`)."""
        if key is None:
            return decrypt_packet(ciphertext, b"")
        return decrypt_packet(ciphertext, key)
