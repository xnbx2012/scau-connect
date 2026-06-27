"""General-purpose cryptographic utilities.

Provides helpers for AES-GCM, ChaCha20-Poly1305, HKDF key derivation, and
random byte generation. Used throughout scau-connect for session token
encryption and any at-rest secrets.
"""

from __future__ import annotations

import hashlib
import hmac
import secrets

__all__ = [
    "random_bytes",
    "sha256_hex",
    "hmac_sha256",
    "aes_gcm_encrypt",
    "aes_gcm_decrypt",
    "hkdf_expand",
]


def random_bytes(n: int = 32) -> bytes:
    """Return ``n`` cryptographically random bytes.

    Parameters
    ----------
    n : int
        Number of bytes (default 32).

    Returns
    -------
    bytes
    """
    return secrets.token_bytes(n)


def sha256_hex(data: bytes) -> str:
    """Return the SHA-256 hex digest of *data*."""
    return hashlib.sha256(data).hexdigest()


def hmac_sha256(key: bytes, data: bytes) -> bytes:
    """Return the HMAC-SHA-256 of *data* using *key*."""
    return hmac.new(key, data, hashlib.sha256).digest()


def aes_gcm_encrypt(plaintext: bytes, key: bytes, nonce: bytes) -> tuple[bytes, bytes]:
    """Encrypt *plaintext* with AES-256-GCM.

    Parameters
    ----------
    plaintext : bytes
        Data to encrypt.
    key : bytes
        32-byte AES-256 key.
    nonce : bytes
        12-byte unique nonce / IV.

    Returns
    -------
    tuple[bytes, bytes]
        ``(ciphertext, tag)`` — tag is 16 bytes.
    """
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM

    if len(key) != 32:
        raise ValueError("AES-256 key must be 32 bytes")
    if len(nonce) != 12:
        raise ValueError("AES-GCM nonce must be 12 bytes")

    aesgcm = AESGCM(key)
    ciphertext = aesgcm.encrypt(nonce, plaintext, None)
    return ciphertext[:-16], ciphertext[-16:]


def aes_gcm_decrypt(ciphertext: bytes, tag: bytes, key: bytes, nonce: bytes) -> bytes:
    """Decrypt AES-256-GCM ciphertext.

    Parameters
    ----------
    ciphertext : bytes
        Encrypted data (without the authentication tag).
    tag : bytes
        16-byte authentication tag.
    key : bytes
        32-byte AES-256 key.
    nonce : bytes
        12-byte nonce used during encryption.

    Returns
    -------
    bytes
        Decrypted plaintext.

    Raises
    ------
    cryptography.exceptions.InvalidTag
        If authentication fails.
    """
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM

    aesgcm = AESGCM(key)
    return aesgcm.decrypt(nonce, ciphertext + tag, None)


def hkdf_expand(prk: bytes, info: bytes, length: int = 32) -> bytes:
    """HKDF-Expand (RFC 5869) using SHA-256.

    Parameters
    ----------
    prk : bytes
        Pseudo-random key (at least 32 bytes).
    info : bytes
        Context / application-specific info.
    length : int
        Desired output length in bytes.

    Returns
    -------
    bytes
    """
    n = (length + 31) // 32  # number of SHA-256 blocks needed
    result = b""
    t = b""
    for i in range(1, n + 1):
        t = hmac.new(prk, t + info + bytes([i]), hashlib.sha256).digest()
        result += t
    return result[:length]
