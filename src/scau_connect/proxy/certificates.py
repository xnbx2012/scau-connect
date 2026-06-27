"""Local certificate authority helpers for HTTPS MITM proxying.

This module creates a persistent root CA and per-host leaf certificates so the
local HTTP proxy can terminate CONNECT tunnels and inspect decrypted HTTP
requests before forwarding them through the authenticated aTrust web proxy.
"""

from __future__ import annotations

import datetime as _dt
import hashlib
from dataclasses import dataclass
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID


@dataclass
class CertificateBundle:
    ca_cert_path: Path
    ca_key_path: Path
    cert_dir: Path


class CertificateAuthority:
    def __init__(self, base_dir: str | Path) -> None:
        self.base_dir = Path(base_dir)
        self.base_dir.mkdir(parents=True, exist_ok=True)
        self.ca_cert_path = self.base_dir / "local-ca.crt.pem"
        self.ca_key_path = self.base_dir / "local-ca.key.pem"
        self.cert_dir = self.base_dir / "leaf"
        self.cert_dir.mkdir(exist_ok=True)
        self._ca_key = None
        self._ca_cert = None
        self._ensure_root_ca()

    def bundle(self) -> CertificateBundle:
        return CertificateBundle(self.ca_cert_path, self.ca_key_path, self.cert_dir)

    def _ensure_root_ca(self) -> None:
        if self.ca_cert_path.exists() and self.ca_key_path.exists():
            self._ca_key = serialization.load_pem_private_key(
                self.ca_key_path.read_bytes(), password=None
            )
            self._ca_cert = x509.load_pem_x509_certificate(self.ca_cert_path.read_bytes())
            return

        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        subject = issuer = x509.Name([
            x509.NameAttribute(NameOID.COUNTRY_NAME, "CN"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "scau-connect local CA"),
            x509.NameAttribute(NameOID.COMMON_NAME, "scau-connect local CA"),
        ])
        now = _dt.datetime.now(_dt.timezone.utc)
        cert = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(issuer)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - _dt.timedelta(days=1))
            .not_valid_after(now + _dt.timedelta(days=3650))
            .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
            .add_extension(
                x509.KeyUsage(
                    digital_signature=True,
                    content_commitment=False,
                    key_encipherment=False,
                    data_encipherment=False,
                    key_agreement=False,
                    key_cert_sign=True,
                    crl_sign=True,
                    encipher_only=False,
                    decipher_only=False,
                ),
                critical=True,
            )
            .sign(key, hashes.SHA256())
        )
        self.ca_key_path.write_bytes(
            key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption(),
            )
        )
        self.ca_cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
        self._ca_key = key
        self._ca_cert = cert

    def leaf_paths(self, hostname: str) -> tuple[Path, Path]:
        digest = hashlib.sha256(hostname.encode("utf-8")).hexdigest()[:16]
        return self.cert_dir / f"{digest}.crt.pem", self.cert_dir / f"{digest}.key.pem"

    def ensure_leaf(self, hostname: str) -> tuple[Path, Path]:
        cert_path, key_path = self.leaf_paths(hostname)
        if cert_path.exists() and key_path.exists():
            return cert_path, key_path
        if self._ca_key is None or self._ca_cert is None:
            self._ensure_root_ca()
        assert self._ca_key is not None and self._ca_cert is not None

        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        subject = x509.Name([
            x509.NameAttribute(NameOID.COUNTRY_NAME, "CN"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "scau-connect MITM"),
            x509.NameAttribute(NameOID.COMMON_NAME, hostname),
        ])
        now = _dt.datetime.now(_dt.timezone.utc)
        san = x509.SubjectAlternativeName([
            x509.DNSName(hostname),
            x509.DNSName(f"*.{hostname}"),
        ])
        cert = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(self._ca_cert.subject)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - _dt.timedelta(days=1))
            .not_valid_after(now + _dt.timedelta(days=30))
            .add_extension(san, critical=False)
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
            .add_extension(
                x509.KeyUsage(
                    digital_signature=True,
                    content_commitment=False,
                    key_encipherment=True,
                    data_encipherment=False,
                    key_agreement=False,
                    key_cert_sign=False,
                    crl_sign=False,
                    encipher_only=False,
                    decipher_only=False,
                ),
                critical=True,
            )
            .sign(self._ca_key, hashes.SHA256())
        )
        key_path.write_bytes(
            key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption(),
            )
        )
        cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
        return cert_path, key_path
