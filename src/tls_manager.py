"""MX2 Production TLS & ACME Certificate Management Module.

Provides TLS 1.3/1.2 SSLContext configuration, self-signed development certificate
generation, and ACME / Let's Encrypt http-01 challenge response handling.
"""

import os
import ssl
from datetime import datetime, timedelta, timezone
from typing import Optional

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa


class MX2TLSManager:
    """Manages SSL/TLS contexts and ACME challenges for production HTTPS/QUIC traffic."""

    def __init__(self, cert_dir: str = "config/certs") -> None:
        """Initializes the TLS manager.

        Args:
            cert_dir (str): Directory path to store certificates.
        """
        self.cert_dir = cert_dir
        os.makedirs(os.path.abspath(self.cert_dir), exist_ok=True)
        self.acme_challenges: dict[str, str] = {}

    def ensure_self_signed_cert(self, domain: str = "localhost") -> tuple[str, str]:
        """Generates a self-signed TLS certificate if no certificate exists.

        Args:
            domain (str): Domain name for the Subject Alternative Name (SAN).

        Returns:
            Tuple[str, str]: (certfile_path, keyfile_path)
        """
        cert_path = os.path.join(self.cert_dir, "daemon.crt")
        key_path = os.path.join(self.cert_dir, "daemon.key")

        if os.path.exists(cert_path) and os.path.exists(key_path):
            return cert_path, key_path

        # Generate RSA 2048-bit keypair for development cert
        private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

        # Subject & Issuer
        subject = issuer = x509.Name(
            [
                x509.NameAttribute(x509.NameOID.COMMON_NAME, domain),
                x509.NameAttribute(x509.NameOID.ORGANIZATION_NAME, "MX2 Protocol Development"),
            ]
        )

        now = datetime.now(timezone.utc)
        cert = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(issuer)
            .public_key(private_key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now)
            .not_valid_after(now + timedelta(days=365))
            .add_extension(
                x509.SubjectAlternativeName([x509.DNSName(domain), x509.DNSName("localhost")]),
                critical=False,
            )
            .sign(private_key, hashes.SHA256())
        )

        # Write private key
        with open(key_path, "wb") as f:
            f.write(
                private_key.private_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PrivateFormat.TraditionalOpenSSL,
                    encryption_algorithm=serialization.NoEncryption(),
                )
            )

        # Write certificate
        with open(cert_path, "wb") as f:
            f.write(cert.public_bytes(serialization.Encoding.PEM))

        return cert_path, key_path

    def create_ssl_context(self, certfile: Optional[str] = None, keyfile: Optional[str] = None) -> ssl.SSLContext:
        """Creates a modern SSLContext configured for TLS 1.2+.

        Args:
            certfile (Optional[str]): Path to SSL certificate.
            keyfile (Optional[str]): Path to SSL private key.

        Returns:
            ssl.SSLContext: Standard Python SSLContext instance.
        """
        if not certfile or not keyfile or not os.path.exists(certfile):
            certfile, keyfile = self.ensure_self_signed_cert()

        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(certfile=certfile, keyfile=keyfile)

        # Restrict to secure modern TLS protocols
        if hasattr(ssl, "TLSVersion"):
            context.minimum_version = ssl.TLSVersion.TLSv1_2

        return context

    def register_acme_challenge(self, token: str, key_authorization: str) -> None:
        """Registers an ACME HTTP-01 challenge response."""
        self.acme_challenges[token] = key_authorization

    def resolve_acme_challenge(self, token: str) -> Optional[str]:
        """Resolves an ACME HTTP-01 challenge token."""
        return self.acme_challenges.get(token)
