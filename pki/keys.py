"""Extract PEM material from a stored PKCS12 so agents can sign locally.

Certificates and their private keys are stored in AWS Secrets Manager as
password-protected P12 bundles (encrypted at rest, IAM-controlled). To sign an
envelope or a delegation, a component loads its own P12 from Secrets Manager
and pulls out the private key here.
"""

import base64

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    NoEncryption,
    PrivateFormat,
    pkcs12,
)


def cert_and_key_pem_from_p12(p12_b64: str, password: str) -> tuple[str, str]:
    """Return (cert_pem, key_pem) for the leaf of a base64-encoded P12.

    The private key is returned unencrypted PEM for in-process signing use;
    it must never be serialized onto a wire or into a subprocess argument.
    """
    p12_data = base64.b64decode(p12_b64)
    private_key, certificate, _ = pkcs12.load_key_and_certificates(
        p12_data,
        password.encode() if password else None,
        backend=default_backend(),
    )
    cert_pem = certificate.public_bytes(Encoding.PEM).decode()
    key_pem = private_key.private_bytes(
        Encoding.PEM,
        PrivateFormat.PKCS8,
        NoEncryption(),
    ).decode()
    return cert_pem, key_pem
