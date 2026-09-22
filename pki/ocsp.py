"""Fail-closed OCSP revocation check against the EJBCA responder.

The CertID issuer hashes use SHA-256.
"""

import requests
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.x509 import ocsp

from config.settings import EJBCA_URL, get_tls_verify


class OCSPError(Exception):
    """Raised on any non-definitive OCSP outcome. Callers deny on this."""


def ocsp_check(cert_pem: str, issuer_cert_pem: str, timeout: int = 10) -> str:
    """Return 'GOOD' or 'REVOKED' for the leaf certificate.

    Raises OCSPError on any other outcome (responder unreachable, non-200,
    non-SUCCESSFUL response, or UNKNOWN status) — fail closed.

    Args:
        cert_pem: The leaf certificate to check (PEM).
        issuer_cert_pem: The issuing CA certificate (PEM).
    """
    cert = x509.load_pem_x509_certificate(cert_pem.encode())
    issuer = x509.load_pem_x509_certificate(issuer_cert_pem.encode())
    req = ocsp.OCSPRequestBuilder().add_certificate(cert, issuer, hashes.SHA256()).build()

    ocsp_url = f"{EJBCA_URL}/ejbca/publicweb/status/ocsp"
    try:
        resp = requests.post(
            ocsp_url,
            data=req.public_bytes(serialization.Encoding.DER),
            headers={"Content-Type": "application/ocsp-request"},
            verify=get_tls_verify(),
            timeout=timeout,
        )
        resp.raise_for_status()
    except requests.RequestException as e:
        raise OCSPError(f"OCSP responder unreachable, failing closed: {e}") from e

    o = ocsp.load_der_ocsp_response(resp.content)
    if o.response_status != ocsp.OCSPResponseStatus.SUCCESSFUL:
        raise OCSPError(f"OCSP response status {o.response_status.name}, failing closed")

    status = o.certificate_status
    if status == ocsp.OCSPCertStatus.GOOD:
        return "GOOD"
    if status == ocsp.OCSPCertStatus.REVOKED:
        return "REVOKED"
    raise OCSPError(f"OCSP certificate status {status.name}, failing closed")
