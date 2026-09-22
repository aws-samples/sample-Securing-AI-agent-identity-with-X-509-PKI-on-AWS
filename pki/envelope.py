"""Signed request envelopes: proof-of-possession for every call.

Agent-to-agent and agent-to-mcp requests are signed with the requesting agent's
private key to demonstrate proof-of-possesion. The resulting cryptographic 
object is this envelope, which stores other metadata like a timestamp and nonce
for added security.
"""

import base64
import json
import secrets
import threading
import time

from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding

from config.settings import ALLOWED_CALLER_ROLES, ENVELOPE_MAX_AGE_SECONDS
from pki.ocsp import OCSPError, ocsp_check


class EnvelopeError(Exception):
    """Any validation failure. Callers treat all failures identically: deny."""


def _canonical_bytes(payload_b64: str, timestamp: int, nonce: str) -> bytes:
    return f"{payload_b64}|{timestamp}|{nonce}".encode()


def sign_envelope(payload: dict, cert_pem: str, private_key_pem: str) -> dict:
    """Wrap a payload in a signed envelope. The private key is used locally
    and is NOT part of the envelope — only the public certificate travels."""
    payload_b64 = base64.b64encode(json.dumps(payload, sort_keys=True).encode()).decode()
    timestamp = int(time.time())
    nonce = secrets.token_hex(16)
    key = serialization.load_pem_private_key(private_key_pem.encode(), password=None)
    signature = key.sign(
        _canonical_bytes(payload_b64, timestamp, nonce),
        padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
        hashes.SHA256(),
    )
    return {
        "payload_b64": payload_b64,
        "cert_pem": cert_pem,
        "timestamp": timestamp,
        "nonce": nonce,
        "signature_b64": base64.b64encode(signature).decode(),
        "alg": "RSA-PSS-SHA256",
    }


class ReplayCache:
    """Remembers nonces until their envelope's freshness window has passed."""

    def __init__(self):
        self._seen: dict[str, float] = {}
        self._lock = threading.Lock()

    def check_and_add(self, nonce: str) -> bool:
        """False if the nonce was already used (replay)."""
        now = time.time()
        with self._lock:
            self._seen = {n: exp for n, exp in self._seen.items() if exp > now}
            if nonce in self._seen:
                return False
            self._seen[nonce] = now + 2 * ENVELOPE_MAX_AGE_SECONDS
            return True


def extract_role(cn: str) -> str:
    """Agent CNs follow {username}_{agent-role}; the role is the part after the
    last underscore. A CN with no underscore is a user certificate."""
    if "_" not in cn:
        return "user"
    return cn.rsplit("_", 1)[1]


def cert_common_name(cert: x509.Certificate) -> str:
    return cert.subject.get_attributes_for_oid(x509.NameOID.COMMON_NAME)[0].value


def cert_fingerprint(cert_pem: str) -> str:
    cert = x509.load_pem_x509_certificate(cert_pem.encode())
    return cert.fingerprint(hashes.SHA256()).hex()


def validate_certificate(cert_pem: str, ca_cert_pem: str, check_ocsp: bool = True) -> x509.Certificate:
    """Checks 3, 4, and 6: chains to our CA, within validity, not revoked."""
    cert = x509.load_pem_x509_certificate(cert_pem.encode())
    ca = x509.load_pem_x509_certificate(ca_cert_pem.encode())

    if cert.issuer != ca.subject:
        raise EnvelopeError(f"Certificate issuer '{cert.issuer.rfc4514_string()}' is not our CA")
    try:
        cert.verify_directly_issued_by(ca)
    except (InvalidSignature, ValueError, TypeError) as e:
        raise EnvelopeError(f"Certificate was not signed by our CA: {e}") from e

    now = time.time()
    if not (cert.not_valid_before_utc.timestamp() <= now <= cert.not_valid_after_utc.timestamp()):
        raise EnvelopeError("Certificate outside its validity period")

    if check_ocsp:
        try:
            status = ocsp_check(cert_pem, ca_cert_pem)
        except OCSPError as e:
            raise EnvelopeError(f"Revocation check failed (fail closed): {e}") from e
        if status != "GOOD":
            raise EnvelopeError(f"Certificate for '{cert_common_name(cert)}' has been revoked (OCSP)")
    return cert


def verify_envelope(
    envelope: dict,
    receiver_role: str,
    ca_cert_pem: str,
    replay_cache: ReplayCache,
    check_ocsp: bool = True,
) -> dict:
    """Full six-step validation. Returns the payload dict on success,
    raises EnvelopeError on any failure."""
    try:
        cert = x509.load_pem_x509_certificate(envelope["cert_pem"].encode())
        payload_b64 = envelope["payload_b64"]
        timestamp = int(envelope["timestamp"])
        nonce = envelope["nonce"]
        signature = base64.b64decode(envelope["signature_b64"])
    except (KeyError, ValueError, TypeError) as e:
        raise EnvelopeError(f"Malformed envelope: {e}") from e

    # 1. Proof-of-possession: only the certificate's key holder can sign.
    try:
        cert.public_key().verify(
            signature,
            _canonical_bytes(payload_b64, timestamp, nonce),
            padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
            hashes.SHA256(),
        )
    except InvalidSignature:
        raise EnvelopeError("Envelope signature invalid — caller does not hold the private key")

    # 2. Freshness and replay.
    age = time.time() - timestamp
    if not (-5 <= age <= ENVELOPE_MAX_AGE_SECONDS):
        raise EnvelopeError(f"Envelope expired or from the future (age {age:.0f}s)")
    if not replay_cache.check_and_add(nonce):
        raise EnvelopeError("Envelope nonce already used — replay detected")

    # 3, 4, 6. Chain of trust, validity period, OCSP.
    validate_certificate(envelope["cert_pem"], ca_cert_pem, check_ocsp=check_ocsp)

    # 5. Role authorization: forward-only chain of trust.
    caller_role = extract_role(cert_common_name(cert))
    allowed = ALLOWED_CALLER_ROLES.get(receiver_role, [])
    if caller_role not in allowed:
        raise EnvelopeError(
            f"Agent role '{caller_role}' is not authorized to call '{receiver_role}' "
            f"(allowed: {allowed})"
        )

    return json.loads(base64.b64decode(payload_b64))
