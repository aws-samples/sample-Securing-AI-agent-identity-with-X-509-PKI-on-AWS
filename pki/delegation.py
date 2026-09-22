"""User-signed delegation assertions.

At login, the Streamlit app mints a delegation assertion signed by the
user's key authorizing specific agent certificates (by SHA-256 fingerprint) to
act on the user's behalf until an expiry time. Agents carry this assertion
instead of the user's credential.

Revoking the user cert at logout kills agents' abilities to act, since the
delegation becomes invalid.
"""

import base64
import json
import time

from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding

from config.settings import DELEGATION_MAX_AGE_HOURS
from pki.envelope import EnvelopeError, cert_common_name, cert_fingerprint, validate_certificate


def mint_delegation(
    username: str,
    user_cert_pem: str,
    user_key_pem: str,
    agent_cert_pems: list[str],
) -> dict:
    """Sign a delegation of authority from the user to the given agent
    certificates. Called once at login; the user's key never leaves the
    login flow."""
    claims = {
        "sub": username,
        "agent_fingerprints": sorted(cert_fingerprint(p) for p in agent_cert_pems),
        "iat": int(time.time()),
        "exp": int(time.time()) + DELEGATION_MAX_AGE_HOURS * 3600,
    }
    claims_b64 = base64.b64encode(json.dumps(claims, sort_keys=True).encode()).decode()
    key = serialization.load_pem_private_key(user_key_pem.encode(), password=None)
    signature = key.sign(
        claims_b64.encode(),
        padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
        hashes.SHA256(),
    )
    return {
        "claims_b64": claims_b64,
        "user_cert_pem": user_cert_pem,
        "signature_b64": base64.b64encode(signature).decode(),
        "alg": "RSA-PSS-SHA256",
    }


def verify_delegation(
    delegation: dict,
    agent_cert_pem: str,
    ca_cert_pem: str,
    check_ocsp: bool = True,
) -> dict:
    """Verify a delegation assertion and that `agent_cert_pem` is one of the
    certificates the user authorized. Returns the claims on success."""
    try:
        user_cert = x509.load_pem_x509_certificate(delegation["user_cert_pem"].encode())
        claims_b64 = delegation["claims_b64"]
        signature = base64.b64decode(delegation["signature_b64"])
    except (KeyError, ValueError, TypeError) as e:
        raise EnvelopeError(f"Malformed delegation: {e}") from e

    # Signature: proves the user's key holder authorized this delegation.
    try:
        user_cert.public_key().verify(
            signature,
            claims_b64.encode(),
            padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
            hashes.SHA256(),
        )
    except InvalidSignature:
        raise EnvelopeError("Delegation signature invalid")

    claims = json.loads(base64.b64decode(claims_b64))

    if time.time() > claims["exp"]:
        raise EnvelopeError("Delegation has expired")

    # The user certificate itself: chains to our CA, in validity, not revoked.
    # Revoking the user cert (logout) kills all outstanding delegations.
    validate_certificate(delegation["user_cert_pem"], ca_cert_pem, check_ocsp=check_ocsp)

    # The user cert must actually belong to the delegating subject.
    cn = cert_common_name(user_cert)
    if cn != claims["sub"]:
        raise EnvelopeError(f"Delegation subject '{claims['sub']}' does not match user cert CN '{cn}'")

    # The presenting agent must be on the user's authorized list.
    if cert_fingerprint(agent_cert_pem) not in claims["agent_fingerprints"]:
        raise EnvelopeError("Agent certificate is not authorized by this delegation")

    return claims
