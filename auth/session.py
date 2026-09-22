"""Agent-session bootstrap 

This produces the credentials an orchestrator needs to run.

Login (Keycloak password/cert grant + EJBCA user cert issuance) is handled by
keycloak_auth.py / certificate_manager.py. This module takes it from there and
produces the two crypto artifacts:

  1. agent_access_token — the user's access token downscoped through token exchange
     to `aud = KEYCLOAK_TOKEN_AUDIENCE` (the MCP server).
     The original session token stays UI-side (logout only). This token is
     short-lived, so `refresh_agent_token` re-mints it on demand (below).

  2. delegation — a user-signed assertion authorizing this session's three
     agent certificates (by fingerprint) to act for the user.
     Agents carry the delegation instead of the user's certificate/key.
     The delegation is long-lived for the session.

Both are computed on the UI side and handed to the orchestrator.
"""

import time

from config.settings import (
    ALL_AGENT_ROLES,
    KEYCLOAK_TOKEN_AUDIENCE,
    KEYCLOAK_TOKEN_EXCHANGE_SCOPE,
)
from pki.delegation import mint_delegation
from pki.keys import cert_and_key_pem_from_p12

# Re-exchange a bit before the token actually expires, to cover clock skew and
# the round-trip latency of the exchange/introspection calls themselves.
_TOKEN_EXPIRY_SKEW_SECONDS = 30


def bootstrap_agent_session(username: str, access_token: str,
                            user_p12_data: bytes, user_p12_password: str) -> dict:
    """Produce the downscoped agent token and the user-signed delegation.

    Args:
        username: The logged-in user (also the user certificate CN).
        access_token: The user's full-session Keycloak access token.
        user_p12_data: The user's P12 bundle bytes (from Secrets Manager).
        user_p12_password: Password for the user's P12.

    Returns:
        {"agent_access_token": str, "delegation": dict, "agent_token_expires_at": float}
        where agent_token_expires_at is an epoch time after which the token
        should be re-minted via refresh_agent_token().
    """
    import base64

    from auth.agent_cert_manager import get_or_issue_agent_cert
    from auth.keycloak_auth import KeycloakAuth

    print(f"\n{'='*60}")
    print(f"[SESSION] Bootstrapping agent session for user '{username}'")
    print(f"{'='*60}")

    # 1. Downscope the session token for agent use (RFC 8693). Trusted UI side.
    print(f"[SESSION] Exchanging session token (RFC 8693) → audience '{KEYCLOAK_TOKEN_AUDIENCE}'...")
    kc = KeycloakAuth()
    exchanged = kc.exchange_token(
        access_token, KEYCLOAK_TOKEN_AUDIENCE, KEYCLOAK_TOKEN_EXCHANGE_SCOPE
    )
    agent_access_token = exchanged["access_token"]
    expires_at = time.time() + int(exchanged.get("expires_in", 300))
    print(f"[SESSION] ✓ Downscoped token minted (expires in {int(exchanged.get('expires_in', 300))}s); "
          f"original full-session token stays UI-side")

    # 2. Ensure this user's three agent certificates exist, and collect their
    #    public certs. These exact certs are what the delegation authorizes and
    #    what the agents will present, so they must be pinned now.
    print(f"[SESSION] Ensuring agent certificates exist: {ALL_AGENT_ROLES}")
    agent_cert_pems = []
    for role in ALL_AGENT_ROLES:
        cred = get_or_issue_agent_cert(role, username=username)
        if not cred:
            raise RuntimeError(f"Failed to issue/load agent certificate for role '{role}'")
        cert_pem, _key_pem = cert_and_key_pem_from_p12(cred["p12_data_b64"], cred["password"])
        agent_cert_pems.append(cert_pem)
        print(f"[SESSION]   ✓ {username}_{role}")

    # 3. Mint the delegation with the user's key — the ONLY use of that key on
    #    behalf of agents. The key is extracted in-process and discarded here.
    print(f"[SESSION] Minting user-signed delegation over {len(agent_cert_pems)} agent cert fingerprints...")
    user_cert_pem, user_key_pem = cert_and_key_pem_from_p12(
        base64.b64encode(user_p12_data).decode(), user_p12_password
    )
    delegation = mint_delegation(username, user_cert_pem, user_key_pem, agent_cert_pems)
    print(f"[SESSION] ✓ Delegation minted (user key used only here). Agent session ready.")
    print(f"{'='*60}")

    return {
        "agent_access_token": agent_access_token,
        "delegation": delegation,
        "agent_token_expires_at": expires_at,
    }


def refresh_agent_token(username: str) -> dict:
    """Re-mint the downscoped MCP token for `username`, on demand.

    The downscoped token is short-lived; an agent calls this when its token is
    at/near expiry so a long-running chat doesn't get denied by the MCP server.
    The original session token is kept in Secrets Manager (saved at login and on
    each refresh) — never handed to agents — so this runs entirely from stored
    state without the agent ever seeing the full-session credential:

      1. load the stored original session token,
      2. refresh it via the refresh_token if its access token has expired,
      3. exchange it for a fresh MCP-audience token.

    Returns {"agent_access_token": str, "agent_token_expires_at": float}.
    Raises if no stored token exists or the session can no longer be refreshed
    (the user must re-authenticate) — fail closed.
    """
    from auth.keycloak_auth import KeycloakAuth

    print(f"[SESSION] Re-minting downscoped MCP token for '{username}' (on-demand re-exchange)...")
    kc = KeycloakAuth()
    stored = kc._load_stored_token(username)
    if not stored or not stored.get("access_token"):
        raise RuntimeError(f"No stored session token for '{username}' — re-login required")

    access_token = stored["access_token"]
    try:
        active = bool(kc.validate_token(access_token).get("active"))
    except Exception:
        active = False

    if not active:
        print(f"[SESSION] Stored session token expired — refreshing via refresh_token...")
        refresh = stored.get("refresh_token")
        if not refresh:
            raise RuntimeError(f"Session token for '{username}' expired and cannot be refreshed — re-login required")
        refreshed = kc.refresh_token(refresh)   # raises if the refresh token is also expired
        kc._save_token(username, refreshed)
        access_token = refreshed["access_token"]
        print(f"[SESSION] ✓ Session token refreshed")

    exchanged = kc.exchange_token(
        access_token, KEYCLOAK_TOKEN_AUDIENCE, KEYCLOAK_TOKEN_EXCHANGE_SCOPE
    )
    print(f"[SESSION] ✓ Fresh downscoped token minted (expires in {int(exchanged.get('expires_in', 300))}s)")
    return {
        "agent_access_token": exchanged["access_token"],
        "agent_token_expires_at": time.time() + int(exchanged.get("expires_in", 300)),
    }


def token_needs_refresh(expires_at: float) -> bool:
    """True if a token with the given expiry should be re-minted now."""
    return time.time() >= (expires_at - _TOKEN_EXPIRY_SKEW_SECONDS)
