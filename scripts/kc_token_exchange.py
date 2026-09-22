"""Configure Keycloak for RFC 8693 standard token exchange.

Called by scripts/setup.sh and scripts/setup.bat after the realm/client/user
exist. Steps:

  1. Enable `standard.token.exchange.enabled` on the Streamlit app client.
  2. Create the `<audience>` client — exists only to be a valid `aud` value.
  3. Create an OPTIONAL client scope whose audience mapper stamps that `aud`.
     Optional means only an exchange that REQUESTS the scope gets the audience;
     the original password-grant token stays unscoped and the MCP server
     rejects it.
  4. Attach the scope to the app client as optional.

Config via environment variables:
  KC_HOST (e.g. http://localhost:8080), KC_REALM, KC_CLIENT_ID,
  KC_ADMIN_USER (default admin), KC_ADMIN_PASSWORD,
  KC_AUDIENCE (default mcp-server), KC_EXCHANGE_SCOPE (default mcp-audience)
"""

import json
import os
import sys
import urllib.error
import urllib.parse
import urllib.request

HOST = os.environ["KC_HOST"].rstrip("/")
REALM = os.environ["KC_REALM"]
CLIENT_ID = os.environ["KC_CLIENT_ID"]
ADMIN_USER = os.environ.get("KC_ADMIN_USER", "admin")
ADMIN_PASSWORD = os.environ["KC_ADMIN_PASSWORD"]
AUDIENCE = os.environ.get("KC_AUDIENCE", "mcp-server")
SCOPE = os.environ.get("KC_EXCHANGE_SCOPE", "mcp-audience")


def _req(method, url, token=None, data=None, form=False):
    headers = {}
    body = None
    if token:
        headers["Authorization"] = f"Bearer {token}"
    if form is not None and data is not None and form:
        body = urllib.parse.urlencode(data).encode()
        headers["Content-Type"] = "application/x-www-form-urlencoded"
    elif data is not None:
        body = json.dumps(data).encode()
        headers["Content-Type"] = "application/json"
    # Validate URL scheme to prevent SSRF - only allow http/https
    parsed = urllib.parse.urlparse(url)
    if parsed.scheme not in ("http", "https"):
        return 400, {"error": f"Invalid URL scheme: {parsed.scheme}. Only http and https are allowed."}
    # Additional validation: ensure hostname is present
    if not parsed.netloc:
        return 400, {"error": "Invalid URL: missing hostname"}
    r = urllib.request.Request(url, data=body, headers=headers, method=method)
    try:
        with urllib.request.urlopen(r, timeout=15) as resp:  # nosec B310 - URL scheme validated above
            raw = resp.read()
            return resp.status, (json.loads(raw) if raw else None)
    except urllib.error.HTTPError as e:
        raw = e.read()
        try:
            err_parsed = json.loads(raw) if raw else None
        except Exception:
            err_parsed = raw.decode(errors="replace")
        return e.code, err_parsed


def main():
    # Admin token (master realm, admin-cli public client).
    status, tok = _req(
        "POST",
        f"{HOST}/realms/master/protocol/openid-connect/token",
        data={
            "grant_type": "password",
            "client_id": "admin-cli",
            "username": ADMIN_USER,
            "password": ADMIN_PASSWORD,
        },
        form=True,
    )
    if status != 200 or not tok:
        print(f"[token-exchange] FAILED to obtain admin token (HTTP {status}): {tok}", file=sys.stderr)
        return 1
    admin = tok["access_token"]
    adm = f"{HOST}/admin/realms/{REALM}"

    # 1. Enable standard token exchange on the app client.
    status, clients = _req("GET", f"{adm}/clients?clientId={urllib.parse.quote(CLIENT_ID)}", token=admin)
    if status != 200 or not clients:
        print(f"[token-exchange] Could not find client '{CLIENT_ID}' (HTTP {status})", file=sys.stderr)
        return 1
    client = clients[0]
    cid = client["id"]
    client.setdefault("attributes", {})["standard.token.exchange.enabled"] = "true"
    status, _ = _req("PUT", f"{adm}/clients/{cid}", token=admin, data=client)
    print(f"[token-exchange] enable standard token exchange on {CLIENT_ID}: HTTP {status}")

    # 2. Audience target client (idempotent; 409 = already exists).
    status, _ = _req("POST", f"{adm}/clients", token=admin, data={
        "clientId": AUDIENCE, "enabled": True, "publicClient": False,
        "standardFlowEnabled": False, "directAccessGrantsEnabled": False,
        "serviceAccountsEnabled": False,
    })
    print(f"[token-exchange] create '{AUDIENCE}' audience client: HTTP {status}")

    # 3. Optional client scope with an audience mapper (idempotent).
    status, _ = _req("POST", f"{adm}/client-scopes", token=admin, data={
        "name": SCOPE, "protocol": "openid-connect",
        "attributes": {"include.in.token.scope": "true", "display.on.consent.screen": "false"},
        "protocolMappers": [{
            "name": f"{AUDIENCE}-aud", "protocol": "openid-connect",
            "protocolMapper": "oidc-audience-mapper",
            "config": {"included.client.audience": AUDIENCE,
                       "access.token.claim": "true", "id.token.claim": "false"},
        }],
    })
    print(f"[token-exchange] create '{SCOPE}' optional scope: HTTP {status}")

    # 4. Attach the scope to the app client as optional.
    status, scopes = _req("GET", f"{adm}/client-scopes", token=admin)
    scid = next((s["id"] for s in (scopes or []) if s.get("name") == SCOPE), None)
    if scid:
        status, _ = _req("PUT", f"{adm}/clients/{cid}/optional-client-scopes/{scid}", token=admin)
        print(f"[token-exchange] attach '{SCOPE}' as optional to {CLIENT_ID}: HTTP {status}")
    else:
        print(f"[token-exchange] WARNING: scope '{SCOPE}' not found to attach", file=sys.stderr)

    print("[token-exchange] done.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
