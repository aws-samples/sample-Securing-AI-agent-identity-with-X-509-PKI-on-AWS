# System Architecture: AI Database Assistant with PKI Authentication

## Overview

This system implements a secure AI-powered database assistant with three layers of certificate-based authentication:
1. **User authentication** — OAuth token + X.509 certificate at login; the token is then **downscoped via RFC 8693** to an MCP-only audience and then handed to the orchestrator.
2. **MCP server authentication** — Audience-scoped token + a signed **agent envelope**
with the tool call + a user-signed **delegation assertion** validated on every SQL operation.
3. **Agent-to-agent authentication** — each agent has its own EJBCA-issued certificate and **signs a request envelope** with its private key; receiving agents verify proof-of-possession before processing.

All certificates are issued by EJBCA Enterprise (PKI CA), stored in AWS Secrets Manager, and validated (CA chain + expiry + OCSP) at every hop. AI agents are powered by Amazon Bedrock via the Strands SDK.

## Component Diagram

```
                              AWS Cloud (us-east-1)
 ┌────────────────────────────────────────────────────────────────────────────┐
 │                                                                            │
 │  ┌──────────────┐  ┌──────────────┐  ┌─────────────────────────────────┐  │
 │  │  Keycloak    │  │  EJBCA       │  │  AWS Secrets Manager            │  │
 │  │  IDP (EC2)   │  │  PKI (EC2)   │  │  mcp/certs/{user}/*            │  │
 │  │  OAuth2+X509 │  │  CA Server   │  │  mcp/agents/{agent}/*          │  │
 │  └──────┬───────┘  └──────┬───────┘  └────────────┬────────────────────┘  │
 │         │                 │                        │                       │
 │  ┌──────┴─────────────────┴────────────────────────┴────────────────────┐  │
 │  │                    Streamlit App (Local)                              │  │
 │  │                                                                      │  │
 │  │  ┌────────────────────────────────────────────────────────────────┐  │  │
 │  │  │  Orchestrator Agent [cert: CN=orchestrator-agent]              │  │  │
 │  │  │                                                                │  │  │
 │  │  │  ┌─────────────────────────┐  ┌────────────────────────────┐  │  │  │
 │  │  │  │  MySQL Agent            │  │  Email Agent               │  │  │  │
 │  │  │  │  [cert: CN=mysql-agent] │  │  [validates orchestrator]  │  │  │  │
 │  │  │  │  validates orchestrator │  │                            │  │  │  │
 │  │  │  └───────────┬────────────┘  └────────────┬───────────────┘  │  │  │
 │  │  └──────────────┼────────────────────────────┼───────────────────┘  │  │
 │  │                 │ stdio                      │                       │  │
 │  │  ┌──────────────┴─────────────────┐         │                       │  │
 │  │  │  FastMCP Server                │         │                       │  │
 │  │  │  validates:                    │         │                       │  │
 │  │  │  • user token (Keycloak)       │         │                       │  │
 │  │  │  • user cert (EJBCA OCSP)      │         │                       │  │
 │  │  │  • agent cert (CN=mysql-agent) │         │                       │  │
 │  │  └───────────┬───────────────────┘         │                       │  │
 │  └──────────────┼─────────────────────────────┼───────────────────────┘  │
 │                 │                              │                          │
 │  ┌──────────────┴───────┐  ┌──────────────────┴──┐  ┌──────────────────┐ │
 │  │  Amazon RDS MySQL    │  │  Amazon SES         │  │  Amazon Bedrock  │ │
 │  │  Database            │  │  Email              │  │  Claude 4.5      │ │
 │  └──────────────────────┘  └─────────────────────┘  └──────────────────┘ │
 └────────────────────────────────────────────────────────────────────────────┘
```

## Traffic Flow

### Login and Certificate Issuance
```
1. User enters username + password in Streamlit
2. Streamlit → Keycloak: password grant → OAuth token
3. Streamlit → Keycloak: RFC 8693 token exchange → downscoped token (aud=mcp-server) for agents
4. Streamlit → EJBCA: enroll user certificate via pkcs10enroll (key generated locally) → user P12 (7-day)
5. Streamlit → EJBCA: issue agent certs (orchestrator-agent, mysql-agent, email-agent)
**NOTE:** There is no separate step to create end-entities for the certificates. EJBCA will
automatically create the end-entities when it receives the CSR's if a matching one does not
already exist.
6. Streamlit mints a user-signed delegation over the 3 agent cert fingerprints (user key used only here).
7. Streamlit → Secrets Manager: store user and agent PKCS bundles, user OAuth token
   (agents carry the downscoped token + delegation; the user's key/full token stay UI-side)
```

### Database Query (Triple Auth on MCP Server)
```
8.  User submits query in Streamlit chat
9.  Orchestrator signs request → MySQL Agent
10. MySQL Agent verifies the envelope (PoP + CA chain + role=orchestrator-agent + OCSP)
11. MySQL Agent spawns FastMCP Server over stdio and passes signed request, user-signed delgation, and downscoped OAuth token.
13. MCP Server validates user OAuth token with Keycloak /introspect
14. MCP Server verifies the agent's signature (PoP, freshness, replay, CA chain, role=mysql-agent, OCSP)
15. MCP Server verifies the delegation against the calling agent's fingerprint + OCSP on the user cert
16. MCP Server cross-checks: token username == delegation.sub == agent-CN prefix
17. MCP Server executes SQL on RDS MySQL
```

### Email (Agent-to-Agent Auth)
```
18. Orchestrator signs request → Email Agent
19. Email Agent verifies the envelope (PoP + CA chain + role=orchestrator-agent + OCSP)
20. Email Agent → AWS SES: send email
```

### LLM
```
21. All agents → Amazon Bedrock inference
```

## Authentication Layers

### Layer 1: User Authentication (Login)
- Password validated with Keycloak IDP
- X.509 certificate issued by EJBCA via `pkcs10enroll` (key generated locally, 7-day validity)
- Certificate + token stored in AWS Secrets Manager

### Layer 2: Agent-to-Agent Authentication
- Each agent has its own EJBCA-issued PKCS bundle
- Orchestrator requests are signed → validated by MySQL and Email Agent.
- Validation: certificates are validated by expiry check +
OCSP revocation check + CN in allowed callers list. Orchestrator's signature + nonce + timestamp are validated.

```python
ALLOWED_CALLER_ROLES = {
    "mysql-agent":  ["orchestrator-agent"],
    "email-agent":  ["orchestrator-agent"],
    "mcp-server":   ["mysql-agent"],
}
```

### Layer 3: MCP Server Triple Authentication
Every tool call validates three credentials:
```python
# 1. OAuth token: active and audience-scoped to this server
info = introspect(auth["access_token"]); assert info["active"] and AUDIENCE in info["aud"]

# 2. Calling agent's signature + nonce + timestamp
payload = verify_envelope(auth["envelope"], "mcp-server", ca_pem, replay_cache)
assert payload == {"tool": tool_name, "args": args}

# 3. User's delegation is checked for calling agent's fingerprint
claims = verify_delegation(auth["delegation"], agent_cert_pem, ca_pem)

# Cross-check: all three identities are the same entity
assert token_username == claims["sub"] == agent_cn.rsplit("_", 1)[0]
```

## Certificate Storage (AWS Secrets Manager)

| Secret Path | Content |
|-------------|---------|
| `mcp/certs/{user}/certificate` | User P12 (base64) + password + metadata |
| `mcp/certs/{user}/token` | OAuth access + refresh tokens |
| `mcp/certs/users` | JSON array of usernames with stored certs |
| `mcp/certs/last_user` | Last logged-in username |
| `mcp/agents/{user}/orchestrator-agent/certificate` | Per-user orchestrator agent P12 |
| `mcp/agents/{user}/mysql-agent/certificate` | Per-user MySQL agent P12 |
| `mcp/agents/{user}/email-agent/certificate` | Per-user email agent P12 |

Agent certs are scoped per user (e.g., `mcp/agents/deepak/orchestrator-agent/certificate`).
EJBCA entity names follow the format `{username}_{agent-role}` (e.g., `deepak_orchestrator-agent`).

## AWS Services Used

| Service | Purpose |
|---------|---------|
| Amazon Bedrock | LLM inference (Claude Sonnet 4.5) |
| Amazon RDS MySQL | Application database |
| Amazon SES | Email delivery |
| AWS Secrets Manager | Certificate + token storage (users + agents) |
| Amazon EC2 | Keycloak IDP + EJBCA PKI servers |

## Project Structure

```
├── streamlit_app.py              # Web UI, user auth flows, chat interface
├── fastmcp_server.py             # MCP Server: triple auth + SQL execution
├── run.bat                       # Windows startup script
├── run.sh                        # macOS / Linux startup script
├── .env.example                  # Environment template (no secrets)
├── .gitignore                    # Git exclusions
├── requirements.txt              # Python dependencies (cross-platform)
├── certs/
│   └── README.md                 # Instructions for generating EJBCA certs
│   # api-admin.p12              (gitignored - generate from your EJBCA)
│   # UserCA.pem                 (gitignored - export from your EJBCA CA)
├── config/
│   ├── __init__.py
│   └── settings.py               # Central config (loads .env); roles + ALLOWED_CALLER_ROLES
├── pki/                          # Cryptographic primitives
│   ├── __init__.py
│   ├── envelope.py               # sign/verify signed envelopes (PoP, replay, chain, role, OCSP)
│   ├── delegation.py             # mint/verify user-signed delegation assertions
│   ├── ocsp.py                   # OCSP check
│   └── keys.py                   # extract cert+key PEM from a stored P12
├── auth/
│   ├── __init__.py
│   ├── keycloak_auth.py          # Keycloak OAuth + RFC 8693 exchange + user cert issuance
│   ├── session.py                # login bootstrap: token downscope + delegation minting
│   ├── certificate_manager.py    # User certificate CRUD via Secrets Manager
│   └── agent_cert_manager.py     # Per-user agent certificate issuance/revocation
├── agents/
│   ├── __init__.py
│   ├── orchestrator_agent.py     # Routes queries
│   ├── mysql_agent.py            # Verifies orchestrator request; signs requests to MySQL MCP server
│   └── email_agent.py            # Verifies orchestrator request before sending
├── tests/
│   ├── test_pki.py               # Offline adversarial crypto tests (no stack)
│   └── test_mcp_triple_auth.py   # Live-stack MCP triple-auth integration test
└── generated-diagrams/           # Architecture diagrams (.drawio, .png)
```

## Security Summary

- **Triple MCP auth**: audience-scoped token + signed agent request + signed user delegation validated on every tool call
- **Agent-to-agent-to-MCP cert auth**: Agent pass signed requests to each other and the MCP server. Forward-only chain of trust prevents lateral calls between agents and confused deputies.
- **Downscoped OAuth Tokens**: Agents carry a short-lived downscoped token with permissions only for the MCP servers they have access to. Agents are unable to make lateral calls, and leaked tokens have limited impact.
- **User-Signed Delegation**: Agents prove they act for the user via a user-signed delegation; revoking the user cert at logout invalidates all outstanding delegations and kills agents' ability to act.
- **Identity cross-check**: Token username must match certificate CN and thumbprint on user delegation.
- **OCSP check**: All certs (user + agent) are checked for revocation in real-time.
- **Short-lived certificates**: 7-day validity for both user and agent certs
- **Secrets Manager**: No certs or tokens on local filesystem
- **SQL safety**: DROP, TRUNCATE, ALTER, CREATE, GRANT, REVOKE blocked

## Platform Support

This project runs on **Windows**, **macOS**, and **Linux**. All Python dependencies are cross-platform.

| Component | Windows | macOS / Linux |
|-----------|---------|---------------|
| Startup script | `run.bat` | `run.sh` |
| Virtual env activation | `venv\Scripts\activate` | `source venv/bin/activate` |
| Python command | `python` | `python3` |
| Cert verification | `certutil -dump file.p12` | `openssl pkcs12 -info -in file.p12 -nokeys` |

See `certs/README.md` for platform-specific certificate setup instructions.
