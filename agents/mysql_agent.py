"""MySQL Agent with signed agent-to-agent authentication.

    1. Validates orchestrator's signature on the request
    2. Signs request to MCP server, passes OAuth token and user delegation
    3. MCP server validates all three

Orchestrator agent resets auth context before each invocation to support
multiple users.

"""
from mcp import stdio_client, StdioServerParameters
from strands import Agent, tool
from strands.tools.mcp import MCPClient
import sys
import os
import time
import random

from config.settings import get_bedrock_model, EJBCA_ISSUING_CA_CERT, MYSQL_AGENT
from pki.envelope import ReplayCache, sign_envelope, verify_envelope


# Per-invocation auth context (set before each orchestrator invocation).
_auth_context = {}
_replay_cache = ReplayCache()


def set_auth_context(agent_access_token: str, delegation: dict, username: str = None,
                     agent_token_expires_at: float = 0):
    """Set the authentication context for the current user session.

    Args:
        agent_access_token: The user's RFC 8693 downscoped OAuth token
            (audience = MCP server). NOT the full-session token.
        delegation: The user-signed delegation assertion authorizing this
            session's agent certificates.
        username: Current user's username.
        agent_token_expires_at: Epoch time after which the downscoped token
            must be re-minted (see _ensure_valid_agent_token).
    """
    global _auth_context
    _auth_context = {
        "agent_access_token": agent_access_token,
        "delegation": delegation,
        "username": username or "unknown",
        "agent_token_expires_at": agent_token_expires_at,
    }


def _ensure_valid_agent_token() -> str:
    """Return a currently-valid downscoped MCP token, re-minting it on demand.

    The downscoped token is short-lived and refreshed when it expires. The 
    agent never has the user's full-session credential, only a more narrowly
    scoped version from token exchange.
    """
    from auth.session import refresh_agent_token, token_needs_refresh

    ctx = _auth_context
    if not token_needs_refresh(ctx.get("agent_token_expires_at", 0)):
        return ctx["agent_access_token"]

    print(f"[MySQL Agent] Downscoped token near/at expiry — re-exchanging for '{ctx.get('username')}'")
    fresh = refresh_agent_token(ctx["username"])   # raises if session can't be refreshed
    ctx["agent_access_token"] = fresh["agent_access_token"]
    ctx["agent_token_expires_at"] = fresh["agent_token_expires_at"]
    return ctx["agent_access_token"]


def _load_mysql_agent_identity(username: str):
    """Load this agent's own certificate + private key (PEM) from Secrets
    Manager. The key is used in-process to sign MCP envelopes and never leaves."""
    from auth.agent_cert_manager import get_or_issue_agent_cert
    from pki.keys import cert_and_key_pem_from_p12

    cred = get_or_issue_agent_cert(MYSQL_AGENT, username=username)
    if not cred:
        raise PermissionError("mysql-agent certificate unavailable — is the user logged in?")
    return cert_and_key_pem_from_p12(cred["p12_data_b64"], cred["password"])


def handle_query(envelope: dict) -> str:
    """Entry point for the orchestrator. Verifies the caller's signed envelope
    (only orchestrator-agent is authorized), extracts the request, and answers
    it via the MCP server under triple auth.

    Args:
        envelope: Signed request envelope from the orchestrator, payload
            {"request": <natural-language question>}.

    Returns:
        Query results or an error message.
    """
    ctx = _auth_context
    delegation = ctx.get("delegation")
    username = ctx.get("username", "unknown")

    # Re-mint the downscoped MCP token if it is at/near expiry (long chats).
    try:
        agent_access_token = _ensure_valid_agent_token()
    except Exception as e:
        print(f"[MySQL Agent] ✗ Could not refresh session token for '{username}': {e}")
        return f"Access denied: your session has expired — please log in again. ({e})"

    ca_pem = open(EJBCA_ISSUING_CA_CERT).read()

    # 1. Verify the orchestrator's envelope (proof-of-possession + role + OCSP).
    try:
        print(f"[MySQL Agent] Verifying orchestrator envelope for user '{username}' "
              f"(PoP + CA chain + role + OCSP)...")
        payload = verify_envelope(envelope, MYSQL_AGENT, ca_pem, _replay_cache)
        query = payload["request"]
        print(f"[MySQL Agent] ✓ Orchestrator envelope verified — caller authenticated")
    except Exception as e:
        print(f"[MySQL Agent] ✗ Orchestrator envelope verification FAILED: {e}")
        return f"Access denied: Agent authentication failed - {e}"

    # 2. Load our own identity for signing outbound MCP envelopes.
    try:
        agent_cert_pem, agent_key_pem = _load_mysql_agent_identity(username)
    except Exception as e:
        return f"Error: could not load mysql-agent identity - {e}"

    # Retry with backoff on MCP connection issues.
    max_retries = 2
    for attempt in range(max_retries + 1):
        try:
            if attempt > 0:
                delay = (2 ** attempt) + random.uniform(0, 1)
                print(f"  Retrying MCP connection (attempt {attempt + 1}/{max_retries + 1}) after {delay:.1f}s...")
                time.sleep(delay)

            return _run_via_mcp(query, agent_access_token, delegation,
                                agent_cert_pem, agent_key_pem, username)
        except Exception as e:
            print(f"  MySQL agent error (attempt {attempt + 1}): {e}")
            if attempt == max_retries:
                return f"Error querying database: {str(e)}"
            continue

    return "Error: Unable to process request after multiple attempts."


def _run_via_mcp(query: str, agent_access_token: str, delegation: dict,
                 agent_cert_pem: str, agent_key_pem: str, username: str) -> str:
    """Spawn the MCP server, expose auth-injecting wrapper tools to the LLM, and
    answer the query. Each wrapper signs a fresh envelope bound to the
    tool + args and attaches the token + delegation in the `auth` argument."""
    current_dir = os.path.dirname(os.path.abspath(__file__))
    project_root = os.path.dirname(current_dir)
    server_path = os.path.join(project_root, "fastmcp_server.py")

    print(f"\n{'='*60}")
    print(f"[MySQL Agent] Creating MCP client for user: {username}")
    print(f"[MySQL Agent] MCP Server path: {server_path}")
    print(f"[MySQL Agent] Downscoped token provided: {bool(agent_access_token)}")
    print(f"[MySQL Agent] Delegation provided: {bool(delegation)}")
    print(f"[MySQL Agent] Signing MCP calls with mysql-agent key")
    print(f"{'='*60}")

    # No credentials in the environment — only the executable + script path.
    stdio_mcp_client = MCPClient(
        lambda: stdio_client(
            StdioServerParameters(
                command=sys.executable,
                args=[server_path],
                env=dict(os.environ),
            )
        )
    )

    tool_counter = {"n": 0}

    def call_mcp(tool_name: str, args: dict) -> str:
        """Sign the exact invocation and call the MCP server. The envelope binds
        tool name + args, so it authorizes this call and nothing else."""
        tool_counter["n"] += 1
        envelope = sign_envelope({"tool": tool_name, "args": args}, agent_cert_pem, agent_key_pem)
        print(f"\n[MySQL Agent] → MCP call #{tool_counter['n']}: {tool_name}({args})")
        print(f"[MySQL Agent]   signed envelope over {{tool, args}} with mysql-agent key "
              f"(nonce={envelope['nonce'][:8]}...); attaching downscoped token + delegation")
        auth = {
            "access_token": agent_access_token,
            "delegation": delegation,
            "envelope": envelope,
        }
        result = stdio_mcp_client.call_tool_sync(
            tool_use_id=f"mysql-agent-{tool_counter['n']}",
            name=tool_name,
            arguments={**args, "auth": auth},
        )
        text = "".join(
            c.get("text", "") if isinstance(c, dict) else getattr(c, "text", "")
            for c in result["content"]
        )
        print(f"[MySQL Agent]   ← MCP result ({len(text)} chars): {text[:150]}"
              f"{'...' if len(text) > 150 else ''}")
        return text

    with stdio_mcp_client:
        print(f"[MySQL Agent] MCP client connected; exposing 3 auth-injecting tools to the LLM")
        print(f"[MySQL Agent] Handing query to the LLM: {query!r}")

        @tool
        def list_tables() -> str:
            """List all tables in the application database."""
            return call_mcp("list_tables", {})

        @tool
        def describe_table(table_name: str) -> str:
            """Describe the columns of a database table."""
            return call_mcp("describe_table", {"table_name": table_name})

        @tool
        def execute_sql(query: str) -> str:
            """Execute a SQL query against the database."""
            return call_mcp("execute_sql", {"query": query})

        agent = Agent(
            model=get_bedrock_model(),
            tools=[list_tables, describe_table, execute_sql],
            system_prompt="""You are a MySQL database agent with MCP tools.

WORKFLOW for every request:
1. Call describe_table with table_name "users" to learn column names
2. Write SQL using those exact column names
3. Call execute_sql with your SQL query
4. After getting results from execute_sql, you MUST write the complete data as your final text response.

You can execute ALL SQL operations: SELECT, INSERT, UPDATE, DELETE.
The execute_sql tool supports read AND write operations. Do not refuse write requests.

CRITICAL: Always end with a text message containing the actual data. Never end on just a tool call.
Copy the full output from execute_sql into your response.
""",
        )

        response = agent(query)
        response_str = str(response)

        if not response_str.strip():
            if hasattr(response, 'message') and response.message:
                for block in response.message.get('content', []):
                    if isinstance(block, dict) and 'text' in block:
                        response_str = block['text']
                        break

        if not response_str.strip() and hasattr(response, 'messages'):
            for msg in reversed(response.messages):
                if not isinstance(msg, dict):
                    continue
                for block in msg.get('content', []):
                    if isinstance(block, dict) and 'toolResult' in block:
                        for inner in block['toolResult'].get('content', []):
                            if isinstance(inner, dict) and 'text' in inner and len(inner['text']) > 20:
                                response_str = inner['text']
                                break
                    if response_str.strip():
                        break
                if response_str.strip():
                    break

        print(f"\n{'='*60}")
        print(f"[MySQL Agent] Response: {response_str[:300]}")
        print(f"{'='*60}")
        return response_str
