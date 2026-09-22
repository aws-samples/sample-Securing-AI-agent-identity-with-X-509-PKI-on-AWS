"""MySQL MCP Server — the gateway between AI agents and the database.

This server provides SQL query execution capabilities via the Model Context Protocol (MCP).
It connects to MySQL database and exposes tools for executing SQL queries.

Security: Every tool call validates the agent's OAuth token with Keycloak IDP,
the agent's signature on the request, and the agent's delegation from the user
before executing any database operation.
"""
import sys
import json
import re
import pymysql
from pymysql.cursors import DictCursor
from fastmcp import FastMCP
import requests

from cryptography import x509

from config.settings import (
    RDS_HOST, RDS_PORT, RDS_USER, RDS_PASS, RDS_DB,
    KEYCLOAK_URL, KEYCLOAK_REALM, KEYCLOAK_CLIENT_ID, KEYCLOAK_CLIENT_SECRET,
    KEYCLOAK_TOKEN_AUDIENCE, EJBCA_ISSUING_CA_CERT, get_tls_verify,
)
from pki.envelope import EnvelopeError, ReplayCache, cert_common_name, verify_envelope
from pki.delegation import verify_delegation

mcp = FastMCP("MySQL Database Server")

_replay_cache = ReplayCache()
_ca_pem = open(EJBCA_ISSUING_CA_CERT).read()

print(f"[MCP SERVER STARTUP] Server active", file=sys.stderr)
print(f"[MCP SERVER STARTUP] Trust anchor: {EJBCA_ISSUING_CA_CERT}", file=sys.stderr)


def _log(msg: str = "") -> None:
    print(msg, file=sys.stderr)


def get_db_connection():
    """Create and return a MySQL database connection."""
    return pymysql.connect(
        host=RDS_HOST,
        port=RDS_PORT,
        user=RDS_USER,
        password=RDS_PASS,
        database=RDS_DB,
        cursorclass=DictCursor,
        connect_timeout=10
    )


def _introspect(access_token: str) -> dict:
    """Real-time token validation with Keycloak. Fail-closed: any failure to
    reach or parse the introspection endpoint raises."""
    _log(f"[MCP SERVER] --- 1/3 OAuth token introspection ---")
    _log(f"[MCP SERVER] Token present: {bool(access_token)}")
    if not access_token:
        _log(f"[MCP SERVER] ✗ No OAuth token provided. Access denied.")
        raise EnvelopeError("No OAuth token provided")

    introspect_url = (
        f"{KEYCLOAK_URL}/realms/{KEYCLOAK_REALM}"
        f"/protocol/openid-connect/token/introspect"
    )
    _log(f"[MCP SERVER] Introspecting with Keycloak: {introspect_url}")
    try:
        response = requests.post(
            introspect_url,
            data={
                "token": access_token,
                "client_id": KEYCLOAK_CLIENT_ID,
                "client_secret": KEYCLOAK_CLIENT_SECRET,
            },
            verify=get_tls_verify(),
            timeout=10,
        )
        _log(f"[MCP SERVER] Keycloak introspect HTTP {response.status_code}")
        response.raise_for_status()
        return response.json()
    except requests.RequestException as e:
        _log(f"[MCP SERVER] ✗ Introspection unavailable, failing closed: {e}")
        raise EnvelopeError(f"Token introspection unavailable, failing closed: {e}") from e


def _authenticate(tool_name: str, args: dict, auth: dict) -> str:
    """Triple authentication. Returns the authenticated username, or raises
    EnvelopeError (deny) on any failure.

    Args:
        tool_name: The tool being invoked (must match the envelope payload).
        args: The tool arguments (must match the envelope payload).
        auth: {"access_token", "delegation", "envelope"} — no private keys.
    """
    _log(f"\n{'='*60}")
    _log(f"[MCP SERVER] Triple authentication started for tool: {tool_name}")
    _log(f"[MCP SERVER] Args: {args}")
    _log(f"{'='*60}")
    if not isinstance(auth, dict):
        raise EnvelopeError("Missing auth argument")

    # -- 1. OAuth token: real-time introspection + audience restriction --
    info = _introspect(auth.get("access_token"))
    if not info.get("active"):
        _log(f"[MCP SERVER] ✗ Token is INACTIVE/EXPIRED. Access denied.")
        raise EnvelopeError("Access denied: OAuth token is not active")
    aud = info.get("aud", [])
    aud = aud if isinstance(aud, list) else [aud]
    _log(f"[MCP SERVER] Token audience: {aud} (require '{KEYCLOAK_TOKEN_AUDIENCE}')")
    if KEYCLOAK_TOKEN_AUDIENCE not in aud:
        _log(f"[MCP SERVER] ✗ Token audience not scoped to this server. Access denied.")
        raise EnvelopeError("Access denied: OAuth token audience not scoped to this server")
    token_username = info.get("preferred_username", info.get("sub", ""))
    _log(f"[MCP SERVER] ✓ Token active + audience OK for user: {token_username}")

    # -- 2. Calling agent: signed envelope bound to this exact invocation --
    _log(f"[MCP SERVER] --- 2/3 Agent envelope (PoP + freshness + replay + chain + role + OCSP) ---")
    envelope = auth.get("envelope")
    if not envelope:
        _log(f"[MCP SERVER] ✗ No agent envelope provided. Access denied.")
        raise EnvelopeError("Missing agent envelope")
    payload = verify_envelope(envelope, "mcp-server", _ca_pem, _replay_cache)
    if payload != {"tool": tool_name, "args": args}:
        _log(f"[MCP SERVER] ✗ Envelope payload {payload} != invocation. Replay/mismatch. Access denied.")
        raise EnvelopeError("Access denied: envelope payload does not match this tool invocation")
    agent_cert_pem = envelope["cert_pem"]
    agent_cn = cert_common_name(x509.load_pem_x509_certificate(agent_cert_pem.encode()))
    _log(f"[MCP SERVER] ✓ Envelope verified — caller CN={agent_cn}, payload bound to this exact call")

    # -- 3. User authority: delegation assertion covering this agent cert --
    _log(f"[MCP SERVER] --- 3/3 User delegation (signature + expiry + user-cert OCSP + fingerprint) ---")
    delegation = auth.get("delegation")
    if not delegation:
        _log(f"[MCP SERVER] ✗ No delegation assertion provided. Access denied.")
        raise EnvelopeError("Missing delegation assertion")
    claims = verify_delegation(delegation, agent_cert_pem, _ca_pem)
    _log(f"[MCP SERVER] ✓ Delegation verified — subject={claims['sub']}, agent cert is authorized")

    # -- Cross-check: all three identities must be the same person --
    agent_username = agent_cn.rsplit("_", 1)[0]
    _log(f"[MCP SERVER] Identity cross-check: token='{token_username}' delegation='{claims['sub']}' agent='{agent_username}'")
    if not (token_username == claims["sub"] == agent_username):
        _log(f"[MCP SERVER] ✗ Identity mismatch. Access denied.")
        raise EnvelopeError(
            "Access denied: identity mismatch between token "
            f"('{token_username}'), delegation ('{claims['sub']}'), and agent ('{agent_username}')"
        )

    _log(f"[MCP SERVER] ✓✓✓ TRIPLE AUTH PASSED for user '{token_username}' calling {tool_name}")
    _log(f"{'='*60}")
    return token_username


def _authorized_username(tool_name: str, args: dict, auth: dict):
    """Authenticate and return (username, None) on success, or (None, error)."""
    try:
        username = _authenticate(tool_name, args, auth)
        return username, None
    except EnvelopeError as e:
        _log(f"[MCP SERVER] ✗ {tool_name} DENIED: {e}")
        return None, f"Access denied: {e}"
    except Exception as e:
        _log(f"[MCP SERVER] ✗ {tool_name} DENIED (failing closed): {e}")
        return None, f"Access denied (failing closed): {e}"


# Allowed column names for the users table (whitelist)
_ALLOWED_COLUMNS = frozenset([
    'id', 'username', 'email', 'name', 'first_name', 'last_name',
    'created_at', 'updated_at', 'status', 'role', 'department'
])

# Allowed filter columns (subset that can be used in WHERE clauses)
_ALLOWED_FILTER_COLUMNS = frozenset([
    'id', 'username', 'email', 'name', 'status', 'role', 'department'
])


def _validate_identifier(name: str, allowed: frozenset, label: str) -> bool:
    """Validate that an identifier is in the allowed set (defense in depth)."""
    # Only allow simple alphanumeric identifiers with underscores
    if not re.match(r'^[a-zA-Z_][a-zA-Z0-9_]*$', name):
        return False
    return name.lower() in allowed


@mcp.tool()
def query_users(
    columns: list[str] = None,
    where_column: str = None,
    where_value: str = None,
    limit: int = 100,
    count_only: bool = False,
    auth: dict = None
) -> str:
    """Query the users table with parameterized, safe SQL execution.

    This tool constructs SQL queries server-side using parameterized templates,
    completely separating SQL structure from user-supplied data values.

    Args:
        columns: List of column names to select (default: all allowed columns).
                 Allowed: id, username, email, name, first_name, last_name,
                 created_at, updated_at, status, role, department
        where_column: Column name for WHERE filter (optional).
                      Allowed: id, username, email, name, status, role, department
        where_value: Value to filter by (required if where_column is set).
                     This value is passed as a bound parameter, never interpolated.
        limit: Maximum rows to return (1-1000, default 100)
        count_only: If True, return COUNT(*) instead of rows
        auth: Per-call authentication {access_token, delegation, envelope}

    Returns:
        Formatted string with query results or error message
    """
    # Build canonical args for authentication (before any processing)
    auth_args = {
        "columns": columns,
        "where_column": where_column,
        "where_value": where_value,
        "limit": limit,
        "count_only": count_only
    }
    
    _log(f"\n[MCP SERVER] query_users called with args: {auth_args}")
    username, error = _authorized_username("query_users", auth_args, auth)
    if error:
        return error

    # --- Input validation (defense in depth) ---
    
    # Validate limit
    if not isinstance(limit, int) or limit < 1 or limit > 1000:
        return "Error: limit must be an integer between 1 and 1000"
    
    # Validate columns if provided
    if columns is not None:
        if not isinstance(columns, list) or len(columns) == 0:
            return "Error: columns must be a non-empty list of column names"
        for col in columns:
            if not _validate_identifier(col, _ALLOWED_COLUMNS, "column"):
                return f"Error: Invalid or disallowed column name: '{col}'. Allowed columns: {sorted(_ALLOWED_COLUMNS)}"
    
    # Validate WHERE clause parameters
    if where_column is not None:
        if not _validate_identifier(where_column, _ALLOWED_FILTER_COLUMNS, "filter column"):
            return f"Error: Invalid or disallowed filter column: '{where_column}'. Allowed: {sorted(_ALLOWED_FILTER_COLUMNS)}"
        if where_value is None:
            return "Error: where_value is required when where_column is specified"
        if not isinstance(where_value, str):
            return "Error: where_value must be a string"
        # Limit value length as defense in depth
        if len(where_value) > 255:
            return "Error: where_value exceeds maximum length of 255 characters"
    
    if where_value is not None and where_column is None:
        return "Error: where_column is required when where_value is specified"

    # --- Build parameterized SQL query ---
    params = []
    
    if count_only:
        sql_template = "SELECT COUNT(*) AS count FROM users"
    else:
        # Build column list (use validated columns or default to *)
        if columns:
            # Columns are already validated against allowlist
            col_list = ", ".join(col.lower() for col in columns)
        else:
            col_list = "*"
        # Security Note: col_list is safe - built only from columns validated against
        # _ALLOWED_COLUMNS whitelist and regex-checked for [a-zA-Z_][a-zA-Z0-9_]* pattern.
        # User-supplied data (where_value) is parameterized with %s, never interpolated.
        sql_template = f"SELECT {col_list} FROM users"  # nosec B608
    
    # Add WHERE clause with bound parameter (never string interpolation)
    if where_column is not None:
        # Column name is validated and safe; value is parameterized
        sql_template += f" WHERE {where_column.lower()} = %s"
        params.append(where_value)
    
    # Add LIMIT (integer already validated)
    if not count_only:
        sql_template += f" LIMIT {limit}"

    _log(f"[MCP SERVER] SQL template: {sql_template}")
    _log(f"[MCP SERVER] Bound parameters: {params}")
    _log(f"[MCP SERVER] Executing against '{RDS_DB}' for user '{username}'...")

    try:
        connection = get_db_connection()
        try:
            with connection.cursor() as cursor:
                # Execute with parameterized query - SQL structure and data are separated
                cursor.execute(sql_template, tuple(params) if params else None)
                results = cursor.fetchall()
                _log(f"[MCP SERVER] ✓ Query returned {len(results)} row(s)")
                
                if count_only:
                    count = results[0]['count'] if results else 0
                    return f"[Authenticated as: {username}] Count: {count}"
                
                if results:
                    cols = [d[0] for d in cursor.description] if cursor.description else []
                    return (
                        f"[Authenticated as: {username}] "
                        f"Query executed successfully. Returned {len(results)} rows.\n\n"
                        f"Columns: {cols}\n\n"
                        f"Rows:\n{json.dumps(results, indent=2, default=str)}"
                    )
                return f"[Authenticated as: {username}] Query executed successfully. No results found."
        finally:
            connection.close()
    except pymysql.Error as e:
        return f"Database error: {str(e)}"
    except Exception as e:
        return f"Unexpected error: {str(e)}"


# Backwards compatibility: keep execute_sql but delegate to query_users
@mcp.tool()
def execute_sql(query: str, auth: dict) -> str:
    """Execute a SQL query against the MySQL database (users table only).
    
    DEPRECATED: Use query_users() for new integrations. This wrapper parses
    simple SELECT queries and delegates to query_users() with parameterized execution.

    Args:
        query: SQL query to execute (must be a simple SELECT on 'users' table)
        auth: Per-call authentication {access_token, delegation, envelope}

    Returns:
        Formatted string with query results or error message
    """
    _log(f"\n[MCP SERVER] execute_sql called with query: {query}")
    
    # Parse the legacy query string into structured parameters
    query_lower = query.lower().strip()
    normalized = ' '.join(query_lower.split())
    
    # Block dangerous keywords as first line of defense
    dangerous_keywords = ['drop', 'truncate', 'alter', 'create', 'grant', 'revoke', 
                          'delete', 'update', 'insert', 'union', 'exec', 'execute',
                          '--', ';', '/*', '*/', 'xp_', 'sp_', 'into', 'outfile']
    if any(keyword in query_lower for keyword in dangerous_keywords):
        _log(f"[MCP SERVER] ✗ Rejected: query contains a forbidden keyword")
        return "Error: Query contains forbidden keywords. Use query_users() for safe queries."
    
    # Only allow queries on 'users' table
    if 'from users' not in normalized and 'from `users`' not in normalized:
        return "Error: Only queries on the 'users' table are allowed. Use query_users() instead."
    
    # Parse COUNT(*) queries
    count_match = re.match(r'^select\s+count\s*\(\s*\*\s*\)\s+(?:as\s+\w+\s+)?from\s+users\s*$', normalized)
    if count_match:
        return query_users(count_only=True, auth=auth)
    
    # Parse simple SELECT queries: SELECT columns FROM users [WHERE col = 'val'] [LIMIT n]
    select_match = re.match(
        r'^select\s+([\w\s,\*]+)\s+from\s+users'
        r'(?:\s+where\s+(\w+)\s*=\s*[\'"]?([^\'"]+)[\'"]?)?'
        r'(?:\s+limit\s+(\d+))?\s*$',
        normalized
    )
    
    if not select_match:
        return (
            "Error: Could not parse query. Use query_users() for safe database access. "
            "Supported legacy patterns: SELECT columns FROM users [WHERE column='value'] [LIMIT n]"
        )
    
    col_str, where_col, where_val, limit_str = select_match.groups()
    
    # Parse columns
    columns = None
    if col_str.strip() != '*':
        columns = [c.strip() for c in col_str.split(',') if c.strip()]
    
    # Parse limit
    limit = int(limit_str) if limit_str else 100
    
    # Delegate to the safe, parameterized query_users function
    return query_users(
        columns=columns,
        where_column=where_col,
        where_value=where_val,
        limit=limit,
        count_only=False,
        auth=auth
    )


@mcp.tool()
def list_tables(auth: dict) -> str:
    """List all tables in the database.

    Args:
        auth: Per-call authentication {access_token, delegation, envelope}

    Returns:
        Formatted string with table names or error message
    """
    _log(f"\n[MCP SERVER] list_tables called")
    username, error = _authorized_username("list_tables", {}, auth)
    if error:
        return error

    try:
        connection = get_db_connection()
        try:
            with connection.cursor() as cursor:
                cursor.execute("SHOW TABLES")
                results = cursor.fetchall()
                table_key = f"Tables_in_{RDS_DB}"
                tables = [row[table_key] for row in results]
                _log(f"[MCP SERVER] ✓ Found {len(tables)} table(s) in '{RDS_DB}'")
                return (
                    f"[Authenticated as: {username}] "
                    f"Found {len(tables)} tables in database '{RDS_DB}':\n"
                    + "\n".join(f"- {table}" for table in tables)
                )
        finally:
            connection.close()
    except Exception as e:
        return f"Error listing tables: {str(e)}"


@mcp.tool()
def describe_table(table_name: str, auth: dict) -> str:
    """Describe the structure of a table (users table only).

    Args:
        table_name: Name of the table to describe
        auth: Per-call authentication {access_token, delegation, envelope}

    Returns:
        Formatted string with table structure or error message
    """
    _log(f"\n[MCP SERVER] describe_table called for table: {table_name}")
    username, error = _authorized_username("describe_table", {"table_name": table_name}, auth)
    if error:
        return error

    if table_name.lower() != 'users':
        _log(f"[MCP SERVER] ✗ Rejected: only the 'users' table can be described")
        return "Error: Only 'users' table can be described"

    try:
        connection = get_db_connection()
        try:
            with connection.cursor() as cursor:
                cursor.execute("DESCRIBE users")
                results = cursor.fetchall()
                return (
                    f"[Authenticated as: {username}] "
                    f"Table '{table_name}' structure ({len(results)} columns):\n"
                    f"{json.dumps(results, indent=2, default=str)}"
                )
        finally:
            connection.close()
    except Exception as e:
        return f"Error describing table: {str(e)}"


if __name__ == "__main__":
    mcp.run()
