"""Orchestrator Agent with agent-to-agent signature authentication.

Pattern: Orchestrator Agent with @tool wrappers that call sub-agent functions.
When the orchestrator calls another agent, it signs that request, and the sub-
agent verifies the signature against the orchestrator's cert.
"""
from strands import Agent, tool
from strands.agent.conversation_manager import SlidingWindowConversationManager

from config.settings import get_bedrock_model, ORCHESTRATOR_AGENT
from pki.envelope import sign_envelope


def create_orchestrator_agent(user_email: str, agent_access_token: str = None,
                              delegation: dict = None, username: str = None,
                              agent_token_expires_at: float = 0) -> Agent:
    """Create orchestrator agent with signed-envelope agent-to-agent auth.

    Args:
        user_email: User's email address for context.
        agent_access_token: The user's RFC 8693 downscoped OAuth token
            (audience = MCP server) that sub-agents carry to the MCP server.
        delegation: The user-signed delegation assertion for this session.
        username: Current logged-in username (for user-scoped agent certs).
        agent_token_expires_at: Epoch expiry of the downscoped token; the MySQL
            agent re-mints it on demand past this point.

    Returns:
        Configured orchestrator agent.
    """
    _current_username = username or "unknown"
    print(f"\n{'='*60}")
    print(f"[ORCHESTRATOR] Creating orchestrator agent for user '{_current_username}'")
    print(f"{'='*60}")

    # Load this orchestrator's own certificate + private key (PEM). The key is
    # used in-process to sign envelopes and never leaves this process.
    from auth.agent_cert_manager import get_or_issue_agent_cert
    from pki.keys import cert_and_key_pem_from_p12

    orch_cred = get_or_issue_agent_cert(ORCHESTRATOR_AGENT, username=_current_username)
    if not orch_cred:
        raise PermissionError("orchestrator-agent certificate unavailable — is the user logged in?")
    orch_cert_pem, orch_key_pem = cert_and_key_pem_from_p12(
        orch_cred["p12_data_b64"], orch_cred["password"]
    )
    print(f"[ORCHESTRATOR] Orchestrator identity loaded (CN={_current_username}_{ORCHESTRATOR_AGENT})")

    # Give the MySQL agent the token + delegation for this session. It loads its
    # own signing key; the orchestrator authenticates per call via the envelope.
    from agents.mysql_agent import set_auth_context, handle_query
    set_auth_context(agent_access_token, delegation, username=_current_username,
                     agent_token_expires_at=agent_token_expires_at)
    print(f"[ORCHESTRATOR] Auth context configured for user '{_current_username}'")

    from agents.email_agent import handle_email

    @tool
    def query_database(query: str) -> str:
        """Query the database. Pass the user's question in natural language.

        Args:
            query: Natural-language question about the database.

        Returns:
            Query results or an error message.
        """
        print(f"\n[ORCHESTRATOR] → routing to MySQL Agent: {query!r}")
        envelope = sign_envelope({"request": query}, orch_cert_pem, orch_key_pem)
        print(f"[ORCHESTRATOR] Signed envelope with orchestrator key (nonce={envelope['nonce'][:8]}...) → MySQL Agent")
        return handle_query(envelope)

    @tool
    def send_results_email(recipient: str, content: str, subject: str = "Database Query Results") -> str:
        """Send query results or information via email.

        Args:
            recipient: Email address to send to.
            content: Content to send in the email.
            subject: Email subject line.

        Returns:
            Confirmation message.
        """
        print(f"\n[ORCHESTRATOR] → routing to Email Agent: to={recipient!r}, subject={subject!r}")
        request = (
            f"Send an email:\nRecipient: {recipient}\nSubject: {subject}\n"
            f"Content: {content}\n\nFormat professionally and send."
        )
        envelope = sign_envelope({"request": request}, orch_cert_pem, orch_key_pem)
        print(f"[ORCHESTRATOR] Signed envelope with orchestrator key (nonce={envelope['nonce'][:8]}...) → Email Agent")
        try:
            return handle_email(envelope)
        except Exception as e:
            return f"Error sending email: {str(e)}"

    conversation_manager = SlidingWindowConversationManager(
        window_size=4,
        should_truncate_results=True
    )

    orchestrator = Agent(
        system_prompt=f"""You are a routing assistant that forwards requests to specialized sub-agents.

TOOLS:
1. query_database: For ANY database question. Pass the user's EXACT words. Do NOT write SQL.
2. send_results_email: ONLY when user explicitly asks to send/email something.

User email: {user_email}

RULES:
- Forward the user's question EXACTLY as-is to query_database.
- When query_database returns, ANSWER the user in clear, natural language based on
  that data. Present it readably (prose for a single value, a simple markdown table
  or bulleted list for rows). Do NOT dump raw JSON, and do NOT reply with only a
  confirmation like "Query Response returned" — the user must see the actual answer.
- Base your answer only on what the tool returned; do not invent or omit data.
- NEVER call send_results_email unless user explicitly says "send", "email", or "mail".
- When user says "send to my email" use {user_email} as recipient.
- Call send_results_email ONCE per recipient. Never call it again for the same recipient.
DO NOT CALL THE EMAIL AGENT.
""",
        conversation_manager=conversation_manager,
        tools=[query_database, send_results_email],
        model=get_bedrock_model()
    )

    return orchestrator
