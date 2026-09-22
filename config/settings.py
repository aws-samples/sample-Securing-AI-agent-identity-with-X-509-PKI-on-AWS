"""Application configuration settings."""
import os
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

# AWS Configuration
AWS_REGION = os.getenv("AWS_REGION", "us-east-1")
BEDROCK_MODEL_ID = os.getenv("BEDROCK_MODEL_ID", "us.anthropic.claude-sonnet-4-5-20250929-v1:0")

# Whether to use Bedrock's streaming (converse_stream) API. Some models
# do not support tool use over the streaming API, so this defaults to off.
# Set BEDROCK_STREAMING=true only if your model supports streaming tool use.
BEDROCK_STREAMING = os.getenv("BEDROCK_STREAMING", "false").lower() in ("1", "true", "yes", "on")


def get_bedrock_model():
    """Build the Strands BedrockModel used by all agents.

    Returns a configured BedrockModel instance.
    """
    from strands.models import BedrockModel

    return BedrockModel(
        model_id=BEDROCK_MODEL_ID,
        region_name=AWS_REGION,
        streaming=BEDROCK_STREAMING,
    )

# AWS SES Configuration
SES_SENDER_EMAIL = os.getenv("SES_SENDER_EMAIL")
SES_REGION = os.getenv("SES_REGION", "us-east-1")

# Keycloak Configuration
KEYCLOAK_URL = os.getenv("KEYCLOAK_URL")
KEYCLOAK_REALM = os.getenv("KEYCLOAK_REALM", "master")
KEYCLOAK_CLIENT_ID = os.getenv("KEYCLOAK_CLIENT_ID", "mcp-client")
KEYCLOAK_CLIENT_SECRET = os.getenv("KEYCLOAK_CLIENT_SECRET")
KEYCLOAK_ADMIN_USER = os.getenv("KEYCLOAK_ADMIN_USER")
KEYCLOAK_ADMIN_PASSWORD = os.getenv("KEYCLOAK_ADMIN_PASSWORD")

# RFC 8693 token exchange. At login the user's full-session access token is
# downscoped to a token whose audience is restricted to the MCP server; only
# that exchanged token is handed to agents. The original session token stays
# UI-side (logout only). The MCP server rejects any token whose `aud` does not
# contain KEYCLOAK_TOKEN_AUDIENCE, so a leaked original token cannot be abused.
# KEYCLOAK_TOKEN_EXCHANGE_SCOPE is an optional client scope whose audience
# mapper stamps that audience; requested only during the exchange, so the
# original token stays unscoped.
KEYCLOAK_TOKEN_AUDIENCE = os.getenv("KEYCLOAK_TOKEN_AUDIENCE", "mcp-server")
KEYCLOAK_TOKEN_EXCHANGE_SCOPE = os.getenv("KEYCLOAK_TOKEN_EXCHANGE_SCOPE", "mcp-audience")

# EJBCA Configuration
EJBCA_URL = os.getenv("EJBCA_URL")
EJBCA_CA_NAME = os.getenv("EJBCA_CA_NAME", "UserCA")
EJBCA_CERT_PROFILE = os.getenv("EJBCA_CERT_PROFILE", "ShortLivedUserCert")
EJBCA_END_ENTITY_PROFILE = os.getenv("EJBCA_END_ENTITY_PROFILE", "UserCertProfile")
EJBCA_API_ADMIN_CERT_PATH = os.getenv("EJBCA_API_ADMIN_CERT_PATH", "./certs/api-admin.p12")
EJBCA_API_ADMIN_CERT_PASSWORD = os.getenv("EJBCA_API_ADMIN_CERT_PASSWORD")
CERT_VALIDITY_DAYS = int(os.getenv("CERT_VALIDITY_DAYS", "7"))

# The issuing CA certificate (PEM). This is the same
# CA whose OCSP responder answers revocation checks. Resolved to an absolute
# path so the MCP subprocess finds it regardless of its working directory.
_PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
EJBCA_ISSUING_CA_CERT = os.getenv(
    "EJBCA_ISSUING_CA_CERT",
    os.path.join(_PROJECT_ROOT, "certs", "UserCA.pem"),
)

ORCHESTRATOR_AGENT = "orchestrator-agent"
MYSQL_AGENT = "mysql-agent"
EMAIL_AGENT = "email-agent"
ALL_AGENT_ROLES = [ORCHESTRATOR_AGENT, MYSQL_AGENT, EMAIL_AGENT]

ALLOWED_CALLER_ROLES = {
    MYSQL_AGENT: [ORCHESTRATOR_AGENT],
    EMAIL_AGENT: [ORCHESTRATOR_AGENT],
    "mcp-server": [MYSQL_AGENT],
}

# --- Signed-envelope / delegation security policy ---
ENVELOPE_MAX_AGE_SECONDS = int(os.getenv("ENVELOPE_MAX_AGE_SECONDS", "60"))  # reject older envelopes
DELEGATION_MAX_AGE_HOURS = int(os.getenv("DELEGATION_MAX_AGE_HOURS", "12"))  # delegation assertion lifetime

# MySQL Database Configuration
RDS_HOST = os.getenv("RDS_HOST")
RDS_PORT = int(os.getenv("RDS_PORT", "3306"))
RDS_USER = os.getenv("RDS_USER")
RDS_PASS = os.getenv("RDS_PASS")
RDS_DB = os.getenv("RDS_DB")

# Application Configuration
APP_SECRET_KEY = os.getenv("APP_SECRET_KEY", "change-this-secret-key")

# TLS Certificate Verification
# Path to CA certificate bundle for TLS verification. Defaults to True (use
# system CA bundle). Set to a specific CA cert path for custom/private CAs.
# For self-signed certs in development, set TLS_CA_CERT_PATH to the CA bundle.
# SECURITY: Never set TLS_VERIFY_DISABLED=true in production.
TLS_CA_CERT_PATH = os.getenv("TLS_CA_CERT_PATH", "")
TLS_VERIFY_DISABLED = os.getenv("TLS_VERIFY_DISABLED", "false").lower() in ("1", "true", "yes", "on")


def get_tls_verify():
    """Return TLS verification setting for requests library.
    
    Returns:
        - The CA cert path if TLS_CA_CERT_PATH is configured (for custom CAs)
        - True (default) to use system CA bundle for standard TLS verification
        - False only if TLS_VERIFY_DISABLED is explicitly set (development only)
    
    SECURITY: TLS verification is enabled by default. For self-signed or private
    CA certificates, set TLS_CA_CERT_PATH to the CA bundle path. Only disable
    TLS verification (TLS_VERIFY_DISABLED=true) in isolated development environments.
    """
    if TLS_CA_CERT_PATH:
        return TLS_CA_CERT_PATH
    if TLS_VERIFY_DISABLED:
        return False
    return True
