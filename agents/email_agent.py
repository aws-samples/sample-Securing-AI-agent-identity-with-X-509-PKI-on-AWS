"""Email Agent

Validates the orchestrator's signature before sending email.

"""
from strands import Agent, tool
import boto3
from botocore.exceptions import ClientError

from config.settings import SES_SENDER_EMAIL, SES_REGION, get_bedrock_model, EMAIL_AGENT, EJBCA_ISSUING_CA_CERT
from pki.envelope import ReplayCache, verify_envelope

_replay_cache = ReplayCache()


@tool
def send_email(recipient: str, subject: str, body: str) -> str:
    """Send an email using AWS SES.

    Args:
        recipient: Email address of the recipient
        subject: Email subject line
        body: Email body content (plain text or HTML)

    Returns:
        Success or error message
    """
    print(f"[Email Agent] Sending email via SES")
    try:
        ses_client = boto3.client('ses', region_name=SES_REGION)

        response = ses_client.send_email(
            Source=SES_SENDER_EMAIL,
            Destination={'ToAddresses': [recipient]},
            Message={
                'Subject': {'Data': subject, 'Charset': 'UTF-8'},
                'Body': {'Text': {'Data': body, 'Charset': 'UTF-8'}}
            }
        )

        message_id = response['MessageId']
        print(f"[Email Agent] ✓ Email sent (SES Message ID: {message_id})")
        return f"Email sent successfully to {recipient}. Message ID: {message_id}"

    except ClientError as e:
        error_code = e.response['Error']['Code']
        error_message = e.response['Error']['Message']
        print(f"[Email Agent] ✗ SES send failed: {error_code} - {error_message}")
        return f"Failed to send email: {error_code} - {error_message}"
    except Exception as e:
        print(f"[Email Agent] ✗ Unexpected error sending email: {e}")
        return f"Unexpected error sending email: {str(e)}"


def handle_email(envelope: dict) -> str:
    """Entry point for the orchestrator. Verifies the caller's signed envelope
    (only orchestrator-agent is authorized), then composes and sends the email.

    Args:
        envelope: Signed request envelope from the orchestrator, payload
            {"request": <email instructions>}.

    Returns:
        The email agent's confirmation, or raises on auth failure.
    """
    ca_pem = open(EJBCA_ISSUING_CA_CERT).read()

    print(f"\n{'='*60}")
    print(f"[Email Agent] Handling email request")
    print(f"[Email Agent] Verifying orchestrator envelope (PoP + freshness + replay + CA chain + role + OCSP)...")
    payload = verify_envelope(envelope, EMAIL_AGENT, ca_pem, _replay_cache)
    request = payload["request"]
    print(f"[Email Agent] ✓ Orchestrator envelope verified — caller authenticated")
    print(f"[Email Agent] Handing request to the LLM to compose + send")
    print(f"{'='*60}")

    system_prompt = """You are a specialized email assistant.

Guidelines:
- Always use the send_email tool to send emails
- Format the email body with proper structure (greeting, content, closing)
- Use clear, descriptive subject lines
- Confirm to the user when email is sent successfully
"""

    email_agent = Agent(
        name="email_agent",
        system_prompt=system_prompt,
        tools=[send_email],
        model=get_bedrock_model()
    )

    return str(email_agent(request))
