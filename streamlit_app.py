"""Streamlit AI Chat App with Keycloak + EJBCA Authentication.

Authentication Flow:

Flow 1: First-Time User Login
1. User opens app → Login form displayed
2. User enters username + password
3. App → Keycloak: Validate credentials (password grant)
4. Keycloak validates → App → EJBCA: Issue certificate
5. EJBCA returns P12 certificate (7-day validity)
6. App stores certificate in AWS Secrets Manager (mcp/certs/{username}/certificate)
7. User logged in → Orchestrator Agent ready

Flow 2: Certificate-Based Auto-Login (Browser Reopen)
1. User closes browser (without logout)
2. User reopens app
3. App reads mcp/certs/users secret for list of users with certificates
4. Shows list of users with valid certificates (like Gmail)
5. User selects account → Auto-login with certificate (NO PASSWORD!)
6. Orchestrator Agent ready

Flow 3: Logout
1. User clicks "Logout & Revoke Certificate"
2. App revokes certificate in EJBCA
3. App deletes certificate from Secrets Manager
4. Session cleared → User logged out
5. Next login requires username + password

Flow 4: Multiple Users
1. User A logs in → Certificate A stored in Secrets Manager
2. User A closes browser (no logout)
3. User B logs in → Certificate B stored in Secrets Manager
4. Both users can auto-login by selecting their account
"""
import streamlit as st
from datetime import datetime, timezone
import traceback
import os
import json
import requests
import boto3
from botocore.exceptions import ClientError

from auth.keycloak_auth import KeycloakAuth
from auth.certificate_manager import CertificateManager, find_valid_certificate
from auth.session import bootstrap_agent_session
from agents.orchestrator_agent import create_orchestrator_agent
from config.settings import SES_SENDER_EMAIL, AWS_REGION


# Page configuration
st.set_page_config(
    page_title="AI Database Assistant",
    page_icon="🤖",
    layout="wide"
)

# Initialize session state
if "authenticated" not in st.session_state:
    st.session_state.authenticated = False
if "username" not in st.session_state:
    st.session_state.username = None
if "access_token" not in st.session_state:
    st.session_state.access_token = None
if "refresh_token" not in st.session_state:
    st.session_state.refresh_token = None
if "cert_expires_at" not in st.session_state:
    st.session_state.cert_expires_at = None
if "auto_login" not in st.session_state:
    st.session_state.auto_login = False
if "messages" not in st.session_state:
    st.session_state.messages = []
if "orchestrator" not in st.session_state:
    st.session_state.orchestrator = None
if "oauth_state" not in st.session_state:
    st.session_state.oauth_state = None


def get_all_valid_users():
    """Get all users with valid certificates from Secrets Manager.
    
    Returns:
        List of usernames with valid certificates
    """
    sm = boto3.client('secretsmanager', region_name=AWS_REGION)
    try:
        resp = sm.get_secret_value(SecretId='mcp/certs/users')
        usernames = json.loads(resp['SecretString'])
    except ClientError as e:
        if e.response['Error']['Code'] == 'ResourceNotFoundException':
            return []
        raise
    except Exception:
        return []
    
    valid_users = []
    for username in usernames:
        cert_manager = CertificateManager(username)
        if cert_manager.is_valid():
            valid_users.append(username)
    
    return valid_users


def get_last_user_cookie():
    """Get the last logged-in username from Secrets Manager."""
    sm = boto3.client('secretsmanager', region_name=AWS_REGION)
    try:
        resp = sm.get_secret_value(SecretId='mcp/certs/last_user')
        return resp['SecretString'].strip()
    except ClientError as e:
        if e.response['Error']['Code'] == 'ResourceNotFoundException':
            return None
        raise
    except Exception:
        return None


def set_last_user_cookie(username):
    """Save the last logged-in username to Secrets Manager."""
    sm = boto3.client('secretsmanager', region_name=AWS_REGION)
    try:
        sm.put_secret_value(SecretId='mcp/certs/last_user', SecretString=username)
    except ClientError as e:
        if e.response['Error']['Code'] == 'ResourceNotFoundException':
            sm.create_secret(Name='mcp/certs/last_user', SecretString=username)
        else:
            raise


def clear_last_user_cookie():
    """Clear the last logged-in username from Secrets Manager."""
    sm = boto3.client('secretsmanager', region_name=AWS_REGION)
    try:
        sm.delete_secret(SecretId='mcp/certs/last_user', ForceDeleteWithoutRecovery=True)
    except ClientError as e:
        if e.response['Error']['Code'] != 'ResourceNotFoundException':
            raise


def revoke_certificate_in_ejbca(username):
    """Revoke user's certificate in EJBCA using the certificate revocation endpoint.
    
    Uses the EJBCA REST API v1 certificate revocation endpoint:
    PUT /v1/certificate/{issuer_dn}/{certificate_serial_number}/revoke
    
    Args:
        username: Username whose certificate to revoke
        
    Returns:
        True if successful, False otherwise
    """
    try:
        from config.settings import EJBCA_URL, EJBCA_API_ADMIN_CERT_PATH, EJBCA_API_ADMIN_CERT_PASSWORD, get_tls_verify
        from auth.keycloak_auth import _convert_p12_to_pem
        from cryptography.hazmat.primitives.serialization import pkcs12
        from cryptography import x509
        
        # Get certificate manager
        cert_manager = CertificateManager(username)
        cert_data = cert_manager.get_certificate()
        
        if not cert_data:
            print(f"No certificate found for {username}")
            return False
        
        p12_data, password, metadata = cert_data
        
        # Extract certificate info to get issuer DN and serial number
        private_key, certificate, additional_certs = pkcs12.load_key_and_certificates(
            p12_data,
            password.encode() if password else None
        )
        
        # Get issuer DN
        issuer_dn = certificate.issuer.rfc4514_string()
        
        # Get serial number in hex format (uppercase)
        serial_hex = format(certificate.serial_number, 'X')
        
        print(f"Revoking certificate: Issuer={issuer_dn}, Serial={serial_hex}")
        
        # Convert admin cert to PEM
        cert_path, key_path = _convert_p12_to_pem(EJBCA_API_ADMIN_CERT_PATH, EJBCA_API_ADMIN_CERT_PASSWORD)
        
        try:
            # URL encode the issuer DN
            from urllib.parse import quote
            issuer_dn_encoded = quote(issuer_dn, safe='')
            
            # Revoke certificate using the proper REST API endpoint
            revoke_url = f"{EJBCA_URL}/ejbca/ejbca-rest-api/v1/certificate/{issuer_dn_encoded}/{serial_hex}/revoke"
            
            response = requests.put(
                revoke_url,
                params={"reason": "CESSATION_OF_OPERATION"},
                cert=(cert_path, key_path),
                verify=get_tls_verify(),
                headers={"Content-Type": "application/json"}
            )
            
            if response.status_code in [200, 204]:
                print(f"✓ Certificate revoked in EJBCA")
                return True
            elif response.status_code == 409:
                # Already revoked
                print(f"✓ Certificate already revoked in EJBCA")
                return True
            else:
                print(f"Failed to revoke certificate: {response.status_code} - {response.text}")
                return False
        finally:
            # Clean up temp files
            try:
                os.unlink(cert_path)
                os.unlink(key_path)
            except:
                pass
    except Exception as e:
        print(f"Error revoking certificate: {e}")
        import traceback
        traceback.print_exc()
        return False


def logout_from_keycloak(refresh_token):
    """Logout from Keycloak (end session).
    
    Args:
        refresh_token: Refresh token to revoke
        
    Returns:
        True if successful, False otherwise
    """
    try:
        from config.settings import KEYCLOAK_URL, KEYCLOAK_REALM, KEYCLOAK_CLIENT_ID, KEYCLOAK_CLIENT_SECRET, get_tls_verify
        
        if not refresh_token:
            print("No refresh token available for logout")
            return False
        
        logout_url = f"{KEYCLOAK_URL}/realms/{KEYCLOAK_REALM}/protocol/openid-connect/logout"
        
        response = requests.post(
            logout_url,
            data={
                "client_id": KEYCLOAK_CLIENT_ID,
                "client_secret": KEYCLOAK_CLIENT_SECRET,
                "refresh_token": refresh_token
            },
            verify=get_tls_verify(),
            headers={"Content-Type": "application/x-www-form-urlencoded"}
        )
        
        if response.status_code in [200, 204]:
            print("✓ Logged out from Keycloak")
            return True
        elif response.status_code == 400:
            # Token might be invalid/expired, but that's OK for logout
            print("✓ Keycloak session ended (token was invalid/expired)")
            return True
        else:
            print(f"Keycloak logout response: {response.status_code} - {response.text}")
            return False
    except Exception as e:
        print(f"Error logging out from Keycloak: {e}")
        import traceback
        traceback.print_exc()
        return False


def login_page():
    """Display login page."""
    st.title("🔐 AI Database Assistant - Login")
    
    st.markdown("""
    Welcome to the AI Database Assistant! This application uses:
    - **Keycloak** for authentication
    - **EJBCA PKI** for short-lived certificates
    - **Strands Agents** for intelligent database queries and email
    """)
    
    # Get all users with valid certificates
    valid_users = get_all_valid_users()
    
    if valid_users:
        st.success(f"✓ Found {len(valid_users)} user(s) with valid certificates")
        
        st.subheader("🔓 Login with Certificate")
        
        # Show user selection if multiple users
        if len(valid_users) == 1:
            selected_user = valid_users[0]
            st.info(f"User: **{selected_user}**")
            
            if st.button("Login with Certificate", use_container_width=True, type="primary"):
                if attempt_certificate_login(selected_user):
                    st.rerun()
                else:
                    st.error("Certificate login failed. Please login with password.")
        else:
            st.write("Select a user to login:")
            
            # Create buttons for each user
            cols = st.columns(min(len(valid_users), 3))
            for idx, username in enumerate(valid_users):
                with cols[idx % 3]:
                    if st.button(f"👤 {username}", use_container_width=True, key=f"cert_login_{username}"):
                        if attempt_certificate_login(username):
                            st.rerun()
                        else:
                            st.error(f"Certificate login failed for {username}")
        
        st.divider()
        st.caption("Or login with username and password below:")
    
    st.subheader("Login with Username & Password")
    
    with st.form("login_form"):
        username = st.text_input("Username", value="")
        password = st.text_input("Password", type="password")
        submit = st.form_submit_button("Login")
        
        if submit:
            if not username or not password:
                st.error("Please enter both username and password")
                return
            
            try:
                with st.spinner("Authenticating with Keycloak..."):
                    keycloak_auth = KeycloakAuth()
                    result = keycloak_auth.login_with_password(username, password)
                
                # Store authentication state
                st.session_state.authenticated = True
                st.session_state.username = username
                st.session_state.access_token = result["access_token"]
                st.session_state.refresh_token = result["refresh_token"]
                st.session_state.cert_expires_at = result["certificate_expires_at"]
                st.session_state.auto_login = False
                
                # Save username to cookie for auto-login
                set_last_user_cookie(username)
                
                # Create orchestrator agent
                user_email = SES_SENDER_EMAIL or f"{username}@example.com"
                print(f"\n{'='*60}")
                print(f"[AUTH] Login successful for user: {username}")
                print(f"[AUTH] Access token obtained from Keycloak")
                print(f"[AUTH] Passing token to orchestrator agent")
                print(f"{'='*60}")
                
                # Bootstrap the agent session: downscope the token (RFC 8693)
                # and mint the user-signed delegation over this session's agent
                # certs. The user's private key is used only here to sign the
                # delegation and never leaves the login flow.
                cert_manager = CertificateManager(username)
                cert_data = cert_manager.get_certificate()
                if not cert_data:
                    raise RuntimeError("User certificate unavailable after login")
                p12_data, p12_password, _ = cert_data
                session_creds = bootstrap_agent_session(
                    username, result["access_token"], p12_data, p12_password
                )

                st.session_state.orchestrator = create_orchestrator_agent(
                    user_email,
                    session_creds["agent_access_token"],
                    session_creds["delegation"],
                    username=username,
                    agent_token_expires_at=session_creds["agent_token_expires_at"],
                )

                st.success("✓ Login successful! Certificate issued.")
                st.rerun()
                
            except Exception as e:
                st.error(f"Login failed: {str(e)}")
                st.code(traceback.format_exc())


def attempt_certificate_login(username):
    """Attempt to login with certificate.
    
    Args:
        username: Username to login with
        
    Returns:
        True if successful, False otherwise
    """
    try:
        keycloak_auth = KeycloakAuth()
        result = keycloak_auth.login_with_certificate(username)
        
        if result:
            st.session_state.authenticated = True
            st.session_state.username = username
            st.session_state.access_token = result["access_token"]
            st.session_state.refresh_token = result.get("refresh_token")
            st.session_state.cert_expires_at = result["certificate_expires_at"]
            st.session_state.auto_login = True
            
            # Update cookie with successful login
            set_last_user_cookie(username)
            
            # Create orchestrator agent
            user_email = SES_SENDER_EMAIL or f"{username}@example.com"
            print(f"\n{'='*60}")
            print(f"[AUTH] Certificate login successful for user: {username}")
            print(f"[AUTH] Access token obtained from Keycloak")
            print(f"[AUTH] Passing token to orchestrator agent")
            print(f"{'='*60}")
            
            # Bootstrap the agent session: downscope the token (RFC 8693) and
            # mint the user-signed delegation over this session's agent certs.
            cert_manager = CertificateManager(username)
            cert_data = cert_manager.get_certificate()
            if not cert_data:
                raise RuntimeError("User certificate unavailable after login")
            p12_data, p12_password, _ = cert_data
            session_creds = bootstrap_agent_session(
                username, result["access_token"], p12_data, p12_password
            )

            st.session_state.orchestrator = create_orchestrator_agent(
                user_email,
                session_creds["agent_access_token"],
                session_creds["delegation"],
                username=username,
                agent_token_expires_at=session_creds["agent_token_expires_at"],
            )

            return True
    except Exception as e:
        st.error(f"Certificate login failed: {e}")
        return False
    
    return False



def chat_page():
    """Display chat interface."""
    # Sidebar
    with st.sidebar:
        st.title("👤 User Info")
        st.write(f"**Username:** {st.session_state.username}")
        
        if st.session_state.auto_login:
            st.success("🔓 Auto-logged in with certificate")
        
        # Certificate status
        st.subheader("📜 Certificate Status")
        if st.session_state.cert_expires_at:
            expires_at = datetime.fromisoformat(st.session_state.cert_expires_at)
            now = datetime.now(timezone.utc)
            days_left = (expires_at - now).days
            
            if days_left > 3:
                st.success(f"✓ Valid for {days_left} more days")
            elif days_left > 0:
                st.warning(f"⚠ Expires in {days_left} days")
            else:
                st.error("✗ Certificate expired")
            
            st.caption(f"Expires: {expires_at.strftime('%Y-%m-%d %H:%M UTC')}")
        
        st.divider()
        
        # Logout options
        st.subheader("🚪 Logout")
        
        if st.button("Logout & Revoke Certificate", use_container_width=True, type="primary"):
            # Logout from Keycloak
            if st.session_state.refresh_token:
                with st.spinner("Logging out from Keycloak..."):
                    logout_from_keycloak(st.session_state.refresh_token)
            
            # Revoke certificate in EJBCA
            if st.session_state.username:
                with st.spinner("Revoking certificate in EJBCA..."):
                    revoke_certificate_in_ejbca(st.session_state.username)
                    
                    # Delete certificate locally
                    cert_manager = CertificateManager(st.session_state.username)
                    cert_manager.delete_certificate()
                    
                    # Delete stored token
                    from auth.keycloak_auth import KeycloakAuth
                    KeycloakAuth()._delete_stored_token(st.session_state.username)
                    
                    # Revoke all agent certs for this user
                    from auth.agent_cert_manager import revoke_all_agent_certs
                    revoke_all_agent_certs(st.session_state.username)
            
            # Clear session
            for key in list(st.session_state.keys()):
                del st.session_state[key]
            
            st.success("✓ Logged out successfully")
            st.rerun()
        
        st.caption("Revokes your certificate and logs you out")
    
    # Main chat interface
    st.title("🤖 AI Database Assistant")
    
    st.markdown("""
    Ask me anything about the database or request to send results via email!
    
    **Examples:**
    - "Show me all users in the database"
    - "How many users are there?"
    - "Send the user list to my email"
    - "Query the users table and email me the results"
    """)
    
    # Display chat messages
    for message in st.session_state.messages:
        with st.chat_message(message["role"]):
            st.markdown(message["content"])
    
    # Chat input
    if prompt := st.chat_input("Ask me anything..."):
        # Add user message
        st.session_state.messages.append({"role": "user", "content": prompt})
        with st.chat_message("user"):
            st.markdown(prompt)
        
        # Get agent response
        with st.chat_message("assistant"):
            with st.spinner("Thinking..."):
                try:
                    orchestrator = st.session_state.orchestrator
                    response = orchestrator(prompt)
                    
                    # Handle AgentResult response format (same as reference project app.py)
                    response_text = ""
                    if hasattr(response, 'message') and response.message:
                        content = response.message.get('content', [])
                        if content:
                            for block in content:
                                if isinstance(block, dict) and 'text' in block:
                                    response_text += block['text']
                                elif isinstance(block, str):
                                    response_text += block
                    
                    if not response_text.strip():
                        response_text = str(response)
                    
                    if response_text and response_text.strip():
                        st.markdown(response_text)
                    else:
                        st.warning("Received empty response. Please try again.")
                    
                    st.session_state.messages.append({"role": "assistant", "content": response_text})
                    
                except Exception as e:
                    error_msg = f"Error: {str(e)}"
                    st.error(error_msg)
                    st.code(traceback.format_exc())
                    st.session_state.messages.append({"role": "assistant", "content": error_msg})


def main():
    """Main application entry point."""
    if not st.session_state.authenticated:
        login_page()
    else:
        chat_page()


if __name__ == "__main__":
    main()
