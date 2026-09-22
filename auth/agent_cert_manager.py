"""Agent certificate management for agent-to-agent authentication.

Issues X.509 certificates from EJBCA for each agent, scoped per user.
Each user gets their own set of agent certs (e.g., deepak_orchestrator-agent).
Certs are stored in AWS Secrets Manager and revoked on logout.

Storage: mcp/agents/{username}/{agent-role}/certificate
EJBCA entity: {username}_{agent-role}
"""
import json
import base64
import os
import requests
import secrets as secrets_mod
from datetime import datetime, timezone, timedelta
from typing import Optional, Dict, List
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.serialization import pkcs12, BestAvailableEncryption
from cryptography.x509 import ocsp
from cryptography.x509.oid import NameOID
import boto3
from botocore.exceptions import ClientError

from config.settings import (
    AWS_REGION, EJBCA_URL, EJBCA_CA_NAME, EJBCA_CERT_PROFILE,
    EJBCA_END_ENTITY_PROFILE, EJBCA_API_ADMIN_CERT_PATH,
    EJBCA_API_ADMIN_CERT_PASSWORD, CERT_VALIDITY_DAYS,
    ORCHESTRATOR_AGENT, MYSQL_AGENT, EMAIL_AGENT, ALL_AGENT_ROLES,
    get_tls_verify,
)
from auth.keycloak_auth import _convert_p12_to_pem


def _get_agent_entity_name(username: str, agent_role: str) -> str:
    """Get the EJBCA entity name for a user's agent cert.
    
    Args:
        username: User's username
        agent_role: Agent role (e.g., 'orchestrator-agent')
    
    Returns:
        Entity name like 'deepak_orchestrator-agent'
    """
    return f"{username}_{agent_role}"


def _get_secret_id(username: str, agent_role: str) -> str:
    """Get the Secrets Manager secret ID for a user's agent cert.
    
    Args:
        username: User's username
        agent_role: Agent role
    
    Returns:
        Secret ID like 'mcp/agents/deepak/orchestrator-agent/certificate'
    """
    return f"mcp/agents/{username}/{agent_role}/certificate"


def get_or_issue_agent_cert(agent_role: str, username: str) -> Optional[Dict]:
    """Get existing agent certificate or issue a new one from EJBCA.

    Each user gets their own agent certs scoped to their session.

    Args:
        agent_role: Agent role (e.g., 'orchestrator-agent')
        username: Current logged-in user

    Returns:
        Dict with 'p12_data_b64', 'password', 'metadata' or None on failure
    """
    sm = boto3.client('secretsmanager', region_name=AWS_REGION)
    secret_id = _get_secret_id(username, agent_role)
    entity_name = _get_agent_entity_name(username, agent_role)

    # Try to load existing cert
    try:
        resp = sm.get_secret_value(SecretId=secret_id)
        data = json.loads(resp['SecretString'])

        # Check if cert is still valid (not expired)
        metadata = data.get("metadata", {})
        expires_at_str = metadata.get("expires_at")
        if expires_at_str:
            expires_at = datetime.fromisoformat(expires_at_str)
            if datetime.now(timezone.utc) < expires_at:
                # Also check OCSP revocation status before reusing
                if _check_agent_cert_ocsp(data):
                    print(f"[Agent Certs] Reusing existing cert for {entity_name} (valid + not revoked)")
                    return data
                else:
                    print(f"[Agent Certs] Cert for {entity_name} is REVOKED, re-issuing")
            else:
                print(f"[Agent Certs] Cert expired for {entity_name}, re-issuing")
    except ClientError as e:
        if e.response['Error']['Code'] != 'ResourceNotFoundException':
            raise
        print(f"[Agent Certs] No certificate found for {entity_name}, issuing new one")

    # Issue new certificate from EJBCA
    try:
        cert_data = _issue_agent_certificate(entity_name, username, agent_role)
        if cert_data:
            # Store in Secrets Manager (overwrite if exists, create if not)
            secret_value = json.dumps(cert_data)
            try:
                sm.put_secret_value(SecretId=secret_id, SecretString=secret_value)
            except ClientError as e:
                error_code = e.response['Error']['Code']
                if error_code == 'ResourceNotFoundException':
                    sm.create_secret(Name=secret_id, SecretString=secret_value)
                elif error_code == 'InvalidRequestException' and 'marked for deletion' in str(e):
                    sm.restore_secret(SecretId=secret_id)
                    sm.put_secret_value(SecretId=secret_id, SecretString=secret_value)
                else:
                    raise
            print(f"[Agent Certs] Certificate issued and stored for {entity_name}")
            return cert_data
    except Exception as e:
        print(f"[Agent Certs] Failed to issue certificate for {entity_name}: {e}")
        return None

    return None


def revoke_all_agent_certs(username: str) -> None:
    """Revoke all agent certificates for a user in EJBCA and delete from Secrets Manager.

    Called during logout to clean up all agent certs for the session.

    Args:
        username: User whose agent certs to revoke
    """
    sm = boto3.client('secretsmanager', region_name=AWS_REGION)

    for agent_role in ALL_AGENT_ROLES:
        secret_id = _get_secret_id(username, agent_role)
        entity_name = _get_agent_entity_name(username, agent_role)

        try:
            # Load cert from Secrets Manager
            resp = sm.get_secret_value(SecretId=secret_id)
            data = json.loads(resp['SecretString'])

            # Revoke in EJBCA
            _revoke_agent_cert_in_ejbca(data)
            print(f"[Agent Certs] ✓ Revoked {entity_name} in EJBCA")

        except ClientError as e:
            if e.response['Error']['Code'] != 'ResourceNotFoundException':
                print(f"[Agent Certs] Error revoking {entity_name}: {e}")
        except Exception as e:
            print(f"[Agent Certs] Error revoking {entity_name}: {e}")

        # Delete from Secrets Manager
        try:
            sm.delete_secret(SecretId=secret_id, ForceDeleteWithoutRecovery=True)
            print(f"[Agent Certs] ✓ Deleted {entity_name} from Secrets Manager")
        except ClientError as e:
            if e.response['Error']['Code'] != 'ResourceNotFoundException':
                print(f"[Agent Certs] Error deleting secret {secret_id}: {e}")


def _revoke_agent_cert_in_ejbca(cert_data: Dict) -> bool:
    """Revoke an agent certificate in EJBCA.

    Args:
        cert_data: Dict with 'p12_data_b64' and 'password'

    Returns:
        True if revoked successfully
    """
    try:
        p12_data = base64.b64decode(cert_data["p12_data_b64"])
        password = cert_data.get("password", "")

        private_key, certificate, _ = pkcs12.load_key_and_certificates(
            p12_data,
            password.encode() if password else None,
            backend=default_backend()
        )

        issuer_dn = certificate.issuer.rfc4514_string()
        serial_hex = format(certificate.serial_number, 'X')

        cert_path, key_path = _convert_p12_to_pem(EJBCA_API_ADMIN_CERT_PATH, EJBCA_API_ADMIN_CERT_PASSWORD)

        try:
            from urllib.parse import quote
            issuer_dn_encoded = quote(issuer_dn, safe='')
            revoke_url = f"{EJBCA_URL}/ejbca/ejbca-rest-api/v1/certificate/{issuer_dn_encoded}/{serial_hex}/revoke"

            response = requests.put(
                revoke_url,
                params={"reason": "CESSATION_OF_OPERATION"},
                cert=(cert_path, key_path),
                verify=get_tls_verify(),
                headers={"Content-Type": "application/json"}
            )
            return response.status_code in [200, 204, 409]
        finally:
            try:
                os.unlink(cert_path)
                os.unlink(key_path)
            except:
                pass
    except Exception as e:
        print(f"[Agent Certs] Revocation error: {e}")
        return False


def _check_agent_cert_ocsp(cert_data: Dict) -> bool:
    """Check if a stored agent certificate is safe to REUSE via OCSP.

    Fail closed: only an explicit GOOD status permits reuse. A REVOKED status
    or any failure to obtain a definitive answer returns False, causing the
    caller to re-issue rather than reuse an unverifiable certificate.

    Args:
        cert_data: Dict with 'p12_data_b64' and 'password'

    Returns:
        True only if OCSP explicitly reports GOOD, False otherwise.
    """
    from pki.ocsp import OCSPError, ocsp_check

    try:
        p12_data = base64.b64decode(cert_data["p12_data_b64"])
        password = cert_data.get("password", "")
        private_key, certificate, additional_certs = pkcs12.load_key_and_certificates(
            p12_data,
            password.encode() if password else None,
            backend=default_backend()
        )
        issuer_cert = additional_certs[0] if additional_certs else certificate
        cert_pem = certificate.public_bytes(serialization.Encoding.PEM).decode()
        issuer_pem = issuer_cert.public_bytes(serialization.Encoding.PEM).decode()
    except Exception as e:
        print(f"[Agent Certs] Could not parse stored cert for OCSP, will re-issue: {e}")
        return False

    try:
        return ocsp_check(cert_pem, issuer_pem) == "GOOD"
    except OCSPError as e:
        print(f"[Agent Certs] OCSP check failed (fail closed, will re-issue): {e}")
        return False


def _issue_agent_certificate(entity_name: str, username: str, agent_role: str) -> Optional[Dict]:
    """Issue a certificate from EJBCA for a user-scoped agent.

    Args:
        entity_name: EJBCA entity name (e.g., 'deepak_orchestrator-agent')
        username: User's username
        agent_role: Agent role

    Returns:
        Dict with p12_data_b64, password, metadata
    """
    cert_path, key_path = _convert_p12_to_pem(EJBCA_API_ADMIN_CERT_PATH, EJBCA_API_ADMIN_CERT_PASSWORD)

    try:
        # Generate the agent keypair + CSR locally (private key never leaves the app)
        agent_email = f"{entity_name}@internal.agents"
        private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        csr = (
            x509.CertificateSigningRequestBuilder()
            .subject_name(x509.Name([
                x509.NameAttribute(NameOID.COMMON_NAME, entity_name),
                x509.NameAttribute(NameOID.EMAIL_ADDRESS, agent_email),
            ]))
            .sign(private_key, hashes.SHA256())
        )

        # Enroll via pkcs10enroll. It creates the end entity on first use and
        # re-enrolls it thereafter, so no /v1/endentity call (absent in EJBCA CE)
        # is required. See auth/keycloak_auth.py:_enroll_certificate_pkcs10.
        enroll_url = f"{EJBCA_URL}/ejbca/ejbca-rest-api/v1/certificate/pkcs10enroll"
        enroll_payload = {
            "certificate_request": csr.public_bytes(serialization.Encoding.PEM).decode(),
            "certificate_profile_name": EJBCA_CERT_PROFILE,
            "end_entity_profile_name": EJBCA_END_ENTITY_PROFILE,
            "certificate_authority_name": EJBCA_CA_NAME,
            "username": entity_name,
            "password": secrets_mod.token_urlsafe(16),  # one-time enrollment secret
            "include_chain": True,
            "response_format": "DER",
        }

        response = requests.post(
            enroll_url, json=enroll_payload,
            cert=(cert_path, key_path), verify=get_tls_verify(),
            headers={"Content-Type": "application/json"}, timeout=30
        )

        if response.status_code not in [200, 201]:
            raise Exception(f"Enrollment failed: {response.status_code} - {response.text}")

        result = response.json()
        leaf_b64 = result.get("certificate")
        if not leaf_b64:
            raise Exception(f"No certificate in response: {result}")

        leaf_cert = x509.load_der_x509_certificate(base64.b64decode(leaf_b64))

        # Parse the issuing chain (base64 DER). The P12 must carry the CA cert so
        # downstream OCSP checks can find the issuer via additional_certs[0].
        chain = []
        for encoded in (result.get("certificate_chain") or []):
            der = base64.b64decode(encoded)
            try:
                chain.append(x509.load_der_x509_certificate(der))
            except Exception:
                chain.append(x509.load_pem_x509_certificate(der))

        # Package the local private key + issued cert into a password-protected P12
        p12_password = secrets_mod.token_urlsafe(16)
        p12_data = pkcs12.serialize_key_and_certificates(
            name=entity_name.encode(),
            key=private_key,
            cert=leaf_cert,
            cas=chain or None,
            encryption_algorithm=BestAvailableEncryption(p12_password.encode()),
        )

        issued_at = datetime.now(timezone.utc)
        try:
            expires_at = leaf_cert.not_valid_after_utc
        except AttributeError:
            expires_at = leaf_cert.not_valid_after.replace(tzinfo=timezone.utc)

        return {
            "p12_data_b64": base64.b64encode(p12_data).decode(),
            "password": p12_password,
            "metadata": {
                "entity_name": entity_name,
                "username": username,
                "agent_role": agent_role,
                "subject_cn": entity_name,
                "serial_number": str(leaf_cert.serial_number),
                "issued_at": issued_at.isoformat(),
                "expires_at": expires_at.isoformat()
            }
        }

    finally:
        try:
            os.unlink(cert_path)
            os.unlink(key_path)
        except:
            pass
