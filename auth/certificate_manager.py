"""Certificate management using AWS Secrets Manager for storage and validation."""
import json
import base64
import tempfile
import os
from datetime import datetime, timezone
from typing import Optional, Dict
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.serialization import pkcs12
from cryptography.x509 import ocsp
import requests
import boto3
from botocore.exceptions import ClientError

from config.settings import AWS_REGION, EJBCA_URL


def find_valid_certificate() -> Optional[str]:
    """Find any valid certificate in Secrets Manager and return the username.

    Reads the mcp/certs/users secret to get the list of usernames,
    then checks each for a valid certificate.

    Returns:
        Username if a valid certificate is found, None otherwise
    """
    sm = boto3.client('secretsmanager', region_name=AWS_REGION)
    try:
        resp = sm.get_secret_value(SecretId='mcp/certs/users')
        usernames = json.loads(resp['SecretString'])
    except ClientError as e:
        if e.response['Error']['Code'] == 'ResourceNotFoundException':
            return None
        raise
    except Exception:
        return None

    for username in usernames:
        cert_manager = CertificateManager(username)
        if cert_manager.is_valid():
            return username

    return None


class CertificateManager:
    """Manages client certificate storage and validation via AWS Secrets Manager."""

    def __init__(self, username: str):
        """Initialize certificate manager for a user.

        Args:
            username: Username for certificate storage
        """
        self.username = username
        self.sm = boto3.client('secretsmanager', region_name=AWS_REGION)

    def store_certificate(self, p12_data: bytes, password: str, metadata: Dict) -> None:
        """Store P12 certificate and metadata in Secrets Manager.

        Args:
            p12_data: P12 certificate bytes
            password: Certificate password
            metadata: Certificate metadata (issued_at, expires_at, etc.)
        """
        secret_value = json.dumps({
            "p12_data_b64": base64.b64encode(p12_data).decode('utf-8'),
            "password": password,
            "metadata": metadata
        })

        secret_id = f"mcp/certs/{self.username}/certificate"
        self._put_secret(secret_id, secret_value)

        # Update users list
        self._add_user_to_list()

    def get_certificate(self) -> Optional[tuple[bytes, str, Dict]]:
        """Get stored certificate from Secrets Manager if it exists and is valid.

        Returns:
            Tuple of (p12_data, password, metadata) or None if not found/invalid
        """
        secret_id = f"mcp/certs/{self.username}/certificate"
        try:
            resp = self.sm.get_secret_value(SecretId=secret_id)
            data = json.loads(resp['SecretString'])
        except ClientError as e:
            if e.response['Error']['Code'] == 'ResourceNotFoundException':
                return None
            raise
        except Exception:
            return None

        metadata = data.get("metadata", {})

        # Check expiration
        expires_at_str = metadata.get("expires_at")
        if expires_at_str:
            expires_at = datetime.fromisoformat(expires_at_str)
            if datetime.now(timezone.utc) >= expires_at:
                self.delete_certificate()
                return None

        p12_data = base64.b64decode(data["p12_data_b64"])
        password = data["password"]

        return p12_data, password, metadata

    def is_valid(self) -> bool:
        """Check if stored certificate exists and is valid (not expired and not revoked).

        Returns:
            True only if the certificate is present, unexpired, and OCSP GOOD.
        """
        from pki.ocsp import OCSPError

        cert_data = self.get_certificate()
        if not cert_data:
            return False

        p12_data, password, metadata = cert_data
        try:
            good = self._check_ocsp_status(p12_data, password)
        except OCSPError as e:
            print(f"Certificate for {self.username}: OCSP unavailable (fail closed): {e}")
            return False

        if not good:
            print(f"Certificate for {self.username} is REVOKED")
            self.delete_certificate()
            return False

        return True

    def _check_ocsp_status(self, p12_data: bytes, password: str) -> bool:
        """Real-time revocation check via the shared fail-closed OCSP helper.

        Args:
            p12_data: P12 certificate bytes
            password: Certificate password

        Returns:
            True if OCSP reports GOOD, False if REVOKED.

        Raises:
            OCSPError: if the responder is unreachable or returns no definitive
                status (fail closed — the caller must deny/treat as invalid).
        """
        from pki.ocsp import OCSPError, ocsp_check

        try:
            private_key, certificate, additional_certs = pkcs12.load_key_and_certificates(
                p12_data,
                password.encode(),
                backend=default_backend()
            )
            issuer_cert = additional_certs[0] if additional_certs else certificate
            cert_pem = certificate.public_bytes(serialization.Encoding.PEM).decode()
            issuer_pem = issuer_cert.public_bytes(serialization.Encoding.PEM).decode()
        except Exception as e:
            raise OCSPError(f"Could not parse stored certificate: {e}") from e

        return ocsp_check(cert_pem, issuer_pem) == "GOOD"

    def get_expiration(self) -> Optional[datetime]:
        """Get certificate expiration date from Secrets Manager.

        Returns:
            Expiration datetime or None if no certificate
        """
        secret_id = f"mcp/certs/{self.username}/certificate"
        try:
            resp = self.sm.get_secret_value(SecretId=secret_id)
            data = json.loads(resp['SecretString'])
            metadata = data.get("metadata", {})
            expires_at_str = metadata.get("expires_at")
            if expires_at_str:
                return datetime.fromisoformat(expires_at_str)
            return None
        except ClientError as e:
            if e.response['Error']['Code'] == 'ResourceNotFoundException':
                return None
            raise
        except Exception:
            return None

    def delete_certificate(self) -> None:
        """Delete stored certificate from Secrets Manager and remove user from list."""
        secret_id = f"mcp/certs/{self.username}/certificate"
        try:
            self.sm.delete_secret(SecretId=secret_id, ForceDeleteWithoutRecovery=True)
        except ClientError as e:
            if e.response['Error']['Code'] != 'ResourceNotFoundException':
                raise

        # Remove user from list
        self._remove_user_from_list()

    def extract_certificate_info(self, p12_data: bytes, password: str) -> Dict:
        """Extract information from P12 certificate.

        Args:
            p12_data: P12 certificate bytes
            password: Certificate password

        Returns:
            Dictionary with certificate information
        """
        try:
            private_key, certificate, additional_certs = pkcs12.load_key_and_certificates(
                p12_data,
                password.encode(),
                backend=default_backend()
            )

            subject = certificate.subject
            issuer = certificate.issuer

            try:
                not_before = certificate.not_valid_before_utc.isoformat()
                not_after = certificate.not_valid_after_utc.isoformat()
            except AttributeError:
                not_before = certificate.not_valid_before.replace(tzinfo=timezone.utc).isoformat()
                not_after = certificate.not_valid_after.replace(tzinfo=timezone.utc).isoformat()

            return {
                "subject_cn": subject.get_attributes_for_oid(x509.NameOID.COMMON_NAME)[0].value,
                "subject_email": subject.get_attributes_for_oid(x509.NameOID.EMAIL_ADDRESS)[0].value if subject.get_attributes_for_oid(x509.NameOID.EMAIL_ADDRESS) else None,
                "issuer_cn": issuer.get_attributes_for_oid(x509.NameOID.COMMON_NAME)[0].value,
                "serial_number": str(certificate.serial_number),
                "not_before": not_before,
                "not_after": not_after,
                "issued_at": not_before,
                "expires_at": not_after
            }
        except Exception as e:
            raise ValueError(f"Failed to extract certificate info: {e}")

    def get_certificate_for_request(self) -> Optional[tuple[str, str]]:
        """Get certificate in format suitable for HTTP requests.

        Reads from Secrets Manager, writes temp PEM files needed for HTTP requests.

        Returns:
            Tuple of (cert_path, key_path) to temporary PEM files, or None
        """
        cert_data = self.get_certificate()
        if not cert_data:
            return None

        p12_data, password, _ = cert_data

        private_key, certificate, _ = pkcs12.load_key_and_certificates(
            p12_data,
            password.encode(),
            backend=default_backend()
        )

        # Write cert to temp file
        cert_fd, cert_path = tempfile.mkstemp(suffix='.pem')
        key_fd, key_path = tempfile.mkstemp(suffix='.pem')

        try:
            with os.fdopen(cert_fd, 'wb') as f:
                f.write(certificate.public_bytes(serialization.Encoding.PEM))

            with os.fdopen(key_fd, 'wb') as f:
                f.write(private_key.private_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PrivateFormat.TraditionalOpenSSL,
                    encryption_algorithm=serialization.NoEncryption()
                ))

            return cert_path, key_path
        except Exception as e:
            try:
                os.unlink(cert_path)
                os.unlink(key_path)
            except:
                pass
            raise e

    # --- Internal helpers ---

    def _put_secret(self, secret_id: str, secret_value: str) -> None:
        """Create or update a secret in Secrets Manager.

        Args:
            secret_id: Secret name/ID
            secret_value: Secret string value
        """
        try:
            self.sm.put_secret_value(SecretId=secret_id, SecretString=secret_value)
        except ClientError as e:
            if e.response['Error']['Code'] == 'ResourceNotFoundException':
                self.sm.create_secret(Name=secret_id, SecretString=secret_value)
            else:
                raise

    def _add_user_to_list(self) -> None:
        """Add this username to the mcp/certs/users list."""
        users = self._get_users_list()
        if self.username not in users:
            users.append(self.username)
            self._put_secret('mcp/certs/users', json.dumps(users))

    def _remove_user_from_list(self) -> None:
        """Remove this username from the mcp/certs/users list."""
        users = self._get_users_list()
        if self.username in users:
            users.remove(self.username)
            self._put_secret('mcp/certs/users', json.dumps(users))

    def _get_users_list(self) -> list:
        """Get the current list of usernames from Secrets Manager.

        Returns:
            List of usernames
        """
        try:
            resp = self.sm.get_secret_value(SecretId='mcp/certs/users')
            return json.loads(resp['SecretString'])
        except ClientError as e:
            if e.response['Error']['Code'] == 'ResourceNotFoundException':
                return []
            raise
        except Exception:
            return []
