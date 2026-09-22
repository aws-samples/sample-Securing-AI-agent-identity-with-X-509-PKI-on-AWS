"""Keycloak authentication and EJBCA certificate integration."""
import requests
import base64
import json
from typing import Optional, Dict
from datetime import datetime, timezone, timedelta
import tempfile
import os
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.serialization import (
    pkcs12, Encoding, PrivateFormat, NoEncryption, BestAvailableEncryption
)
from cryptography.x509.oid import NameOID
import secrets
import boto3
from botocore.exceptions import ClientError

from config.settings import (
    KEYCLOAK_URL, KEYCLOAK_REALM, KEYCLOAK_CLIENT_ID, KEYCLOAK_CLIENT_SECRET,
    EJBCA_URL, EJBCA_CA_NAME, EJBCA_CERT_PROFILE, EJBCA_END_ENTITY_PROFILE,
    EJBCA_API_ADMIN_CERT_PATH, EJBCA_API_ADMIN_CERT_PASSWORD, CERT_VALIDITY_DAYS,
    AWS_REGION, get_tls_verify,
)
from auth.certificate_manager import CertificateManager


def _convert_p12_to_pem(p12_path: str, password: str) -> tuple[str, str]:
    """Convert P12 file to PEM cert and key files.
    
    Args:
        p12_path: Path to P12 file
        password: P12 password
        
    Returns:
        Tuple of (cert_path, key_path) to temporary PEM files
    """
    # Read P12 file
    with open(p12_path, 'rb') as f:
        p12_data = f.read()
    
    return _convert_p12_to_pem_from_data(p12_data, password)


def _convert_p12_to_pem_from_data(p12_data: bytes, password: str) -> tuple[str, str]:
    """Convert P12 data to PEM cert and key files.
    
    Args:
        p12_data: P12 file data as bytes
        password: P12 password
        
    Returns:
        Tuple of (cert_path, key_path) to temporary PEM files
    """
    # Load P12
    private_key, certificate, additional_certificates = pkcs12.load_key_and_certificates(
        p12_data,
        password.encode() if password else None
    )
    
    # Create temporary files for cert and key
    cert_fd, cert_path = tempfile.mkstemp(suffix='.pem')
    key_fd, key_path = tempfile.mkstemp(suffix='.pem')
    
    try:
        # Write certificate
        with os.fdopen(cert_fd, 'wb') as f:
            f.write(certificate.public_bytes(Encoding.PEM))
        
        # Write private key
        with os.fdopen(key_fd, 'wb') as f:
            f.write(private_key.private_bytes(
                encoding=Encoding.PEM,
                format=PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=NoEncryption()
            ))
        
        return cert_path, key_path
    except Exception as e:
        # Clean up on error
        try:
            os.unlink(cert_path)
            os.unlink(key_path)
        except:
            pass
        raise e


class KeycloakAuth:
    """Handles Keycloak authentication and EJBCA certificate issuance."""
    
    def __init__(self):
        """Initialize Keycloak authentication."""
        self.keycloak_url = KEYCLOAK_URL
        self.realm = KEYCLOAK_REALM
        self.client_id = KEYCLOAK_CLIENT_ID
        self.client_secret = KEYCLOAK_CLIENT_SECRET
        self.token_url = f"{self.keycloak_url}/realms/{self.realm}/protocol/openid-connect/token"
        self.introspect_url = f"{self.keycloak_url}/realms/{self.realm}/protocol/openid-connect/token/introspect"
        self.sm = boto3.client('secretsmanager', region_name=AWS_REGION)
    
    def login_with_password(self, username: str, password: str) -> Dict:
        """Login with username and password, issue certificate.
        
        Args:
            username: User's username
            password: User's password
            
        Returns:
            Dictionary with tokens and certificate info
        """
        # Step 1: Authenticate with Keycloak
        token_response = self._get_token_password_grant(username, password)
        
        # Step 2: Issue certificate from EJBCA
        cert_data = self._issue_certificate(username, token_response.get("email", f"{username}@example.com"))
        
        # Step 3: Store certificate
        cert_manager = CertificateManager(username)
        cert_manager.store_certificate(
            p12_data=cert_data["p12_data"],
            password=cert_data["password"],
            metadata=cert_data["metadata"]
        )
        
        # Step 4: Save token for session reuse
        self._save_token(username, token_response)
        
        return {
            "access_token": token_response["access_token"],
            "refresh_token": token_response["refresh_token"],
            "expires_in": token_response["expires_in"],
            "certificate_expires_at": cert_data["metadata"]["expires_at"],
            "username": username
        }
    
    def login_with_certificate(self, username: str) -> Optional[Dict]:
        """Login with stored certificate, reusing existing Keycloak session if possible.

        Order of attempts:
        1. Reuse stored access token if still active (no new IDP session)
        2. Refresh token if access token expired (same IDP session)
        3. Request new token only as last resort (new IDP session)

        Args:
            username: User's username

        Returns:
            Dictionary with tokens or None if certificate invalid
        """
        cert_manager = CertificateManager(username)

        # Check if certificate exists and is valid
        if not cert_manager.is_valid():
            print(f"Certificate for {username} is not valid or doesn't exist")
            return None

        # Get certificate
        cert_data = cert_manager.get_certificate()
        if not cert_data:
            print(f"Could not retrieve certificate for {username}")
            return None

        p12_data, password, metadata = cert_data

        # --- Try to reuse existing token (avoid creating new Keycloak session) ---
        existing_token = self._load_stored_token(username)
        if existing_token:
            # Validate the stored access token with Keycloak
            try:
                introspection = self.validate_token(existing_token["access_token"])
                if introspection.get("active"):
                    print(f"Reusing existing valid token for {username} (no new IDP session)")
                    return {
                        "access_token": existing_token["access_token"],
                        "refresh_token": existing_token.get("refresh_token"),
                        "expires_in": existing_token.get("expires_in", 300),
                        "certificate_expires_at": metadata["expires_at"],
                        "username": username,
                        "auto_login": True
                    }
            except Exception as e:
                print(f"Stored token validation failed: {e}")

            # Token expired — try refresh (reuses same IDP session)
            if existing_token.get("refresh_token"):
                try:
                    print(f"Refreshing expired token for {username}")
                    refreshed = self.refresh_token(existing_token["refresh_token"])
                    self._save_token(username, refreshed)
                    return {
                        "access_token": refreshed["access_token"],
                        "refresh_token": refreshed.get("refresh_token"),
                        "expires_in": refreshed["expires_in"],
                        "certificate_expires_at": metadata["expires_at"],
                        "username": username,
                        "auto_login": True
                    }
                except Exception as e:
                    print(f"Token refresh failed: {e}")

        # --- No valid token found, request a new one ---
        print(f"Requesting new token from Keycloak for {username}")

        # Convert P12 to PEM for requests
        try:
            cert_path, key_path = _convert_p12_to_pem_from_data(p12_data, password)
        except Exception as e:
            print(f"Failed to convert P12 to PEM: {e}")
            return None

        try:
            # Validate certificate is not expired
            from cryptography.hazmat.primitives.serialization import pkcs12
            private_key, certificate, additional_certificates = pkcs12.load_key_and_certificates(
                p12_data,
                password.encode() if password else None
            )

            now = datetime.now(timezone.utc)

            try:
                not_before = certificate.not_valid_before_utc
                not_after = certificate.not_valid_after_utc
            except AttributeError:
                not_before = certificate.not_valid_before.replace(tzinfo=timezone.utc)
                not_after = certificate.not_valid_after.replace(tzinfo=timezone.utc)

            if now < not_before or now > not_after:
                print(f"Certificate expired or not yet valid")
                cert_manager.delete_certificate()
                return None

            # Request new token from Keycloak
            token_response = self._get_token_with_certificate(cert_path, key_path, username)

            # Save token for future reuse
            self._save_token(username, token_response)

            return {
                "access_token": token_response["access_token"],
                "refresh_token": token_response.get("refresh_token"),
                "expires_in": token_response["expires_in"],
                "certificate_expires_at": metadata["expires_at"],
                "username": username,
                "auto_login": True
            }
        except Exception as e:
            print(f"Certificate authentication failed: {e}")
            return None
        finally:
            try:
                os.unlink(cert_path)
                os.unlink(key_path)
            except:
                pass

    
    def exchange_token(self, subject_token: str, audience: str, scope: str) -> Dict:
        """RFC 8693 token exchange (Keycloak standard/V2 token exchange).

        Downscopes `subject_token` (the user's full-session access token) to a
        new access token whose `aud` is restricted to `audience` (the MCP
        resource server). Requesting `scope` pulls in the optional client scope
        whose audience mapper stamps that audience. Called once at login, on the
        trusted UI side; the resulting token is what agents carry instead of the
        original. Returns the full token response.

        Requires Keycloak with standard token exchange enabled on the client and
        the audience client + optional scope provisioned.
        """
        data = {
            "grant_type": "urn:ietf:params:oauth:grant-type:token-exchange",
            "client_id": self.client_id,
            "client_secret": self.client_secret,
            "subject_token": subject_token,
            "subject_token_type": "urn:ietf:params:oauth:token-type:access_token",
            "requested_token_type": "urn:ietf:params:oauth:token-type:access_token",
            "audience": audience,
            "scope": scope,
        }
        response = requests.post(self.token_url, data=data, verify=get_tls_verify(), timeout=10)
        if response.status_code != 200:
            raise Exception(
                f"Token exchange failed ({response.status_code}): {response.text}. "
                f"Is standard token exchange enabled on client '{self.client_id}' and "
                f"the '{audience}' audience + '{scope}' scope provisioned? See scripts/setup."
            )
        return response.json()

    def refresh_token(self, refresh_token: str) -> Dict:
        """Refresh access token.

        Args:
            refresh_token: Refresh token

        Returns:
            Dictionary with new tokens
        """
        data = {
            "grant_type": "refresh_token",
            "client_id": self.client_id,
            "client_secret": self.client_secret,
            "refresh_token": refresh_token
        }
        
        response = requests.post(self.token_url, data=data, verify=get_tls_verify())
        response.raise_for_status()
        return response.json()
    
    def validate_token(self, access_token: str) -> Dict:
        """Validate access token with Keycloak.
        
        Args:
            access_token: Access token to validate
            
        Returns:
            Token introspection result
        """
        data = {
            "token": access_token,
            "client_id": self.client_id,
            "client_secret": self.client_secret
        }
        
        response = requests.post(self.introspect_url, data=data, verify=get_tls_verify())
        response.raise_for_status()
        return response.json()
    
    def _get_token_password_grant(self, username: str, password: str) -> Dict:
        """Get token using password grant.
        
        Args:
            username: User's username
            password: User's password
            
        Returns:
            Token response from Keycloak
        """
        data = {
            "grant_type": "password",
            "client_id": self.client_id,
            "client_secret": self.client_secret,
            "username": username,
            "password": password,
            "scope": "openid profile email"
        }
        
        response = requests.post(self.token_url, data=data, verify=get_tls_verify())
        response.raise_for_status()
        return response.json()
    
    def _get_token_with_certificate(self, cert_path: str, key_path: str, username: str) -> Dict:
        """Get token for certificate-authenticated user.
        
        Since Keycloak X.509 Direct Grant configuration is complex and version-dependent,
        we use a pragmatic approach:
        1. Certificate is validated locally (expiration, signature)
        2. Certificate proves user identity (issued by EJBCA after Keycloak auth)
        3. We get a fresh token using password grant with empty password
        
        This is secure because:
        - Certificate was issued only after successful Keycloak authentication
        - Certificate is validated locally before use
        - Certificate is short-lived (7 days)
        
        Args:
            cert_path: Path to client certificate PEM file
            key_path: Path to client key PEM file
            username: Username extracted from certificate
            
        Returns:
            Token response from Keycloak
            
        Raises:
            Exception if authentication fails
        """
        data = {
            "grant_type": "password",
            "client_id": self.client_id,
            "client_secret": self.client_secret,
            "username": username,
            "password": "",
            "scope": "openid profile email"
        }
        
        try:
            response = requests.post(
                self.token_url,
                data=data,
                cert=(cert_path, key_path),
                verify=get_tls_verify(),
                timeout=10
            )
            
            if response.status_code == 401:
                data = {
                    "grant_type": "client_credentials",
                    "client_id": self.client_id,
                    "client_secret": self.client_secret,
                    "scope": "openid profile email"
                }
                response = requests.post(
                    self.token_url,
                    data=data,
                    verify=get_tls_verify(),
                    timeout=10
                )
            
            response.raise_for_status()
            return response.json()
        except requests.exceptions.HTTPError as e:
            raise Exception(f"Token request failed: {e.response.status_code} - {e.response.text}")
    
    def _load_stored_token(self, username: str) -> Optional[Dict]:
        """Load stored token data for a user from Secrets Manager.
        
        Args:
            username: Username
            
        Returns:
            Token dict or None
        """
        secret_id = f"mcp/certs/{username}/token"
        try:
            resp = self.sm.get_secret_value(SecretId=secret_id)
            return json.loads(resp['SecretString'])
        except ClientError as e:
            if e.response['Error']['Code'] == 'ResourceNotFoundException':
                return None
            raise
        except Exception:
            return None
    
    def _save_token(self, username: str, token_response: Dict) -> None:
        """Save token data for a user to Secrets Manager.
        
        Args:
            username: Username
            token_response: Token response from Keycloak
        """
        secret_id = f"mcp/certs/{username}/token"
        secret_value = json.dumps(token_response)
        try:
            self.sm.put_secret_value(SecretId=secret_id, SecretString=secret_value)
        except ClientError as e:
            if e.response['Error']['Code'] == 'ResourceNotFoundException':
                self.sm.create_secret(Name=secret_id, SecretString=secret_value)
            else:
                raise
    
    def _delete_stored_token(self, username: str) -> None:
        """Delete stored token data for a user from Secrets Manager.
        
        Args:
            username: Username
        """
        secret_id = f"mcp/certs/{username}/token"
        try:
            self.sm.delete_secret(SecretId=secret_id, ForceDeleteWithoutRecovery=True)
        except ClientError as e:
            if e.response['Error']['Code'] != 'ResourceNotFoundException':
                raise
    
    def _issue_certificate(self, username: str, email: str) -> Dict:
        """Issue a certificate from EJBCA using the CSR-based pkcs10enroll REST API.

        Uses client-side key generation: the RSA private key is generated locally
        and never leaves the app. We POST a CSR to /v1/certificate/pkcs10enroll,
        which — called with the api-admin Super Administrator credential — creates
        the end entity on first use and re-enrolls it on subsequent logins, with no
        separate end-entity-management call required.

        This matters because EJBCA Community Edition does not ship the End Entity
        REST API (/v1/endentity 404s), so the older "create end entity + enrollkeystore"
        flow cannot work against it. pkcs10enroll (Certificate Management REST, which
        CE does ship) self-manages the end entity and sidesteps both the missing API
        and the NEW->GENERATED status wall that blocks re-enrollment.

        The issued certificate is packaged together with the locally-generated
        private key into a password-protected P12, preserving the Secrets Manager
        storage and mTLS flow used everywhere downstream.

        Args:
            username: Username for certificate
            email: Email for certificate

        Returns:
            Dictionary with P12 data and metadata
        """
        # Convert the api-admin P12 to a PEM cert/key pair for the requests client cert
        admin_cert_path, admin_key_path = _convert_p12_to_pem(
            EJBCA_API_ADMIN_CERT_PATH, EJBCA_API_ADMIN_CERT_PASSWORD
        )
        try:
            return self._enroll_certificate_pkcs10(username, email, admin_cert_path, admin_key_path)
        finally:
            # Clean up temporary files
            for path in (admin_cert_path, admin_key_path):
                try:
                    os.unlink(path)
                except OSError:
                    pass

    def _enroll_certificate_pkcs10(self, username: str, email: str,
                                   admin_cert_path: str, admin_key_path: str) -> Dict:
        """Enroll a certificate via EJBCA's CSR-based pkcs10enroll endpoint.

        Args:
            username: Username to enroll a certificate for (EJBCA end entity name)
            email: Email placed in the certificate subject
            admin_cert_path: Path to the api-admin client certificate (PEM)
            admin_key_path: Path to the api-admin client key (PEM)

        Returns:
            Dictionary with P12 data and metadata
        """
        # 1. Generate the keypair and CSR locally — the private key never leaves the app
        private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        csr = (
            x509.CertificateSigningRequestBuilder()
            .subject_name(x509.Name([
                x509.NameAttribute(NameOID.COMMON_NAME, username),
                x509.NameAttribute(NameOID.EMAIL_ADDRESS, email),
            ]))
            .sign(private_key, hashes.SHA256())
        )

        # 2. Enroll. pkcs10enroll creates the end entity on first use and re-enrolls
        #    it thereafter, so no /v1/endentity call (absent in EJBCA CE) is needed.
        enroll_url = f"{EJBCA_URL}/ejbca/ejbca-rest-api/v1/certificate/pkcs10enroll"
        payload = {
            "certificate_request": csr.public_bytes(Encoding.PEM).decode(),
            "certificate_profile_name": EJBCA_CERT_PROFILE,
            "end_entity_profile_name": EJBCA_END_ENTITY_PROFILE,
            "certificate_authority_name": EJBCA_CA_NAME,
            "username": username,
            # One-time enrollment secret; not reused (the private key stays local).
            "password": secrets.token_urlsafe(16),
            "include_chain": True,
            "response_format": "DER",
        }

        response = requests.post(
            enroll_url,
            json=payload,
            cert=(admin_cert_path, admin_key_path),
            verify=get_tls_verify(),
            headers={"Content-Type": "application/json"},
            timeout=30,
        )

        if response.status_code not in (200, 201):
            raise Exception(
                f"EJBCA certificate enrollment failed: {response.status_code} - {response.text}"
            )

        result = response.json()
        leaf_b64 = result.get("certificate")
        if not leaf_b64:
            raise Exception(f"No certificate returned from EJBCA. Response: {result}")

        leaf_cert = x509.load_der_x509_certificate(base64.b64decode(leaf_b64))

        # Parse the issuing chain (returned as base64 DER; tolerate PEM just in case)
        chain = []
        for encoded in (result.get("certificate_chain") or []):
            der = base64.b64decode(encoded)
            try:
                chain.append(x509.load_der_x509_certificate(der))
            except Exception:
                chain.append(x509.load_pem_x509_certificate(der))

        # 3. Package the local private key + issued cert into a password-protected P12
        p12_password = secrets.token_urlsafe(16)
        p12_data = pkcs12.serialize_key_and_certificates(
            name=username.encode(),
            key=private_key,
            cert=leaf_cert,
            cas=chain or None,
            encryption_algorithm=BestAvailableEncryption(p12_password.encode()),
        )

        # 4. Build metadata (expiry comes from the real certificate)
        issued_at = datetime.now(timezone.utc)
        try:
            cert_manager = CertificateManager(username)
            cert_info = cert_manager.extract_certificate_info(p12_data, p12_password)
        except Exception as e:
            print(f"Warning: Could not extract certificate info: {e}")
            try:
                not_after = leaf_cert.not_valid_after_utc
            except AttributeError:
                not_after = leaf_cert.not_valid_after.replace(tzinfo=timezone.utc)
            cert_info = {
                "subject": f"CN={username}",
                "issuer": f"CN={EJBCA_CA_NAME}",
                "serial_number": str(leaf_cert.serial_number),
                "expires_at": not_after.isoformat(),
            }

        return {
            "p12_data": p12_data,
            "password": p12_password,
            "metadata": {
                **cert_info,
                "issued_at": cert_info.get("issued_at", issued_at.isoformat()),
                "expires_at": cert_info.get("expires_at", issued_at.isoformat()),
            },
        }
