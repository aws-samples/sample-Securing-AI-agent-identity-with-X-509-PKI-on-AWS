# Certificates Directory

Place your EJBCA certificates here. These files are **not** committed to the repository.

## Required Files

| File | Description | How to Generate |
|------|-------------|-----------------|
| `api-admin.p12` | EJBCA REST API admin certificate | Export from EJBCA Admin UI (SuperAdmin role) |
| `UserCA.pem` | EJBCA CA certificate (trust anchor) | Export from EJBCA: CA Functions > UserCA > Download PEM |

## Optional Files

| File | Description |
|------|-------------|
| `SuperAdmin.p12` | EJBCA SuperAdmin certificate (for full admin access) |

## How to Generate

### 1. api-admin.p12 (Required)

This certificate authenticates REST API calls to EJBCA for issuing/revoking user and agent certificates.

**Steps:**
1. Log into EJBCA Admin UI (`https://your-ejbca-server/ejbca/adminweb/`)
2. Go to **RA Functions** > **Add End Entity**
3. Create an entity with:
   - Username: `api-admin`
   - Password: (choose a strong password)
   - CA: `ManagementCA` (or your admin CA)
   - Certificate Profile: `ENDUSER`
   - End Entity Profile: `EMPTY`
   - Token: `P12`
4. Go to **RA Functions** > **Search End Entities** > find `api-admin`
5. Click **Create Certificate** > Download P12
6. In **System Configuration** > **Administrator Roles**, add this certificate to the `Super Administrator` role
7. Place the downloaded file as `certs/api-admin.p12`

### 2. UserCA.pem (Required)

The CA certificate that signs all user and agent certificates. Used for OCSP validation.

**Steps:**
1. Log into EJBCA Admin UI
2. Go to **CA Functions** > **Basic Functions**
3. Click on your CA (e.g., `UserCA`)
4. Click **Download PEM** (certificate only, not chain)
5. Place the downloaded file as `certs/UserCA.pem`

### 3. EJBCA Configuration

Before using this project, configure EJBCA with:

**Certificate Authority:**
- Name: `UserCA` (or update `EJBCA_CA_NAME` in `.env`)
- Key Algorithm: RSA 2048+
- Validity: 10+ years (CA cert)

**Certificate Profile:** `ShortLivedUserCert`
- Validity: 7 days (or update `CERT_VALIDITY_DAYS` in `.env`)
- Key Algorithm: RSA 2048
- Available CAs: `UserCA`

**End Entity Profile:** `UserCertProfile`
- Required fields: CN (Common Name), EMAIL
- Available Certificate Profiles: `ShortLivedUserCert`
- Available CAs: `UserCA`
- Default Token: P12

**REST API:**
- Enable REST API V1 in System Configuration
- Ensure the `api-admin` certificate has permissions for:
  - End Entity Management (create, delete, search)
  - Certificate Management (enroll, revoke, status)

## Security Notes

- **Never commit** `.p12` or `.pem` files to version control
- Store P12 passwords in `.env` (also gitignored)
- The `api-admin.p12` has full EJBCA API access — protect it accordingly
- Rotate the admin certificate periodically

## Platform Notes

### macOS
```bash
# Place certs
cp ~/Downloads/api-admin.p12 ./certs/api-admin.p12
cp ~/Downloads/UserCA.pem ./certs/UserCA.pem

# Verify P12 is readable
openssl pkcs12 -info -in ./certs/api-admin.p12 -nokeys
```

### Windows
```powershell
# Place certs
copy C:\path\to\api-admin.p12 .\certs\api-admin.p12
copy C:\path\to\UserCA.pem .\certs\UserCA.pem

# Verify P12 is readable
certutil -dump .\certs\api-admin.p12
```

### Linux
```bash
# Place certs
cp /path/to/api-admin.p12 ./certs/api-admin.p12
cp /path/to/UserCA.pem ./certs/UserCA.pem

# Verify P12 is readable
openssl pkcs12 -info -in ./certs/api-admin.p12 -nokeys
```
