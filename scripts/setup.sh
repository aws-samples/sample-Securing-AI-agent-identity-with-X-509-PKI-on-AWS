#!/usr/bin/env bash
#
# setup.sh
#
# Performs every step in README.md:
#   1. Python venv + dependencies
#   2. Generates .env with resolved values (secrets auto-generated)
#   3. Deploys Keycloak locally in Docker + configures realm/client/user
#   4. Deploys EJBCA Enterprise (Community edition) locally in Docker + CA/admin cert/profiles
#   5. Provisions AWS resources (RDS MySQL, SES sender, Bedrock model check)
#   6. Leaves the app ready to launch with ./run.sh
#
# All AWS resources are tagged Project=tcx
#
# Requirements on PATH: docker, aws (v2, configured creds), python3, openssl, curl
#
set -euo pipefail

# ----------------------------------------------------------------------------
# Configuration
# ----------------------------------------------------------------------------
PROJECT_TAG="tcx"
AWS_REGION="us-east-2"
BEDROCK_MODEL_ID="us.meta.llama4-scout-17b-instruct-v1:0"   # Llama 4 Scout 17B Instruct (cross-region inference profile)
SES_SENDER_EMAIL="user@example.com"

# Local Docker
KEYCLOAK_CONTAINER="tcx-keycloak"
EJBCA_CONTAINER="tcx-ejbca"
# 26.3: ships supported RFC 8693 "standard token exchange" (the login-time
# downscoping the app relies on) without a preview feature flag.
KEYCLOAK_IMAGE="quay.io/keycloak/keycloak:26.3"
EJBCA_IMAGE="keyfactor/ejbca-ce:latest"
KEYCLOAK_PORT="8080"
EJBCA_HTTPS_PORT="8443"
EJBCA_HTTP_PORT="8082"

# Keycloak realm / client
KC_REALM="mcp-realm"
KC_CLIENT_ID="mcp-app-client"
KC_DEMO_USER="testuser"

# EJBCA
# Use EJBCA's built-in ENDUSER certificate profile and EMPTY end entity profile.
EJBCA_CA_NAME="UserCA"
EJBCA_CERT_PROFILE="ENDUSER"
EJBCA_END_ENTITY_PROFILE="EMPTY"

# AWS RDS
RDS_ID="tcx-mysql"
RDS_SG_NAME="tcx-rds-sg"
RDS_SUBNET_GROUP="tcx-public"
RDS_DB="mysqldb"
RDS_USER="admin"

# These scripts live in ./scripts but operate on the project root (parent dir),
# so resolve it and cd there regardless of where the script is invoked from.
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
cd "$PROJECT_ROOT"

# ----------------------------------------------------------------------------
# Helpers
# ----------------------------------------------------------------------------
log()  { printf '\n\033[1;36m==> %s\033[0m\n' "$*"; }
info() { printf '    %s\n' "$*"; }
warn() { printf '\033[1;33m[warn] %s\033[0m\n' "$*"; }
die()  { printf '\033[1;31m[error] %s\033[0m\n' "$*" >&2; exit 1; }

gen_secret() { openssl rand -hex 16; }

require() { command -v "$1" >/dev/null 2>&1 || die "'$1' is required but not found on PATH."; }

# EJBCA CLI wrapper (path differs between image versions — detect once).
EJBCA_CLI=""
ejbca_cli() { docker exec "$EJBCA_CONTAINER" bash -lc "$EJBCA_CLI $*"; }

# ----------------------------------------------------------------------------
# 0. Preflight
# ----------------------------------------------------------------------------
log "Checking prerequisites"
require docker
require aws
require python3
require openssl
require curl
docker info >/dev/null 2>&1 || die "Docker daemon is not running."
aws sts get-caller-identity --region "$AWS_REGION" >/dev/null 2>&1 || die "AWS credentials are not configured. Run 'aws configure'."
info "All prerequisites satisfied."
info "AWS account: $(aws sts get-caller-identity --query Account --output text)"
info "AWS region : $AWS_REGION"

# Generate secrets (persisted to .env)
KC_ADMIN_PASSWORD="$(gen_secret)"
KC_CLIENT_SECRET="$(gen_secret)"    # set explicitly on the client (no read-back)
KC_DEMO_PASSWORD="$(gen_secret)"
EJBCA_ADMIN_CERT_PASSWORD="$(gen_secret)"
RDS_PASS="$(gen_secret)"
APP_SECRET_KEY="$(gen_secret)"

# ----------------------------------------------------------------------------
# 1. Python venv + dependencies
# ----------------------------------------------------------------------------
log "Creating Python virtual environment and installing dependencies"
if [ ! -d .venv ]; then
    python3 -m venv .venv
fi
# shellcheck disable=SC1091
source .venv/bin/activate
python -m pip install --upgrade pip >/dev/null
pip install -r requirements.txt
info "Dependencies installed into ./.venv"

mkdir -p certs

# ----------------------------------------------------------------------------
# 2. Deploy Keycloak
# ----------------------------------------------------------------------------
log "Deploying Keycloak in Docker"
if [ "$(docker ps -aq -f name="^${KEYCLOAK_CONTAINER}$")" ]; then
    warn "Container ${KEYCLOAK_CONTAINER} already exists — removing it."
    docker rm -f "$KEYCLOAK_CONTAINER" >/dev/null
fi
docker run -d --name "$KEYCLOAK_CONTAINER" \
    -p "${KEYCLOAK_PORT}:8080" \
    -e KC_BOOTSTRAP_ADMIN_USERNAME=admin \
    -e KC_BOOTSTRAP_ADMIN_PASSWORD="$KC_ADMIN_PASSWORD" \
    -e KEYCLOAK_ADMIN=admin \
    -e KEYCLOAK_ADMIN_PASSWORD="$KC_ADMIN_PASSWORD" \
    "$KEYCLOAK_IMAGE" start-dev >/dev/null
info "Keycloak container started; waiting for it to become ready..."

for i in $(seq 1 60); do
    if curl -sf "http://localhost:${KEYCLOAK_PORT}/realms/master" >/dev/null 2>&1; then break; fi
    sleep 3
    [ "$i" -eq 60 ] && die "Keycloak did not become ready in time."
done
info "Keycloak is up at http://localhost:${KEYCLOAK_PORT}"

log "Configuring Keycloak realm '${KC_REALM}', client '${KC_CLIENT_ID}', user '${KC_DEMO_USER}'"
KCADM="/opt/keycloak/bin/kcadm.sh"
kc() { docker exec "$KEYCLOAK_CONTAINER" "$KCADM" "$@"; }

kc config credentials --server http://localhost:8080 --realm master --user admin --password "$KC_ADMIN_PASSWORD"
# Realm
kc create realms -s realm="$KC_REALM" -s enabled=true 2>/dev/null || info "Realm already exists."
# Confidential client with Direct Access Grants (Resource Owner Password Credentials)
kc create clients -r "$KC_REALM" \
    -s clientId="$KC_CLIENT_ID" \
    -s enabled=true \
    -s publicClient=false \
    -s directAccessGrantsEnabled=true \
    -s serviceAccountsEnabled=true \
    -s standardFlowEnabled=false \
    -s secret="$KC_CLIENT_SECRET" 2>/dev/null || info "Client already exists."
# Demo user
kc create users -r "$KC_REALM" -s username="$KC_DEMO_USER" -s enabled=true \
    -s email="${KC_DEMO_USER}@example.com" -s emailVerified=true \
    -s firstName="Test" -s lastName="User" 2>/dev/null || info "User already exists."
kc set-password -r "$KC_REALM" --username "$KC_DEMO_USER" --new-password "$KC_DEMO_PASSWORD"

# RFC 8693 standard token exchange: downscope the login token to aud=mcp-server
# so the MCP server can reject a leaked full-session token. Provisioned by a
# stdlib-only Python helper shared with setup.bat (idempotent).
log "Configuring token exchange (mcp-server audience, mcp-audience scope)"
KC_HOST="http://localhost:${KEYCLOAK_PORT}" KC_REALM="$KC_REALM" KC_CLIENT_ID="$KC_CLIENT_ID" \
KC_ADMIN_USER=admin KC_ADMIN_PASSWORD="$KC_ADMIN_PASSWORD" \
KC_AUDIENCE=mcp-server KC_EXCHANGE_SCOPE=mcp-audience \
  .venv/bin/python scripts/kc_token_exchange.py \
  || warn "Token exchange configuration failed — see README to configure it manually."
info "Keycloak configured. Client secret captured."

# ----------------------------------------------------------------------------
# 3. Deploy EJBCA
# ----------------------------------------------------------------------------
log "Deploying EJBCA Enterprise (Community edition) in Docker"
if [ "$(docker ps -aq -f name="^${EJBCA_CONTAINER}$")" ]; then
    warn "Container ${EJBCA_CONTAINER} already exists — removing it."
    docker rm -f "$EJBCA_CONTAINER" >/dev/null
fi
docker run -d --name "$EJBCA_CONTAINER" \
    -p "${EJBCA_HTTP_PORT}:8080" \
    -p "${EJBCA_HTTPS_PORT}:8443" \
    -e TLS_SETUP_ENABLED=true \
    "$EJBCA_IMAGE" >/dev/null
info "EJBCA container started; first boot can take 1–2 minutes..."

for i in $(seq 1 100); do
    if curl -sk "https://localhost:${EJBCA_HTTPS_PORT}/ejbca/publicweb/healthcheck/ejbcahealth" 2>/dev/null | grep -qi "ALLOK"; then break; fi
    sleep 3
    [ "$i" -eq 100 ] && warn "EJBCA health check timed out — continuing, but EJBCA steps below may fail."
done
info "EJBCA is up at https://localhost:${EJBCA_HTTPS_PORT}/ejbca/"

# Detect the EJBCA CLI path inside the container.
if docker exec "$EJBCA_CONTAINER" bash -lc 'command -v ejbca.sh' >/dev/null 2>&1; then
    EJBCA_CLI="ejbca.sh"
else
    EJBCA_CLI="/opt/keyfactor/bin/ejbca/ejbca.sh"
fi

# EJBCA fine-grained configuration is version-sensitive on the CE image; run it
# best-effort and print a manual fallback if any step fails.
ejbca_ok=true
{
    log "Creating EJBCA CA '${EJBCA_CA_NAME}'"
    ejbca_cli ca init "$EJBCA_CA_NAME" "\"CN=${EJBCA_CA_NAME},O=${PROJECT_TAG},C=US\"" soft null 2048 RSA 3650 --policy 2.5.29.32.0 SHA256WithRSA \
        || info "CA '${EJBCA_CA_NAME}' may already exist."

    # Enable the Certificate Management REST API. The app issues user certs via
    # POST /v1/certificate/pkcs10enroll (CSR-based), which creates the end entity
    # on first use and re-enrolls it thereafter. This protocol is DISABLED by
    # default on the CE image, and the End Entity REST API is absent from CE
    # entirely — so pkcs10enroll (not endentity+enrollkeystore) is the only
    # enrollment path that works here.
    log "Enabling EJBCA REST Certificate Management protocol"
    ejbca_cli config protocols enable --name "\"REST Certificate Management\"" \
        || info "REST Certificate Management may already be enabled."

    log "Creating EJBCA REST API admin end entity"
    ejbca_cli ra addendentity \
        --username api-admin \
        --dn "\"CN=api-admin,O=${PROJECT_TAG}\"" \
        --caname ManagementCA \
        --type 1 --token P12 \
        --password "$EJBCA_ADMIN_CERT_PASSWORD" \
        --certprofile ENDUSER --eeprofile EMPTY || info "api-admin entity may already exist."
    ejbca_cli ra setclearpwd api-admin "$EJBCA_ADMIN_CERT_PASSWORD" || true

    log "Granting api-admin the Super Administrator role"
    ejbca_cli roles addrolemember \
        --role "\"Super Administrator Role\"" \
        --caname ManagementCA \
        --with CertificateAuthenticationToken:WITH_COMMONNAME \
        --value api-admin || true

    log "Generating api-admin P12 keystore (batch)"
    # 'batch' run from /tmp writes the keystore to /tmp/p12/<username>.p12
    docker exec "$EJBCA_CONTAINER" bash -lc "cd /tmp && $EJBCA_CLI batch api-admin"
    if docker cp "${EJBCA_CONTAINER}:/tmp/p12/api-admin.p12" ./certs/api-admin.p12 2>/dev/null; then
        info "Copied api-admin.p12 -> ./certs/api-admin.p12"
    else
        warn "Could not locate generated api-admin.p12 (expected /tmp/p12/api-admin.p12)."
    fi

    log "Exporting ${EJBCA_CA_NAME} CA certificate (trust anchor)"
    ejbca_cli ca getcacert "$EJBCA_CA_NAME" /tmp/UserCA.pem || true
    docker cp "${EJBCA_CONTAINER}:/tmp/UserCA.pem" ./certs/UserCA.pem 2>/dev/null || \
        warn "Could not export UserCA.pem — export it manually from the EJBCA admin UI."
} || ejbca_ok=false

if [ "$ejbca_ok" != true ] || [ ! -f ./certs/api-admin.p12 ]; then
    warn "-------------------------------------------------------------------"
    warn "EJBCA auto-configuration was only partially successful."
    warn "Check the admin UI (https://localhost:${EJBCA_HTTPS_PORT}/ejbca/adminweb/) and verify:"
    warn "  - CA '${EJBCA_CA_NAME}' exists"
    warn "  - certs/api-admin.p12 (REST admin) and certs/UserCA.pem (trust anchor) were created"
    warn "The app uses the built-in '${EJBCA_CERT_PROFILE}' cert profile and '${EJBCA_END_ENTITY_PROFILE}'"
    warn "end entity profile, so no custom profile creation is required."
    warn "-------------------------------------------------------------------"
fi

# ----------------------------------------------------------------------------
# 4. AWS — Bedrock model check
# ----------------------------------------------------------------------------
log "Checking AWS Bedrock access for Llama 4 Scout 17B Instruct"
if aws bedrock list-foundation-models --region "$AWS_REGION" \
     --query "modelSummaries[?contains(modelId,'llama4-scout')].modelId" --output text 2>/dev/null | grep -q llama4-scout; then
    info "Llama 4 Scout base model is visible in Bedrock ($AWS_REGION)."
else
    warn "Llama 4 Scout not listed. Enable it in the Bedrock console:"
    warn "  Bedrock > Model access > enable 'Llama 4 Scout 17B Instruct'."
fi
info "App will invoke inference profile: ${BEDROCK_MODEL_ID}"

# ----------------------------------------------------------------------------
# 5. AWS — SES sender verification
# ----------------------------------------------------------------------------
log "Verifying SES sender identity ${SES_SENDER_EMAIL}"
if aws sesv2 create-email-identity \
     --email-identity "$SES_SENDER_EMAIL" \
     --tags "Key=Project,Value=${PROJECT_TAG}" \
     --region "$AWS_REGION" >/dev/null 2>&1; then
    info "SES verification email sent to ${SES_SENDER_EMAIL}."
else
    info "SES identity already exists (or is pending)."
fi
warn "ACTION REQUIRED: click the verification link in the email sent to ${SES_SENDER_EMAIL}."

# ----------------------------------------------------------------------------
# 6. AWS — RDS MySQL
# ----------------------------------------------------------------------------
log "Provisioning Amazon RDS MySQL (tagged Project=${PROJECT_TAG})"
VPC_ID="$(aws ec2 describe-vpcs --filters Name=isDefault,Values=true \
            --query 'Vpcs[0].VpcId' --output text --region "$AWS_REGION")"
[ "$VPC_ID" != "None" ] || die "No default VPC found in $AWS_REGION. Create one or adjust the script."

# Security group
SG_ID="$(aws ec2 describe-security-groups --filters "Name=group-name,Values=${RDS_SG_NAME}" \
           "Name=vpc-id,Values=${VPC_ID}" --query 'SecurityGroups[0].GroupId' \
           --output text --region "$AWS_REGION" 2>/dev/null || echo None)"
if [ "$SG_ID" = "None" ] || [ -z "$SG_ID" ]; then
    SG_ID="$(aws ec2 create-security-group --group-name "$RDS_SG_NAME" \
                --description "tcx RDS MySQL access" --vpc-id "$VPC_ID" --region "$AWS_REGION" \
                --tag-specifications "ResourceType=security-group,Tags=[{Key=Project,Value=${PROJECT_TAG}}]" \
                --query GroupId --output text)"
    info "Created security group ${SG_ID}"
else
    info "Reusing security group ${SG_ID}"
fi
MY_IP="$(curl -s https://checkip.amazonaws.com | tr -d '[:space:]')"
aws ec2 authorize-security-group-ingress --group-id "$SG_ID" --protocol tcp --port 3306 \
    --cidr "${MY_IP}/32" --region "$AWS_REGION" >/dev/null 2>&1 \
    && info "Authorized MySQL (3306) ingress from ${MY_IP}/32" \
    || info "Ingress rule already present."

# --- Public DB subnet group -------------------------------------------------
# A publicly-accessible RDS instance is only reachable if it lives in a subnet
# whose route table has a default route to an Internet Gateway. The VPC's
# default subnet group can include private subnets (common in corporate VPCs
# with a Transit Gateway), and RDS may place the instance in one of them —
# yielding a public IP that is unroutable. So we build a subnet group that
# contains only genuinely public subnets (one per AZ, ≥2 AZs required).
log "Selecting public subnets for the RDS subnet group"
IGW_ID="$(aws ec2 describe-internet-gateways --region "$AWS_REGION" \
    --filters "Name=attachment.vpc-id,Values=${VPC_ID}" \
    --query 'InternetGateways[0].InternetGatewayId' --output text 2>/dev/null || echo None)"
[ "$IGW_ID" != "None" ] && [ -n "$IGW_ID" ] || die "No Internet Gateway attached to ${VPC_ID}; cannot host a publicly-accessible RDS there."

MAIN_RT="$(aws ec2 describe-route-tables --region "$AWS_REGION" \
    --filters "Name=vpc-id,Values=${VPC_ID}" "Name=association.main,Values=true" \
    --query 'RouteTables[0].RouteTableId' --output text)"

PUBLIC_SUBNETS=""
SEEN_AZS=""
while read -r SUBNET_ID SUBNET_AZ; do
    [ -n "$SUBNET_ID" ] || continue
    RT_ID="$(aws ec2 describe-route-tables --region "$AWS_REGION" \
        --filters "Name=association.subnet-id,Values=${SUBNET_ID}" \
        --query 'RouteTables[0].RouteTableId' --output text 2>/dev/null || echo None)"
    if [ "$RT_ID" = "None" ] || [ -z "$RT_ID" ]; then RT_ID="$MAIN_RT"; fi
    IGW_ROUTE="$(aws ec2 describe-route-tables --region "$AWS_REGION" --route-table-ids "$RT_ID" \
        --query "RouteTables[0].Routes[?DestinationCidrBlock=='0.0.0.0/0' && starts_with(GatewayId, 'igw-')].GatewayId" \
        --output text 2>/dev/null || echo "")"
    if [ -n "$IGW_ROUTE" ] && [ "$IGW_ROUTE" != "None" ]; then
        case " $SEEN_AZS " in
            *" $SUBNET_AZ "*) : ;;                        # one public subnet per AZ is enough
            *) SEEN_AZS="$SEEN_AZS $SUBNET_AZ"
               PUBLIC_SUBNETS="$PUBLIC_SUBNETS $SUBNET_ID" ;;
        esac
    fi
done < <(aws ec2 describe-subnets --region "$AWS_REGION" \
            --filters "Name=vpc-id,Values=${VPC_ID}" \
            --query 'Subnets[].[SubnetId,AvailabilityZone]' --output text)

PUBLIC_SUBNETS="$(echo "$PUBLIC_SUBNETS" | xargs)"          # trim leading/trailing space
AZ_COUNT="$(echo "$SEEN_AZS" | wc -w | tr -d ' ')"
[ "${AZ_COUNT:-0}" -ge 2 ] || die "Need public (IGW-routed) subnets in at least 2 AZs for the RDS subnet group; found: ${PUBLIC_SUBNETS:-none}."
info "Public subnets: ${PUBLIC_SUBNETS}"

if aws rds describe-db-subnet-groups --db-subnet-group-name "$RDS_SUBNET_GROUP" --region "$AWS_REGION" >/dev/null 2>&1; then
    info "DB subnet group ${RDS_SUBNET_GROUP} already exists — reusing."
else
    # shellcheck disable=SC2086  # PUBLIC_SUBNETS is an intentional space-separated list
    aws rds create-db-subnet-group \
        --db-subnet-group-name "$RDS_SUBNET_GROUP" \
        --db-subnet-group-description "tcx public subnets for RDS" \
        --subnet-ids $PUBLIC_SUBNETS \
        --region "$AWS_REGION" \
        --tags "Key=Project,Value=${PROJECT_TAG}" >/dev/null
    info "Created DB subnet group ${RDS_SUBNET_GROUP}"
fi

# DB instance
if aws rds describe-db-instances --db-instance-identifier "$RDS_ID" --region "$AWS_REGION" >/dev/null 2>&1; then
    info "RDS instance ${RDS_ID} already exists — reusing."
else
    aws rds create-db-instance \
        --db-instance-identifier "$RDS_ID" \
        --db-instance-class db.t3.micro \
        --engine mysql \
        --master-username "$RDS_USER" \
        --master-user-password "$RDS_PASS" \
        --allocated-storage 20 \
        --db-name "$RDS_DB" \
        --vpc-security-group-ids "$SG_ID" \
        --db-subnet-group-name "$RDS_SUBNET_GROUP" \
        --publicly-accessible \
        --backup-retention-period 0 \
        --no-multi-az \
        --storage-encrypted \
        --region "$AWS_REGION" \
        --tags "Key=Project,Value=${PROJECT_TAG}" >/dev/null
    info "RDS instance creation started (this takes ~10-15 minutes)..."
fi
info "Waiting for RDS instance to become available..."
aws rds wait db-instance-available --db-instance-identifier "$RDS_ID" --region "$AWS_REGION"
RDS_HOST="$(aws rds describe-db-instances --db-instance-identifier "$RDS_ID" \
              --query 'DBInstances[0].Endpoint.Address' --output text --region "$AWS_REGION")"
info "RDS endpoint: ${RDS_HOST}"

# Reachability guard: confirm the instance actually landed in a public subnet.
RDS_ENI_SUBNET="$(aws ec2 describe-network-interfaces --region "$AWS_REGION" \
    --filters "Name=group-id,Values=${SG_ID}" "Name=description,Values=RDSNetworkInterface" \
    --query 'NetworkInterfaces[0].SubnetId' --output text 2>/dev/null || echo None)"
case " $PUBLIC_SUBNETS " in
    *" $RDS_ENI_SUBNET "*) info "RDS network interface is in public subnet ${RDS_ENI_SUBNET}." ;;
    *) warn "RDS network interface is in '${RDS_ENI_SUBNET}', which is NOT a known public subnet — the DB may be unreachable and seeding below will fail." ;;
esac

log "Seeding database schema (mysqldb.users)"
RDS_HOST="$RDS_HOST" RDS_USER="$RDS_USER" RDS_PASS="$RDS_PASS" RDS_DB="$RDS_DB" python - <<'PY'
import os, time, pymysql
host, user, pw, db = os.environ["RDS_HOST"], os.environ["RDS_USER"], os.environ["RDS_PASS"], os.environ["RDS_DB"]
for attempt in range(10):
    try:
        conn = pymysql.connect(host=host, user=user, password=pw, database=db, port=3306, connect_timeout=10)
        break
    except Exception as e:
        print(f"   waiting for DB connectivity ({attempt+1}/10): {e}")
        time.sleep(15)
else:
    raise SystemExit("Could not connect to RDS to seed schema.")
with conn.cursor() as cur:
    cur.execute("""CREATE TABLE IF NOT EXISTS users (
        id INT AUTO_INCREMENT PRIMARY KEY,
        username VARCHAR(255) NOT NULL,
        email VARCHAR(255)
    )""")
    cur.execute("SELECT COUNT(*) FROM users")
    if cur.fetchone()[0] == 0:
        cur.executemany("INSERT INTO users (username, email) VALUES (%s, %s)",
                        [("alice", "alice@example.com"), ("bob", "bob@example.com")])
conn.commit(); conn.close()
print("   Seeded users table.")
PY

# ----------------------------------------------------------------------------
# 7. Write .env  (README §2)
# ----------------------------------------------------------------------------
log "Writing .env"
cat > .env <<EOF
# Generated by setup.sh on $(date -u +%Y-%m-%dT%H:%M:%SZ)

# AWS Configuration
AWS_REGION=${AWS_REGION}
BEDROCK_MODEL_ID=${BEDROCK_MODEL_ID}

# AWS SES Configuration
SES_SENDER_EMAIL=${SES_SENDER_EMAIL}
SES_REGION=${AWS_REGION}

# Keycloak Configuration
KEYCLOAK_URL=http://localhost:${KEYCLOAK_PORT}
KEYCLOAK_REALM=${KC_REALM}
KEYCLOAK_CLIENT_ID=${KC_CLIENT_ID}
KEYCLOAK_CLIENT_SECRET=${KC_CLIENT_SECRET}
KEYCLOAK_ADMIN_USER=admin
KEYCLOAK_ADMIN_PASSWORD=${KC_ADMIN_PASSWORD}
# RFC 8693 token exchange target/scope (provisioned above)
KEYCLOAK_TOKEN_AUDIENCE=mcp-server
KEYCLOAK_TOKEN_EXCHANGE_SCOPE=mcp-audience

# EJBCA Configuration
EJBCA_URL=https://localhost:${EJBCA_HTTPS_PORT}
EJBCA_CA_NAME=${EJBCA_CA_NAME}
EJBCA_CERT_PROFILE=${EJBCA_CERT_PROFILE}
EJBCA_END_ENTITY_PROFILE=${EJBCA_END_ENTITY_PROFILE}
EJBCA_API_ADMIN_CERT_PATH=./certs/api-admin.p12
EJBCA_API_ADMIN_CERT_PASSWORD=${EJBCA_ADMIN_CERT_PASSWORD}
CERT_VALIDITY_DAYS=7

# MySQL Database Configuration
RDS_HOST=${RDS_HOST}
RDS_PORT=3306
RDS_USER=${RDS_USER}
RDS_PASS=${RDS_PASS}
RDS_DB=${RDS_DB}

# Application Configuration
APP_SECRET_KEY=${APP_SECRET_KEY}
EOF
chmod 600 .env
info ".env written (permissions 600)."

# ----------------------------------------------------------------------------
# Done
# ----------------------------------------------------------------------------
log "Setup complete 🎉"
cat <<EOF

  Keycloak : http://localhost:${KEYCLOAK_PORT}
  EJBCA    : https://localhost:${EJBCA_HTTPS_PORT}/ejbca/
  RDS      : ${RDS_HOST}
  Demo user: ${KC_DEMO_USER}   (realm ${KC_REALM})

  All credentials have been securely written to .env (permissions 600).
  To retrieve credentials, run:  cat .env | grep -E '(PASSWORD|SECRET)'

  Remaining manual actions:
    • Click the SES verification link emailed to ${SES_SENDER_EMAIL}
    • Ensure Bedrock model access for Llama 4 Scout is enabled

  Launch the app:   ./run.sh   (then open http://localhost:8501)
  Tear everything down:   ./cleanup.sh
EOF
