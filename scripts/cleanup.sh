#!/usr/bin/env bash
#
# cleanup.sh
#
#   • Removes the local Keycloak and EJBCA Docker containers
#   • Deletes the AWS RDS instance and its security group
#   • Deletes the SES sender identity
#   • Deletes all mcp/* secrets created by the app in AWS Secrets Manager
#   • Removes generated certs (certs/api-admin.p12, certs/UserCA.pem)
#
# Only AWS resources tagged/named for this project (Project=tcx) are touched.
#
set -uo pipefail

# ----------------------------------------------------------------------------
# Configuration (must match setup.sh)
# ----------------------------------------------------------------------------
PROJECT_TAG="tcx"
AWS_REGION="us-east-2"
SES_SENDER_EMAIL="user@example.com"

KEYCLOAK_CONTAINER="tcx-keycloak"
EJBCA_CONTAINER="tcx-ejbca"

RDS_ID="tcx-mysql"
RDS_SG_NAME="tcx-rds-sg"
RDS_SUBNET_GROUP="tcx-public"

# These scripts live in ./scripts but operate on the project root (parent dir),
# so resolve it and cd there regardless of where the script is invoked from.
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
cd "$PROJECT_ROOT"

log()  { printf '\n\033[1;36m==> %s\033[0m\n' "$*"; }
info() { printf '    %s\n' "$*"; }
warn() { printf '\033[1;33m[warn] %s\033[0m\n' "$*"; }

# Confirmation
FORCE="${1:-}"
if [ "$FORCE" != "-y" ] && [ "$FORCE" != "--yes" ]; then
    printf 'This will DELETE the Docker containers and the AWS resources tagged Project=%s (RDS, SES, secrets).\n' "$PROJECT_TAG"
    read -r -p "Continue? [y/N] " ans
    case "$ans" in y|Y|yes|YES) ;; *) echo "Aborted."; exit 0 ;; esac
fi

# ----------------------------------------------------------------------------
# 1. Docker containers
# ----------------------------------------------------------------------------
log "Removing Docker containers"
for c in "$KEYCLOAK_CONTAINER" "$EJBCA_CONTAINER"; do
    if [ "$(docker ps -aq -f name="^${c}$")" ]; then
        docker rm -f "$c" >/dev/null && info "Removed container ${c}"
    else
        info "Container ${c} not present."
    fi
done

# ----------------------------------------------------------------------------
# 2. RDS instance
# ----------------------------------------------------------------------------
log "Deleting RDS instance ${RDS_ID}"
if aws rds describe-db-instances --db-instance-identifier "$RDS_ID" --region "$AWS_REGION" >/dev/null 2>&1; then
    aws rds delete-db-instance --db-instance-identifier "$RDS_ID" \
        --skip-final-snapshot --delete-automated-backups \
        --region "$AWS_REGION" >/dev/null
    info "Deletion requested; waiting for RDS instance to be fully deleted..."
    aws rds wait db-instance-deleted --db-instance-identifier "$RDS_ID" --region "$AWS_REGION" \
        && info "RDS instance deleted." \
        || warn "Timed out waiting for RDS deletion — check the console."
else
    info "RDS instance ${RDS_ID} not found."
fi

# ----------------------------------------------------------------------------
# 3. RDS DB subnet group (only after the instance is gone)
# ----------------------------------------------------------------------------
log "Deleting DB subnet group ${RDS_SUBNET_GROUP}"
if aws rds describe-db-subnet-groups --db-subnet-group-name "$RDS_SUBNET_GROUP" --region "$AWS_REGION" >/dev/null 2>&1; then
    for attempt in $(seq 1 10); do
        if aws rds delete-db-subnet-group --db-subnet-group-name "$RDS_SUBNET_GROUP" --region "$AWS_REGION" >/dev/null 2>&1; then
            info "Deleted DB subnet group ${RDS_SUBNET_GROUP}"; break
        fi
        info "DB subnet group still in use, retrying ($attempt/10)..."
        sleep 15
        [ "$attempt" -eq 10 ] && warn "Could not delete DB subnet group ${RDS_SUBNET_GROUP} — delete it manually once the RDS ENIs are released."
    done
else
    info "DB subnet group ${RDS_SUBNET_GROUP} not found."
fi

# ----------------------------------------------------------------------------
# 4. RDS security group (only after the instance is gone)
# ----------------------------------------------------------------------------
log "Deleting security group ${RDS_SG_NAME}"
SG_ID="$(aws ec2 describe-security-groups --filters "Name=group-name,Values=${RDS_SG_NAME}" \
           --query 'SecurityGroups[0].GroupId' --output text --region "$AWS_REGION" 2>/dev/null || echo None)"
if [ "$SG_ID" != "None" ] && [ -n "$SG_ID" ]; then
    for attempt in $(seq 1 10); do
        if aws ec2 delete-security-group --group-id "$SG_ID" --region "$AWS_REGION" >/dev/null 2>&1; then
            info "Deleted security group ${SG_ID}"; break
        fi
        info "Security group still in use, retrying ($attempt/10)..."
        sleep 15
        [ "$attempt" -eq 10 ] && warn "Could not delete security group ${SG_ID} — delete it manually once the RDS ENIs are released."
    done
else
    info "Security group ${RDS_SG_NAME} not found."
fi

# ----------------------------------------------------------------------------
# 5. SES identity
# ----------------------------------------------------------------------------
log "Deleting SES sender identity ${SES_SENDER_EMAIL}"
if aws sesv2 delete-email-identity --email-identity "$SES_SENDER_EMAIL" --region "$AWS_REGION" >/dev/null 2>&1; then
    info "Deleted SES identity."
else
    info "SES identity not found (or already deleted)."
fi

# ----------------------------------------------------------------------------
# 6. Secrets Manager (mcp/* created by the app at runtime)
# ----------------------------------------------------------------------------
log "Deleting Secrets Manager secrets under mcp/*"
SECRETS="$(aws secretsmanager list-secrets --region "$AWS_REGION" \
             --query "SecretList[?starts_with(Name, 'mcp/')].Name" --output text 2>/dev/null || true)"
if [ -n "${SECRETS// /}" ]; then
    for s in $SECRETS; do
        aws secretsmanager delete-secret --secret-id "$s" --force-delete-without-recovery \
            --region "$AWS_REGION" >/dev/null 2>&1 && info "Deleted secret ${s}"
    done
else
    info "No mcp/* secrets found."
fi

# ----------------------------------------------------------------------------
# 7. Generated certs
# ----------------------------------------------------------------------------
log "Removing generated certificates"
rm -f ./certs/api-admin.p12 ./certs/UserCA.pem && info "Removed certs/api-admin.p12 and certs/UserCA.pem" || true

log "Cleanup complete ✅"
info "Note: ./.venv and ./.env were left in place. Remove them manually if desired."
