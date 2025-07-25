#!/bin/bash
#
# fetch_secrets.sh
#
# This helper script pulls application credentials out of AWS Secrets Manager and
# writes them to `.env` files used by Docker Compose.  It expects that the
# `aws` CLI and `jq` are installed and that the caller has permission to read
# the specified secrets.  The resulting files will be created in the current
# working directory.

set -euo pipefail

REGION="${AWS_REGION:-us-east-1}"
N8N_SECRET_NAME="${N8N_SECRET_NAME:-n8n/credentials}"
DB_SECRET_NAME="${DB_SECRET_NAME:-zep/db}"
QDRANT_SECRET_NAME="${QDRANT_SECRET_NAME:-qdrant/credentials}"

# These environment variables must be exported by the caller when connecting to
# the Aurora cluster.  The DB_HOST and DB_PORT are usually published as
# Pulumi stack outputs and should be set before running this script.
DB_HOST="${DB_HOST:?DB_HOST must be set to the Aurora cluster endpoint}"
DB_PORT="${DB_PORT:-5432}"
DB_NAME="${DB_NAME:-zep}"

echo "Fetching n8n credentials from $N8N_SECRET_NAME …"
n8n_secret=$(aws secretsmanager get-secret-value --region "$REGION" --secret-id "$N8N_SECRET_NAME" --query SecretString --output text)
echo "$n8n_secret" | jq -r 'to_entries|map("\(.key)=\(.value)")|.[]' > .env.n8n
echo ".env.n8n written."

echo "Fetching database credentials from $DB_SECRET_NAME …"
db_secret=$(aws secretsmanager get-secret-value --region "$REGION" --secret-id "$DB_SECRET_NAME" --query SecretString --output text)
DB_USER=$(echo "$db_secret" | jq -r '.username')
DB_PASS=$(echo "$db_secret" | jq -r '.password')
cat > .env.zep <<EOF
POSTGRES_URI=postgresql://$DB_USER:$DB_PASS@$DB_HOST:$DB_PORT/$DB_NAME
QDRANT_URL=http://qdrant:6333
EOF
echo ".env.zep written."

if aws secretsmanager describe-secret --region "$REGION" --secret-id "$QDRANT_SECRET_NAME" >/dev/null 2>&1; then
  echo "Fetching Qdrant credentials from $QDRANT_SECRET_NAME …"
  qdrant_secret=$(aws secretsmanager get-secret-value --region "$REGION" --secret-id "$QDRANT_SECRET_NAME" --query SecretString --output text)
  echo "$qdrant_secret" | jq -r 'to_entries|map("QDRANT_\(.key)=\(.value)")|.[]' > .env.qdrant
  echo ".env.qdrant written."
fi
