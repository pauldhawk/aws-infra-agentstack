#!/bin/bash
#
# backup_to_s3.sh
#
# Compresses the local Docker volumes for n8n, Zep and Qdrant and uploads
# the archive to an S3 bucket.  Assumes the AWS CLI is installed and the
# executing user/role has write permissions on the target bucket.

set -euo pipefail

REGION="${AWS_REGION:-us-east-1}"
BUCKET="${BACKUP_BUCKET:?A BACKUP_BUCKET environment variable must be set}"

TIMESTAMP=$(date +"%Y-%m-%d-%H-%M-%S")
ARCHIVE="/tmp/n8n_backup_${TIMESTAMP}.tar.gz"

echo "Creating backup archive $ARCHIVE …"
tar czf "$ARCHIVE" -C . n8n_data zep_data qdrant_data

echo "Uploading to s3://$BUCKET/ …"
aws s3 cp "$ARCHIVE" "s3://$BUCKET/" --region "$REGION" --sse AES256

echo "Cleanup …"
rm -f "$ARCHIVE"
echo "Backup complete."
