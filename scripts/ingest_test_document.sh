#!/bin/bash
#
# ingest_test_document.sh
#
# This script demonstrates how to ingest a simple document into the Zep
# memory service.  Zep exposes a REST API on port 8000; you can run this
# script on the EC2 host or from any machine with network access to the
# service.  Refer to the Zep documentation for additional endpoints and
# payload formats.

set -euo pipefail

ZEP_URL="${ZEP_URL:-http://localhost:8000}"

echo "Ingesting test document into Zep at $ZEP_URL …"

payload='{"documents": [{"id": "test-doc", "description": "Sample document", "text": "Hello world, this is a test document for Zep memory."}]}'

curl -s -X POST "$ZEP_URL/api/v1/documents" \
  -H "Content-Type: application/json" \
  -d "$payload" | jq .

echo "Document ingested."
