#!/usr/bin/env python3
"""Fetch a secret from AWS Secrets Manager and print its value.

This utility makes it easy to pull secrets at development time without
logging into the AWS console.  It requires valid AWS credentials to be
available in the environment (e.g. via `aws configure` or an assumed role).

Usage:
    python get_secrets.py <secret_name> [region]

If a region is not provided, the default region configured for the AWS
session will be used.
"""
import json
import sys
from typing import Any

import boto3
from botocore.exceptions import ClientError


def fetch_secret(name: str, region: str | None = None) -> Any:
    """Retrieve a secret string from Secrets Manager and decode JSON if possible."""
    session = boto3.Session(region_name=region)
    client = session.client("secretsmanager")
    try:
        resp = client.get_secret_value(SecretId=name)
    except ClientError as exc:
        raise SystemExit(f"error fetching secret: {exc}") from exc
    secret = resp.get("SecretString")
    try:
        return json.loads(secret)
    except Exception:
        return secret


def main() -> None:
    if len(sys.argv) < 2:
        print("Usage: python get_secrets.py <secret_name> [region]", file=sys.stderr)
        raise SystemExit(1)
    name = sys.argv[1]
    region = sys.argv[2] if len(sys.argv) > 2 else None
    value = fetch_secret(name, region)
    print(json.dumps(value, indent=2) if isinstance(value, dict) else value)


if __name__ == "__main__":
    main()