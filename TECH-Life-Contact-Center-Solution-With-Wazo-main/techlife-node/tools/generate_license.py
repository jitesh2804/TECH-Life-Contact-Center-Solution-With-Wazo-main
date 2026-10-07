#!/usr/bin/env python3
"""Generate Ed25519-signed TECH-Life tenant license files."""

import argparse
import base64
import ipaddress
import json
import re
import sys
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path

try:
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
except ImportError:
    print("Missing dependency. Install it with: python -m pip install cryptography", file=sys.stderr)
    raise SystemExit(1)


def canonical_json(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def prompt_value(label, validator=None):
    while True:
        value = input(f"{label}: ").strip()
        if value and (validator is None or validator(value)):
            return value
        print("Please enter a valid value.")


def main():
    parser = argparse.ArgumentParser(description="Create signed, tenant-bound TECH-Life licenses.")
    parser.add_argument("--init-keys", action="store_true", help="Create an Ed25519 key pair and exit.")
    parser.add_argument("--private-key", type=Path, default=Path("license_private.pem"))
    parser.add_argument("--public-key", type=Path, default=Path("license_public.pem"))
    parser.add_argument("--output", type=Path, default=Path("tenant-license.json"))
    args = parser.parse_args()

    if args.init_keys:
        if args.private_key.exists() or args.public_key.exists():
            parser.error("A key file already exists; choose unused output paths to avoid replacing keys.")
        private_key = Ed25519PrivateKey.generate()
        args.private_key.write_bytes(private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        ))
        args.public_key.write_bytes(private_key.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        ))
        try:
            args.private_key.chmod(0o600)
        except OSError:
            pass
        print(f"Private signing key: {args.private_key.resolve()}")
        print(f"Public verification key: {args.public_key.resolve()}")
        print("Keep the private key offline and never copy it to the application server.")
        return

    if not args.private_key.is_file():
        parser.error(f"Private key not found: {args.private_key}. Run once with --init-keys first.")

    tenant_slug = prompt_value("TECH-Life tenant slug")

    def valid_ip(value):
        try:
            ipaddress.ip_address(value)
            return True
        except ValueError:
            return False

    server_ip = prompt_value("Server IP address", valid_ip)
    domain_id = prompt_value("Domain ID")

    def valid_mac(value):
        return re.fullmatch(r"(?:[0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}", value) is not None

    server_mac = prompt_value("Server MAC address (example: 00:11:22:33:44:55)", valid_mac).replace("-", ":").lower()

    while True:
        try:
            max_users = int(prompt_value("Maximum licensed user count", lambda value: value.isdigit() and int(value) > 0))
            break
        except ValueError:
            print("Enter a positive whole number.")

    while True:
        try:
            valid_days = int(prompt_value("License duration in days", lambda value: value.isdigit() and int(value) > 0))
            break
        except ValueError:
            print("Enter a positive whole number.")

    issued_at = datetime.now(timezone.utc).replace(microsecond=0)
    expires_at = issued_at + timedelta(days=valid_days)
    payload = {
        "version": 1,
        "license_id": str(uuid.uuid4()),
        "tenant_slug": tenant_slug,
        "server_ip": server_ip,
        "domain_id": domain_id,
        "server_mac": server_mac,
        "max_users": max_users,
        "issued_at": issued_at.isoformat().replace("+00:00", "Z"),
        "expires_at": expires_at.isoformat().replace("+00:00", "Z"),
    }

    private_key = serialization.load_pem_private_key(args.private_key.read_bytes(), password=None)
    signature = private_key.sign(canonical_json(payload))
    document = {
        "payload": payload,
        "signature": base64.b64encode(signature).decode("ascii"),
    }
    args.output.write_text(json.dumps(document, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    print(f"License created: {args.output.resolve()}")
    print(f"Tenant: {tenant_slug} | User limit: {max_users} | Expires: {payload['expires_at']}")


if __name__ == "__main__":
    main()
