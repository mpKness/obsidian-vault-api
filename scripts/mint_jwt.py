#!/usr/bin/env python3
"""Mint HS256 JWTs for the obsidian-vault-api service."""

from __future__ import annotations

import argparse
import base64
import hashlib
import hmac
import json
import os
import sys
import time


def b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def sign_hs256(message: bytes, secret: bytes) -> bytes:
    return hmac.new(secret, message, hashlib.sha256).digest()


def build_token(secret: str, issuer: str, audience: str, subject: str | None, ttl_seconds: int) -> str:
    now = int(time.time())

    header = {"alg": "HS256", "typ": "JWT"}
    payload = {
        "iss": issuer,
        "aud": audience,
        "iat": now,
        "exp": now + ttl_seconds,
    }
    if subject:
        payload["sub"] = subject

    header_part = b64url(json.dumps(header, separators=(",", ":")).encode("utf-8"))
    payload_part = b64url(json.dumps(payload, separators=(",", ":")).encode("utf-8"))
    signing_input = f"{header_part}.{payload_part}".encode("ascii")

    sig = b64url(sign_hs256(signing_input, secret.encode("utf-8")))
    return f"{header_part}.{payload_part}.{sig}"


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Mint an HS256 JWT for obsidian-vault-api")
    parser.add_argument("--secret", default=os.getenv("JWT_SECRET", ""), help="JWT secret (defaults to JWT_SECRET env var)")
    parser.add_argument("--issuer", default=os.getenv("JWT_ISSUER", "obsidian-vault-api"), help="iss claim")
    parser.add_argument("--audience", default=os.getenv("JWT_AUDIENCE", "vault-clients"), help="aud claim")
    parser.add_argument("--subject", default=None, help="optional sub claim")
    parser.add_argument("--ttl", type=int, default=3600, help="token lifetime in seconds (default: 3600)")
    return parser.parse_args()


def main() -> int:
    args = parse_args()

    if not args.secret:
        print("error: missing JWT secret. Set JWT_SECRET or pass --secret", file=sys.stderr)
        return 2
    if args.ttl <= 0:
        print("error: --ttl must be > 0", file=sys.stderr)
        return 2

    token = build_token(
        secret=args.secret,
        issuer=args.issuer,
        audience=args.audience,
        subject=args.subject,
        ttl_seconds=args.ttl,
    )
    print(token)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
