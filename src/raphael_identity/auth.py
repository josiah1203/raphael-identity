"""Authentication service — migrated from hblabs-platform."""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import secrets
import time
from base64 import urlsafe_b64encode
from dataclasses import dataclass
from typing import Any

from raphael_identity.passwords import hash_password, validate_password_strength, verify_password
from raphael_identity.store import IdentityStore

ACCESS_TTL = 15 * 60
REFRESH_TTL = 30 * 24 * 3600


@dataclass
class AuthTokens:
    access_token: str
    refresh_token: str
    expires_in: int = ACCESS_TTL


def _b64url(data: bytes) -> str:
    return urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


class AuthService:
    def __init__(self, store: IdentityStore, *, jwt_secret: str, invite_only: bool = False) -> None:
        self.store = store
        self.jwt_secret = jwt_secret
        self.invite_only = invite_only

    def _hash_token(self, token: str) -> str:
        return hashlib.sha256(token.encode()).hexdigest()

    def _encode_jwt(self, sub: str, org_id: str, *, ttl: int = ACCESS_TTL) -> str:
        header = _b64url(json.dumps({"alg": "HS256", "typ": "JWT"}).encode())
        payload = {
            "sub": sub,
            "org_id": org_id,
            "iss": "raphael-identity",
            "exp": int(time.time()) + ttl,
            "iat": int(time.time()),
        }
        body = _b64url(json.dumps(payload).encode())
        sig = hmac.new(self.jwt_secret.encode(), f"{header}.{body}".encode(), hashlib.sha256).digest()
        return f"{header}.{body}.{_b64url(sig)}"

    def register(
        self, email: str, password: str, *, invite_token: str | None = None, org_id: str = "org_default"
    ) -> AuthTokens | dict[str, str]:
        email = email.lower()
        if err := validate_password_strength(password):
            return {"error": err}
        existing = self.store.fetchone("SELECT id FROM users WHERE email = ?", (email,))
        if existing:
            return {"error": "email_exists"}
        user_id = f"usr_{secrets.token_hex(8)}"
        pw_hash = hash_password(password)
        self.store.execute(
            "INSERT INTO users (id, org_id, email, password_hash, invite_accepted, created_at) VALUES (?, ?, ?, ?, 1, ?)",
            (user_id, org_id, email, pw_hash, time.time()),
        )
        return self._issue_tokens(user_id, org_id)

    def login(self, email: str, password: str) -> AuthTokens | dict[str, str]:
        email = email.lower()
        row = self.store.fetchone("SELECT * FROM users WHERE email = ?", (email,))
        if not row or not row["password_hash"]:
            return {"error": "invalid_credentials"}
        if not verify_password(password, row["password_hash"]):
            return {"error": "invalid_credentials"}
        return self._issue_tokens(row["id"], row["org_id"])

    def _issue_tokens(self, user_id: str, org_id: str) -> AuthTokens:
        access = self._encode_jwt(user_id, org_id)
        refresh = secrets.token_urlsafe(32)
        self.store.execute(
            "INSERT INTO refresh_tokens (token_hash, user_id, expires_at) VALUES (?, ?, ?)",
            (self._hash_token(refresh), user_id, time.time() + REFRESH_TTL),
        )
        return AuthTokens(access_token=access, refresh_token=refresh)

    def create_api_key(self, user_id: str, org_id: str, name: str, scopes: list[str] | None = None) -> dict[str, str]:
        raw = f"raph_{secrets.token_urlsafe(32)}"
        key_id = f"key_{secrets.token_hex(8)}"
        self.store.execute(
            """INSERT INTO api_keys (id, org_id, user_id, name, key_prefix, key_hash, scopes, created_at)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                key_id,
                org_id,
                user_id,
                name,
                raw[:12],
                self._hash_token(raw),
                ",".join(scopes or []),
                time.time(),
            ),
        )
        return {"id": key_id, "key": raw, "prefix": raw[:12]}

    def verify_api_key(self, raw_key: str) -> dict[str, Any] | None:
        row = self.store.fetchone(
            "SELECT * FROM api_keys WHERE key_hash = ? AND revoked = 0",
            (self._hash_token(raw_key),),
        )
        if not row:
            return None
        return {
            "user_id": row["user_id"],
            "org_id": row["org_id"],
            "scopes": [s for s in (row["scopes"] or "").split(",") if s],
        }
