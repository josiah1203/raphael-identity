"""Hosted platform authentication service."""

from __future__ import annotations

import hashlib
import os
import secrets
import time
from dataclasses import dataclass
from typing import Any

import httpx

from raphael_identity.hblabs.auth.mfa import RealWebAuthnClient, generate_totp_secret, verify_totp
from raphael_identity.hblabs.auth.passwords import (
    HibpClient,
    LiveHibpClient,
    hash_password,
    validate_password_strength,
    verify_password_with_migration,
)
from raphael_identity.hblabs.db import PlatformStore


ACCESS_TTL = 15 * 60  # 15 minutes
REFRESH_TTL = 30 * 24 * 3600  # 30 days


@dataclass
class AuthTokens:
    access_token: str
    refresh_token: str
    expires_in: int = ACCESS_TTL


class AuthService:
    """Email/password, magic link, OAuth, invite-only beta, MFA."""

    OAUTH_PROVIDERS = {"google", "github"}
    OAUTH_CONFIG = {
        "google": {
            "auth_url": "https://accounts.google.com/o/oauth2/v2/auth",
            "token_url": "https://oauth2.googleapis.com/token",
            "user_info_url": "https://www.googleapis.com/oauth2/v3/userinfo",
            "scope": "openid email profile",
        },
        "github": {
            "auth_url": "https://github.com/login/oauth/authorize",
            "token_url": "https://github.com/login/oauth/access_token",
            "user_info_url": "https://api.github.com/user",
            "scope": "read:user user:email",
        },
    }

    def __init__(
        self,
        store: PlatformStore,
        *,
        jwt_secret: str,
        invite_only: bool = True,
        hibp: HibpClient | None = None,
    ) -> None:
        self.store = store
        self.jwt_secret = jwt_secret
        self.invite_only = invite_only
        self.hibp = hibp or LiveHibpClient()
        self.webauthn = RealWebAuthnClient()

    def _new_id(self, prefix: str = "") -> str:
        return f"{prefix}{secrets.token_hex(16)}" if prefix else secrets.token_hex(16)

    def _hash_token(self, token: str) -> str:
        return hashlib.sha256(token.encode()).hexdigest()

    def _encode_jwt(self, sub: str, org_id: str, *, ttl: int = ACCESS_TTL) -> str:
        import base64
        import hmac
        import json
        from base64 import urlsafe_b64encode

        def b64url(data: bytes) -> str:
            return urlsafe_b64encode(data).rstrip(b"=").decode("ascii")

        header = b64url(json.dumps({"alg": "HS256", "typ": "JWT"}).encode())
        payload = {
            "sub": sub,
            "org_id": org_id,
            "iss": "raphael-identity",
            "exp": int(time.time()) + ttl,
            "iat": int(time.time()),
        }
        body = b64url(json.dumps(payload).encode())
        sig = hmac.new(self.jwt_secret.encode(), f"{header}.{body}".encode(), hashlib.sha256).digest()
        return f"{header}.{body}.{b64url(sig)}"

    def verify_access_token(self, token: str) -> dict[str, Any] | None:
        import base64
        import hmac
        import json
        from base64 import urlsafe_b64encode

        def b64url(data: bytes) -> str:
            return urlsafe_b64encode(data).rstrip(b"=").decode("ascii")

        try:
            header_b64, body_b64, sig_b64 = token.split(".")
            pad = lambda s: s + "=" * (-len(s) % 4)
            body = json.loads(base64.urlsafe_b64decode(pad(body_b64)))
            expected = hmac.new(self.jwt_secret.encode(), f"{header_b64}.{body_b64}".encode(), hashlib.sha256).digest()
            if b64url(expected) != sig_b64 or body.get("exp", 0) < time.time():
                return None
            return body
        except Exception:
            return None

    def create_api_key(self, user_id: str, org_id: str, name: str, scopes: list[str] | None = None) -> dict[str, str]:
        raw = f"raph_{secrets.token_urlsafe(32)}"
        key_id = self._new_id("key_")
        self.store.execute(
            """INSERT INTO api_keys (id, org_id, user_id, name, key_prefix, key_hash, scopes, created_at)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
            (key_id, org_id, user_id, name, raw[:12], self._hash_token(raw), ",".join(scopes or []), time.time()),
        )
        return {"id": key_id, "key": raw, "prefix": raw[:12]}

    def verify_api_key(self, raw_key: str) -> dict[str, Any] | None:
        row = self.store.fetchone(
            "SELECT * FROM api_keys WHERE key_hash = ? AND revoked = 0",
            (self._hash_token(raw_key),),
        )
        if not row:
            return None
        keys = row.keys()
        user_id = row["user_id"] if "user_id" in keys else "usr_default"
        scopes = row["scopes"] if "scopes" in keys else ""
        return {
            "user_id": user_id,
            "org_id": row["org_id"],
            "scopes": [s for s in (scopes or "").split(",") if s],
        }

    def create_invite(self, email: str, org_id: str) -> str:
        token = secrets.token_urlsafe(32)
        user_id = self._new_id("usr_")
        self.store.execute(
            """INSERT INTO users (id, org_id, email, invite_token, invite_accepted, created_at)
               VALUES (?, ?, ?, ?, 0, ?)""",
            (user_id, org_id, email.lower(), self._hash_token(token), time.time()),
        )
        return token

    def register(
        self,
        email: str,
        password: str,
        *,
        invite_token: str | None = None,
        org_id: str = "org_default",
    ) -> AuthTokens | dict[str, str]:
        email = email.lower()
        if err := validate_password_strength(password, self.hibp):
            return {"error": err}

        user = self.store.fetchone("SELECT * FROM users WHERE email = ?", (email,))
        if user and user["password_hash"]:
            return {"error": "email_exists"}

        if self.invite_only:
            if not invite_token:
                return {"error": "invite_required"}
            row = self.store.fetchone(
                "SELECT * FROM users WHERE email = ? AND invite_token = ?",
                (email, self._hash_token(invite_token)),
            )
            if not row:
                return {"error": "invalid_invite"}
            user_id = row["id"]
            org_id = row["org_id"]
            self.store.execute(
                """UPDATE users SET password_hash = ?, invite_accepted = 1, invite_token = NULL
                   WHERE id = ?""",
                (hash_password(password), user_id),
            )
        else:
            user_id = self._new_id("usr_")
            self.store.execute(
                """INSERT INTO users (id, org_id, email, password_hash, invite_accepted, created_at)
                   VALUES (?, ?, ?, ?, 1, ?)""",
                (user_id, org_id, email, hash_password(password), time.time()),
            )

        return self._issue_tokens(user_id, org_id)

    def login(self, email: str, password: str, *, totp_code: str | None = None) -> AuthTokens | dict[str, str]:
        user = self.store.fetchone("SELECT * FROM users WHERE email = ?", (email.lower(),))
        if not user or not user["password_hash"]:
            return {"error": "invalid_credentials"}
        ok, upgraded = verify_password_with_migration(password, user["password_hash"])
        if not ok:
            return {"error": "invalid_credentials"}
        if upgraded:
            self.store.execute(
                "UPDATE users SET password_hash = ? WHERE id = ?",
                (upgraded, user["id"]),
            )
        if user["mfa_secret"]:
            if not totp_code or not verify_totp(user["mfa_secret"], totp_code):
                return {"error": "mfa_required"}
        return self._issue_tokens(user["id"], user["org_id"])

    def _issue_tokens(self, user_id: str, org_id: str) -> AuthTokens:
        access = self._encode_jwt(user_id, org_id, ttl=ACCESS_TTL)
        refresh = secrets.token_urlsafe(48)
        self.store.execute(
            "INSERT INTO refresh_tokens (token_hash, user_id, expires_at) VALUES (?, ?, ?)",
            (self._hash_token(refresh), user_id, time.time() + REFRESH_TTL),
        )
        return AuthTokens(access_token=access, refresh_token=refresh)

    def refresh(self, refresh_token: str) -> AuthTokens | dict[str, str]:
        row = self.store.fetchone(
            """SELECT rt.*, u.org_id FROM refresh_tokens rt
               JOIN users u ON u.id = rt.user_id
               WHERE rt.token_hash = ? AND rt.revoked = 0""",
            (self._hash_token(refresh_token),),
        )
        if not row or row["expires_at"] < time.time():
            return {"error": "invalid_refresh_token"}
        return self._issue_tokens(row["user_id"], row["org_id"])

    def create_magic_link(self, email: str) -> str:
        token = secrets.token_urlsafe(32)
        self.store.execute(
            "INSERT INTO magic_links (token_hash, email, expires_at) VALUES (?, ?, ?)",
            (self._hash_token(token), email.lower(), time.time() + 900),
        )
        return token

    def redeem_magic_link(self, token: str) -> AuthTokens | dict[str, str]:
        row = self.store.fetchone(
            "SELECT * FROM magic_links WHERE token_hash = ? AND used = 0",
            (self._hash_token(token),),
        )
        if not row or row["expires_at"] < time.time():
            return {"error": "invalid_magic_link"}
        self.store.execute("UPDATE magic_links SET used = 1 WHERE token_hash = ?", (row["token_hash"],))
        user = self.store.fetchone("SELECT * FROM users WHERE email = ?", (row["email"],))
        if not user:
            user_id = self._new_id("usr_")
            org_id = self._new_id("org_")
            self.store.execute(
                "INSERT INTO orgs (id, name, created_at) VALUES (?, ?, ?)",
                (org_id, f"{row['email']}'s org", time.time()),
            )
            self.store.execute(
                """INSERT INTO users (id, org_id, email, invite_accepted, created_at)
                   VALUES (?, ?, ?, 1, ?)""",
                (user_id, org_id, row["email"], time.time()),
            )
            return self._issue_tokens(user_id, org_id)
        return self._issue_tokens(user["id"], user["org_id"])

    def oauth_start(self, provider: str, redirect_uri: str) -> dict[str, str]:
        if provider not in self.OAUTH_PROVIDERS:
            return {"error": "unsupported_provider"}

        config = self.OAUTH_CONFIG[provider]
        client_id = os.environ.get(f"{provider.upper()}_CLIENT_ID")
        if not client_id:
            return {"error": "provider_not_configured"}

        state = secrets.token_urlsafe(24)
        self.store.execute(
            "INSERT INTO oauth_states (state, provider, redirect_uri, expires_at) VALUES (?, ?, ?, ?)",
            (state, provider, redirect_uri, time.time() + 600),
        )

        params = {
            "client_id": client_id,
            "redirect_uri": redirect_uri,
            "response_type": "code",
            "scope": config["scope"],
            "state": state,
        }
        query = "&".join(f"{k}={v}" for k, v in params.items())
        return {"authorization_url": f"{config['auth_url']}?{query}", "state": state}

    def oauth_callback(
        self, provider: str, state: str, code: str
    ) -> AuthTokens | dict[str, str]:
        row = self.store.fetchone(
            "SELECT * FROM oauth_states WHERE state = ? AND provider = ?",
            (state, provider),
        )
        if not row or row["expires_at"] < time.time():
            return {"error": "invalid_oauth_state"}
        self.store.execute("DELETE FROM oauth_states WHERE state = ?", (state,))

        config = self.OAUTH_CONFIG[provider]
        client_id = os.environ.get(f"{provider.upper()}_CLIENT_ID")
        client_secret = os.environ.get(f"{provider.upper()}_CLIENT_SECRET")

        # Exchange code for token
        with httpx.Client() as client:
            resp = client.post(
                config["token_url"],
                data={
                    "client_id": client_id,
                    "client_secret": client_secret,
                    "code": code,
                    "redirect_uri": row["redirect_uri"],
                    "grant_type": "authorization_code",
                },
                headers={"Accept": "application/json"},
            )
            if resp.status_code != 200:
                return {"error": "token_exchange_failed"}
            tokens = resp.json()

            # Fetch user info
            user_resp = client.get(
                config["user_info_url"],
                headers={"Authorization": f"Bearer {tokens['access_token']}"},
            )
            if user_resp.status_code != 200:
                return {"error": "user_info_failed"}
            user_info = user_resp.json()

        email = user_info.get("email")
        if not email and provider == "github":
            # GitHub might not return email in primary user info if it's private
            with httpx.Client() as client:
                emails_resp = client.get(
                    "https://api.github.com/user/emails",
                    headers={"Authorization": f"Bearer {tokens['access_token']}"},
                )
                if emails_resp.status_code == 200:
                    emails = emails_resp.json()
                    primary = next((e for e in emails if e.get("primary")), emails[0])
                    email = primary.get("email")

        if not email:
            return {"error": "email_not_provided"}

        user = self.store.fetchone("SELECT * FROM users WHERE email = ?", (email.lower(),))
        if not user:
            if self.invite_only:
                return {"error": "invite_required"}
            user_id = self._new_id("usr_")
            org_id = self._new_id("org_")
            self.store.execute(
                "INSERT INTO orgs (id, name, created_at) VALUES (?, ?, ?)",
                (org_id, email, time.time()),
            )
            self.store.execute(
                """INSERT INTO users (id, org_id, email, invite_accepted, created_at)
                   VALUES (?, ?, ?, 1, ?)""",
                (user_id, org_id, email.lower(), time.time()),
            )
            return self._issue_tokens(user_id, org_id)
        return self._issue_tokens(user["id"], user["org_id"])

    def setup_mfa(self, user_id: str, email: str) -> dict[str, str]:
        setup = generate_totp_secret(email=email)
        self.store.execute("UPDATE users SET mfa_secret = ? WHERE id = ?", (setup.secret, user_id))
        return {"secret": setup.secret, "provisioning_uri": setup.provisioning_uri}

    def setup_webauthn(self, user_id: str) -> dict[str, Any]:
        cred = self.webauthn.register(user_id)
        import json

        self.store.execute(
            "UPDATE users SET webauthn_credential = ? WHERE id = ?",
            (json.dumps({"credential_id": cred.credential_id, "public_key": cred.public_key}), user_id),
        )
        return {"credential_id": cred.credential_id}

    def generate_recovery_codes(self, user_id: str, count: int = 8) -> list[str]:
        codes = [secrets.token_hex(4) for _ in range(count)]
        import json

        hashed = [hashlib.sha256(c.encode()).hexdigest() for c in codes]
        self.store.execute(
            "UPDATE users SET recovery_codes = ? WHERE id = ?",
            (json.dumps(hashed), user_id),
        )
        return codes

    def use_recovery_code(self, email: str, code: str) -> AuthTokens | dict[str, str]:
        import json

        user = self.store.fetchone("SELECT * FROM users WHERE email = ?", (email.lower(),))
        if not user or not user["recovery_codes"]:
            return {"error": "invalid_recovery_code"}
        stored: list[str] = json.loads(user["recovery_codes"])
        code_hash = hashlib.sha256(code.encode()).hexdigest()
        if code_hash not in stored:
            return {"error": "invalid_recovery_code"}
        stored.remove(code_hash)
        self.store.execute(
            "UPDATE users SET recovery_codes = ? WHERE id = ?",
            (json.dumps(stored), user["id"]),
        )
        return self._issue_tokens(user["id"], user["org_id"])
