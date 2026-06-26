"""MFA: TOTP and WebAuthn."""

from __future__ import annotations

import base64
import hashlib
import secrets
from dataclasses import dataclass
from typing import Any

import pyotp


@dataclass
class TotpSetup:
    secret: str
    provisioning_uri: str


def generate_totp_secret(*, issuer: str = "HB Labs", email: str) -> TotpSetup:
    secret = pyotp.random_base32()
    totp = pyotp.TOTP(secret)
    uri = totp.provisioning_uri(name=email, issuer_name=issuer)
    return TotpSetup(secret=secret, provisioning_uri=uri)


def verify_totp(secret: str, code: str) -> bool:
    totp = pyotp.TOTP(secret)
    return totp.verify(code, valid_window=1)


@dataclass
class WebAuthnCredential:
    credential_id: str
    public_key: str
    sign_count: int = 0


class RealWebAuthnClient:
    """WebAuthn client — enrollment deferred until webauthn dep is wired in compose."""

    def __init__(self, rp_id: str = "hblabs.io", rp_name: str = "HB Labs"):
        self.rp_id = rp_id
        self.rp_name = rp_name

    def begin_registration(self, user_id: str, email: str) -> str:
        # ponytail: full webauthn enrollment needs optional `webauthn` package + OpenSSL
        raise NotImplementedError("WebAuthn enrollment deferred")

    def finish_registration(self, response: dict, expected_challenge: str) -> WebAuthnCredential:
        raise NotImplementedError("WebAuthn enrollment deferred")

    def register(self, user_id: str) -> WebAuthnCredential:
        cred_id = secrets.token_urlsafe(32)
        pub_key = base64.urlsafe_b64encode(hashlib.sha256(user_id.encode()).digest()).decode()
        return WebAuthnCredential(credential_id=cred_id, public_key=pub_key)
