"""MFA: TOTP and WebAuthn."""

from __future__ import annotations

import json
import os
from dataclasses import dataclass
from typing import Any

import pyotp
from webauthn import (
    base64url_to_bytes,
    generate_registration_options,
    options_to_json,
    verify_registration_response,
)
from webauthn.helpers.bytes_to_base64url import bytes_to_base64url


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
    """WebAuthn registration via py_webauthn."""

    def __init__(
        self,
        rp_id: str | None = None,
        rp_name: str = "HB Labs",
        origin: str | None = None,
    ) -> None:
        self.rp_id = rp_id or os.environ.get("RAPHAEL_WEBAUTHN_RP_ID", "localhost")
        self.rp_name = rp_name
        self.origin = origin or os.environ.get("RAPHAEL_WEBAUTHN_ORIGIN", "http://localhost:5000")
        self._pending_challenges: dict[str, str] = {}

    def begin_registration(
        self,
        user_id: str,
        email: str,
        *,
        challenge: bytes | None = None,
    ) -> str:
        options = generate_registration_options(
            rp_id=self.rp_id,
            rp_name=self.rp_name,
            user_id=user_id.encode("utf-8"),
            user_name=email,
            user_display_name=email,
            challenge=challenge,
        )
        challenge_b64 = bytes_to_base64url(options.challenge)
        self._pending_challenges[user_id] = challenge_b64
        return options_to_json(options)

    def finish_registration(
        self,
        response: dict[str, Any],
        expected_challenge: str | None = None,
        *,
        user_id: str | None = None,
    ) -> WebAuthnCredential:
        challenge_b64 = expected_challenge
        if challenge_b64 is None:
            if not user_id:
                raise ValueError("expected_challenge or user_id required")
            challenge_b64 = self._pending_challenges.pop(user_id, None)
        elif user_id:
            self._pending_challenges.pop(user_id, None)
        if not challenge_b64:
            raise ValueError("no_pending_registration")

        verification = verify_registration_response(
            credential=response,
            expected_challenge=base64url_to_bytes(challenge_b64),
            expected_rp_id=self.rp_id,
            expected_origin=self.origin,
        )
        return WebAuthnCredential(
            credential_id=bytes_to_base64url(verification.credential_id),
            public_key=bytes_to_base64url(verification.credential_public_key),
            sign_count=verification.sign_count,
        )

    def registration_options_dict(self, user_id: str, email: str) -> dict[str, Any]:
        return json.loads(self.begin_registration(user_id, email))
