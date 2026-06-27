"""WebAuthn registration tests using py_webauthn example credential as virtual authenticator."""

from __future__ import annotations

import json

import pytest
from webauthn import base64url_to_bytes

from raphael_identity.hblabs.auth.mfa import RealWebAuthnClient

# Fixed challenge + attestation from py_webauthn examples/registration.py (localhost RP).
KNOWN_CHALLENGE = (
    "CeTWogmg0cchuiYuFrv8DXXdMZSIQRVZJOga_xayVVEcBj0Cw3y73yhD4FkGSe-RrP6hPJJAIm3LVien4hXELg"
)
VIRTUAL_AUTHENTICATOR_RESPONSE = {
    "id": "ZoIKP1JQvKdrYj1bTUPJ2eTUsbLeFkv-X5xJQNr4k6s",
    "rawId": "ZoIKP1JQvKdrYj1bTUPJ2eTUsbLeFkv-X5xJQNr4k6s",
    "response": {
        "attestationObject": (
            "o2NmbXRkbm9uZWdhdHRTdG10oGhhdXRoRGF0YVkBZ0mWDeWIDoxodDQXD2R2YFuP5K65ooYyx5lc87qDHZdjRQ"
            "AAAAAAAAAAAAAAAAAAAAAAAAAAACBmggo_UlC8p2tiPVtNQ8nZ5NSxst4WS_5fnElA2viTq6QBAwM5AQAgWQEA31dt"
            "Hqc70D_h7XHQ6V_nBs3Tscu91kBL7FOw56_VFiaKYRH6Z4KLr4J0S12hFJ_3fBxpKfxyMfK66ZMeAVbOl_wemY4S5"
            "Xs4yHSWy21Xm_dgWhLJjZ9R1tjfV49kDPHB_ssdvP7wo3_NmoUPYMgK-edgZ_ehttp_I6hUUCnVaTvn_m76b2j9y"
            "EPReSwl-wlGsabYG6INUhTuhSOqG-UpVVQdNJVV7GmIPHCA2cQpJBDZBohT4MBGme_feUgm4sgqVCWzKk6CzIKI"
            "z5AIVnspLbu05SulAVnSTB3NxTwCLNJR_9v9oSkvphiNbmQBVQH1tV_psyi9HM1Jtj9VJVKMeyFDAQAB"
        ),
        "clientDataJSON": (
            "eyJ0eXBlIjoid2ViYXV0aG4uY3JlYXRlIiwiY2hhbGxlbmdlIjoiQ2VUV29nbWcwY2NodWlZdUZydjhEWFhk"
            "TVpTSVFSVlpKT2dhX3hheVZWRWNCajBDdzN5NzN5aEQ0RmtHU2UtUnJQNmhQSkpBSW0zTFZpZW40aFhFTGciLCJv"
            "cmlnaW4iOiJodHRwOi8vbG9jYWxob3N0OjUwMDAiLCJjcm9zc09yaWdpbiI6ZmFsc2V9"
        ),
        "transports": ["internal"],
    },
    "type": "public-key",
    "clientExtensionResults": {},
    "authenticatorAttachment": "platform",
}


@pytest.fixture
def webauthn_client() -> RealWebAuthnClient:
    return RealWebAuthnClient(rp_id="localhost", origin="http://localhost:5000")


def test_begin_registration_returns_options(webauthn_client: RealWebAuthnClient) -> None:
    options_json = webauthn_client.begin_registration("usr_test", "user@example.com")
    options = json.loads(options_json)
    assert options["rp"]["id"] == "localhost"
    assert options["rp"]["name"] == "HB Labs"
    assert options["user"]["name"] == "user@example.com"
    assert "challenge" in options
    assert "pubKeyCredParams" in options


def test_finish_registration_virtual_authenticator(webauthn_client: RealWebAuthnClient) -> None:
    cred = webauthn_client.finish_registration(
        VIRTUAL_AUTHENTICATOR_RESPONSE,
        KNOWN_CHALLENGE,
    )
    assert cred.credential_id == "ZoIKP1JQvKdrYj1bTUPJ2eTUsbLeFkv-X5xJQNr4k6s"
    assert cred.public_key
    assert cred.sign_count >= 0


def test_finish_registration_pending_challenge(webauthn_client: RealWebAuthnClient) -> None:
    webauthn_client.begin_registration(
        "usr_pending",
        "pending@example.com",
        challenge=base64url_to_bytes(KNOWN_CHALLENGE),
    )
    cred = webauthn_client.finish_registration(
        VIRTUAL_AUTHENTICATOR_RESPONSE,
        user_id="usr_pending",
    )
    assert cred.credential_id == "ZoIKP1JQvKdrYj1bTUPJ2eTUsbLeFkv-X5xJQNr4k6s"


def test_finish_registration_without_challenge_raises(webauthn_client: RealWebAuthnClient) -> None:
    with pytest.raises(ValueError, match="no_pending_registration"):
        webauthn_client.finish_registration(VIRTUAL_AUTHENTICATOR_RESPONSE, user_id="usr_missing")


def test_webauthn_setup_via_auth_service() -> None:
    import tempfile
    from pathlib import Path

    from raphael_identity.hblabs.auth.mfa import RealWebAuthnClient
    from raphael_identity.hblabs.auth.service import AuthService
    from raphael_identity.hblabs.db import PlatformStore

    with tempfile.TemporaryDirectory() as tmp:
        store = PlatformStore(Path(tmp) / "identity.db")
        auth = AuthService(store, jwt_secret="dev-secret-with-32-byte-minimum-length!!", invite_only=False)
        auth.webauthn = RealWebAuthnClient(rp_id="localhost", origin="http://localhost:5000")
        store.execute(
            "INSERT INTO users (id, org_id, email, invite_accepted, created_at) VALUES (?, ?, ?, 1, ?)",
            ("usr_wa", "org_default", "wa@example.com", 0.0),
        )
        auth.webauthn.begin_registration(
            "usr_wa",
            "wa@example.com",
            challenge=base64url_to_bytes(KNOWN_CHALLENGE),
        )
        result = auth.finish_webauthn_setup("usr_wa", VIRTUAL_AUTHENTICATOR_RESPONSE)
        assert result["credential_id"] == "ZoIKP1JQvKdrYj1bTUPJ2eTUsbLeFkv-X5xJQNr4k6s"
        row = store.fetchone("SELECT webauthn_credential FROM users WHERE id = ?", ("usr_wa",))
        assert row and "ZoIKP1JQvKdrYj1bTUPJ2eTUsbLeFkv-X5xJQNr4k6s" in row["webauthn_credential"]
