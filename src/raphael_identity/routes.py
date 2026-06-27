"""Identity API routes at /v1/identity/*."""

from __future__ import annotations

import os
from typing import Any

from fastapi import APIRouter, Header, HTTPException

from raphael_identity.hblabs.auth.passwords import HibpClient
from raphael_identity.hblabs.auth.service import AuthService
from raphael_identity.hblabs.db import PlatformStore
from raphael_identity.models import ApiKeyBody, AuthBody, PhoneBody, RegisterBody
from raphael_identity.seed import seed_dev_user

router = APIRouter(tags=["identity"])


class _NoHibp(HibpClient):
    def is_pwned(self, password: str) -> bool:
        return False


_db = os.environ.get("RAPHAEL_IDENTITY_DB", "/tmp/raphael-identity.db")
_store = PlatformStore(_db)
_auth = AuthService(
    _store,
    jwt_secret=os.environ.get("RAPHAEL_JWT_SECRET", "dev-secret-with-32-byte-minimum-length!!"),
    invite_only=False,
    hibp=_NoHibp(),
)
seed_dev_user(_store, _auth)


def _user_from_token(authorization: str | None) -> dict[str, str]:
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(401, detail={"error": "unauthorized"})
    payload = _auth.verify_access_token(authorization[7:])
    if not payload:
        raise HTTPException(401, detail={"error": "invalid_token"})
    return {"user_id": str(payload.get("sub", "usr_default")), "org_id": str(payload.get("org_id", "org_default"))}


def _profile_for_user(user_id: str) -> dict[str, Any]:
    row = _store.fetchone("SELECT id, email, org_id, phone, phone_verified FROM users WHERE id = ?", (user_id,))
    if not row:
        raise HTTPException(404, detail={"error": "not_found"})
    return {
        "user_id": row["id"],
        "email": row["email"],
        "org_id": row["org_id"],
        "phone": row["phone"],
        "phone_verified": bool(row["phone_verified"]),
    }


@router.post("/register")
def register(body: RegisterBody) -> dict[str, Any]:
    result = _auth.register(body.email, body.password, org_id=body.org_id)
    if isinstance(result, dict) and "error" in result:
        raise HTTPException(400, detail=result)
    return {"access_token": result.access_token, "refresh_token": result.refresh_token}


@router.post("/login")
def login(body: AuthBody) -> dict[str, Any]:
    result = _auth.login(body.email, body.password)
    if isinstance(result, dict) and "error" in result:
        raise HTTPException(401, detail=result)
    return {"access_token": result.access_token, "refresh_token": result.refresh_token}


@router.post("/verify-key")
def verify_key(body: ApiKeyBody) -> dict[str, Any]:
    result = _auth.verify_api_key(body.api_key)
    if not result:
        raise HTTPException(401, detail={"error": "invalid_key"})
    return result


@router.get("/me")
def me(authorization: str | None = Header(default=None)) -> dict[str, str]:
    return _user_from_token(authorization)


@router.get("/profile")
def get_profile(authorization: str | None = Header(default=None)) -> dict[str, Any]:
    session = _user_from_token(authorization)
    return _profile_for_user(session["user_id"])


@router.patch("/profile")
def patch_profile(body: PhoneBody, authorization: str | None = Header(default=None)) -> dict[str, Any]:
    session = _user_from_token(authorization)
    phone = body.phone.strip()
    if not phone:
        raise HTTPException(400, detail={"error": "phone_required"})
    _store.execute(
        "UPDATE users SET phone = ?, phone_verified = 0 WHERE id = ?",
        (phone, session["user_id"]),
    )
    return _profile_for_user(session["user_id"])


@router.get("/oauth/{provider}/start")
def oauth_start(provider: str, redirect_uri: str) -> dict[str, str]:
    result = _auth.oauth_start(provider, redirect_uri)
    if "error" in result:
        raise HTTPException(400, detail=result)
    return result


@router.get("/oauth/{provider}/callback")
def oauth_callback(provider: str, state: str, code: str) -> dict[str, Any]:
    result = _auth.oauth_callback(provider, state, code)
    if isinstance(result, dict) and "error" in result:
        raise HTTPException(400, detail=result)
    return {"access_token": result.access_token, "refresh_token": result.refresh_token}


@router.post("/password/reset-request")
def password_reset_request(body: dict[str, Any]) -> dict[str, str]:
    email = str(body.get("email", "")).strip()
    if not email:
        raise HTTPException(400, detail={"error": "email_required"})
    return {"status": "sent", "email": email}


@router.post("/password/change")
def password_change(body: dict[str, Any], authorization: str | None = Header(default=None)) -> dict[str, str]:
    session = _user_from_token(authorization)
    current = str(body.get("current_password", ""))
    new_password = str(body.get("new_password", ""))
    if len(new_password) < 8:
        raise HTTPException(400, detail={"error": "password_too_short"})
    row = _store.fetchone("SELECT email FROM users WHERE id = ?", (session["user_id"],))
    if not row:
        raise HTTPException(404, detail={"error": "not_found"})
    login_result = _auth.login(row["email"], current)
    if isinstance(login_result, dict) and "error" in login_result:
        raise HTTPException(400, detail={"error": "invalid_current_password"})
    return {"status": "changed", "user_id": session["user_id"]}


@router.get("/api-keys")
def list_api_keys(authorization: str | None = Header(default=None)) -> dict[str, list]:
    session = _user_from_token(authorization)
    rows = _store.fetchall(
        "SELECT id, name, prefix, created_at FROM api_keys WHERE user_id = ? ORDER BY created_at DESC",
        (session["user_id"],),
    )
    return {
        "keys": [
            {"id": r["id"], "name": r["name"], "prefix": r["prefix"], "created_at": r["created_at"]}
            for r in rows
        ]
    }


@router.post("/api-keys")
def create_api_key(body: dict[str, Any], authorization: str | None = Header(default=None)) -> dict[str, str]:
    session = _user_from_token(authorization)
    org_id = body.get("org_id", session.get("org_id", "org_default"))
    return _auth.create_api_key(session["user_id"], org_id, body.get("name", "default"))
