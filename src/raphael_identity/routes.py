"""Identity API routes at /v1/identity/*."""

from __future__ import annotations

import os
from typing import Any

from fastapi import APIRouter, Header, HTTPException

from raphael_identity.hblabs.auth.passwords import HibpClient
from raphael_identity.hblabs.auth.service import AuthService
from raphael_identity.hblabs.db import PlatformStore
from raphael_identity.models import ApiKeyBody, AuthBody, RegisterBody
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
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(401, detail={"error": "unauthorized"})
    payload = _auth.verify_access_token(authorization[7:])
    if not payload:
        raise HTTPException(401, detail={"error": "invalid_token"})
    return {"user_id": str(payload.get("sub", "usr_default")), "org_id": str(payload.get("org_id", "org_default"))}


@router.post("/api-keys")
def create_api_key(body: dict[str, Any], x_raphael_user_id: str | None = Header(default=None)) -> dict[str, str]:
    user_id = x_raphael_user_id or body.get("user_id", "usr_dev")
    org_id = body.get("org_id", "org_default")
    return _auth.create_api_key(user_id, org_id, body.get("name", "default"))
