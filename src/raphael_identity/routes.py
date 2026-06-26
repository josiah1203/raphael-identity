"""Identity API routes at /v1/identity/*."""

from __future__ import annotations

import os
from typing import Any

from fastapi import APIRouter, Header, HTTPException

from raphael_identity.auth import AuthService
from raphael_identity.store import IdentityStore

router = APIRouter(tags=["identity"])

_store = IdentityStore()
_auth = AuthService(
    _store,
    jwt_secret=os.environ.get("RAPHAEL_JWT_SECRET", "dev-secret-with-32-byte-minimum-length!!"),
    invite_only=False,
)


@router.post("/register")
def register(body: dict[str, Any]) -> dict[str, Any]:
    result = _auth.register(body["email"], body["password"], org_id=body.get("org_id", "org_default"))
    if isinstance(result, dict) and "error" in result:
        raise HTTPException(400, detail=result)
    return {"access_token": result.access_token, "refresh_token": result.refresh_token}


@router.post("/login")
def login(body: dict[str, Any]) -> dict[str, Any]:
    result = _auth.login(body["email"], body["password"])
    if isinstance(result, dict) and "error" in result:
        raise HTTPException(401, detail=result)
    return {"access_token": result.access_token, "refresh_token": result.refresh_token}


@router.get("/me")
def me(authorization: str | None = Header(default=None)) -> dict[str, str]:
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(401, detail={"error": "unauthorized"})
    # ponytail: full JWT decode deferred; gateway forwards validated context in prod
    return {"status": "ok", "note": "use /v1/identity/session with gateway-injected headers"}


@router.post("/api-keys")
def create_api_key(body: dict[str, Any], x_raphael_user_id: str | None = Header(default=None)) -> dict[str, str]:
    user_id = x_raphael_user_id or body.get("user_id", "usr_dev")
    org_id = body.get("org_id", "org_default")
    return _auth.create_api_key(user_id, org_id, body.get("name", "default"))
