"""Request/response models for identity API."""

from __future__ import annotations

from pydantic import BaseModel, Field


class AuthBody(BaseModel):
    email: str = Field(..., min_length=3)
    password: str = Field(..., min_length=8)


class RegisterBody(AuthBody):
    org_id: str = "org_default"


class ApiKeyBody(BaseModel):
    api_key: str
    name: str = "default"
    org_id: str = "org_default"
    user_id: str | None = None


class PhoneBody(BaseModel):
    phone: str = Field(..., min_length=7)
