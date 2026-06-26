"""Password hashing and HIBP breach check — re-exported from raphael_audit.core.security."""

from __future__ import annotations

from raphael_audit.core.security.passwords import (
    HibpClient,
    LiveHibpClient,
    hash_password,
    is_legacy_sha256_hash,
    validate_password_strength,
    verify_password,
    verify_password_legacy_sha256,
    verify_password_with_migration,
)

__all__ = [
    "HibpClient",
    "LiveHibpClient",
    "hash_password",
    "is_legacy_sha256_hash",
    "validate_password_strength",
    "verify_password",
    "verify_password_legacy_sha256",
    "verify_password_with_migration",
]
