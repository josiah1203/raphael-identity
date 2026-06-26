"""Dev seed user — idempotent on service startup."""

from __future__ import annotations

import os

from raphael_identity.auth import AuthService
from raphael_identity.store import IdentityStore

DEV_EMAIL = os.environ.get("RAPHAEL_DEV_USER_EMAIL", "dev@raphael.app")
DEV_PASSWORD = os.environ.get("RAPHAEL_DEV_USER_PASSWORD", "raphaeldev1")


def seed_dev_user(store: IdentityStore, auth: AuthService) -> None:
    if os.environ.get("RAPHAEL_SEED_DEV_USER", "true").lower() in ("0", "false", "no"):
        return
    email = DEV_EMAIL.lower()
    if store.fetchone("SELECT id FROM users WHERE email = ?", (email,)):
        return
    result = auth.register(email, DEV_PASSWORD, org_id="org_default")
    if isinstance(result, dict) and "error" in result:
        return  # ponytail: already exists or race; login still works if seeded elsewhere
