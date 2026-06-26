"""Dev seed user — idempotent on service startup."""

from __future__ import annotations

import os
import secrets
import time
from typing import Any

from raphael_identity.hblabs.auth.passwords import hash_password

DEV_EMAIL = os.environ.get("RAPHAEL_DEV_USER_EMAIL", "dev@raphael.app")
DEV_PASSWORD = os.environ.get("RAPHAEL_DEV_USER_PASSWORD", "raphaeldev1")


def seed_dev_user(store: Any, auth: Any) -> None:
    if os.environ.get("RAPHAEL_SEED_DEV_USER", "true").lower() in ("0", "false", "no"):
        return
    email = DEV_EMAIL.lower()
    org_id = "org_default"
    pw_hash = hash_password(DEV_PASSWORD)
    existing = store.fetchone("SELECT id FROM users WHERE email = ?", (email,))
    if existing:
        # ponytail: refresh hash when auth scheme changes; dev password may be <12 chars
        store.execute("UPDATE users SET password_hash = ? WHERE email = ?", (pw_hash, email))
        return
    user_id = f"usr_{secrets.token_hex(8)}"
    store.execute(
        """INSERT INTO users (id, org_id, email, password_hash, invite_accepted, created_at)
           VALUES (?, ?, ?, ?, 1, ?)""",
        (user_id, org_id, email, pw_hash, time.time()),
    )
