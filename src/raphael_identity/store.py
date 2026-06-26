"""Platform store for identity service (SQLite dev; Postgres in prod)."""

from __future__ import annotations

import os
import sqlite3
import time
from pathlib import Path
from typing import Any


class IdentityStore:
    def __init__(self, db_path: str | Path | None = None) -> None:
        path = db_path or os.environ.get("RAPHAEL_IDENTITY_DB", ":memory:")
        self.db_path = Path(path) if path != ":memory:" else Path(":memory:")
        if self.db_path != Path(":memory:"):
            self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._conn = sqlite3.connect(str(self.db_path), check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        self._init_schema()

    def _init_schema(self) -> None:
        self._conn.executescript(
            """
            CREATE TABLE IF NOT EXISTS users (
                id TEXT PRIMARY KEY,
                org_id TEXT NOT NULL DEFAULT 'org_default',
                email TEXT UNIQUE NOT NULL,
                password_hash TEXT,
                invite_token TEXT,
                invite_accepted INTEGER DEFAULT 0,
                mfa_secret TEXT,
                created_at REAL NOT NULL
            );
            CREATE TABLE IF NOT EXISTS refresh_tokens (
                token_hash TEXT PRIMARY KEY,
                user_id TEXT NOT NULL,
                expires_at REAL NOT NULL,
                revoked INTEGER DEFAULT 0
            );
            CREATE TABLE IF NOT EXISTS api_keys (
                id TEXT PRIMARY KEY,
                org_id TEXT NOT NULL,
                user_id TEXT NOT NULL,
                name TEXT NOT NULL,
                key_prefix TEXT NOT NULL,
                key_hash TEXT NOT NULL,
                scopes TEXT DEFAULT '',
                created_at REAL NOT NULL,
                revoked INTEGER DEFAULT 0
            );
            """
        )
        self._conn.commit()

    def execute(self, sql: str, params: tuple[Any, ...] = ()) -> sqlite3.Cursor:
        cur = self._conn.execute(sql, params)
        self._conn.commit()
        return cur

    def fetchone(self, sql: str, params: tuple[Any, ...] = ()) -> sqlite3.Row | None:
        return self._conn.execute(sql, params).fetchone()
