import secrets
import sqlite3
import time
from contextlib import closing, contextmanager
from pathlib import Path

from .oidc import AuthorizationRequest, VerifiedIdentity


AUTHORIZATION_TTL = 300
SESSION_IDLE_TTL = 30 * 60
SESSION_TTL = 8 * 60 * 60

SCHEMA = """
CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY,
    user_name TEXT NOT NULL UNIQUE,
    full_name TEXT NOT NULL,
    oidc_issuer TEXT NOT NULL,
    oidc_sub TEXT NOT NULL,
    role TEXT NOT NULL DEFAULT 'user' CHECK (role IN ('user', 'admin')),
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    UNIQUE (oidc_issuer, oidc_sub)
);

CREATE TABLE IF NOT EXISTS pending_authorizations (
    id TEXT PRIMARY KEY,
    state TEXT NOT NULL,
    nonce TEXT NOT NULL,
    verifier TEXT NOT NULL,
    expires_at INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS sessions (
    id TEXT PRIMARY KEY,
    user_id INTEGER NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    csrf_token TEXT NOT NULL,
    created_at INTEGER NOT NULL,
    last_seen_at INTEGER NOT NULL
);
"""


class Store:
    def __init__(self, path: Path):
        self.path = path

    @contextmanager
    def connect(self):
        with closing(sqlite3.connect(self.path)) as db, db:
            db.row_factory = sqlite3.Row
            db.execute("PRAGMA foreign_keys = ON")
            yield db

    def initialize(self) -> None:
        with self.connect() as db:
            db.executescript(SCHEMA)

    def start_authorization(self, pending: AuthorizationRequest) -> str:
        flow_id = secrets.token_urlsafe(32)
        now = int(time.time())
        with self.connect() as db:
            db.execute("DELETE FROM pending_authorizations WHERE expires_at <= ?", (now,))
            db.execute(
                """INSERT INTO pending_authorizations (id, state, nonce, verifier, expires_at)
                   VALUES (?, ?, ?, ?, ?)""",
                (flow_id, pending.state, pending.nonce, pending.verifier, now + AUTHORIZATION_TTL),
            )
        return flow_id

    def consume_authorization(self, flow_id: str) -> AuthorizationRequest | None:
        with self.connect() as db:
            row = db.execute(
                """DELETE FROM pending_authorizations WHERE id = ?
                   RETURNING state, nonce, verifier, expires_at""",
                (flow_id,),
            ).fetchone()
        if row is None or row["expires_at"] <= int(time.time()):
            return None
        return AuthorizationRequest(row["state"], row["nonce"], row["verifier"])

    def find_user(self, identity: VerifiedIdentity) -> sqlite3.Row | None:
        with self.connect() as db:
            return db.execute(
                "SELECT id FROM users WHERE oidc_issuer = ? AND oidc_sub = ?",
                (identity.issuer, identity.subject),
            ).fetchone()

    def create_session(self, user_id: int, previous_id: str | None) -> str:
        session_id = secrets.token_urlsafe(32)
        now = int(time.time())
        with self.connect() as db:
            db.execute(
                "DELETE FROM sessions WHERE id = ? OR created_at <= ? OR last_seen_at <= ?",
                (previous_id, now - SESSION_TTL, now - SESSION_IDLE_TTL),
            )
            db.execute(
                """INSERT INTO sessions (id, user_id, csrf_token, created_at, last_seen_at)
                   VALUES (?, ?, ?, ?, ?)""",
                (session_id, user_id, secrets.token_urlsafe(32), now, now),
            )
        return session_id

    def read_session(self, session_id: str) -> sqlite3.Row | None:
        now = int(time.time())
        with self.connect() as db:
            session = db.execute(
                """UPDATE sessions SET last_seen_at = max(last_seen_at, ?)
                   WHERE id = ? AND created_at > ? AND last_seen_at > ?
                   RETURNING user_id, csrf_token""",
                (now, session_id, now - SESSION_TTL, now - SESSION_IDLE_TTL),
            ).fetchone()
            if session is None:
                return None
            return db.execute(
                "SELECT user_name, full_name, role, ? AS csrf_token FROM users WHERE id = ?",
                (session["csrf_token"], session["user_id"]),
            ).fetchone()

    def delete_session(self, session_id: str) -> None:
        with self.connect() as db:
            db.execute("DELETE FROM sessions WHERE id = ?", (session_id,))
