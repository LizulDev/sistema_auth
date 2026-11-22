import json
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
    id_token_inspection TEXT,
    created_at INTEGER NOT NULL,
    last_seen_at INTEGER NOT NULL
);
"""


class Store:
    def __init__(self, path: Path):
        self.path = Path(path)

    @contextmanager
    def connect(self):
        with closing(sqlite3.connect(self.path)) as db, db:
            db.row_factory = sqlite3.Row
            db.execute("PRAGMA foreign_keys = ON")
            yield db

    def initialize(self) -> None:
        with self.connect() as db:
            db.executescript(SCHEMA)
            cols = {
                row["name"]
                for row in db.execute("PRAGMA table_info(sessions)").fetchall()
            }
            if "id_token_inspection" not in cols:
                db.execute("ALTER TABLE sessions ADD COLUMN id_token_inspection TEXT")

    def upsert_user(
        self,
        *,
        user_name: str,
        full_name: str,
        oidc_issuer: str,
        oidc_sub: str,
        role: str = "user",
    ) -> int:
        with self.connect() as db:
            db.execute(
                """
                INSERT INTO users (user_name, full_name, oidc_issuer, oidc_sub, role)
                VALUES (?, ?, ?, ?, ?)
                ON CONFLICT(oidc_issuer, oidc_sub) DO UPDATE SET
                    user_name = excluded.user_name,
                    full_name = excluded.full_name,
                    role = excluded.role
                """,
                (user_name, full_name, oidc_issuer, oidc_sub, role),
            )
            row = db.execute(
                "SELECT id FROM users WHERE oidc_issuer = ? AND oidc_sub = ?",
                (oidc_issuer, oidc_sub),
            ).fetchone()
            return int(row["id"])

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
                "SELECT id, user_name, full_name, oidc_sub, role FROM users WHERE oidc_issuer = ? AND oidc_sub = ?",
                (identity.issuer, identity.subject),
            ).fetchone()

    def sync_verified_role(self, user_id: int, role: str) -> None:
        if role not in ("admin", "user"):
            return
        with self.connect() as db:
            db.execute("UPDATE users SET role = ? WHERE id = ?", (role, user_id))

    def create_session(
        self,
        user_id: int,
        previous_id: str | None,
        *,
        id_token_inspection: dict | None = None,
    ) -> str:
        session_id = secrets.token_urlsafe(32)
        now = int(time.time())
        inspection_json = json.dumps(id_token_inspection, ensure_ascii=False) if id_token_inspection else None
        with self.connect() as db:
            db.execute(
                "DELETE FROM sessions WHERE id = ? OR created_at <= ? OR last_seen_at <= ?",
                (previous_id, now - SESSION_TTL, now - SESSION_IDLE_TTL),
            )
            db.execute(
                """INSERT INTO sessions (id, user_id, csrf_token, id_token_inspection, created_at, last_seen_at)
                   VALUES (?, ?, ?, ?, ?, ?)""",
                (session_id, user_id, secrets.token_urlsafe(32), inspection_json, now, now),
            )
        return session_id

    def read_session(self, session_id: str) -> dict | None:
        now = int(time.time())
        with self.connect() as db:
            session = db.execute(
                """UPDATE sessions SET last_seen_at = max(last_seen_at, ?)
                   WHERE id = ? AND created_at > ? AND last_seen_at > ?
                   RETURNING user_id, csrf_token, id_token_inspection""",
                (now, session_id, now - SESSION_TTL, now - SESSION_IDLE_TTL),
            ).fetchone()
            if session is None:
                return None
            user = db.execute(
                "SELECT id, user_name, full_name, oidc_issuer, oidc_sub, role FROM users WHERE id = ?",
                (session["user_id"],),
            ).fetchone()
            if user is None:
                return None
            inspection = (
                json.loads(session["id_token_inspection"])
                if session["id_token_inspection"]
                else None
            )
            return {
                "id": user["id"],
                "user_name": user["user_name"],
                "full_name": user["full_name"],
                "oidc_issuer": user["oidc_issuer"],
                "oidc_sub": user["oidc_sub"],
                "role": user["role"],
                "csrf_token": session["csrf_token"],
                "id_token_inspection": inspection,
            }

    def delete_session(self, session_id: str) -> None:
        with self.connect() as db:
            db.execute("DELETE FROM sessions WHERE id = ?", (session_id,))
