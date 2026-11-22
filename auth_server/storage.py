import hashlib
import hmac
import json
import secrets
import sqlite3
import time
from contextlib import closing, contextmanager
from pathlib import Path

from argon2 import PasswordHasher, Type
from argon2.exceptions import InvalidHashError, VerifyMismatchError


OP_SESSION_IDLE_TTL = 30 * 60
OP_SESSION_TTL = 8 * 60 * 60
AUTH_REQUEST_TTL = 5 * 60

_PASSWORD_HASHER = PasswordHasher(type=Type.ID)
_DUMMY_PASSWORD_HASH = _PASSWORD_HASHER.hash("dummy-password-for-constant-time-check")

SCHEMA = """
CREATE TABLE IF NOT EXISTS op_users (
    id INTEGER PRIMARY KEY,
    username TEXT NOT NULL UNIQUE,
    password_hash TEXT NOT NULL,
    sub TEXT NOT NULL UNIQUE,
    full_name TEXT NOT NULL,
    email TEXT NOT NULL UNIQUE,
    email_verified INTEGER NOT NULL DEFAULT 1,
    role TEXT NOT NULL DEFAULT 'user' CHECK (role IN ('user', 'admin')),
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS oauth_clients (
    client_id TEXT PRIMARY KEY,
    client_secret_hash TEXT NOT NULL,
    client_name TEXT NOT NULL,
    redirect_uris TEXT NOT NULL,
    allowed_scopes TEXT NOT NULL,
    allowed_grants TEXT NOT NULL,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS op_sessions (
    id TEXT PRIMARY KEY,
    user_id INTEGER NOT NULL REFERENCES op_users (id) ON DELETE CASCADE,
    csrf_token TEXT NOT NULL,
    created_at INTEGER NOT NULL,
    last_seen_at INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS authorize_requests (
    id TEXT PRIMARY KEY,
    client_id TEXT NOT NULL REFERENCES oauth_clients (client_id) ON DELETE CASCADE,
    redirect_uri TEXT NOT NULL,
    scope TEXT NOT NULL,
    state TEXT NOT NULL,
    nonce TEXT NOT NULL,
    code_challenge TEXT NOT NULL,
    code_challenge_method TEXT NOT NULL,
    csrf_token TEXT NOT NULL,
    expires_at INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS user_consents (
    id INTEGER PRIMARY KEY,
    user_id INTEGER NOT NULL REFERENCES op_users (id) ON DELETE CASCADE,
    client_id TEXT NOT NULL REFERENCES oauth_clients (client_id) ON DELETE CASCADE,
    scope TEXT NOT NULL,
    granted_at INTEGER NOT NULL,
    UNIQUE (user_id, client_id, scope)
);

CREATE TABLE IF NOT EXISTS authorization_codes (
    code_hash TEXT PRIMARY KEY,
    grant_id TEXT NOT NULL UNIQUE,
    client_id TEXT NOT NULL REFERENCES oauth_clients (client_id) ON DELETE CASCADE,
    redirect_uri TEXT NOT NULL,
    code_challenge TEXT NOT NULL,
    sub TEXT NOT NULL,
    user_id INTEGER NOT NULL REFERENCES op_users (id) ON DELETE CASCADE,
    nonce TEXT NOT NULL,
    scope TEXT NOT NULL,
    issued_at INTEGER NOT NULL,
    expires_at INTEGER NOT NULL,
    used_at INTEGER
);

CREATE TABLE IF NOT EXISTS access_tokens (
    jti TEXT PRIMARY KEY,
    grant_id TEXT NOT NULL,
    client_id TEXT NOT NULL REFERENCES oauth_clients (client_id) ON DELETE CASCADE,
    user_id INTEGER NOT NULL REFERENCES op_users (id) ON DELETE CASCADE,
    sub TEXT NOT NULL,
    scope TEXT NOT NULL,
    issued_at INTEGER NOT NULL,
    expires_at INTEGER NOT NULL,
    revoked INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS refresh_tokens (
    token_hash TEXT PRIMARY KEY,
    grant_id TEXT NOT NULL,
    client_id TEXT NOT NULL REFERENCES oauth_clients (client_id) ON DELETE CASCADE,
    user_id INTEGER NOT NULL REFERENCES op_users (id) ON DELETE CASCADE,
    sub TEXT NOT NULL,
    scope TEXT NOT NULL,
    issued_at INTEGER NOT NULL,
    expires_at INTEGER NOT NULL,
    used_at INTEGER,
    revoked INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS login_attempts (
    id INTEGER PRIMARY KEY,
    attempt_key TEXT NOT NULL,
    attempted_at INTEGER NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_login_attempts_key_time
    ON login_attempts (attempt_key, attempted_at);
CREATE INDEX IF NOT EXISTS idx_access_tokens_grant
    ON access_tokens (grant_id);
CREATE INDEX IF NOT EXISTS idx_refresh_tokens_grant
    ON refresh_tokens (grant_id);
"""


def sha256_hex(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def hash_password(password: str) -> str:
    return _PASSWORD_HASHER.hash(password)


def verify_password(password_hash: str, password: str) -> bool:
    try:
        return _PASSWORD_HASHER.verify(password_hash, password)
    except (VerifyMismatchError, InvalidHashError):
        return False


def hash_client_secret(secret: str) -> str:
    salt = secrets.token_bytes(16)
    derived = hashlib.scrypt(secret.encode("utf-8"), salt=salt, n=2**14, r=8, p=1, dklen=32)
    return f"scrypt${salt.hex()}${derived.hex()}"


def verify_client_secret(stored_hash: str, secret: str) -> bool:
    parts = stored_hash.split("$")
    if len(parts) != 3 or parts[0] != "scrypt":
        return False
    salt = bytes.fromhex(parts[1])
    expected = bytes.fromhex(parts[2])
    derived = hashlib.scrypt(secret.encode("utf-8"), salt=salt, n=2**14, r=8, p=1, dklen=32)
    return hmac.compare_digest(derived, expected)


class AuthServerStore:
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

    # --- Clients ---

    def upsert_client(
        self,
        *,
        client_id: str,
        client_secret: str,
        client_name: str,
        redirect_uris: list[str],
        allowed_scopes: list[str] | None = None,
        allowed_grants: list[str] | None = None,
    ) -> None:
        scopes = allowed_scopes or ["openid", "profile", "email"]
        grants = allowed_grants or ["authorization_code"]
        secret_hash = hash_client_secret(client_secret)
        with self.connect() as db:
            db.execute(
                """
                INSERT INTO oauth_clients
                    (client_id, client_secret_hash, client_name, redirect_uris, allowed_scopes, allowed_grants)
                VALUES (?, ?, ?, ?, ?, ?)
                ON CONFLICT(client_id) DO UPDATE SET
                    client_secret_hash = excluded.client_secret_hash,
                    client_name = excluded.client_name,
                    redirect_uris = excluded.redirect_uris,
                    allowed_scopes = excluded.allowed_scopes,
                    allowed_grants = excluded.allowed_grants
                """,
                (
                    client_id,
                    secret_hash,
                    client_name,
                    json.dumps(redirect_uris),
                    json.dumps(scopes),
                    json.dumps(grants),
                ),
            )

    def get_client(self, client_id: str) -> dict | None:
        with self.connect() as db:
            row = db.execute(
                "SELECT * FROM oauth_clients WHERE client_id = ?",
                (client_id,),
            ).fetchone()
        if row is None:
            return None
        return {
            "client_id": row["client_id"],
            "client_secret_hash": row["client_secret_hash"],
            "client_name": row["client_name"],
            "redirect_uris": json.loads(row["redirect_uris"]),
            "allowed_scopes": json.loads(row["allowed_scopes"]),
            "allowed_grants": json.loads(row["allowed_grants"]),
        }

    def authenticate_client(self, client_id: str, client_secret: str) -> dict | None:
        client = self.get_client(client_id)
        if client is None:
            # Executa derivacao ficticia para evitar diferenca de tempo
            verify_client_secret(
                "scrypt$00000000000000000000000000000000$0000000000000000000000000000000000000000000000000000000000000000",
                client_secret,
            )
            return None
        if not verify_client_secret(client["client_secret_hash"], client_secret):
            return None
        return client

    # --- Users ---

    def upsert_user(
        self,
        *,
        username: str,
        password: str,
        sub: str,
        full_name: str,
        email: str,
        role: str = "user",
        email_verified: bool = True,
    ) -> None:
        password_hash = hash_password(password)
        with self.connect() as db:
            db.execute(
                """
                INSERT INTO op_users
                    (username, password_hash, sub, full_name, email, email_verified, role)
                VALUES (?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(sub) DO UPDATE SET
                    username = excluded.username,
                    password_hash = excluded.password_hash,
                    full_name = excluded.full_name,
                    email = excluded.email,
                    email_verified = excluded.email_verified,
                    role = excluded.role
                """,
                (username, password_hash, sub, full_name, email, int(email_verified), role),
            )

    def authenticate_user(self, username: str, password: str) -> sqlite3.Row | None:
        with self.connect() as db:
            user = db.execute(
                "SELECT * FROM op_users WHERE username = ?",
                (username,),
            ).fetchone()
        if user is None:
            verify_password(_DUMMY_PASSWORD_HASH, password)
            return None
        if not verify_password(user["password_hash"], password):
            return None
        return user

    def get_user_by_id(self, user_id: int) -> sqlite3.Row | None:
        with self.connect() as db:
            return db.execute("SELECT * FROM op_users WHERE id = ?", (user_id,)).fetchone()

    def get_user_by_sub(self, sub: str) -> sqlite3.Row | None:
        with self.connect() as db:
            return db.execute("SELECT * FROM op_users WHERE sub = ?", (sub,)).fetchone()

    # --- Rate limiting ---

    def check_rate_limit(
        self, keys: list[str], *, max_attempts: int, window_seconds: int
    ) -> tuple[bool, int]:
        now = int(time.time())
        cutoff = now - window_seconds
        with self.connect() as db:
            db.execute("DELETE FROM login_attempts WHERE attempted_at <= ?", (cutoff,))
            for key in keys:
                rows = db.execute(
                    """
                    SELECT attempted_at FROM login_attempts
                    WHERE attempt_key = ? AND attempted_at > ?
                    ORDER BY attempted_at ASC
                    """,
                    (key, cutoff),
                ).fetchall()
                if len(rows) >= max_attempts:
                    oldest = rows[0]["attempted_at"]
                    retry_after = max(1, (oldest + window_seconds) - now)
                    return True, retry_after
        return False, 0

    def record_failed_login(self, keys: list[str]) -> None:
        now = int(time.time())
        with self.connect() as db:
            db.executemany(
                "INSERT INTO login_attempts (attempt_key, attempted_at) VALUES (?, ?)",
                [(key, now) for key in keys],
            )

    def clear_failed_logins(self, keys: list[str]) -> None:
        with self.connect() as db:
            db.executemany(
                "DELETE FROM login_attempts WHERE attempt_key = ?",
                [(key,) for key in keys],
            )

    # --- OP Sessions ---

    def create_session(self, user_id: int, previous_id: str | None = None) -> str:
        session_id = secrets.token_urlsafe(32)
        now = int(time.time())
        with self.connect() as db:
            db.execute(
                "DELETE FROM op_sessions WHERE id = ? OR created_at <= ? OR last_seen_at <= ?",
                (previous_id, now - OP_SESSION_TTL, now - OP_SESSION_IDLE_TTL),
            )
            db.execute(
                """
                INSERT INTO op_sessions (id, user_id, csrf_token, created_at, last_seen_at)
                VALUES (?, ?, ?, ?, ?)
                """,
                (session_id, user_id, secrets.token_urlsafe(32), now, now),
            )
        return session_id

    def read_session(self, session_id: str) -> sqlite3.Row | None:
        now = int(time.time())
        with self.connect() as db:
            session = db.execute(
                """
                UPDATE op_sessions SET last_seen_at = max(last_seen_at, ?)
                WHERE id = ? AND created_at > ? AND last_seen_at > ?
                RETURNING user_id, csrf_token
                """,
                (now, session_id, now - OP_SESSION_TTL, now - OP_SESSION_IDLE_TTL),
            ).fetchone()
            if session is None:
                return None
            return db.execute(
                """
                SELECT id, username, sub, full_name, email, email_verified, role,
                       ? AS csrf_token
                FROM op_users WHERE id = ?
                """,
                (session["csrf_token"], session["user_id"]),
            ).fetchone()

    def delete_session(self, session_id: str) -> None:
        with self.connect() as db:
            db.execute("DELETE FROM op_sessions WHERE id = ?", (session_id,))

    # --- Pending /authorize requests ---

    def create_authorize_request(
        self,
        *,
        client_id: str,
        redirect_uri: str,
        scope: str,
        state: str,
        nonce: str,
        code_challenge: str,
        code_challenge_method: str,
    ) -> tuple[str, str]:
        req_id = secrets.token_urlsafe(32)
        csrf_token = secrets.token_urlsafe(32)
        now = int(time.time())
        with self.connect() as db:
            db.execute("DELETE FROM authorize_requests WHERE expires_at <= ?", (now,))
            db.execute(
                """
                INSERT INTO authorize_requests
                    (id, client_id, redirect_uri, scope, state, nonce,
                     code_challenge, code_challenge_method, csrf_token, expires_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    req_id,
                    client_id,
                    redirect_uri,
                    scope,
                    state,
                    nonce,
                    code_challenge,
                    code_challenge_method,
                    csrf_token,
                    now + AUTH_REQUEST_TTL,
                ),
            )
        return req_id, csrf_token

    def get_authorize_request(self, req_id: str) -> sqlite3.Row | None:
        now = int(time.time())
        with self.connect() as db:
            row = db.execute(
                "SELECT * FROM authorize_requests WHERE id = ? AND expires_at > ?",
                (req_id, now),
            ).fetchone()
        return row

    def consume_authorize_request(self, req_id: str) -> sqlite3.Row | None:
        now = int(time.time())
        with self.connect() as db:
            row = db.execute(
                "DELETE FROM authorize_requests WHERE id = ? RETURNING *",
                (req_id,),
            ).fetchone()
        if row is None or row["expires_at"] <= now:
            return None
        return row

    # --- Consents ---

    def record_consent(self, user_id: int, client_id: str, scope: str) -> None:
        now = int(time.time())
        with self.connect() as db:
            db.execute(
                """
                INSERT INTO user_consents (user_id, client_id, scope, granted_at)
                VALUES (?, ?, ?, ?)
                ON CONFLICT(user_id, client_id, scope) DO UPDATE SET granted_at = excluded.granted_at
                """,
                (user_id, client_id, scope, now),
            )

    # --- Authorization codes & token lifecycle ---

    def issue_authorization_code(
        self,
        *,
        client_id: str,
        redirect_uri: str,
        code_challenge: str,
        sub: str,
        user_id: int,
        nonce: str,
        scope: str,
        ttl: int,
    ) -> str:
        code = secrets.token_urlsafe(32)
        grant_id = secrets.token_urlsafe(24)
        now = int(time.time())
        with self.connect() as db:
            db.execute(
                """
                INSERT INTO authorization_codes
                    (code_hash, grant_id, client_id, redirect_uri, code_challenge,
                     sub, user_id, nonce, scope, issued_at, expires_at, used_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, NULL)
                """,
                (
                    sha256_hex(code),
                    grant_id,
                    client_id,
                    redirect_uri,
                    code_challenge,
                    sub,
                    user_id,
                    nonce,
                    scope,
                    now,
                    now + ttl,
                ),
            )
        return code

    def get_authorization_code(self, code: str) -> sqlite3.Row | None:
        with self.connect() as db:
            return db.execute(
                "SELECT * FROM authorization_codes WHERE code_hash = ?",
                (sha256_hex(code),),
            ).fetchone()

    def mark_code_used(self, code_hash: str) -> bool:
        now = int(time.time())
        with self.connect() as db:
            cursor = db.execute(
                """
                UPDATE authorization_codes SET used_at = ?
                WHERE code_hash = ? AND used_at IS NULL
                """,
                (now, code_hash),
            )
            return cursor.rowcount == 1

    def revoke_grant_tokens(self, grant_id: str) -> None:
        with self.connect() as db:
            db.execute("UPDATE access_tokens SET revoked = 1 WHERE grant_id = ?", (grant_id,))
            db.execute("UPDATE refresh_tokens SET revoked = 1 WHERE grant_id = ?", (grant_id,))

    def store_access_token(
        self,
        *,
        jti: str,
        grant_id: str,
        client_id: str,
        user_id: int,
        sub: str,
        scope: str,
        issued_at: int,
        expires_at: int,
    ) -> None:
        with self.connect() as db:
            db.execute(
                """
                INSERT INTO access_tokens
                    (jti, grant_id, client_id, user_id, sub, scope, issued_at, expires_at, revoked)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, 0)
                """,
                (jti, grant_id, client_id, user_id, sub, scope, issued_at, expires_at),
            )

    def get_active_access_token(self, jti: str) -> sqlite3.Row | None:
        now = int(time.time())
        with self.connect() as db:
            return db.execute(
                """
                SELECT * FROM access_tokens
                WHERE jti = ? AND revoked = 0 AND expires_at > ?
                """,
                (jti, now),
            ).fetchone()

    def store_refresh_token(
        self,
        *,
        refresh_token: str,
        grant_id: str,
        client_id: str,
        user_id: int,
        sub: str,
        scope: str,
        issued_at: int,
        expires_at: int,
    ) -> None:
        with self.connect() as db:
            db.execute(
                """
                INSERT INTO refresh_tokens
                    (token_hash, grant_id, client_id, user_id, sub, scope,
                     issued_at, expires_at, used_at, revoked)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, NULL, 0)
                """,
                (
                    sha256_hex(refresh_token),
                    grant_id,
                    client_id,
                    user_id,
                    sub,
                    scope,
                    issued_at,
                    expires_at,
                ),
            )

    def is_refresh_token_active(self, refresh_token: str) -> bool:
        now = int(time.time())
        with self.connect() as db:
            row = db.execute(
                """
                SELECT 1 FROM refresh_tokens
                WHERE token_hash = ? AND revoked = 0 AND used_at IS NULL AND expires_at > ?
                """,
                (sha256_hex(refresh_token), now),
            ).fetchone()
        return row is not None
