import logging
import os
import re
from pathlib import Path

from flask import Flask, abort, request

from .config import LOOPBACK_HOSTS, AuthServerSettings
from .keys import KeyManager
from .routes import create_routes
from .storage import AuthServerStore


_SENSITIVE_QUERY_RE = re.compile(r"(/authorize|/callback)\?[^\s\"']+")


class SensitiveQueryFilter(logging.Filter):
    """Mascara query strings em logs de acesso para nao vazar parametros OAuth/OIDC."""

    def filter(self, record: logging.LogRecord) -> bool:
        try:
            rendered = record.getMessage()
        except Exception:
            return True
        sanitized = _SENSITIVE_QUERY_RE.sub(r"\1?[REDACTED]", rendered)
        if sanitized != rendered:
            record.msg = sanitized
            record.args = ()
        return True


def _install_log_filter() -> None:
    werkzeug_logger = logging.getLogger("werkzeug")
    if not any(isinstance(f, SensitiveQueryFilter) for f in werkzeug_logger.filters):
        werkzeug_logger.addFilter(SensitiveQueryFilter())


def create_app(test_config: dict | None = None) -> Flask:
    app = Flask(__name__, instance_relative_config=True)
    _install_log_filter()

    if test_config and "ALLOW_LOCAL_HTTP" in test_config:
        allow_local_http = bool(test_config["ALLOW_LOCAL_HTTP"])
    else:
        allow_local_http = os.getenv("ALLOW_LOCAL_HTTP", "false").lower() == "true"

    if test_config and "SETTINGS" in test_config:
        settings = test_config["SETTINGS"]
    else:
        settings = AuthServerSettings.from_env(allow_local_http=allow_local_http)

    instance = Path(test_config["INSTANCE_PATH"]) if (test_config and "INSTANCE_PATH" in test_config) else Path(app.instance_path)
    instance.mkdir(parents=True, exist_ok=True)

    db_path = Path(test_config["DB_PATH"]) if (test_config and "DB_PATH" in test_config) else (instance / "auth_server.sqlite3")
    key_dir = Path(test_config["KEY_DIR"]) if (test_config and "KEY_DIR" in test_config) else (instance / "keys")

    store = AuthServerStore(db_path)
    store.initialize()
    keys = KeyManager(key_dir)

    app.extensions["auth_store"] = store
    app.extensions["auth_keys"] = keys
    app.extensions["auth_settings"] = settings

    app.register_blueprint(create_routes(store, keys, settings))

    @app.before_request
    def require_tls():
        if request.is_secure:
            return
        client_is_local = request.remote_addr in LOOPBACK_HOSTS
        host_is_local = request.host.partition(":")[0] in {"localhost", "127.0.0.1"}
        if not (allow_local_http and client_is_local and host_is_local):
            abort(400, "Use HTTPS para acessar o Servidor de Autorizacao.")

    @app.after_request
    def security_headers(response):
        response.headers.setdefault("Cache-Control", "no-store")
        response.headers.setdefault("Pragma", "no-cache")
        response.headers["Referrer-Policy"] = "no-referrer"
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        return response

    return app
