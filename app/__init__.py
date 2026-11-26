import logging
import os
import re
from pathlib import Path

from flask import Flask, abort, request

from .config import LOOPBACK_HOSTS, OidcSettings
from .routes import create_routes
from .storage import Store


_CALLBACK_QUERY_RE = re.compile(r"(/callback)\?[^\s\"']+")


class CallbackQueryMaskFilter(logging.Filter):
    """Mascara a query string de /callback nos logs para nao vazar authorization code ou state."""

    def filter(self, record: logging.LogRecord) -> bool:
        try:
            rendered = record.getMessage()
        except Exception:
            return True
        sanitized = _CALLBACK_QUERY_RE.sub(r"\1?[REDACTED]", rendered)
        if sanitized != rendered:
            record.msg = sanitized
            record.args = ()
        return True


def _install_log_filter() -> None:
    for logger_name in ("werkzeug", "app", __name__):
        target = logging.getLogger(logger_name)
        if not any(isinstance(f, CallbackQueryMaskFilter) for f in target.filters):
            target.addFilter(CallbackQueryMaskFilter())


def create_app(test_config: dict | None = None) -> Flask:
    app = Flask(__name__, instance_relative_config=True)
    app.logger.setLevel(logging.INFO)
    _install_log_filter()

    if test_config and "ALLOW_LOCAL_HTTP" in test_config:
        allow_local_http = bool(test_config["ALLOW_LOCAL_HTTP"])
    else:
        allow_local_http = os.getenv("ALLOW_LOCAL_HTTP", "false").lower() == "true"

    if test_config and "SETTINGS" in test_config:
        settings = test_config["SETTINGS"]
    else:
        settings = OidcSettings.from_env(allow_local_http=allow_local_http)

    instance = (
        Path(test_config["INSTANCE_PATH"])
        if (test_config and "INSTANCE_PATH" in test_config)
        else Path(app.instance_path)
    )
    instance.mkdir(parents=True, exist_ok=True)
    db_path = (
        Path(test_config["DB_PATH"])
        if (test_config and "DB_PATH" in test_config)
        else (instance / "app.sqlite3")
    )

    store = Store(db_path)
    store.initialize()

    app.extensions["client_store"] = store
    app.extensions["oidc_settings"] = settings
    if test_config and "HTTP_CLIENT_FACTORY" in test_config:
        app.extensions["http_client_factory"] = test_config["HTTP_CLIENT_FACTORY"]

    app.register_blueprint(create_routes(store, settings))

    @app.before_request
    def require_tls():
        if request.is_secure:
            return
        client_is_local = request.remote_addr in LOOPBACK_HOSTS
        host_is_local = request.host.partition(":")[0] in {"localhost", "127.0.0.1"}
        if not (allow_local_http and client_is_local and host_is_local):
            abort(400, "Use HTTPS para acessar a aplicacao.")

    @app.after_request
    def prevent_sensitive_caching(response):
        response.headers["Cache-Control"] = "no-store"
        response.headers["Pragma"] = "no-cache"
        response.headers["Referrer-Policy"] = "no-referrer"
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        return response

    return app
