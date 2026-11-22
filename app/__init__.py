import os
from pathlib import Path

from flask import Flask, abort, request

from .config import LOOPBACK_HOSTS, OidcSettings
from .routes import create_routes
from .storage import Store


def create_app() -> Flask:
    app = Flask(__name__, instance_relative_config=True)
    allow_local_http = os.getenv("ALLOW_LOCAL_HTTP", "false").lower() == "true"
    settings = OidcSettings.from_env(allow_local_http=allow_local_http)

    instance = Path(app.instance_path)
    instance.mkdir(parents=True, exist_ok=True)
    store = Store(instance / "app.sqlite3")
    store.initialize()
    app.register_blueprint(create_routes(store, settings))

    @app.before_request
    def require_tls():
        if request.is_secure:
            return
        client_is_local = request.remote_addr in LOOPBACK_HOSTS
        host_is_local = request.host.partition(":")[0] in {"localhost", "127.0.0.1"}
        if not (allow_local_http and client_is_local and host_is_local):
            abort(400, "Use HTTPS para acessar a aplicação.")

    @app.after_request
    def prevent_sensitive_caching(response):
        response.headers["Cache-Control"] = "no-store"
        response.headers["Referrer-Policy"] = "no-referrer"
        return response

    return app
