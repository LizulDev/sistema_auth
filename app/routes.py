import hmac

from flask import Blueprint, abort, current_app, make_response, redirect, render_template, request, url_for

from . import oidc
from .config import OidcSettings
from .storage import AUTHORIZATION_TTL, SESSION_TTL, Store


FLOW_COOKIE = "oidc_flow"
SESSION_COOKIE = "session_id"


def cookie_options(path: str = "/") -> dict:
    return {"httponly": True, "secure": request.is_secure, "samesite": "Lax", "path": path}


def matches(received: str, expected: str) -> bool:
    return hmac.compare_digest(received.encode("utf-8"), expected.encode("utf-8"))


def create_routes(store: Store, settings: OidcSettings) -> Blueprint:
    web = Blueprint("web", __name__)

    def current_user():
        session_id = request.cookies.get(SESSION_COOKIE)
        return store.read_session(session_id) if session_id else None

    @web.get("/")
    def index():
        return render_template("index.html", user=current_user(), configured=settings.configured)

    @web.get("/login")
    def login():
        if not settings.configured:
            abort(503, "O provedor OpenID Connect ainda precisa ser configurado.")
        pending = oidc.AuthorizationRequest.generate()
        flow_id = store.start_authorization(pending)
        response = redirect(pending.authorization_url(settings))
        response.set_cookie(
            FLOW_COOKIE, flow_id, max_age=AUTHORIZATION_TTL, **cookie_options(path="/callback")
        )
        return response

    @web.get("/callback")
    def callback():
        flow_id = request.cookies.get(FLOW_COOKIE)
        pending = store.consume_authorization(flow_id) if flow_id else None
        states = request.args.getlist("state")
        codes = request.args.getlist("code")
        session_id = None

        if pending is None or len(states) != 1 or not matches(states[0], pending.state):
            current_app.logger.warning("Callback rejeitado por estado ausente, expirado ou inválido.")
            result = ("A solicitação de login é inválida ou expirou. Inicie o login novamente.", 400)
        elif "error" in request.args:
            current_app.logger.warning("O provedor devolveu um erro de autorização.")
            result = ("O provedor não concluiu a autorização.", 400)
        elif len(codes) != 1 or not codes[0]:
            current_app.logger.warning("Callback rejeitado por código ausente ou ambíguo.")
            result = ("O provedor não devolveu um código de autorização válido.", 400)
        else:
            try:
                identity = oidc.authenticate(settings, codes[0], pending)
            except oidc.OidcUnavailable:
                result = ("A integração com o provedor ainda precisa ser implementada.", 501)
            except oidc.OidcAuthenticationError:
                current_app.logger.warning("A autenticação OIDC falhou.")
                result = ("Não foi possível concluir o login.", 400)
            else:
                user = store.find_user(identity)
                if user is None:
                    result = ("Esta identidade não tem acesso à aplicação.", 403)
                else:
                    session_id = store.create_session(user["id"], request.cookies.get(SESSION_COOKIE))
                    result = redirect(url_for("web.index"))

        response = make_response(result)
        response.delete_cookie(FLOW_COOKIE, **cookie_options(path="/callback"))
        if session_id is not None:
            response.set_cookie(SESSION_COOKIE, session_id, max_age=SESSION_TTL, **cookie_options())
        return response

    @web.get("/admin")
    def admin():
        user = current_user()
        if user is None:
            abort(401, "Entre para acessar esta área.")
        if user["role"] != "admin":
            abort(403, "Acesso restrito a administradores.")
        return render_template("admin.html")

    @web.post("/logout")
    def logout():
        user = current_user()
        if user is not None:
            token = request.form.get("csrf_token", "")
            if not matches(token, user["csrf_token"]):
                abort(403, "A solicitação de saída é inválida.")
            store.delete_session(request.cookies[SESSION_COOKIE])
        response = redirect(url_for("web.index"), code=303)
        response.delete_cookie(SESSION_COOKIE, **cookie_options())
        return response

    return web
