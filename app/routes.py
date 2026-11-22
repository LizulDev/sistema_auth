import hmac
import json

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

    def get_http_client():
        factory = current_app.extensions.get("http_client_factory")
        return factory() if callable(factory) else None

    @web.get("/")
    def index():
        user = current_user()
        inspection = user.get("id_token_inspection") if user else None
        header_pretty = (
            json.dumps(inspection["header"], indent=2, ensure_ascii=False)
            if inspection and "header" in inspection
            else None
        )
        payload_pretty = (
            json.dumps(inspection["payload"], indent=2, ensure_ascii=False)
            if inspection and "payload" in inspection
            else None
        )
        userinfo_pretty = (
            json.dumps(inspection["userinfo"], indent=2, ensure_ascii=False)
            if inspection and "userinfo" in inspection
            else None
        )
        return render_template(
            "index.html",
            user=user,
            configured=settings.configured,
            issuer=settings.issuer,
            inspection=inspection,
            header_pretty=header_pretty,
            payload_pretty=payload_pretty,
            userinfo_pretty=userinfo_pretty,
        )

    @web.get("/login")
    def login():
        if not settings.configured:
            abort(503, "O provedor OpenID Connect ainda precisa ser configurado.")

        auth_endpoint = settings.authorization_endpoint
        if not auth_endpoint:
            http_client = get_http_client()
            try:
                metadata = oidc.discover_provider(settings, http_client=http_client)
            except oidc.OidcAuthenticationError:
                abort(503, "Nao foi possivel descobrir os endpoints do provedor OpenID Connect.")
            auth_endpoint = metadata.authorization_endpoint

        pending = oidc.AuthorizationRequest.generate()
        flow_id = store.start_authorization(pending)
        response = redirect(
            pending.authorization_url(settings, authorization_endpoint=auth_endpoint)
        )
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
            current_app.logger.warning("Callback rejeitado por estado ausente, expirado ou invalido.")
            result = ("A solicitacao de login e invalida ou expirou. Inicie o login novamente.", 400)
        elif "error" in request.args:
            current_app.logger.warning(
                "O provedor devolveu erro de autorizacao: %s",
                request.args.get("error", "unknown"),
            )
            result = ("O provedor nao concluiu a autorizacao.", 400)
        elif len(codes) != 1 or not codes[0]:
            current_app.logger.warning("Callback rejeitado por codigo ausente ou ambiguo.")
            result = ("O provedor nao devolveu um codigo de autorizacao valido.", 400)
        else:
            http_client = get_http_client()
            try:
                identity = oidc.authenticate(
                    settings, codes[0], pending, http_client=http_client
                )
            except oidc.OidcUnavailable:
                result = ("A integracao com o provedor ainda precisa ser configurada.", 501)
            except oidc.OidcAuthenticationError as exc:
                current_app.logger.warning("A autenticacao OIDC falhou: %s", exc)
                result = ("Nao foi possivel concluir o login.", 400)
            else:
                # Checklist #9: localizar usuario por (oidc_issuer, oidc_sub) e converter no id interno
                user = store.find_user(identity)
                if user is None:
                    current_app.logger.warning("Identidade OIDC nao cadastrada na tabela local.")
                    result = ("Esta identidade nao tem acesso a aplicacao.", 403)
                else:
                    if identity.role in ("admin", "user"):
                        store.sync_verified_role(user["id"], identity.role)

                    inspection = dict(identity.id_token_inspection) if identity.id_token_inspection else None
                    if inspection is not None:
                        checks = list(inspection.get("checks", []))
                        checks.append(
                            {
                                "item": 9,
                                "check": "sub localizado na tabela users por (oidc_issuer, oidc_sub) e convertido no id interno",
                                "status": "OK",
                                "detail": f"id={user['id']} (sub={identity.subject})",
                            }
                        )
                        checks.sort(key=lambda c: c["item"])
                        inspection["checks"] = checks

                    session_id = store.create_session(
                        user["id"],
                        request.cookies.get(SESSION_COOKIE),
                        id_token_inspection=inspection,
                    )
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
            abort(401, "Entre para acessar esta area.")
        if user["role"] != "admin":
            abort(403, "Acesso restrito a administradores.")
        return render_template("admin.html", user=user)

    @web.post("/logout")
    def logout():
        user = current_user()
        if user is not None:
            token = request.form.get("csrf_token", "")
            if not matches(token, user["csrf_token"]):
                abort(403, "A solicitacao de saida e invalida.")
            store.delete_session(request.cookies[SESSION_COOKIE])
        response = redirect(url_for("web.index"), code=303)
        response.delete_cookie(SESSION_COOKIE, **cookie_options())
        return response

    return web
