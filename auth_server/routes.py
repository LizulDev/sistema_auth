import base64
import hashlib
import hmac
import re
import secrets
import time
from urllib.parse import unquote_plus, urlencode, urlsplit, urlunsplit

from flask import (
    Blueprint,
    current_app,
    jsonify,
    make_response,
    redirect,
    render_template,
    request,
    url_for,
)

from .config import AuthServerSettings
from .keys import KeyManager
from .storage import OP_SESSION_TTL, AuthServerStore


OP_SESSION_COOKIE = "op_session_id"
PKCE_RE = re.compile(r"^[A-Za-z0-9._~-]{43,128}$")
SUPPORTED_SCOPES = ("openid", "profile", "email")

SCOPE_DESCRIPTIONS = {
    "openid": "Confirmar sua identidade unica (sub) via OpenID Connect",
    "profile": "Ler seu nome completo e perfil de acesso (role)",
    "email": "Ler seu endereco de e-mail e status de verificacao",
}


def _cookie_options() -> dict:
    return {
        "httponly": True,
        "secure": request.is_secure,
        "samesite": "Lax",
        "path": "/",
    }


def _matches(received: str, expected: str) -> bool:
    return hmac.compare_digest(received.encode("utf-8"), expected.encode("utf-8"))


def _single_param(source, name: str) -> tuple[str | None, bool]:
    """Retorna (valor, duplicado). Evita parameter pollution (RFC 6749 §3.1)."""
    values = source.getlist(name)
    if len(values) > 1:
        return None, True
    if not values:
        return None, False
    return values[0], False


def _token_error(
    error: str,
    description: str,
    status: int = 400,
    www_authenticate: str | None = None,
):
    response = make_response(
        jsonify({"error": error, "error_description": description}),
        status,
    )
    response.headers["Cache-Control"] = "no-store"
    response.headers["Pragma"] = "no-cache"
    if www_authenticate:
        response.headers["WWW-Authenticate"] = www_authenticate
    return response


def _userinfo_unauthorized(description: str):
    response = make_response(
        jsonify({"error": "invalid_token", "error_description": description}),
        401,
    )
    response.headers["WWW-Authenticate"] = (
        f'Bearer realm="userinfo", error="invalid_token", error_description="{description}"'
    )
    response.headers["Cache-Control"] = "no-store"
    response.headers["Pragma"] = "no-cache"
    return response


def _parse_basic_auth(header_value: str) -> tuple[str, str] | None:
    if not header_value.startswith("Basic "):
        return None
    encoded = header_value[6:].strip()
    if not encoded:
        return None
    try:
        decoded = base64.b64decode(encoded, validate=True).decode("utf-8")
    except Exception:
        return None
    if ":" not in decoded:
        return None
    raw_id, raw_secret = decoded.split(":", 1)
    # RFC 6749 §2.3.1: credenciais em Basic auth sao application/x-www-form-urlencoded
    return unquote_plus(raw_id), unquote_plus(raw_secret)


def _append_query_params(base_uri: str, params: list[tuple[str, str]]) -> str:
    """Anexa parametros de callback preservando a redirect_uri exata e o state byte a byte."""
    parts = urlsplit(base_uri)
    encoded_extra = urlencode(params)
    new_query = f"{parts.query}&{encoded_extra}" if parts.query else encoded_extra
    return urlunsplit((parts.scheme, parts.netloc, parts.path, new_query, parts.fragment))


def _compute_s256(code_verifier: str) -> str:
    digest = hashlib.sha256(code_verifier.encode("ascii")).digest()
    return base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")


def create_routes(
    store: AuthServerStore,
    keys: KeyManager,
    settings: AuthServerSettings,
) -> Blueprint:
    op = Blueprint("op", __name__)

    def current_op_user():
        session_id = request.cookies.get(OP_SESSION_COOKIE)
        return store.read_session(session_id) if session_id else None

    @op.get("/")
    def index():
        return render_template(
            "index.html",
            user=current_op_user(),
            issuer=settings.issuer,
            active_kid=keys.active_kid,
        )

    @op.get("/.well-known/openid-configuration")
    def openid_configuration():
        issuer = settings.issuer
        metadata = {
            "issuer": issuer,
            "authorization_endpoint": f"{issuer}/authorize",
            "token_endpoint": f"{issuer}/token",
            "userinfo_endpoint": f"{issuer}/userinfo",
            "jwks_uri": f"{issuer}/jwks.json",
            "end_session_endpoint": f"{issuer}/logout",
            "scopes_supported": list(SUPPORTED_SCOPES),
            "response_types_supported": ["code"],
            "grant_types_supported": ["authorization_code"],
            "code_challenge_methods_supported": ["S256"],
            "id_token_signing_alg_values_supported": ["RS256"],
            "token_endpoint_auth_methods_supported": [
                "client_secret_post",
                "client_secret_basic",
            ],
            "subject_types_supported": ["public"],
            "claims_supported": [
                "iss",
                "sub",
                "aud",
                "exp",
                "iat",
                "nonce",
                "azp",
                "name",
                "email",
                "email_verified",
                "role",
            ],
        }
        return jsonify(metadata)

    @op.get("/jwks.json")
    def jwks():
        return jsonify(keys.public_jwks())

    @op.get("/authorize")
    def authorize_get():
        # 1. Validar client_id e redirect_uri primeiro — se invalidos, NUNCA redirecionar (RFC 6749 §4.1.2.1)
        client_id, dup_client = _single_param(request.args, "client_id")
        redirect_uri, dup_redirect = _single_param(request.args, "redirect_uri")

        if dup_client or dup_redirect or not client_id or not redirect_uri:
            return (
                render_template(
                    "error.html",
                    error="invalid_request",
                    description="Parametros client_id ou redirect_uri ausentes ou duplicados.",
                ),
                400,
            )

        client = store.get_client(client_id)
        if client is None:
            return (
                render_template(
                    "error.html",
                    error="invalid_request",
                    description="Aplicacao cliente (client_id) nao cadastrada.",
                ),
                400,
            )

        # Comparacao EXATA de string: sem curingas, sem prefixo, sem normalizacao (RFC 9700 §2.1)
        if not any(_matches(redirect_uri, registered) for registered in client["redirect_uris"]):
            current_app.logger.warning("Requisicao /authorize rejeitada por redirect_uri nao cadastrada.")
            return (
                render_template(
                    "error.html",
                    error="invalid_request",
                    description="redirect_uri invalida: comparacao exata falhou.",
                ),
                400,
            )

        # 2. Validar demais parametros obrigatorios (RFC 6749, RFC 7636, OIDC Core)
        params = {}
        for name in ("response_type", "scope", "state", "nonce", "code_challenge", "code_challenge_method"):
            val, dup = _single_param(request.args, name)
            if dup or not val:
                return (
                    render_template(
                        "error.html",
                        error="invalid_request",
                        description=f"Parametro obrigatorio ausente ou duplicado: {name}.",
                    ),
                    400,
                )
            params[name] = val

        if params["response_type"] != "code":
            return (
                render_template(
                    "error.html",
                    error="invalid_request",
                    description='response_type deve ser exatamente "code" (fluxo Implicit e proibido).',
                ),
                400,
            )

        if params["code_challenge_method"] != "S256":
            return (
                render_template(
                    "error.html",
                    error="invalid_request",
                    description='code_challenge_method deve ser "S256" (metodo "plain" e rejeitado).',
                ),
                400,
            )

        if not PKCE_RE.match(params["code_challenge"]):
            return (
                render_template(
                    "error.html",
                    error="invalid_request",
                    description="code_challenge em formato invalido.",
                ),
                400,
            )

        requested_scopes = params["scope"].split()
        if "openid" not in requested_scopes:
            return (
                render_template(
                    "error.html",
                    error="invalid_scope",
                    description='O escopo deve conter obrigatoriamente "openid".',
                ),
                400,
            )

        invalid_scopes = [s for s in requested_scopes if s not in client["allowed_scopes"]]
        if invalid_scopes:
            return (
                render_template(
                    "error.html",
                    error="invalid_scope",
                    description="Escopo desconhecido ou nao permitido para este cliente.",
                ),
                400,
            )

        normalized_scope = " ".join(dict.fromkeys(requested_scopes))
        req_id, csrf_token = store.create_authorize_request(
            client_id=client_id,
            redirect_uri=redirect_uri,
            scope=normalized_scope,
            state=params["state"],
            nonce=params["nonce"],
            code_challenge=params["code_challenge"],
            code_challenge_method="S256",
        )

        scopes_info = [
            {"name": s, "description": SCOPE_DESCRIPTIONS.get(s, s)}
            for s in normalized_scope.split()
        ]

        user = current_op_user()
        if user is None:
            return render_template(
                "login.html",
                auth_req_id=req_id,
                csrf_token=csrf_token,
                client_name=client["client_name"],
                scopes=scopes_info,
                error=None,
            )

        return render_template(
            "consent.html",
            auth_req_id=req_id,
            csrf_token=csrf_token,
            client_name=client["client_name"],
            scopes=scopes_info,
            user=user,
        )

    @op.post("/authorize")
    def authorize_post():
        req_id = request.form.get("auth_req_id", "")
        csrf_token = request.form.get("csrf_token", "")
        action = request.form.get("action", "")

        auth_req = store.get_authorize_request(req_id) if req_id else None
        if auth_req is None or not _matches(csrf_token, auth_req["csrf_token"]):
            return (
                render_template(
                    "error.html",
                    error="invalid_request",
                    description="Requisicao de autorizacao invalida ou expirada. Reinicie o fluxo.",
                ),
                400,
            )

        client = store.get_client(auth_req["client_id"])
        if client is None:
            return (
                render_template(
                    "error.html",
                    error="invalid_request",
                    description="Aplicacao cliente invalida.",
                ),
                400,
            )

        scopes_info = [
            {"name": s, "description": SCOPE_DESCRIPTIONS.get(s, s)}
            for s in auth_req["scope"].split()
        ]

        if action == "login":
            username = request.form.get("username", "").strip()
            password = request.form.get("password", "")
            client_ip = request.remote_addr or "unknown"
            rate_keys = [f"ip:{client_ip}"]
            if username:
                rate_keys.append(f"user:{username.lower()}")

            limited, retry_after = store.check_rate_limit(
                rate_keys,
                max_attempts=settings.rate_limit_max,
                window_seconds=settings.rate_limit_window,
            )
            if limited:
                current_app.logger.warning("Login bloqueado por rate limiting.")
                response = make_response(
                    render_template(
                        "login.html",
                        auth_req_id=req_id,
                        csrf_token=auth_req["csrf_token"],
                        client_name=client["client_name"],
                        scopes=scopes_info,
                        error="Muitas tentativas de autenticacao. Aguarde antes de tentar novamente.",
                    ),
                    429,
                )
                response.headers["Retry-After"] = str(retry_after)
                return response

            user = store.authenticate_user(username, password)
            if user is None:
                store.record_failed_login(rate_keys)
                current_app.logger.warning("Falha de autenticacao no Servidor de Autorizacao.")
                return (
                    render_template(
                        "login.html",
                        auth_req_id=req_id,
                        csrf_token=auth_req["csrf_token"],
                        client_name=client["client_name"],
                        scopes=scopes_info,
                        error="Credenciais invalidas. Verifique usuario e senha.",
                    ),
                    401,
                )

            store.clear_failed_logins(rate_keys)
            session_id = store.create_session(user["id"], request.cookies.get(OP_SESSION_COOKIE))
            response = make_response(
                render_template(
                    "consent.html",
                    auth_req_id=req_id,
                    csrf_token=auth_req["csrf_token"],
                    client_name=client["client_name"],
                    scopes=scopes_info,
                    user=user,
                ),
                200,
            )
            response.set_cookie(
                OP_SESSION_COOKIE,
                session_id,
                max_age=OP_SESSION_TTL,
                **_cookie_options(),
            )
            return response

        if action == "consent":
            user = current_op_user()
            if user is None:
                return (
                    render_template(
                        "login.html",
                        auth_req_id=req_id,
                        csrf_token=auth_req["csrf_token"],
                        client_name=client["client_name"],
                        scopes=scopes_info,
                        error="Sua sessao expirou. Autentique-se novamente.",
                    ),
                    401,
                )

            consumed = store.consume_authorize_request(req_id)
            if consumed is None:
                return (
                    render_template(
                        "error.html",
                        error="invalid_request",
                        description="Requisicao de autorizacao ja utilizada ou expirada.",
                    ),
                    400,
                )

            decision = request.form.get("decision", "")
            if decision != "approve":
                denied_url = _append_query_params(
                    consumed["redirect_uri"],
                    [
                        ("error", "access_denied"),
                        ("error_description", "O usuario recusou o consentimento."),
                        ("state", consumed["state"]),
                    ],
                )
                return redirect(denied_url, code=302)

            store.record_consent(user["id"], consumed["client_id"], consumed["scope"])
            code = store.issue_authorization_code(
                client_id=consumed["client_id"],
                redirect_uri=consumed["redirect_uri"],
                code_challenge=consumed["code_challenge"],
                sub=user["sub"],
                user_id=user["id"],
                nonce=consumed["nonce"],
                scope=consumed["scope"],
                ttl=settings.code_ttl,
            )
            callback_url = _append_query_params(
                consumed["redirect_uri"],
                [("code", code), ("state", consumed["state"])],
            )
            return redirect(callback_url, code=302)

        return (
            render_template(
                "error.html",
                error="invalid_request",
                description="Acao de autorizacao desconhecida.",
            ),
            400,
        )

    @op.post("/token")
    def token():
        content_type = request.mimetype or ""
        if content_type != "application/x-www-form-urlencoded":
            return _token_error(
                "invalid_request",
                "Content-Type deve ser application/x-www-form-urlencoded.",
                400,
            )

        # Autenticacao do cliente: client_secret_basic OU client_secret_post (nunca ambos)
        auth_header = request.headers.get("Authorization")
        basic_creds = _parse_basic_auth(auth_header) if auth_header else None
        if auth_header and basic_creds is None:
            return _token_error(
                "invalid_client",
                "Cabecalho Authorization Basic malformado.",
                401,
                www_authenticate='Basic realm="oauth2"',
            )

        post_client_id, dup_cid = _single_param(request.form, "client_id")
        post_client_secret, dup_csec = _single_param(request.form, "client_secret")
        if dup_cid or dup_csec:
            return _token_error("invalid_request", "Parametros de cliente duplicados.", 400)

        if basic_creds is not None and (post_client_id is not None or post_client_secret is not None):
            return _token_error(
                "invalid_request",
                "Nao utilize client_secret_basic e client_secret_post simultaneamente.",
                400,
            )

        if basic_creds is not None:
            client_id, client_secret = basic_creds
        elif post_client_id and post_client_secret:
            client_id, client_secret = post_client_id, post_client_secret
        else:
            return _token_error(
                "invalid_client",
                "Credenciais do cliente ausentes.",
                401,
                www_authenticate='Basic realm="oauth2"',
            )

        client = store.authenticate_client(client_id, client_secret)
        if client is None:
            return _token_error(
                "invalid_client",
                "client_id inexistente ou client_secret invalido.",
                401,
                www_authenticate='Basic realm="oauth2"',
            )

        # Validar grant_type
        grant_type, dup_grant = _single_param(request.form, "grant_type")
        if dup_grant or not grant_type:
            return _token_error("invalid_request", "Parametro grant_type ausente ou duplicado.", 400)
        if grant_type != "authorization_code":
            return _token_error(
                "unsupported_grant_type",
                'Apenas grant_type="authorization_code" e suportado.',
                400,
            )
        if "authorization_code" not in client["allowed_grants"]:
            return _token_error(
                "unauthorized_client",
                "Cliente nao autorizado a utilizar authorization_code.",
                400,
            )

        # Validar parametros do authorization_code + PKCE
        code, dup_code = _single_param(request.form, "code")
        redirect_uri, dup_uri = _single_param(request.form, "redirect_uri")
        code_verifier, dup_ver = _single_param(request.form, "code_verifier")
        if dup_code or dup_uri or dup_ver or not code or not redirect_uri or not code_verifier:
            return _token_error(
                "invalid_request",
                "Parametros code, redirect_uri e code_verifier sao obrigatorios e unicos.",
                400,
            )

        code_row = store.get_authorization_code(code)
        if code_row is None:
            return _token_error("invalid_grant", "Authorization code invalido.", 400)

        # Se o code ja foi usado: revogar imediatamente TODOS os tokens emitidos a partir dele (RFC 6749 §4.1.2)
        if code_row["used_at"] is not None:
            store.revoke_grant_tokens(code_row["grant_id"])
            current_app.logger.warning(
                "Reutilizacao de authorization code detectada; tokens associados foram revogados."
            )
            return _token_error(
                "invalid_grant",
                "Authorization code ja utilizado; todos os tokens associados foram revogados.",
                400,
            )

        now = int(time.time())
        if code_row["expires_at"] <= now:
            store.mark_code_used(code_row["code_hash"])
            return _token_error("invalid_grant", "Authorization code expirado.", 400)

        if not _matches(code_row["client_id"], client["client_id"]):
            return _token_error(
                "invalid_grant",
                "Authorization code nao pertence ao cliente autenticado.",
                400,
            )

        if not _matches(code_row["redirect_uri"], redirect_uri):
            return _token_error(
                "invalid_grant",
                "redirect_uri divergente da utilizada em /authorize.",
                400,
            )

        try:
            computed_challenge = _compute_s256(code_verifier)
        except UnicodeEncodeError:
            return _token_error("invalid_grant", "code_verifier invalido.", 400)

        if not _matches(computed_challenge, code_row["code_challenge"]):
            return _token_error("invalid_grant", "code_verifier nao corresponde ao code_challenge.", 400)

        # Consumo atomico de uso unico (protege contra condicao de corrida)
        if not store.mark_code_used(code_row["code_hash"]):
            store.revoke_grant_tokens(code_row["grant_id"])
            return _token_error(
                "invalid_grant",
                "Authorization code ja utilizado; tokens associados foram revogados.",
                400,
            )

        user = store.get_user_by_id(code_row["user_id"])
        if user is None:
            return _token_error("invalid_grant", "Usuario associado ao codigo nao encontrado.", 400)

        iat = int(time.time())
        exp = iat + settings.token_ttl
        jti = secrets.token_urlsafe(32)

        id_token_payload = {
            "iss": settings.issuer,
            "sub": user["sub"],
            "aud": client["client_id"],
            "exp": exp,
            "iat": iat,
            "nonce": code_row["nonce"],
            "azp": client["client_id"],
            "name": user["full_name"],
            "email": user["email"],
            "email_verified": bool(user["email_verified"]),
            "role": user["role"],
        }
        id_token = keys.sign_jwt(id_token_payload)

        access_token_payload = {
            "iss": settings.issuer,
            "sub": user["sub"],
            "aud": f"{settings.issuer}/userinfo",
            "exp": exp,
            "iat": iat,
            "jti": jti,
            "scope": code_row["scope"],
            "client_id": client["client_id"],
            "token_use": "access",
        }
        access_token = keys.sign_jwt(access_token_payload)

        refresh_token = secrets.token_urlsafe(32)
        store.store_access_token(
            jti=jti,
            grant_id=code_row["grant_id"],
            client_id=client["client_id"],
            user_id=user["id"],
            sub=user["sub"],
            scope=code_row["scope"],
            issued_at=iat,
            expires_at=exp,
        )
        store.store_refresh_token(
            refresh_token=refresh_token,
            grant_id=code_row["grant_id"],
            client_id=client["client_id"],
            user_id=user["id"],
            sub=user["sub"],
            scope=code_row["scope"],
            issued_at=iat,
            expires_at=iat + settings.refresh_ttl,
        )

        response = make_response(
            jsonify(
                {
                    "access_token": access_token,
                    "token_type": "Bearer",
                    "expires_in": settings.token_ttl,
                    "scope": code_row["scope"],
                    "refresh_token": refresh_token,
                    "id_token": id_token,
                }
            ),
            200,
        )
        response.headers["Cache-Control"] = "no-store"
        response.headers["Pragma"] = "no-cache"
        return response

    @op.route("/userinfo", methods=["GET", "POST"])
    def userinfo():
        auth_header = request.headers.get("Authorization", "")
        if not auth_header.startswith("Bearer "):
            return _userinfo_unauthorized("Bearer access token ausente.")
        token_value = auth_header[7:].strip()
        if not token_value or " " in token_value:
            return _userinfo_unauthorized("Bearer access token malformado.")

        try:
            claims = keys.verify_jwt(token_value, expected_issuer=settings.issuer)
        except ValueError:
            return _userinfo_unauthorized("Access token invalido ou expirado.")

        if claims.get("token_use") != "access" or not claims.get("jti"):
            return _userinfo_unauthorized("Token fornecido nao e um access token valido.")

        token_row = store.get_active_access_token(claims["jti"])
        if token_row is None:
            return _userinfo_unauthorized("Access token revogado ou expirado.")

        user = store.get_user_by_sub(claims["sub"])
        if user is None:
            return _userinfo_unauthorized("Usuario do token nao encontrado.")

        scopes = set(token_row["scope"].split())
        payload = {"sub": user["sub"]}
        if "profile" in scopes:
            payload["name"] = user["full_name"]
        if "email" in scopes:
            payload["email"] = user["email"]
            payload["email_verified"] = bool(user["email_verified"])

        response = make_response(jsonify(payload), 200)
        response.headers["Cache-Control"] = "no-store"
        response.headers["Pragma"] = "no-cache"
        return response

    @op.post("/logout")
    def logout():
        session_id = request.cookies.get(OP_SESSION_COOKIE)
        if session_id:
            user = store.read_session(session_id)
            if user is not None:
                form_csrf = request.form.get("csrf_token")
                if form_csrf is not None and not _matches(form_csrf, user["csrf_token"]):
                    return (
                        render_template(
                            "error.html",
                            error="invalid_request",
                            description="Token CSRF invalido no logout.",
                        ),
                        403,
                    )
                store.delete_session(session_id)

        response = redirect(url_for("op.index"), code=303)
        response.delete_cookie(OP_SESSION_COOKIE, **_cookie_options())
        return response

    return op
