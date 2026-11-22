"""
Suite de testes de seguranca — Avaliacao A1/3 Cyber Security (OAuth 2.0 + OIDC Opcao 1).
Cobre todos os 15 testes negativos obrigatorios da secao 5 do enunciado,
alem de fluxos ponta a ponta, rotacao de chaves JWKS e politicas de transporte/log.
"""

import base64
import hashlib
import hmac
import json
import logging
import re
import time
from urllib.parse import parse_qs, urlsplit

import httpx
import jwt
import pytest

from app import CallbackQueryMaskFilter, create_app as create_client_app
from app.config import OidcSettings
from app.oidc import (
    AuthorizationRequest,
    OidcAuthenticationError,
    authenticate,
    validate_id_token,
)
from auth_server import create_app as create_op_app
from auth_server.config import AuthServerSettings


ISSUER = "http://localhost:8001"
CLIENT_ID = "app-cybersecurity-33506"
CLIENT_SECRET = "test-only-super-secret-value-987654321"
REDIRECT_URI = "http://localhost:8000/callback"


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _extract_hidden(html: str, name: str) -> str:
    match = re.search(rf'name="{re.escape(name)}"\s+value="([^"]*)"', html)
    assert match, f"Campo oculto {name!r} nao encontrado no HTML"
    return match.group(1)


@pytest.fixture()
def env(tmp_path):
    """Cria instancias isoladas do Servidor de Autorizacao e da Aplicacao Cliente."""
    op_settings = AuthServerSettings(
        issuer=ISSUER,
        allow_local_http=True,
        code_ttl=60,
        token_ttl=900,
        refresh_ttl=86400,
        rate_limit_max=5,
        rate_limit_window=300,
    )
    op_app = create_op_app(
        {
            "ALLOW_LOCAL_HTTP": True,
            "SETTINGS": op_settings,
            "INSTANCE_PATH": tmp_path / "op_instance",
            "DB_PATH": tmp_path / "op_instance" / "auth_server.sqlite3",
            "KEY_DIR": tmp_path / "op_instance" / "keys",
        }
    )
    op_store = op_app.extensions["auth_store"]
    op_keys = op_app.extensions["auth_keys"]

    op_store.upsert_client(
        client_id=CLIENT_ID,
        client_secret=CLIENT_SECRET,
        client_name="App Cyber Security Test",
        redirect_uris=[REDIRECT_URI],
        allowed_scopes=["openid", "profile", "email"],
        allowed_grants=["authorization_code"],
    )
    op_store.upsert_user(
        username="admin",
        password="AdminTestPassword#2026",
        sub="1000000001",
        full_name="Administrador Teste",
        email="admin@unoesc.local",
        role="admin",
        email_verified=True,
    )
    op_store.upsert_user(
        username="usuario",
        password="UserTestPassword#2026",
        sub="1000000002",
        full_name="Usuario Comum Teste",
        email="usuario@unoesc.local",
        role="user",
        email_verified=True,
    )

    def http_client_factory():
        return httpx.Client(
            transport=httpx.WSGITransport(app=op_app),
            base_url=ISSUER,
            timeout=5.0,
        )

    client_settings = OidcSettings(
        issuer=ISSUER,
        authorization_endpoint=f"{ISSUER}/authorize",
        client_id=CLIENT_ID,
        client_secret=CLIENT_SECRET,
        redirect_uri=REDIRECT_URI,
        allow_local_http=True,
        http_timeout=5.0,
        clock_skew_seconds=60,
    )
    client_app = create_client_app(
        {
            "ALLOW_LOCAL_HTTP": True,
            "SETTINGS": client_settings,
            "INSTANCE_PATH": tmp_path / "client_instance",
            "DB_PATH": tmp_path / "client_instance" / "app.sqlite3",
            "HTTP_CLIENT_FACTORY": http_client_factory,
        }
    )
    client_store = client_app.extensions["client_store"]
    client_store.upsert_user(
        user_name="admin",
        full_name="Administrador Teste",
        oidc_issuer=ISSUER,
        oidc_sub="1000000001",
        role="admin",
    )
    client_store.upsert_user(
        user_name="usuario",
        full_name="Usuario Comum Teste",
        oidc_issuer=ISSUER,
        oidc_sub="1000000002",
        role="user",
    )

    return {
        "op_app": op_app,
        "op_client": op_app.test_client(),
        "op_store": op_store,
        "op_keys": op_keys,
        "client_app": client_app,
        "rp_client": client_app.test_client(),
        "client_store": client_store,
        "client_settings": client_settings,
        "http_client_factory": http_client_factory,
    }


def _run_authorize_and_consent(
    op_client,
    *,
    username: str,
    password: str,
    state: str = "state-abc-1234567890",
    nonce: str = "nonce-xyz-1234567890",
    code_verifier: str = "verifier-secret-value-with-enough-length-for-pkce-s256-test",
    redirect_uri: str = REDIRECT_URI,
    decision: str = "approve",
):
    challenge = _b64url(hashlib.sha256(code_verifier.encode("ascii")).digest())
    get_resp = op_client.get(
        "/authorize",
        query_string={
            "response_type": "code",
            "client_id": CLIENT_ID,
            "redirect_uri": redirect_uri,
            "scope": "openid profile email",
            "state": state,
            "nonce": nonce,
            "code_challenge": challenge,
            "code_challenge_method": "S256",
        },
        base_url=ISSUER,
    )
    assert get_resp.status_code == 200
    html = get_resp.get_data(as_text=True)
    req_id = _extract_hidden(html, "auth_req_id")
    csrf = _extract_hidden(html, "csrf_token")

    login_resp = op_client.post(
        "/authorize",
        data={
            "action": "login",
            "auth_req_id": req_id,
            "csrf_token": csrf,
            "username": username,
            "password": password,
        },
        base_url=ISSUER,
    )
    assert login_resp.status_code == 200

    consent_resp = op_client.post(
        "/authorize",
        data={
            "action": "consent",
            "auth_req_id": req_id,
            "csrf_token": csrf,
            "decision": decision,
        },
        base_url=ISSUER,
    )
    assert consent_resp.status_code == 302
    location = consent_resp.headers["Location"]
    parsed = urlsplit(location)
    params = parse_qs(parsed.query)
    return location, params, code_verifier


def _complete_full_browser_login(env, *, username: str, password: str):
    """Simula o fluxo completo do navegador entre Cliente (:8000) e Provedor (:8001)."""
    rp_client = env["rp_client"]
    op_client = env["op_client"]

    # 1. Cliente /login -> 302 para /authorize no OP
    login_init = rp_client.get("/login", base_url="http://localhost:8000")
    assert login_init.status_code == 302
    auth_url = login_init.headers["Location"]
    parsed_auth = urlsplit(auth_url)

    # 2. Provedor GET /authorize
    op_get = op_client.get(f"{parsed_auth.path}?{parsed_auth.query}", base_url=ISSUER)
    assert op_get.status_code == 200
    html = op_get.get_data(as_text=True)
    req_id = _extract_hidden(html, "auth_req_id")
    csrf = _extract_hidden(html, "csrf_token")

    # 3. Provedor POST /authorize (login)
    op_login = op_client.post(
        "/authorize",
        data={
            "action": "login",
            "auth_req_id": req_id,
            "csrf_token": csrf,
            "username": username,
            "password": password,
        },
        base_url=ISSUER,
    )
    assert op_login.status_code == 200

    # 4. Provedor POST /authorize (consent)
    op_consent = op_client.post(
        "/authorize",
        data={
            "action": "consent",
            "auth_req_id": req_id,
            "csrf_token": csrf,
            "decision": "approve",
        },
        base_url=ISSUER,
    )
    assert op_consent.status_code == 302
    cb_url = op_consent.headers["Location"]
    parsed_cb = urlsplit(cb_url)

    # 5. Cliente GET /callback
    cb_resp = rp_client.get(
        f"{parsed_cb.path}?{parsed_cb.query}",
        base_url="http://localhost:8000",
    )
    return cb_resp


def _valid_id_token_payload(now: int | None = None, **overrides) -> dict:
    ts = int(time.time()) if now is None else now
    payload = {
        "iss": ISSUER,
        "sub": "1000000001",
        "aud": CLIENT_ID,
        "exp": ts + 900,
        "iat": ts,
        "nonce": "expected-nonce-123",
        "azp": CLIENT_ID,
        "name": "Administrador Teste",
        "email": "admin@unoesc.local",
        "email_verified": True,
        "role": "admin",
    }
    payload.update(overrides)
    return payload


# ==============================================================================
# 15 TESTES NEGATIVOS OBRIGATORIOS (Secao 5 do Enunciado)
# ==============================================================================


def test_neg_01_id_token_alg_none_rejeitado(env):
    """#1: ID Token com alg 'none' deve ser rejeitado."""
    header = _b64url(json.dumps({"alg": "none", "typ": "JWT", "kid": env["op_keys"].active_kid}).encode())
    payload = _b64url(json.dumps(_valid_id_token_payload()).encode())
    forged = f"{header}.{payload}."

    with pytest.raises(OidcAuthenticationError, match="Algoritmo"):
        validate_id_token(
            forged,
            jwks=env["op_keys"].public_jwks(),
            expected_issuer=ISSUER,
            expected_client_id=CLIENT_ID,
            expected_nonce="expected-nonce-123",
        )


def test_neg_02_id_token_reassinado_hs256_com_chave_publica_rejeitado(env):
    """#2: ID Token reassinado em HS256 usando a chave publica RSA como segredo deve ser rejeitado."""
    public_pem = env["op_keys"].public_pem()
    header = _b64url(json.dumps({"alg": "HS256", "typ": "JWT", "kid": env["op_keys"].active_kid}).encode())
    payload = _b64url(json.dumps(_valid_id_token_payload()).encode())
    signing_input = f"{header}.{payload}".encode("ascii")
    sig = _b64url(hmac.new(public_pem, signing_input, hashlib.sha256).digest())
    forged_hs256 = f"{header}.{payload}.{sig}"

    with pytest.raises(OidcAuthenticationError, match="Algoritmo"):
        validate_id_token(
            forged_hs256,
            jwks=env["op_keys"].public_jwks(),
            expected_issuer=ISSUER,
            expected_client_id=CLIENT_ID,
            expected_nonce="expected-nonce-123",
        )


def test_neg_03_id_token_aud_outro_client_id_rejeitado(env):
    """#3: ID Token valido mas com aud de outro client_id deve ser rejeitado."""
    token = env["op_keys"].sign_jwt(
        _valid_id_token_payload(aud="outro-client-id", azp="outro-client-id")
    )

    with pytest.raises(OidcAuthenticationError, match="aud"):
        validate_id_token(
            token,
            jwks=env["op_keys"].public_jwks(),
            expected_issuer=ISSUER,
            expected_client_id=CLIENT_ID,
            expected_nonce="expected-nonce-123",
        )


def test_neg_04_id_token_iss_diferente_rejeitado(env):
    """#4: ID Token com iss diferente do emissor deve ser rejeitado."""
    token = env["op_keys"].sign_jwt(_valid_id_token_payload(iss="https://attacker.example"))

    with pytest.raises(OidcAuthenticationError, match="iss"):
        validate_id_token(
            token,
            jwks=env["op_keys"].public_jwks(),
            expected_issuer=ISSUER,
            expected_client_id=CLIENT_ID,
            expected_nonce="expected-nonce-123",
        )


def test_neg_05_id_token_exp_vencido_rejeitado(env):
    """#5: ID Token com exp vencido deve ser rejeitado."""
    now = int(time.time())
    token = env["op_keys"].sign_jwt(_valid_id_token_payload(now=now, iat=now - 1200, exp=now - 300))

    with pytest.raises(OidcAuthenticationError, match="exp"):
        validate_id_token(
            token,
            jwks=env["op_keys"].public_jwks(),
            expected_issuer=ISSUER,
            expected_client_id=CLIENT_ID,
            expected_nonce="expected-nonce-123",
            now=now,
        )


def test_neg_06_id_token_iat_no_futuro_rejeitado(env):
    """#6: ID Token com iat no futuro deve ser rejeitado."""
    now = int(time.time())
    token = env["op_keys"].sign_jwt(_valid_id_token_payload(now=now, iat=now + 600, exp=now + 1500))

    with pytest.raises(OidcAuthenticationError, match="iat"):
        validate_id_token(
            token,
            jwks=env["op_keys"].public_jwks(),
            expected_issuer=ISSUER,
            expected_client_id=CLIENT_ID,
            expected_nonce="expected-nonce-123",
            now=now,
        )


def test_neg_07_id_token_nonce_diferente_rejeitado(env):
    """#7: ID Token com nonce diferente do enviado deve ser rejeitado."""
    token = env["op_keys"].sign_jwt(_valid_id_token_payload(nonce="nonce-atacante-replay"))

    with pytest.raises(OidcAuthenticationError, match="nonce"):
        validate_id_token(
            token,
            jwks=env["op_keys"].public_jwks(),
            expected_issuer=ISSUER,
            expected_client_id=CLIENT_ID,
            expected_nonce="expected-nonce-123",
        )


def test_neg_08_callback_state_divergente_ou_ausente_aborta_antes_da_troca(env, monkeypatch):
    """#8: Callback com state divergente ou ausente aborta o fluxo antes de chamar /token."""
    called = {"authenticate": False}

    def _should_not_be_called(*args, **kwargs):
        called["authenticate"] = True
        raise AssertionError("authenticate() nao deveria ser chamado com state invalido")

    monkeypatch.setattr("app.oidc.authenticate", _should_not_be_called)
    rp_client = env["rp_client"]

    # Caso A: state divergente
    init_resp = rp_client.get("/login", base_url="http://localhost:8000")
    assert init_resp.status_code == 302
    bad_state_resp = rp_client.get(
        "/callback?code=any-code&state=state-forjado-csrf",
        base_url="http://localhost:8000",
    )
    assert bad_state_resp.status_code == 400
    assert called["authenticate"] is False

    # Caso B: state ausente
    init_resp2 = rp_client.get("/login", base_url="http://localhost:8000")
    assert init_resp2.status_code == 302
    missing_state_resp = rp_client.get(
        "/callback?code=any-code",
        base_url="http://localhost:8000",
    )
    assert missing_state_resp.status_code == 400
    assert called["authenticate"] is False


def test_neg_09_reutilizacao_authorization_code_revoga_tokens(env):
    """#9: Reutilizacao do mesmo authorization code retorna invalid_grant e revoga tokens emitidos."""
    op_client = env["op_client"]
    _, params, verifier = _run_authorize_and_consent(
        op_client, username="admin", password="AdminTestPassword#2026"
    )
    code = params["code"][0]

    # Primeira troca: sucesso
    first_resp = op_client.post(
        "/token",
        data={
            "grant_type": "authorization_code",
            "code": code,
            "redirect_uri": REDIRECT_URI,
            "code_verifier": verifier,
            "client_id": CLIENT_ID,
            "client_secret": CLIENT_SECRET,
        },
        base_url=ISSUER,
    )
    assert first_resp.status_code == 200
    tokens = first_resp.get_json()
    access_token = tokens["access_token"]
    refresh_token = tokens["refresh_token"]

    # Antes da reutilizacao, access_token funciona em /userinfo
    ui_before = op_client.get(
        "/userinfo",
        headers={"Authorization": f"Bearer {access_token}"},
        base_url=ISSUER,
    )
    assert ui_before.status_code == 200
    assert env["op_store"].is_refresh_token_active(refresh_token) is True

    # Segunda troca com o MESMO code: invalid_grant + revogacao imediata
    replay_resp = op_client.post(
        "/token",
        data={
            "grant_type": "authorization_code",
            "code": code,
            "redirect_uri": REDIRECT_URI,
            "code_verifier": verifier,
            "client_id": CLIENT_ID,
            "client_secret": CLIENT_SECRET,
        },
        base_url=ISSUER,
    )
    assert replay_resp.status_code == 400
    assert replay_resp.get_json()["error"] == "invalid_grant"

    # Tokens emitidos anteriormente devem estar imediatamente revogados
    ui_after = op_client.get(
        "/userinfo",
        headers={"Authorization": f"Bearer {access_token}"},
        base_url=ISSUER,
    )
    assert ui_after.status_code == 401
    assert "Bearer" in ui_after.headers.get("WWW-Authenticate", "")
    assert env["op_store"].is_refresh_token_active(refresh_token) is False


def test_neg_10_code_verifier_incorreto_no_token(env):
    """#10: code_verifier incorreto no /token deve retornar invalid_grant."""
    op_client = env["op_client"]
    _, params, _ = _run_authorize_and_consent(
        op_client, username="admin", password="AdminTestPassword#2026"
    )
    code = params["code"][0]

    resp = op_client.post(
        "/token",
        data={
            "grant_type": "authorization_code",
            "code": code,
            "redirect_uri": REDIRECT_URI,
            "code_verifier": "verifier-errado-nao-bate-com-sha256-code-challenge-12345",
            "client_id": CLIENT_ID,
            "client_secret": CLIENT_SECRET,
        },
        base_url=ISSUER,
    )
    assert resp.status_code == 400
    assert resp.get_json()["error"] == "invalid_grant"


@pytest.mark.parametrize(
    "bad_redirect_uri",
    [
        f"{REDIRECT_URI}/",                  # barra final extra
        f"{REDIRECT_URI}?extra=1",           # parametro adicional
        f"{REDIRECT_URI}/subcaminho",        # subcaminho
        "http://127.0.0.1:8000/callback",    # host diferente (sem normalizacao)
    ],
)
def test_neg_11_redirect_uri_variacoes_rejeitadas_sem_redirecionar(env, bad_redirect_uri):
    """#11: redirect_uri com barra final extra, parametro adicional ou subcaminho deve ser rejeitada (400, sem 302)."""
    challenge = _b64url(hashlib.sha256(b"verifier-para-teste-redirect-uri-12345678901234567890").digest())
    resp = env["op_client"].get(
        "/authorize",
        query_string={
            "response_type": "code",
            "client_id": CLIENT_ID,
            "redirect_uri": bad_redirect_uri,
            "scope": "openid profile email",
            "state": "state-redirect-test",
            "nonce": "nonce-redirect-test",
            "code_challenge": challenge,
            "code_challenge_method": "S256",
        },
        base_url=ISSUER,
    )
    assert resp.status_code == 400
    assert "Location" not in resp.headers


def test_neg_12_um_byte_alterado_na_assinatura_do_id_token_rejeitado(env):
    """#12: Alterar um unico byte na assinatura do ID Token deve resultar em rejeicao."""
    token = env["op_keys"].sign_jwt(_valid_id_token_payload())
    header_b64, payload_b64, sig_b64 = token.split(".")
    padding = "=" * (-len(sig_b64) % 4)
    sig_bytes = bytearray(base64.urlsafe_b64decode(sig_b64 + padding))
    sig_bytes[10] ^= 0x01  # inverte 1 bit de 1 byte da assinatura
    tampered_sig_b64 = _b64url(bytes(sig_bytes))
    tampered_token = f"{header_b64}.{payload_b64}.{tampered_sig_b64}"

    with pytest.raises(OidcAuthenticationError, match="Assinatura"):
        validate_id_token(
            tampered_token,
            jwks=env["op_keys"].public_jwks(),
            expected_issuer=ISSUER,
            expected_client_id=CLIENT_ID,
            expected_nonce="expected-nonce-123",
        )


def test_neg_13_acesso_admin_com_role_user_retorna_403(env):
    """#13: Usuario autenticado com role=user acessando /admin deve receber HTTP 403."""
    cb_resp = _complete_full_browser_login(
        env, username="usuario", password="UserTestPassword#2026"
    )
    assert cb_resp.status_code == 302

    admin_resp = env["rp_client"].get("/admin", base_url="http://localhost:8000")
    assert admin_resp.status_code == 403


def test_neg_14_userinfo_sem_token_ou_expirado_retorna_401_www_authenticate(env):
    """#14: Acesso a /userinfo sem token ou com token expirado retorna HTTP 401 + WWW-Authenticate."""
    op_client = env["op_client"]

    # Sem token
    no_token = op_client.get("/userinfo", base_url=ISSUER)
    assert no_token.status_code == 401
    assert "Bearer" in no_token.headers.get("WWW-Authenticate", "")

    # Token expirado
    now = int(time.time())
    expired_access = env["op_keys"].sign_jwt(
        {
            "iss": ISSUER,
            "sub": "1000000001",
            "aud": f"{ISSUER}/userinfo",
            "exp": now - 600,
            "iat": now - 1500,
            "jti": "expired-jti-123",
            "scope": "openid profile email",
            "client_id": CLIENT_ID,
            "token_use": "access",
        }
    )
    expired_resp = op_client.get(
        "/userinfo",
        headers={"Authorization": f"Bearer {expired_access}"},
        base_url=ISSUER,
    )
    assert expired_resp.status_code == 401
    assert "Bearer" in expired_resp.headers.get("WWW-Authenticate", "")


def test_neg_15_tentativa_login_repetida_bloqueio_rate_limiting(env):
    """#15: Tentativas repetidas de login (forca bruta) devem ser bloqueadas com HTTP 429."""
    op_client = env["op_client"]
    challenge = _b64url(hashlib.sha256(b"verifier-rate-limit-test-1234567890123456789012345678").digest())
    get_resp = op_client.get(
        "/authorize",
        query_string={
            "response_type": "code",
            "client_id": CLIENT_ID,
            "redirect_uri": REDIRECT_URI,
            "scope": "openid profile email",
            "state": "state-rate-limit",
            "nonce": "nonce-rate-limit",
            "code_challenge": challenge,
            "code_challenge_method": "S256",
        },
        base_url=ISSUER,
    )
    assert get_resp.status_code == 200
    html = get_resp.get_data(as_text=True)
    req_id = _extract_hidden(html, "auth_req_id")
    csrf = _extract_hidden(html, "csrf_token")

    # 5 tentativas invalidas retornam 401 com mensagem generica
    for _ in range(5):
        resp = op_client.post(
            "/authorize",
            data={
                "action": "login",
                "auth_req_id": req_id,
                "csrf_token": csrf,
                "username": "admin",
                "password": "senha-errada-bruteforce",
            },
            base_url=ISSUER,
        )
        assert resp.status_code == 401
        assert "Credenciais invalidas" in resp.get_data(as_text=True)

    # 6a tentativa deve ser bloqueada com HTTP 429 + Retry-After
    blocked = op_client.post(
        "/authorize",
        data={
            "action": "login",
            "auth_req_id": req_id,
            "csrf_token": csrf,
            "username": "admin",
            "password": "AdminTestPassword#2026",
        },
        base_url=ISSUER,
    )
    assert blocked.status_code == 429
    assert "Retry-After" in blocked.headers


# ==============================================================================
# TESTES COMPLEMENTARES (Fluxo completo, Discovery, JWKS, Rotacao, Erros §2.8)
# ==============================================================================


def test_fluxo_completo_admin_acessa_admin_e_exibe_id_token_decomposto(env):
    """Fluxo completo Authorization Code + PKCE S256 para admin libera /admin (200) e exibe decomposicao."""
    cb_resp = _complete_full_browser_login(
        env, username="admin", password="AdminTestPassword#2026"
    )
    assert cb_resp.status_code == 302
    assert cb_resp.headers["Location"].endswith("/")

    home = env["rp_client"].get("/", base_url="http://localhost:8000")
    assert home.status_code == 200
    body = home.get_data(as_text=True)
    assert "ID Token Decomposto" in body
    assert "10/10" in body
    assert "RS256" in body

    admin = env["rp_client"].get("/admin", base_url="http://localhost:8000")
    assert admin.status_code == 200
    assert "Área Administrativa" in admin.get_data(as_text=True)


def test_discovery_jwks_e_rotacao_de_chave_rsa(env):
    """Discovery retorna metadados obrigatorios e rotacao de chave mantem a chave anterior publicada."""
    op_client = env["op_client"]
    disc = op_client.get("/.well-known/openid-configuration", base_url=ISSUER)
    assert disc.status_code == 200
    meta = disc.get_json()
    assert meta["issuer"] == ISSUER
    assert meta["scopes_supported"] == ["openid", "profile", "email"]
    assert meta["response_types_supported"] == ["code"]
    assert meta["grant_types_supported"] == ["authorization_code"]
    assert meta["code_challenge_methods_supported"] == ["S256"]
    assert meta["id_token_signing_alg_values_supported"] == ["RS256"]
    assert set(meta["token_endpoint_auth_methods_supported"]) == {
        "client_secret_post",
        "client_secret_basic",
    }

    old_kid = env["op_keys"].active_kid
    old_token = env["op_keys"].sign_jwt(_valid_id_token_payload())

    new_kid = env["op_keys"].rotate_key()
    assert new_kid != old_kid
    new_token = env["op_keys"].sign_jwt(_valid_id_token_payload())

    jwks_resp = op_client.get("/jwks.json", base_url=ISSUER)
    assert jwks_resp.status_code == 200
    jwks = jwks_resp.get_json()
    kids = {k["kid"] for k in jwks["keys"]}
    assert {old_kid, new_kid}.issubset(kids)

    # Tanto o token assinado com a chave antiga quanto com a nova validam na transicao
    validate_id_token(
        old_token,
        jwks=jwks,
        expected_issuer=ISSUER,
        expected_client_id=CLIENT_ID,
        expected_nonce="expected-nonce-123",
    )
    validate_id_token(
        new_token,
        jwks=jwks,
        expected_issuer=ISSUER,
        expected_client_id=CLIENT_ID,
        expected_nonce="expected-nonce-123",
    )


def test_token_client_secret_basic_headers_e_erros_padronizados(env):
    """Valida client_secret_basic, headers no-store/no-cache e erros da secao 2.8."""
    op_client = env["op_client"]
    _, params, verifier = _run_authorize_and_consent(
        op_client, username="admin", password="AdminTestPassword#2026"
    )
    code = params["code"][0]

    basic = base64.b64encode(f"{CLIENT_ID}:{CLIENT_SECRET}".encode("utf-8")).decode("ascii")
    ok = op_client.post(
        "/token",
        headers={"Authorization": f"Basic {basic}"},
        data={
            "grant_type": "authorization_code",
            "code": code,
            "redirect_uri": REDIRECT_URI,
            "code_verifier": verifier,
        },
        base_url=ISSUER,
    )
    assert ok.status_code == 200
    assert ok.headers.get("Cache-Control") == "no-store"
    assert ok.headers.get("Pragma") == "no-cache"

    # invalid_client -> 401 + WWW-Authenticate
    bad_client = op_client.post(
        "/token",
        data={
            "grant_type": "authorization_code",
            "code": "x",
            "redirect_uri": REDIRECT_URI,
            "code_verifier": verifier,
            "client_id": CLIENT_ID,
            "client_secret": "segredo-errado",
        },
        base_url=ISSUER,
    )
    assert bad_client.status_code == 401
    assert bad_client.get_json()["error"] == "invalid_client"
    assert "WWW-Authenticate" in bad_client.headers

    # unsupported_grant_type -> 400 (ROPC password proibido!)
    bad_grant = op_client.post(
        "/token",
        data={
            "grant_type": "password",
            "client_id": CLIENT_ID,
            "client_secret": CLIENT_SECRET,
        },
        base_url=ISSUER,
    )
    assert bad_grant.status_code == 400
    assert bad_grant.get_json()["error"] == "unsupported_grant_type"

    # code_challenge_method=plain rejeitado em /authorize
    plain_resp = op_client.get(
        "/authorize",
        query_string={
            "response_type": "code",
            "client_id": CLIENT_ID,
            "redirect_uri": REDIRECT_URI,
            "scope": "openid",
            "state": "s",
            "nonce": "n",
            "code_challenge": "a" * 43,
            "code_challenge_method": "plain",
        },
        base_url=ISSUER,
    )
    assert plain_resp.status_code == 400


def test_azp_com_multiplos_aud_e_mascara_log_callback(env):
    """Valida checklist #5 (azp com multiplos aud) e mascara de query string em /callback."""
    # Multiplos aud com azp divergente -> rejeitado
    bad_azp = env["op_keys"].sign_jwt(
        _valid_id_token_payload(aud=[CLIENT_ID, "outro-servico"], azp="outro-servico")
    )
    with pytest.raises(OidcAuthenticationError, match="azp"):
        validate_id_token(
            bad_azp,
            jwks=env["op_keys"].public_jwks(),
            expected_issuer=ISSUER,
            expected_client_id=CLIENT_ID,
            expected_nonce="expected-nonce-123",
        )

    # Multiplos aud com azp == client_id -> aceito
    good_azp = env["op_keys"].sign_jwt(
        _valid_id_token_payload(aud=[CLIENT_ID, "outro-servico"], azp=CLIENT_ID)
    )
    validate_id_token(
        good_azp,
        jwks=env["op_keys"].public_jwks(),
        expected_issuer=ISSUER,
        expected_client_id=CLIENT_ID,
        expected_nonce="expected-nonce-123",
    )

    # Filtro de log mascara code e state de /callback
    record = logging.LogRecord(
        name="werkzeug",
        level=logging.INFO,
        pathname=__file__,
        lineno=1,
        msg='127.0.0.1 - - "GET /callback?code=SUPER_SECRET_CODE&state=SECRET_STATE HTTP/1.1" 302 -',
        args=(),
        exc_info=None,
    )
    CallbackQueryMaskFilter().filter(record)
    assert "SUPER_SECRET_CODE" not in record.getMessage()
    assert "/callback?[REDACTED]" in record.getMessage()
