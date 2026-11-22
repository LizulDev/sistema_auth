import base64
import hashlib
import hmac
import json
import logging
import secrets
import time
from dataclasses import dataclass
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

import httpx
import jwt

from .config import OidcSettings, validate_url


logger = logging.getLogger(__name__)

# Lista fixa de algoritmos aceitos (RFC 8725 §3.1). Nunca derivada do cabecalho do token.
ALLOWED_ID_TOKEN_ALGORITHMS = ("RS256",)


def _b64url_decode(segment: str) -> bytes:
    padding = "=" * (-len(segment) % 4)
    try:
        return base64.urlsafe_b64decode((segment + padding).encode("ascii"))
    except Exception as exc:
        raise OidcAuthenticationError("Segmento Base64URL malformado no ID Token.") from exc


@dataclass(frozen=True)
class AuthorizationRequest:
    state: str
    nonce: str
    verifier: str

    @classmethod
    def generate(cls) -> "AuthorizationRequest":
        return cls(
            state=secrets.token_urlsafe(32),
            nonce=secrets.token_urlsafe(32),
            verifier=secrets.token_urlsafe(32),
        )

    @property
    def challenge(self) -> str:
        digest = hashlib.sha256(self.verifier.encode("ascii")).digest()
        return base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")

    def authorization_url(
        self, settings: OidcSettings, *, authorization_endpoint: str | None = None
    ) -> str:
        target = authorization_endpoint or settings.authorization_endpoint
        endpoint = urlsplit(target)
        params = {
            "response_type": "code",
            "client_id": settings.client_id,
            "redirect_uri": settings.redirect_uri,
            "scope": "openid profile email",
            "state": self.state,
            "nonce": self.nonce,
            "code_challenge": self.challenge,
            "code_challenge_method": "S256",
        }
        query = dict(parse_qsl(endpoint.query, keep_blank_values=True)) | params
        return urlunsplit(endpoint._replace(query=urlencode(query)))


@dataclass(frozen=True)
class ProviderMetadata:
    issuer: str
    authorization_endpoint: str
    token_endpoint: str
    userinfo_endpoint: str
    jwks_uri: str


@dataclass(frozen=True)
class DecodedIdToken:
    header: dict
    payload: dict
    signature_b64: str
    signature_hex: str
    signature_bytes: int


@dataclass(frozen=True)
class VerifiedIdentity:
    issuer: str
    subject: str
    name: str | None = None
    email: str | None = None
    email_verified: bool = False
    role: str | None = None
    id_token_inspection: dict | None = None


class OidcUnavailable(Exception):
    """A integracao ainda nao pode concluir a autenticacao."""


class OidcAuthenticationError(Exception):
    """O provedor, a troca do codigo ou a validacao rejeitou a autenticacao."""


def decompose_id_token(id_token: str) -> DecodedIdToken:
    """Decompoe um JWS compacto em cabecalho, payload e assinatura decodificados."""
    if not isinstance(id_token, str):
        raise OidcAuthenticationError("ID Token ausente ou em tipo invalido.")
    parts = id_token.split(".")
    if len(parts) != 3 or not all(parts[:2]):
        raise OidcAuthenticationError("ID Token nao possui estrutura JWS de 3 partes.")

    header_raw = _b64url_decode(parts[0])
    payload_raw = _b64url_decode(parts[1])
    signature_raw = _b64url_decode(parts[2]) if parts[2] else b""

    try:
        header = json.loads(header_raw.decode("utf-8"))
        payload = json.loads(payload_raw.decode("utf-8"))
    except Exception as exc:
        raise OidcAuthenticationError("Cabecalho ou payload do ID Token nao e JSON valido.") from exc

    if not isinstance(header, dict) or not isinstance(payload, dict):
        raise OidcAuthenticationError("Cabecalho e payload do ID Token devem ser objetos JSON.")

    return DecodedIdToken(
        header=header,
        payload=payload,
        signature_b64=parts[2],
        signature_hex=signature_raw.hex(),
        signature_bytes=len(signature_raw),
    )


def _new_http_client(settings: OidcSettings) -> httpx.Client:
    return httpx.Client(
        timeout=httpx.Timeout(settings.http_timeout),
        transport=httpx.HTTPTransport(retries=0),
        follow_redirects=False,
    )


def discover_provider(
    settings: OidcSettings,
    *,
    http_client: httpx.Client | None = None,
) -> ProviderMetadata:
    discovery_url = f"{settings.issuer.rstrip('/')}/.well-known/openid-configuration"
    validate_url(discovery_url, allow_local_http=settings.allow_local_http)

    own_client = http_client is None
    client = http_client or _new_http_client(settings)
    try:
        resp = client.get(discovery_url, headers={"Accept": "application/json"})
    except httpx.HTTPError as exc:
        raise OidcAuthenticationError("Falha de rede na descoberta OpenID Connect.") from exc
    finally:
        if own_client:
            client.close()

    if resp.status_code != 200:
        raise OidcAuthenticationError(f"Descoberta OIDC retornou HTTP {resp.status_code}.")

    try:
        data = resp.json()
    except ValueError as exc:
        raise OidcAuthenticationError("Documento de descoberta OIDC invalido.") from exc

    required_fields = (
        "issuer",
        "authorization_endpoint",
        "token_endpoint",
        "userinfo_endpoint",
        "jwks_uri",
    )
    for field_name in required_fields:
        if not isinstance(data.get(field_name), str) or not data[field_name]:
            raise OidcAuthenticationError(f"Campo obrigatorio ausente na descoberta: {field_name}.")

    if data["issuer"] != settings.issuer:
        raise OidcAuthenticationError("Issuer da descoberta diverge do OIDC_ISSUER configurado.")

    for field_name in required_fields:
        try:
            validate_url(data[field_name], allow_local_http=settings.allow_local_http)
        except ValueError as exc:
            raise OidcAuthenticationError(
                f"URL insegura na descoberta ({field_name})."
            ) from exc

    return ProviderMetadata(
        issuer=data["issuer"],
        authorization_endpoint=data["authorization_endpoint"],
        token_endpoint=data["token_endpoint"],
        userinfo_endpoint=data["userinfo_endpoint"],
        jwks_uri=data["jwks_uri"],
    )


def fetch_jwks(jwks_uri: str, *, http_client: httpx.Client) -> dict:
    try:
        resp = http_client.get(jwks_uri, headers={"Accept": "application/json"})
    except httpx.HTTPError as exc:
        raise OidcAuthenticationError("Falha de rede ao obter JWKS do provedor.") from exc

    if resp.status_code != 200:
        raise OidcAuthenticationError(f"JWKS retornou HTTP {resp.status_code}.")

    try:
        data = resp.json()
    except ValueError as exc:
        raise OidcAuthenticationError("JWKS nao e um JSON valido.") from exc

    if not isinstance(data, dict) or not isinstance(data.get("keys"), list):
        raise OidcAuthenticationError("Formato de JWKS invalido.")

    return data


def _find_jwk_by_kid(jwks: dict, kid: str) -> dict:
    for key in jwks.get("keys", []):
        if isinstance(key, dict) and key.get("kid") == kid:
            if key.get("kty") != "RSA":
                raise OidcAuthenticationError("Chave JWK correspondente nao e do tipo RSA.")
            if "use" in key and key["use"] != "sig":
                raise OidcAuthenticationError("Chave JWK nao esta marcada para assinatura (use=sig).")
            if "alg" in key and key["alg"] not in ALLOWED_ID_TOKEN_ALGORITHMS:
                raise OidcAuthenticationError("Algoritmo da chave JWK nao e permitido.")
            return key
    raise OidcAuthenticationError(f"Chave publica nao encontrada no JWKS para kid={kid!r}.")


def validate_id_token(
    id_token: str,
    *,
    jwks: dict,
    expected_issuer: str,
    expected_client_id: str,
    expected_nonce: str,
    clock_skew_seconds: int = 60,
    now: int | None = None,
) -> tuple[dict, DecodedIdToken, list[dict]]:
    """
    Valida o ID Token conforme os itens 1 a 8 do checklist 4.3 (OIDC Core §3.1.3.7 e RFC 8725).
    Retorna (claims_validados, token_decomposto, checklist_itens_1_a_8).
    """
    decoded = decompose_id_token(id_token)

    # Item 4.2(7): registrar as 3 partes decodificadas no log do servidor
    logger.info(
        "ID Token decomposto | header=%s | payload=%s | signature_bytes=%d signature_b64=%s",
        json.dumps(decoded.header, ensure_ascii=False, sort_keys=True),
        json.dumps(decoded.payload, ensure_ascii=False, sort_keys=True),
        decoded.signature_bytes,
        decoded.signature_b64,
    )

    checks: list[dict] = []

    # Checklist #2: algoritmo na lista fixa; alg="none" e HS256 sempre rejeitados (RFC 8725 §2.1, §3.1)
    alg = decoded.header.get("alg")
    if not isinstance(alg, str) or alg.lower() == "none" or alg not in ALLOWED_ID_TOKEN_ALGORITHMS:
        raise OidcAuthenticationError(f"Algoritmo de ID Token rejeitado: {alg!r}.")

    # Checklist #1: assinatura conferida com chave publica identificada por kid (OIDC Core §3.1.3.7(6-7))
    kid = decoded.header.get("kid")
    if not isinstance(kid, str) or not kid:
        raise OidcAuthenticationError("Cabecalho do ID Token nao contem kid.")

    if not decoded.signature_b64:
        raise OidcAuthenticationError("ID Token sem assinatura.")

    jwk = _find_jwk_by_kid(jwks, kid)
    try:
        public_key = jwt.algorithms.RSAAlgorithm.from_jwk(json.dumps(jwk))
    except Exception as exc:
        raise OidcAuthenticationError("Chave publica JWK invalida.") from exc

    try:
        claims = jwt.decode(
            id_token,
            key=public_key,
            algorithms=list(ALLOWED_ID_TOKEN_ALGORITHMS),
            options={
                "verify_signature": True,
                "verify_exp": False,
                "verify_iat": False,
                "verify_nbf": False,
                "verify_aud": False,
                "verify_iss": False,
                "require": ["iss", "sub", "aud", "exp", "iat", "nonce"],
            },
        )
    except jwt.PyJWTError as exc:
        raise OidcAuthenticationError(f"Assinatura ou estrutura do ID Token invalida: {exc}") from exc

    checks.append(
        {
            "item": 1,
            "check": "Assinatura RS256 validada com chave publica do JWKS identificada por kid",
            "status": "OK",
            "detail": f"kid={kid}",
        }
    )
    checks.append(
        {
            "item": 2,
            "check": "Algoritmo pertence a lista fixa aceita (RS256); alg none/HS256 rejeitados",
            "status": "OK",
            "detail": f"alg={alg}",
        }
    )

    # Checklist #3: iss identico ao issuer publicado na descoberta (OIDC Core §3.1.3.7(2))
    iss = claims.get("iss")
    if not isinstance(iss, str) or not hmac.compare_digest(iss, expected_issuer):
        raise OidcAuthenticationError("Claim iss do ID Token diverge do emissor esperado.")
    checks.append(
        {
            "item": 3,
            "check": "iss identico ao issuer da descoberta",
            "status": "OK",
            "detail": iss,
        }
    )

    # Checklist #4: aud contem client_id da aplicacao (OIDC Core §3.1.3.7(3))
    aud = claims.get("aud")
    if isinstance(aud, str):
        aud_list = [aud]
    elif isinstance(aud, list) and all(isinstance(a, str) for a in aud):
        aud_list = aud
    else:
        raise OidcAuthenticationError("Claim aud do ID Token malformado.")

    if expected_client_id not in aud_list:
        raise OidcAuthenticationError("Claim aud do ID Token nao contem o client_id da aplicacao.")
    checks.append(
        {
            "item": 4,
            "check": "aud contem o client_id da aplicacao",
            "status": "OK",
            "detail": ", ".join(aud_list),
        }
    )

    # Checklist #5: se aud tiver mais de um valor (ou azp presente), azp == client_id (OIDC Core §3.1.3.7(4-5))
    azp = claims.get("azp")
    if len(aud_list) > 1:
        if not isinstance(azp, str) or not hmac.compare_digest(azp, expected_client_id):
            raise OidcAuthenticationError("Claim azp obrigatorio e deve ser igual ao client_id quando aud tem multiplos valores.")
    elif azp is not None:
        if not isinstance(azp, str) or not hmac.compare_digest(azp, expected_client_id):
            raise OidcAuthenticationError("Claim azp presente no ID Token diverge do client_id.")
    checks.append(
        {
            "item": 5,
            "check": "azp validado (obrigatorio com multiplos valores em aud)",
            "status": "OK",
            "detail": azp or "(aud unico)",
        }
    )

    current_time = int(time.time()) if now is None else int(now)

    # Checklist #6: exp esta no futuro (com pequena tolerancia) (OIDC Core §3.1.3.7(9))
    exp = claims.get("exp")
    if isinstance(exp, bool) or not isinstance(exp, (int, float)):
        raise OidcAuthenticationError("Claim exp do ID Token invalido.")
    if exp < current_time - clock_skew_seconds:
        raise OidcAuthenticationError("ID Token expirado (claim exp vencido).")
    checks.append(
        {
            "item": 6,
            "check": "exp esta no futuro (tolerancia maxima de 60s)",
            "status": "OK",
            "detail": f"exp={int(exp)}",
        }
    )

    # Checklist #7: iat nao esta no futuro (OIDC Core §3.1.3.7(10))
    iat = claims.get("iat")
    if isinstance(iat, bool) or not isinstance(iat, (int, float)):
        raise OidcAuthenticationError("Claim iat do ID Token invalido.")
    if iat > current_time + clock_skew_seconds:
        raise OidcAuthenticationError("Claim iat do ID Token esta no futuro.")
    checks.append(
        {
            "item": 7,
            "check": "iat nao esta no futuro (tolerancia maxima de 60s)",
            "status": "OK",
            "detail": f"iat={int(iat)}",
        }
    )

    # Checklist #8: nonce identico ao enviado em /authorize (OIDC Core §3.1.3.7(11))
    nonce = claims.get("nonce")
    if not isinstance(nonce, str) or not hmac.compare_digest(nonce, expected_nonce):
        raise OidcAuthenticationError("Claim nonce do ID Token diverge do valor enviado.")
    checks.append(
        {
            "item": 8,
            "check": "nonce identico ao enviado na requisicao /authorize",
            "status": "OK",
            "detail": "correspondencia exata verificada",
        }
    )

    sub = claims.get("sub")
    if not isinstance(sub, str) or not sub:
        raise OidcAuthenticationError("Claim sub ausente ou invalido no ID Token.")

    return claims, decoded, checks


def fetch_userinfo(
    userinfo_endpoint: str,
    access_token: str,
    *,
    http_client: httpx.Client,
) -> dict:
    try:
        resp = http_client.get(
            userinfo_endpoint,
            headers={
                "Authorization": f"Bearer {access_token}",
                "Accept": "application/json",
            },
        )
    except httpx.HTTPError as exc:
        raise OidcAuthenticationError("Falha de rede ao consultar /userinfo.") from exc

    if resp.status_code != 200:
        raise OidcAuthenticationError(f"Endpoint /userinfo retornou HTTP {resp.status_code}.")

    try:
        data = resp.json()
    except ValueError as exc:
        raise OidcAuthenticationError("Resposta de /userinfo nao e JSON valido.") from exc

    if not isinstance(data, dict) or not isinstance(data.get("sub"), str) or not data["sub"]:
        raise OidcAuthenticationError("Resposta de /userinfo sem claim sub valido.")

    return data


def authenticate(
    settings: OidcSettings,
    code: str,
    pending: AuthorizationRequest,
    *,
    http_client: httpx.Client | None = None,
) -> VerifiedIdentity:
    """
    Executa descoberta OIDC, troca unica do authorization code por tokens (sem retry),
    decomposicao e validacao do ID Token (checklist 4.3) e confirmacao via /userinfo.
    """
    if not settings.configured or not settings.client_secret:
        raise OidcUnavailable("Configuracao OIDC incompleta.")

    own_client = http_client is None
    client = http_client or _new_http_client(settings)
    try:
        metadata = discover_provider(settings, http_client=client)

        # Troca unica do code no token_endpoint (timeout explicito, retries=0)
        try:
            token_resp = client.post(
                metadata.token_endpoint,
                data={
                    "grant_type": "authorization_code",
                    "code": code,
                    "redirect_uri": settings.redirect_uri,
                    "code_verifier": pending.verifier,
                    "client_id": settings.client_id,
                    "client_secret": settings.client_secret,
                },
                headers={
                    "Content-Type": "application/x-www-form-urlencoded",
                    "Accept": "application/json",
                },
            )
        except httpx.HTTPError as exc:
            raise OidcAuthenticationError("Erro de rede/timeout na troca do authorization code.") from exc

        if token_resp.status_code != 200:
            raise OidcAuthenticationError(
                f"Troca do codigo rejeitada pelo provedor (HTTP {token_resp.status_code})."
            )

        try:
            token_data = token_resp.json()
        except ValueError as exc:
            raise OidcAuthenticationError("Resposta de /token nao e JSON valido.") from exc

        id_token = token_data.get("id_token")
        access_token = token_data.get("access_token")
        if not isinstance(id_token, str) or not id_token:
            raise OidcAuthenticationError("Resposta de /token nao contem id_token.")
        if not isinstance(access_token, str) or not access_token:
            raise OidcAuthenticationError("Resposta de /token nao contem access_token.")

        jwks = fetch_jwks(metadata.jwks_uri, http_client=client)
        claims, decoded, checks = validate_id_token(
            id_token,
            jwks=jwks,
            expected_issuer=metadata.issuer,
            expected_client_id=settings.client_id,
            expected_nonce=pending.nonce,
            clock_skew_seconds=settings.clock_skew_seconds,
        )

        # Checklist #10: chamar /userinfo com Bearer access_token e confirmar sub identico
        userinfo = fetch_userinfo(metadata.userinfo_endpoint, access_token, http_client=client)
        if not hmac.compare_digest(userinfo["sub"], claims["sub"]):
            raise OidcAuthenticationError("Claim sub de /userinfo diverge do sub do ID Token.")
        checks.append(
            {
                "item": 10,
                "check": "sub devolvido por /userinfo e identico ao sub do ID Token",
                "status": "OK",
                "detail": userinfo["sub"],
            }
        )

        role = claims.get("role")
        if role is not None and role not in ("admin", "user"):
            raise OidcAuthenticationError("Claim role invalido no ID Token.")

        email_verified = claims.get("email_verified") is True
        email = claims.get("email") if (email_verified and isinstance(claims.get("email"), str)) else None
        name = claims.get("name") if isinstance(claims.get("name"), str) else userinfo.get("name")

        inspection = {
            "header": decoded.header,
            "payload": decoded.payload,
            "signature_b64": decoded.signature_b64,
            "signature_hex_preview": decoded.signature_hex[:64] + "..." if len(decoded.signature_hex) > 64 else decoded.signature_hex,
            "signature_bytes": decoded.signature_bytes,
            "userinfo": userinfo,
            "checks": checks,
        }

        return VerifiedIdentity(
            issuer=claims["iss"],
            subject=claims["sub"],
            name=name,
            email=email,
            email_verified=email_verified,
            role=role,
            id_token_inspection=inspection,
        )
    finally:
        if own_client:
            client.close()
