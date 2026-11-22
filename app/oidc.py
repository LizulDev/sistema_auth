import base64
import hashlib
import secrets
from dataclasses import dataclass
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

from .config import OidcSettings


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

    def authorization_url(self, settings: OidcSettings) -> str:
        endpoint = urlsplit(settings.authorization_endpoint)
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
class VerifiedIdentity:
    issuer: str
    subject: str


class OidcUnavailable(Exception):
    """A integração ainda não pode concluir a autenticação."""


class OidcAuthenticationError(Exception):
    """O provedor, a troca do código ou a validação rejeitou a autenticação."""


def authenticate(
    settings: OidcSettings, code: str, pending: AuthorizationRequest
) -> VerifiedIdentity:
    # Implementar descoberta, troca única do código e verificação do ID Token.
    # Retornar a identidade canônica do emissor somente após validar o token e o nonce.
    raise OidcUnavailable
