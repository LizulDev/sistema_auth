import os
from dataclasses import dataclass
from urllib.parse import urlsplit


LOOPBACK_HOSTS = {"localhost", "127.0.0.1", "::1"}


def validate_url(value: str, *, allow_local_http: bool) -> None:
    url = urlsplit(value)
    local_http = allow_local_http and url.hostname in LOOPBACK_HOSTS and url.scheme == "http"
    if not url.hostname or url.username is not None or url.fragment:
        raise ValueError("Informe uma URL absoluta sem credenciais ou fragmento.")
    if url.scheme != "https" and not local_http:
        raise ValueError("A URL deve usar HTTPS, exceto no desenvolvimento local habilitado.")


@dataclass(frozen=True)
class AuthServerSettings:
    issuer: str
    allow_local_http: bool = False
    code_ttl: int = 60
    token_ttl: int = 900
    refresh_ttl: int = 86400
    rate_limit_max: int = 5
    rate_limit_window: int = 300

    def __post_init__(self) -> None:
        validate_url(self.issuer, allow_local_http=self.allow_local_http)
        if not (1 <= self.code_ttl <= 60):
            raise ValueError("AUTH_SERVER_CODE_TTL deve estar entre 1 e 60 segundos.")
        if self.token_ttl < 60:
            raise ValueError("AUTH_SERVER_TOKEN_TTL deve ser ao menos 60 segundos.")

    @classmethod
    def from_env(cls, *, allow_local_http: bool) -> "AuthServerSettings":
        issuer = os.getenv("AUTH_SERVER_ISSUER", "http://localhost:8001").rstrip("/")
        code_ttl = int(os.getenv("AUTH_SERVER_CODE_TTL", "60"))
        token_ttl = int(os.getenv("AUTH_SERVER_TOKEN_TTL", "900"))
        refresh_ttl = int(os.getenv("AUTH_SERVER_REFRESH_TTL", "86400"))
        rate_limit_max = int(os.getenv("AUTH_SERVER_RATE_LIMIT_MAX", "5"))
        rate_limit_window = int(os.getenv("AUTH_SERVER_RATE_LIMIT_WINDOW", "300"))
        return cls(
            issuer=issuer,
            allow_local_http=allow_local_http,
            code_ttl=code_ttl,
            token_ttl=token_ttl,
            refresh_ttl=refresh_ttl,
            rate_limit_max=rate_limit_max,
            rate_limit_window=rate_limit_window,
        )
