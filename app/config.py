import os
from dataclasses import dataclass, field
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
class OidcSettings:
    issuer: str
    authorization_endpoint: str
    client_id: str
    client_secret: str = field(repr=False)
    redirect_uri: str
    allow_local_http: bool = False
    http_timeout: float = 5.0
    clock_skew_seconds: int = 60

    @classmethod
    def from_env(cls, *, allow_local_http: bool) -> "OidcSettings":
        issuer = os.getenv("OIDC_ISSUER", "").rstrip("/")
        settings = cls(
            issuer=issuer,
            authorization_endpoint=os.getenv("OIDC_AUTHORIZATION_ENDPOINT", ""),
            client_id=os.getenv("OIDC_CLIENT_ID", ""),
            client_secret=os.getenv("OIDC_CLIENT_SECRET", ""),
            redirect_uri=os.getenv("OIDC_REDIRECT_URI", "http://localhost:8000/callback"),
            allow_local_http=allow_local_http,
            http_timeout=float(os.getenv("OIDC_HTTP_TIMEOUT", "5")),
            clock_skew_seconds=int(os.getenv("OIDC_CLOCK_SKEW_SECONDS", "60")),
        )
        if settings.configured:
            urls = [settings.issuer, settings.redirect_uri]
            if settings.authorization_endpoint:
                urls.append(settings.authorization_endpoint)
            for url in urls:
                validate_url(url, allow_local_http=allow_local_http)
        return settings

    @property
    def configured(self) -> bool:
        return all((self.issuer, self.client_id, self.redirect_uri))
