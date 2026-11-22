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

    @classmethod
    def from_env(cls, *, allow_local_http: bool) -> "OidcSettings":
        settings = cls(
            issuer=os.getenv("OIDC_ISSUER", ""),
            authorization_endpoint=os.getenv("OIDC_AUTHORIZATION_ENDPOINT", ""),
            client_id=os.getenv("OIDC_CLIENT_ID", ""),
            client_secret=os.getenv("OIDC_CLIENT_SECRET", ""),
            redirect_uri=os.getenv("OIDC_REDIRECT_URI", "http://localhost:8000/callback"),
        )
        if settings.configured:
            for url in (settings.issuer, settings.authorization_endpoint, settings.redirect_uri):
                validate_url(url, allow_local_http=allow_local_http)
        return settings

    @property
    def configured(self) -> bool:
        return all((self.issuer, self.authorization_endpoint, self.client_id, self.redirect_uri))
