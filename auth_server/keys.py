import base64
import json
import secrets
import time
from pathlib import Path

import jwt
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa


ALLOWED_SIGNING_ALGORITHMS = ("RS256",)


def _int_to_base64url(value: int) -> str:
    length = (value.bit_length() + 7) // 8
    raw = value.to_bytes(length, byteorder="big")
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


class KeyManager:
    """Gerencia chaves RSA do Servidor de Autorizacao com suporte a rotacao em JWKS."""

    def __init__(self, key_dir: Path):
        self.key_dir = Path(key_dir)
        self.metadata_path = self.key_dir / "keys.json"
        self.ensure_initialized()

    def ensure_initialized(self) -> None:
        self.key_dir.mkdir(parents=True, exist_ok=True)
        if not self.metadata_path.exists():
            initial_kid = f"rsa-{time.strftime('%Y-%m')}-{secrets.token_hex(4)}"
            self._generate_and_save_key(initial_kid)
            self._save_metadata({"active_kid": initial_kid, "published_kids": [initial_kid]})

    def _generate_and_save_key(self, kid: str) -> None:
        private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
        key_path = self.key_dir / f"{kid}.pem"
        key_path.write_bytes(pem)

    def _load_metadata(self) -> dict:
        return json.loads(self.metadata_path.read_text(encoding="utf-8"))

    def _save_metadata(self, data: dict) -> None:
        self.metadata_path.write_text(json.dumps(data, indent=2), encoding="utf-8")

    def _load_private_key(self, kid: str):
        key_path = self.key_dir / f"{kid}.pem"
        if not key_path.exists():
            raise KeyError(f"Chave privada nao encontrada para kid={kid}")
        return serialization.load_pem_private_key(key_path.read_bytes(), password=None)

    @property
    def active_kid(self) -> str:
        return self._load_metadata()["active_kid"]

    @property
    def published_kids(self) -> list[str]:
        return list(self._load_metadata()["published_kids"])

    def rotate_key(self, new_kid: str | None = None) -> str:
        """Gera nova chave ativa mantendo a(s) chave(s) anterior(es) publicada(s) na transicao."""
        meta = self._load_metadata()
        kid = new_kid or f"rsa-{time.strftime('%Y-%m')}-{secrets.token_hex(4)}"
        if kid in meta["published_kids"]:
            raise ValueError(f"kid ja existente: {kid}")
        self._generate_and_save_key(kid)
        published = list(meta["published_kids"])
        published.append(kid)
        self._save_metadata({"active_kid": kid, "published_kids": published})
        return kid

    def retire_key(self, kid: str) -> None:
        """Remove uma chave antiga do JWKS apos concluir a janela de transicao."""
        meta = self._load_metadata()
        if kid == meta["active_kid"]:
            raise ValueError("Nao e possivel remover a chave ativa.")
        meta["published_kids"] = [k for k in meta["published_kids"] if k != kid]
        self._save_metadata(meta)

    def public_jwk(self, kid: str) -> dict:
        private_key = self._load_private_key(kid)
        pub_numbers = private_key.public_key().public_numbers()
        return {
            "kid": kid,
            "kty": "RSA",
            "use": "sig",
            "alg": "RS256",
            "n": _int_to_base64url(pub_numbers.n),
            "e": _int_to_base64url(pub_numbers.e),
        }

    def public_jwks(self) -> dict:
        return {"keys": [self.public_jwk(kid) for kid in self.published_kids]}

    def public_pem(self, kid: str | None = None) -> bytes:
        target = kid or self.active_kid
        private_key = self._load_private_key(target)
        return private_key.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )

    def sign_jwt(self, payload: dict) -> str:
        kid = self.active_kid
        private_key = self._load_private_key(kid)
        return jwt.encode(
            payload,
            private_key,
            algorithm="RS256",
            headers={"alg": "RS256", "typ": "JWT", "kid": kid},
        )

    def verify_jwt(self, token: str, *, expected_issuer: str, clock_skew: int = 30) -> dict:
        try:
            header = jwt.get_unverified_header(token)
        except jwt.PyJWTError as exc:
            raise ValueError("Cabecalho JWT invalido.") from exc

        if header.get("alg") not in ALLOWED_SIGNING_ALGORITHMS:
            raise ValueError("Algoritmo JWT nao permitido.")

        kid = header.get("kid")
        if not kid or kid not in self.published_kids:
            raise ValueError("Chave de assinatura desconhecida.")

        public_key = self._load_private_key(kid).public_key()
        try:
            claims = jwt.decode(
                token,
                public_key,
                algorithms=list(ALLOWED_SIGNING_ALGORITHMS),
                issuer=expected_issuer,
                leeway=clock_skew,
                options={
                    "verify_signature": True,
                    "verify_exp": True,
                    "verify_iat": True,
                    "verify_iss": True,
                    "verify_aud": False,
                    "require": ["iss", "sub", "exp", "iat"],
                },
            )
        except jwt.PyJWTError as exc:
            raise ValueError(f"Falha na verificacao do JWT: {exc}") from exc

        return claims
