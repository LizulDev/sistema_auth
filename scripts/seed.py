"""Script de seed e utilitarios para inicializar o Servidor de Autorizacao e a Aplicacao Cliente."""

import argparse
import os
import sys
from pathlib import Path

from dotenv import load_dotenv

PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from app.storage import Store as ClientStore
from auth_server.keys import KeyManager
from auth_server.storage import AuthServerStore


PLACEHOLDER_PREFIX = "DEFINA_"


def _require_secret_env(name: str) -> str:
    value = os.getenv(name, "").strip()
    if not value or value.startswith(PLACEHOLDER_PREFIX):
        raise SystemExit(
            f"Erro: defina um valor real para {name} no seu arquivo .env local "
            "(nunca versione segredos ou senhas no repositorio)."
        )
    return value


def run_seed() -> None:
    load_dotenv(PROJECT_ROOT / ".env")

    issuer = os.getenv("AUTH_SERVER_ISSUER", os.getenv("OIDC_ISSUER", "http://localhost:8001")).rstrip("/")
    client_id = os.getenv("OIDC_CLIENT_ID", "app-cybersecurity-33506").strip()
    client_secret = _require_secret_env("OIDC_CLIENT_SECRET")
    redirect_uri = os.getenv("OIDC_REDIRECT_URI", "http://localhost:8000/callback").strip()

    admin_username = os.getenv("SEED_ADMIN_USERNAME", "admin").strip()
    admin_password = _require_secret_env("SEED_ADMIN_PASSWORD")
    user_username = os.getenv("SEED_USER_USERNAME", "usuario").strip()
    user_password = _require_secret_env("SEED_USER_PASSWORD")

    instance_dir = PROJECT_ROOT / "instance"
    instance_dir.mkdir(parents=True, exist_ok=True)

    # 1. Inicializa chaves RSA do Servidor de Autorizacao (fora do git)
    keys = KeyManager(instance_dir / "keys")

    # 2. Inicializa banco do Servidor de Autorizacao (OpenID Provider)
    op_store = AuthServerStore(instance_dir / "auth_server.sqlite3")
    op_store.initialize()
    op_store.upsert_client(
        client_id=client_id,
        client_secret=client_secret,
        client_name="Aplicacao Cyber Security 33506",
        redirect_uris=[redirect_uri],
        allowed_scopes=["openid", "profile", "email"],
        allowed_grants=["authorization_code"],
    )

    demo_users = [
        {
            "username": admin_username,
            "password": admin_password,
            "sub": "1000000001",
            "full_name": "Administrador (Demo)",
            "email": "admin@unoesc.local",
            "role": "admin",
        },
        {
            "username": user_username,
            "password": user_password,
            "sub": "1000000002",
            "full_name": "Usuario Comum (Demo)",
            "email": "usuario@unoesc.local",
            "role": "user",
        },
    ]

    for u in demo_users:
        op_store.upsert_user(
            username=u["username"],
            password=u["password"],
            sub=u["sub"],
            full_name=u["full_name"],
            email=u["email"],
            role=u["role"],
            email_verified=True,
        )

    # 3. Inicializa banco da Aplicacao Cliente (vinculo estrito por oidc_issuer + oidc_sub)
    client_store = ClientStore(instance_dir / "app.sqlite3")
    client_store.initialize()
    for u in demo_users:
        client_store.upsert_user(
            user_name=u["username"],
            full_name=u["full_name"],
            oidc_issuer=issuer,
            oidc_sub=u["sub"],
            role=u["role"],
        )

    print("Seed concluido com sucesso!")
    print(f"  Issuer:       {issuer}")
    print(f"  Client ID:    {client_id}")
    print(f"  Redirect URI: {redirect_uri}")
    print(f"  Active KID:   {keys.active_kid}")
    print(f"  Usuarios:     {admin_username} (role=admin, sub=1000000001), {user_username} (role=user, sub=1000000002)")


def run_rotate_key(new_kid: str | None) -> None:
    instance_dir = PROJECT_ROOT / "instance"
    keys = KeyManager(instance_dir / "keys")
    created_kid = keys.rotate_key(new_kid=new_kid)
    print(f"Chave RSA rotacionada! Nova chave ativa: {created_kid}")
    print(f"Chaves publicadas em /jwks.json: {', '.join(keys.published_kids)}")


def main() -> None:
    parser = argparse.ArgumentParser(description="Inicializacao do ambiente OAuth 2.0 + OIDC (Opcao 1)")
    parser.add_argument(
        "--rotate-key",
        action="store_true",
        help="Gera uma nova chave RSA ativa mantendo a chave anterior publicada no JWKS.",
    )
    parser.add_argument(
        "--kid",
        default=None,
        help="Identificador opcional (kid) ao usar --rotate-key.",
    )
    args = parser.parse_args()

    if args.rotate_key:
        run_rotate_key(args.kid)
    else:
        run_seed()


if __name__ == "__main__":
    main()
