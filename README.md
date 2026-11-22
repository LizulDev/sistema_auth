# Autenticação e Autorização — OAuth 2.0 + OpenID Connect (Opção 1)

Implementação completa em **Python + Flask + SQLite** para a Avaliação A1/3 de Cyber Security (33506 — UNOESC, 2026), utilizando a **Opção 1**: **Servidor de Autorização próprio (OpenID Provider)** + **Aplicação Cliente (Relying Party)** com fluxo **Authorization Code (RFC 6749)**, **PKCE S256 (RFC 7636)** e **OpenID Connect Core 1.0**.

> **Zero JavaScript no back-end e renderização 100% no servidor**: tokens nunca são expostos a scripts ou `localStorage`.

---

## Arquitetura

| Componente | Pacote | Porta padrão | Responsabilidade |
| --- | --- | --- | --- |
| **Servidor de Autorização (OpenID Provider)** | `auth_server/` | `8001` | Descoberta OIDC, publicação de chaves RSA (JWKS), autenticação de usuários (Argon2id + rate limiting), consentimento explícito, emissão de `authorization_code` (TTL <= 60s), troca `/token` (RS256), `/userinfo` (Bearer) e `/logout`. |
| **Aplicação Cliente (Relying Party)** | `app/` | `8000` | Geração de `state`, `nonce` e PKCE `S256`, callback protegido, descoberta OIDC, troca única do código (sem retry), decomposição e validação completa do ID Token (checklist 4.3), vínculo por `(oidc_issuer, oidc_sub)`, sessão local segura e autorização por `role` em `/admin`. |

### Estrutura de arquivos

```text
├── app/                         # Aplicação Cliente (Relying Party)
│   ├── __init__.py              # Fábrica Flask, política TLS, headers e máscara de logs de /callback
│   ├── config.py                # Configurações OIDC via variáveis de ambiente
│   ├── oidc.py                  # Descoberta, PKCE S256, troca /token, decomposição e validação do ID Token
│   ├── routes.py                # /, /login, /callback, /admin (role=admin), /logout
│   ├── storage.py               # SQLite: users (iss+sub), pending_authorizations, sessions
│   └── templates/               # HTML renderizado no servidor (index.html, admin.html)
├── auth_server/                 # Servidor de Autorização próprio (OpenID Provider)
│   ├── __init__.py              # Fábrica Flask, política TLS, headers e proteção de logs
│   ├── config.py                # Configurações do provedor (issuer, TTLs, rate limit)
│   ├── keys.py                  # Geração de chaves RSA em instance/, assinatura RS256, JWKS e rotação
│   ├── routes.py                # /.well-known/openid-configuration, /jwks.json, /authorize, /token, /userinfo, /logout
│   ├── storage.py               # SQLite: op_users (Argon2id), oauth_clients, codes, tokens, revogação, rate limit
│   └── templates/               # HTML renderizado no servidor (index, login, consent, error)
├── scripts/seed.py              # Inicialização de cliente OAuth e usuários de demonstração (admin e user)
├── tests/test_security_suite.py # Suíte pytest cobrindo os 15 testes negativos obrigatórios + fluxos E2E
├── docs/postman_collection.json # Coleção Postman v2.1 de todos os endpoints
├── .env.example                 # Modelo de variáveis de ambiente (sem segredos reais)
└── requirements.txt             # Dependências Python
```

---

## Política de segredos

Nunca versione `.env`, `client_secret`, chaves privadas RSA (`*.pem`, `*.key`), bancos SQLite (`*.sqlite3`), `instance/` ou `.venv/`. Todos estão bloqueados em `.gitignore`.

---

## Como executar localmente (HTTP em `localhost`)

Requer **Python 3.11+** e **SQLite 3.35+**. No PowerShell, a partir da raiz do projeto:

### 1. Criar ambiente virtual e instalar dependências

```powershell
python -m venv .venv
./.venv/Scripts/python.exe -m pip install -r requirements.txt
```

### 2. Configurar variáveis de ambiente locais

Copie `.env.example` para `.env` e defina valores fortes para `OIDC_CLIENT_SECRET`, `SEED_ADMIN_PASSWORD` e `SEED_USER_PASSWORD`:

```powershell
Copy-Item .env.example .env
```

### 3. Executar o seed (inicializa bancos, chave RSA em `instance/keys/` e usuários demo)

```powershell
./.venv/Scripts/python.exe scripts/seed.py
```

Para demonstrar **rotação de chave RSA** mantendo a chave anterior publicada em `/jwks.json`:

```powershell
./.venv/Scripts/python.exe scripts/seed.py --rotate-key
```

### 4. Subir os dois servidores (em terminais separados)

**Terminal 1 — Servidor de Autorização (porta 8001):**

```powershell
$env:ALLOW_LOCAL_HTTP = 'true'
./.venv/Scripts/python.exe -m flask --app auth_server run --host 127.0.0.1 --port 8001
```

**Terminal 2 — Aplicação Cliente (porta 8000):**

```powershell
$env:ALLOW_LOCAL_HTTP = 'true'
./.venv/Scripts/python.exe -m flask --app app run --host 127.0.0.1 --port 8000
```

Acesse:
- Aplicação Cliente: [http://localhost:8000](http://localhost:8000)
- Servidor de Autorização: [http://localhost:8001](http://localhost:8001)
- Discovery: [http://localhost:8001/.well-known/openid-configuration](http://localhost:8001/.well-known/openid-configuration)
- JWKS: [http://localhost:8001/jwks.json](http://localhost:8001/jwks.json)

---

## Como executar com HTTPS (TLS)

Ambas as aplicações exigem HTTPS por padrão (`ALLOW_LOCAL_HTTP=false`). Para rodar com TLS local:

1. No `.env`, defina `ALLOW_LOCAL_HTTP=false` e atualize `OIDC_ISSUER`, `AUTH_SERVER_ISSUER`, `OIDC_AUTHORIZATION_ENDPOINT` e `OIDC_REDIRECT_URI` para `https://...`.
2. Reexecute `./.venv/Scripts/python.exe scripts/seed.py` para cadastrar a `redirect_uri` HTTPS exata.
3. Inicie ambos os servidores informando `--cert` e `--key` (ex.: certificados gerados com `mkcert` ou OpenSSL):

```powershell
./.venv/Scripts/python.exe -m flask --app auth_server run --host 127.0.0.1 --port 8443 --cert cert.pem --key key.pem
./.venv/Scripts/python.exe -m flask --app app run --host 127.0.0.1 --port 8444 --cert cert.pem --key key.pem
```

Em conexões HTTPS, todos os cookies de sessão e fluxo recebem automaticamente o atributo `Secure` (além de `HttpOnly` e `SameSite=Lax`).

---

## Variáveis de ambiente

| Variável | Componente | Uso |
| --- | --- | --- |
| `ALLOW_LOCAL_HTTP` | Ambos | Com `true`, libera HTTP apenas em `localhost`/`127.0.0.1` para desenvolvimento. |
| `OIDC_ISSUER` | Cliente | Emissor esperado e base da descoberta (`/.well-known/openid-configuration`). |
| `OIDC_AUTHORIZATION_ENDPOINT` | Cliente | Endpoint de autorização (opcional; descoberto automaticamente se omitido). |
| `OIDC_CLIENT_ID` | Cliente | Identificador da aplicação cadastrado no provedor. |
| `OIDC_CLIENT_SECRET` | Cliente | Segredo do cliente usado na autenticação em `/token`. |
| `OIDC_REDIRECT_URI` | Cliente | URI absoluta exata do callback (`/callback`). |
| `OIDC_HTTP_TIMEOUT` | Cliente | Timeout explícito (segundos) nas chamadas HTTP ao provedor (sem retry). |
| `OIDC_CLOCK_SKEW_SECONDS` | Cliente | Tolerância máxima de relógio (padrão `60`s) para `exp` e `iat`. |
| `AUTH_SERVER_ISSUER` | Provedor | Identificador `iss` publicado na descoberta e em todos os tokens emitidos. |
| `AUTH_SERVER_CODE_TTL` | Provedor | Validade do `authorization_code` em segundos (máximo `60`). |
| `AUTH_SERVER_TOKEN_TTL` | Provedor | Validade do `id_token` e `access_token` em segundos (padrão `900`). |
| `AUTH_SERVER_REFRESH_TTL` | Provedor | Validade do `refresh_token` em segundos (padrão `86400`). |
| `AUTH_SERVER_RATE_LIMIT_MAX` | Provedor | Máximo de tentativas de login falhas por janela antes do HTTP `429`. |
| `AUTH_SERVER_RATE_LIMIT_WINDOW` | Provedor | Janela do rate limiting em segundos (padrão `300`). |

---

## Decisões de segurança (Checklist 4.3 & RFCs)

- **Vínculo de identidade (OIDC Core §5.7)**: os usuários locais na tabela `users` são vinculados exclusivamente por `(oidc_issuer, oidc_sub)` — nunca por e-mail ou nome. Identidades não cadastradas previamente são recusadas com HTTP `403`.
- **Assinatura e algoritmo (RFC 8725 §2.1, §3.1)**: o cliente mantém lista fixa `ALLOWED_ID_TOKEN_ALGORITHMS = ("RS256",)`. Tokens com `alg="none"` ou `HS256` (mesmo assinados com os bytes da chave pública) são sempre rejeitados.
- **PKCE S256 (RFC 7636) e `redirect_uri` exata (RFC 9700 §2.1)**: o provedor rejeita `code_challenge_method=plain`, exige comparação exata de string em `redirect_uri` (sem redirecionar em erro — RFC 6749 §4.1.2.1) e revoga todos os tokens emitidos caso um `authorization_code` seja reutilizado.
- **Proteção de logs**: a query string de `/callback` é mascarada automaticamente nos logs de acesso do Werkzeug (`/callback?[REDACTED]`) para impedir vazamento de `code` e `state`.
- **Autorização por `role`**: após a validação criptográfica do ID Token, o perfil (`admin` ou `user`) é aplicado e revalidado no servidor em cada acesso à rota `/admin` (`200` para `admin`, `403` para `user`, `401` sem sessão).

---

## Executar os testes automatizados (incluindo os 15 testes negativos)

```powershell
./.venv/Scripts/python.exe -m pytest -v
```

A suíte `tests/test_security_suite.py` cobre todos os **15 testes negativos obrigatórios** da seção 5 do enunciado, além de fluxos ponta a ponta (login `admin`, login `user`, rotação de chaves JWKS, recusa de consentimento, `client_secret_basic`, headers `Cache-Control: no-store`, máscara de logs e política HTTPS).

## Coleção de requisições

Importe [`docs/postman_collection.json`](docs/postman_collection.json) no Postman ou Insomnia para testar todos os endpoints do provedor e do cliente.
