# Autenticação e Autorização — OAuth 2.0 + OpenID Connect

Projeto em **Python, Flask e SQLite** para a Avaliação A1/3 de Cyber Security — 33506, UNOESC, 2026.

Implementa a **Opção 1**: servidor de autorização próprio (OpenID Provider) e aplicação cliente (Relying Party), com Authorization Code, PKCE S256 e OpenID Connect.

As páginas são renderizadas no servidor. Os tokens são processados no backend, sem armazenamento em `localStorage`.

## Arquitetura

| Componente | Pacote | HTTP local | HTTPS local | Responsabilidade |
|---|---|---|---|---|
| Servidor de autorização | `auth_server/` | `8001` | `8443` | Login, consentimento, descoberta OIDC, JWKS, emissão de tokens, userinfo e logout |
| Aplicação cliente | `app/` | `8000` | `8444` | Início do login, callback, validação do ID Token, sessão local e autorização |

Principais arquivos:

- `app/config.py`: configurações OIDC da aplicação cliente.
- `app/oidc.py`: descoberta, PKCE, troca do código e validação do ID Token.
- `app/routes.py`: rotas da aplicação cliente.
- `app/storage.py`: usuários locais, autorizações pendentes e sessões.
- `auth_server/`: implementação do provedor OIDC.
- `scripts/seed.py`: cadastro do cliente OAuth e dos usuários de demonstração.
- `tests/test_security_suite.py`: testes automatizados.
- `docs/postman_collection.json`: coleção de requisições.
- `docs/relatorio.pdf`: relatório técnico da avaliação (fonte em `docs/relatorio.html`).
- `docs/roteiro-demo.md`: roteiro para a demonstração ao vivo.
- `.env.example`: modelo de configuração sem segredos reais.
- `instance/`: bancos e chaves gerados localmente.

## Requisitos

- Python 3.11 ou superior.
- SQLite 3.35 ou superior.
- PowerShell para executar os comandos deste guia.
- mkcert para a configuração HTTPS local.

O servidor iniciado por `flask run` destina-se ao desenvolvimento local.

## 1. Preparar o ambiente

Execute os comandos na raiz de `sistema_auth`:

```powershell
python -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
```

Na primeira configuração, copie o modelo:

```powershell
Copy-Item .env.example .env
```

Não sobrescreva um `.env` já configurado.

Gere um segredo para a aplicação:

```powershell
.\.venv\Scripts\python.exe -c "import secrets; print(secrets.token_urlsafe(48))"
```

Copie o resultado para `OIDC_CLIENT_SECRET` no `.env`. Defina também senhas próprias:

```env
OIDC_CLIENT_ID=app-cybersecurity-33506
OIDC_CLIENT_SECRET=SUBSTITUA_PELO_SEGREDO_GERADO

SEED_ADMIN_USERNAME=admin
SEED_ADMIN_PASSWORD=SUBSTITUA_POR_UMA_SENHA_FORTE

SEED_USER_USERNAME=usuario
SEED_USER_PASSWORD=SUBSTITUA_POR_OUTRA_SENHA_FORTE
```

Os valores acima são marcadores e precisam ser substituídos.

O `OIDC_CLIENT_SECRET` autentica a aplicação perante o provedor. Ele não é a senha utilizada no formulário de login.

## 2. Escolher HTTP ou HTTPS

Use uma configuração completa e consistente.

| Variável | HTTP local | HTTPS local |
|---|---|---|
| `ALLOW_LOCAL_HTTP` | `true` | `false` |
| `OIDC_ISSUER` | `http://localhost:8001` | `https://localhost:8443` |
| `AUTH_SERVER_ISSUER` | `http://localhost:8001` | `https://localhost:8443` |
| `OIDC_AUTHORIZATION_ENDPOINT` | `http://localhost:8001/authorize` | `https://localhost:8443/authorize` |
| `OIDC_REDIRECT_URI` | `http://localhost:8000/callback` | `https://localhost:8444/callback` |

O protocolo, o host, a porta e o caminho do callback devem corresponder exatamente ao cadastro do cliente OAuth.

Use `localhost` de forma consistente nas URLs do navegador e nas configurações.

### Variáveis antigas no PowerShell

Variáveis definidas com `$env:` pertencem à sessão do terminal e podem prevalecer sobre o `.env`.

Após salvar a configuração no `.env`, execute o bloco abaixo em cada terminal que será usado para iniciar os servidores:

```powershell
$nomesConfiguracao = @(
    "ALLOW_LOCAL_HTTP",
    "OIDC_ISSUER",
    "AUTH_SERVER_ISSUER",
    "OIDC_AUTHORIZATION_ENDPOINT",
    "OIDC_REDIRECT_URI",
    "OIDC_CLIENT_ID",
    "OIDC_CLIENT_SECRET",
    "SEED_ADMIN_USERNAME",
    "SEED_ADMIN_PASSWORD",
    "SEED_USER_USERNAME",
    "SEED_USER_PASSWORD"
)

foreach ($nomeConfiguracao in $nomesConfiguracao) {
    Remove-Item -LiteralPath "Env:$nomeConfiguracao" -ErrorAction SilentlyContinue
}
```

Isso remove as sobrescritas da sessão atual, permitindo carregar os valores do `.env`.

Sempre reinicie os servidores após alterar a configuração.

## 3. Executar o seed

Com o `.env` salvo:

```powershell
.\.venv\Scripts\python.exe scripts/seed.py
```

O script inicializa:

- Chaves RSA em `instance/keys/`.
- Banco do provedor em `instance/auth_server.sqlite3`.
- Banco da aplicação em `instance/app.sqlite3`.
- Cliente OAuth e callback autorizado.
- Usuários de demonstração.

Aguarde a mensagem:

```text
Seed concluido com sucesso!
```

Confira o issuer e o callback impressos antes de continuar.

Para demonstrar a rotação de chave RSA:

```powershell
.\.venv\Scripts\python.exe scripts/seed.py --rotate-key
```

### Banco existente após mudança do issuer

O vínculo local usa o par `(oidc_issuer, oidc_sub)`.

Mudar de `http://localhost:8001` para `https://localhost:8443` altera esse vínculo. Em bancos existentes, o seed pode apresentar:

```text
UNIQUE constraint failed: users.user_name
```

Nesse caso:

1. Pare os servidores.
2. Faça backup dos bancos.
3. Migre explicitamente os vínculos do mesmo provedor local para o novo issuer.
4. Preserve os valores de `oidc_sub`.
5. Execute novamente o seed.

Não vincule automaticamente identidades pelo nome de usuário ou e-mail. Não apague o banco para contornar o erro sem avaliar os dados existentes.

## 4. Executar com HTTP local

No `.env`, configure:

```env
ALLOW_LOCAL_HTTP=true
OIDC_ISSUER=http://localhost:8001
AUTH_SERVER_ISSUER=http://localhost:8001
OIDC_AUTHORIZATION_ENDPOINT=http://localhost:8001/authorize
OIDC_REDIRECT_URI=http://localhost:8000/callback
```

Execute o seed e inicie os servidores em terminais separados.

Terminal 1 — provedor:

```powershell
.\.venv\Scripts\python.exe -m flask --app auth_server run --host 127.0.0.1 --port 8001
```

Terminal 2 — aplicação cliente:

```powershell
.\.venv\Scripts\python.exe -m flask --app app run --host 127.0.0.1 --port 8000
```

Endereços:

- Aplicação: http://localhost:8000
- Provedor: http://localhost:8001
- Descoberta: http://localhost:8001/.well-known/openid-configuration
- JWKS: http://localhost:8001/jwks.json

A exceção HTTP é destinada apenas ao desenvolvimento local.

## 5. Executar com HTTPS local

### 5.1. Gerar o certificado

Obtenha o executável adequado ao Windows nas versões oficiais:

https://github.com/FiloSottile/mkcert/releases

Os comandos abaixo consideram `mkcert.exe` na raiz do projeto.

Instale a autoridade certificadora local:

```powershell
.\mkcert.exe -install
```

Gere o certificado e a chave:

```powershell
.\mkcert.exe -cert-file cert.pem -key-file key.pem localhost 127.0.0.1 ::1
```

Serão criados:

- `cert.pem`: certificado TLS.
- `key.pem`: chave privada TLS.

Se o mkcert confirmar a instalação no Windows e apresentar erro apenas no `keytool` do Java, essa etapa adicional não é necessária para a aplicação Flask.

### 5.2. Configurar o `.env`

```env
ALLOW_LOCAL_HTTP=false
OIDC_ISSUER=https://localhost:8443
AUTH_SERVER_ISSUER=https://localhost:8443
OIDC_AUTHORIZATION_ENDPOINT=https://localhost:8443/authorize
OIDC_REDIRECT_URI=https://localhost:8444/callback
```

Remova sobrescritas antigas do terminal conforme a seção 2 e execute o seed:

```powershell
.\.venv\Scripts\python.exe scripts/seed.py
```

### 5.3. Iniciar o provedor

Em um terminal na raiz do projeto:

```powershell
.\.venv\Scripts\python.exe -m flask --app auth_server run --host 127.0.0.1 --port 8443 --cert cert.pem --key key.pem
```

Mantenha esse terminal aberto.

### 5.4. Configurar a confiança TLS do cliente

Em outro terminal, na raiz do projeto:

```powershell
$caDir = & .\mkcert.exe -CAROOT
$env:SSL_CERT_FILE = Join-Path $caDir "rootCA.pem"
$env:REQUESTS_CA_BUNDLE = $env:SSL_CERT_FILE
```

`SSL_CERT_FILE` é utilizado por clientes que respeitam essa configuração do OpenSSL. `REQUESTS_CA_BUNDLE` atende ao Requests, caso essa biblioteca seja utilizada.

Essas variáveis valem para o terminal atual. Clientes que configuram seu próprio contexto TLS podem exigir o caminho da autoridade explicitamente no código.

Não desative a verificação do certificado.

### 5.5. Testar a conexão pelo Python

Com o provedor ativo:

```powershell
@'
import json
import os
import ssl
import urllib.request

context = ssl.create_default_context(
    cafile=os.environ["SSL_CERT_FILE"]
)

url = "https://localhost:8443/.well-known/openid-configuration"

with urllib.request.urlopen(url, context=context, timeout=5) as response:
    data = json.load(response)
    print("HTTP:", response.status)
    print("Issuer:", data["issuer"])
'@ | .\.venv\Scripts\python.exe -
```

Resultado esperado:

```text
HTTP: 200
Issuer: https://localhost:8443
```

Esse teste usa a biblioteca padrão e não exige instalar Requests.

### 5.6. Iniciar a aplicação cliente

No mesmo terminal em que configurou a confiança TLS:

```powershell
.\.venv\Scripts\python.exe -m flask --app app run --host 127.0.0.1 --port 8444 --cert cert.pem --key key.pem
```

Endereços:

- Aplicação: https://localhost:8444
- Provedor: https://localhost:8443
- Descoberta: https://localhost:8443/.well-known/openid-configuration
- JWKS: https://localhost:8443/jwks.json

Antes do login, confirme que a aplicação mostra:

```text
Provedor (Issuer): https://localhost:8443
```

Em HTTPS, os cookies de sessão e fluxo recebem `Secure`, além de `HttpOnly` e `SameSite=Lax`, conforme a implementação do projeto.

## 6. Realizar o login

1. Abra a aplicação cliente.
2. Clique em **Entrar com OpenID Connect**.
3. No provedor, informe o usuário e a senha cadastrados pelo seed.
4. Confirme o consentimento, quando solicitado.
5. Aguarde o retorno à aplicação cliente.

| Perfil | Usuário configurado em | Senha configurada em |
|---|---|---|
| Administrador | `SEED_ADMIN_USERNAME` | `SEED_ADMIN_PASSWORD` |
| Usuário comum | `SEED_USER_USERNAME` | `SEED_USER_PASSWORD` |

Os nomes padrão são `admin` e `usuario`. As senhas são definidas localmente.

Alterar a senha no `.env` não altera imediatamente o banco: execute o seed com sucesso para atualizar o cadastro.

Após o retorno, a aplicação troca o código por tokens, valida o ID Token, localiza o usuário por issuer e sub e cria a sessão local.

## Variáveis de ambiente

| Variável | Uso |
|---|---|
| `ALLOW_LOCAL_HTTP` | Libera HTTP local quando `true` |
| `OIDC_ISSUER` | Emissor esperado pela aplicação cliente |
| `OIDC_AUTHORIZATION_ENDPOINT` | Endpoint de autorização; pode ser descoberto quando omitido, conforme a implementação |
| `OIDC_CLIENT_ID` | Identificador do cliente OAuth |
| `OIDC_CLIENT_SECRET` | Credencial da aplicação para o endpoint de tokens |
| `OIDC_REDIRECT_URI` | Endereço exato do callback |
| `OIDC_HTTP_TIMEOUT` | Timeout das chamadas ao provedor; padrão de 5 segundos |
| `OIDC_CLOCK_SKEW_SECONDS` | Tolerância de relógio; padrão de 60 segundos |
| `AUTH_SERVER_ISSUER` | Issuer publicado pelo provedor |
| `AUTH_SERVER_CODE_TTL` | Validade do código; máximo de 60 segundos |
| `AUTH_SERVER_TOKEN_TTL` | Validade dos tokens; padrão de 900 segundos |
| `AUTH_SERVER_REFRESH_TTL` | Validade configurada do refresh token; padrão de 86400 segundos |
| `AUTH_SERVER_RATE_LIMIT_MAX` | Limite de tentativas de login falhas por janela |
| `AUTH_SERVER_RATE_LIMIT_WINDOW` | Janela do limite; padrão de 300 segundos |
| `SEED_ADMIN_USERNAME` | Nome do administrador de demonstração |
| `SEED_ADMIN_PASSWORD` | Senha do administrador de demonstração |
| `SEED_USER_USERNAME` | Nome do usuário comum de demonstração |
| `SEED_USER_PASSWORD` | Senha do usuário comum de demonstração |
| `SSL_CERT_FILE` | Caminho local da autoridade certificadora para clientes TLS compatíveis |
| `REQUESTS_CA_BUNDLE` | Caminho da autoridade certificadora para Requests, quando utilizado |

A emissão de um refresh token não implica, por si só, suporte ao grant `refresh_token`. Consulte os grants anunciados na descoberta.

## Solução de problemas

| Problema | Verificação |
|---|---|
| `ERR_CONNECTION_REFUSED` | Confirme que o servidor está ativo na porta e no protocolo configurados |
| Página mostra issuer HTTP durante uso de HTTPS | Revise o `.env`, as variáveis do terminal e reinicie a aplicação |
| `Credenciais inválidas` | Use as credenciais da última execução bem-sucedida do seed |
| HTTP `429` | Aguarde o fim da janela de limitação de tentativas |
| `UNIQUE constraint failed: users.user_name` | Verifique se houve mudança de issuer e migre os vínculos existentes |
| Falha de rede na descoberta OIDC | Teste o endpoint pelo Python e confira a confiança TLS |
| Issuer da descoberta divergente | Alinhe `OIDC_ISSUER` e `AUTH_SERVER_ISSUER` |
| Callback não autorizado | Confira o endereço exato e execute o seed |
| Porta ocupada | Encerre a instância anterior antes de iniciar outro servidor |

Para conferir o issuer recebido pelo Python:

```powershell
.\.venv\Scripts\python.exe -c "import os; print(os.getenv('OIDC_ISSUER'))"
```

Esse comando mostra apenas a variável do processo; não carrega o `.env`.

Após uma falha no callback, comece uma nova tentativa pela página inicial. Não reutilize a URL anterior, pois o código é temporário e de uso único.

## Decisões de segurança

- Identidade local vinculada por `(oidc_issuer, oidc_sub)`.
- ID Tokens aceitos apenas com o algoritmo permitido `RS256`.
- Validação de assinatura e dos claims exigidos pelo fluxo OIDC.
- Uso de `state`, `nonce` e PKCE S256.
- Comparação exata do callback cadastrado.
- Códigos temporários e de uso único.
- Senhas protegidas com Argon2id.
- Limitação de tentativas de autenticação.
- Autorização por perfil verificada no servidor.
- Mascaramento da query string de `/callback` nos logs de acesso.
- Tokens processados no backend.

Referências: RFC 6749, RFC 7636, RFC 8725, RFC 9700 e OpenID Connect Core 1.0.

## Testes automatizados

Execute:

```powershell
.\.venv\Scripts\python.exe -m pytest -v
```

A suíte está em `tests/test_security_suite.py`. Confira os resultados para verificar a cobertura dos testes negativos e dos fluxos previstos na avaliação.

Valide também manualmente:

- Login de administrador e usuário comum.
- Rejeição de senha incorreta.
- Acesso permitido ou negado conforme o perfil.
- Logout.
- Login completo por HTTPS.
- Reexecução do seed sem duplicidades na mesma configuração.

## Coleção de requisições

Importe [docs/postman_collection.json](docs/postman_collection.json) no Postman ou em ferramenta compatível.

## Antes de enviar ao GitHub

Não versione:

- `.env` e credenciais reais.
- `.venv/`.
- `instance/`, bancos e backups locais.
- Chaves privadas RSA ou TLS.
- Certificados locais e arquivos da autoridade do mkcert.
- Executável local `mkcert.exe`.
- Logs contendo dados sensíveis.

Mantenha `.env.example` com marcadores, sem segredos reais.

Revise:

```powershell
git status
git diff
git diff --cached
git diff --check
```

Confira se arquivos locais já estão rastreados:

```powershell
git ls-files .env instance cert.pem key.pem rootCA.pem rootCA-key.pem "mkcert*.exe"
```

O `.gitignore` não remove arquivos já rastreados. Se necessário, use `git rm --cached` somente nos caminhos identificados, preservando os arquivos locais.

Execute os testes e revise os arquivos preparados antes do commit. Credenciais expostas devem ser substituídas, mesmo após sua remoção do código.