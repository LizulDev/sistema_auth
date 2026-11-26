# Roteiro de Demonstração ao Vivo (até 10 minutos)

- **Disciplina:** 33506 — Cyber Security (Avaliação A1/3 — OAuth 2.0 + OpenID Connect, Opção 1)
- **Acadêmicos:** Pedro Diniz; Luiz Felipe Kauê da Silva; Domingos Chicanha Fonseca; Wesley Warken
- **Professor:** Odemir Moreira da Mata Junior
- **Data:** 26/11/2026

---

## 0. Preparação (2 minutos antes de começar)

Abra **3 terminais PowerShell** na raiz do repositório `sistema_auth`:

1. **Confirmar ambiente e seed** (Terminal 3):
   ```powershell
   .\.venv\Scripts\python.exe scripts/seed.py
   ```
   > **Atenção:** nunca abra o arquivo `.env` nem mostre senhas/segredos na tela projetada.

2. **Terminal 1 — Servidor de Autorização (OpenID Provider):**
   - Modo HTTPS local (preferencial com `mkcert` já configurado):
     ```powershell
     .\.venv\Scripts\python.exe -m flask --app auth_server run --host 127.0.0.1 --port 8443 --cert cert.pem --key key.pem
     ```
   - Ou modo HTTP local (exceção de desenvolvimento em `localhost`):
     ```powershell
     .\.venv\Scripts\python.exe -m flask --app auth_server run --host 127.0.0.1 --port 8001
     ```

3. **Terminal 2 — Aplicação Cliente (Relying Party):**
   - Modo HTTPS local (configure a CA do `mkcert` no mesmo terminal):
     ```powershell
     $caDir = & .\mkcert.exe -CAROOT
     $env:SSL_CERT_FILE = Join-Path $caDir "rootCA.pem"
     $env:REQUESTS_CA_BUNDLE = $env:SSL_CERT_FILE
     .\.venv\Scripts\python.exe -m flask --app app run --host 127.0.0.1 --port 8444 --cert cert.pem --key key.pem
     ```
   - Ou modo HTTP local:
     ```powershell
     .\.venv\Scripts\python.exe -m flask --app app run --host 127.0.0.1 --port 8000
     ```

4. **Navegador pronto** em aba anônima com DevTools (`F12` → aba **Application/Cookies** e **Network**) e abas abertas para:
   - Aplicação Cliente (`https://localhost:8444` ou `http://localhost:8000`)
   - Discovery (`https://localhost:8443/.well-known/openid-configuration` ou porta `8001`)
   - JWKS (`https://localhost:8443/jwks.json` ou porta `8001`)

---

## 1. Roteiro Cronometrado (Total: 9 min 30 s)

### Bloco 1 — Arquitetura, Discovery e JWKS (`0:00 – 1:30`)
- Apresentar a separação em **dois processos independentes** em Python/Flask/SQLite (sem JS no back-end, renderização 100% server-side):
  - `auth_server/` (OpenID Provider) — único componente que recebe e verifica a senha (Argon2id).
  - `app/` (Relying Party) — nunca vê a senha, valida o ID Token em `RS256` via JWKS e gerencia sessão local.
- Mostrar no navegador:
  - `/.well-known/openid-configuration`: apontar `issuer`, `authorization_endpoint`, `token_endpoint`, `userinfo_endpoint`, `jwks_uri`, `code_challenge_methods_supported: ["S256"]`, `id_token_signing_alg_values_supported: ["RS256"]`.
  - `/jwks.json`: apontar `kty: "RSA"`, `use: "sig"`, `alg: "RS256"`, `kid`, `n` e `e`.

### Bloco 2 — Fluxo Completo Authorization Code + PKCE S256 (`1:30 – 4:15`)
1. Na Aplicação Cliente (`/`), clicar em **Entrar com OpenID Connect** (`/login`).
2. Na barra de endereços do navegador (ou aba **Network**), destacar os parâmetros enviados ao `/authorize`:
   - `response_type=code`, `client_id`, `redirect_uri`, `scope=openid profile email`, `state`, `nonce`, `code_challenge`, `code_challenge_method=S256`.
3. Informar as credenciais de `admin` na tela do **Servidor de Autorização** e aprovar o **consentimento** dos escopos.
4. De volta à Aplicação Cliente (`/`), destacar:
   - **ID Token Decomposto**: cabeçalho (`RS256`, `kid`), payload (todos os claims obrigatórios) e assinatura (256 bytes).
   - **Checklist 4.3 (10/10 OK)** renderizado no servidor e **resposta de `/userinfo`**.
   - **Terminal 2 (log do servidor)**: mostrar a linha `INFO in oidc: ID Token decomposto` e o mascaramento `/callback?[REDACTED]` (não vaza `code` nem `state`).
   - **DevTools → Cookies**: mostrar `session_id` aleatório (256 bits, `HttpOnly`, `SameSite=Lax`, `Secure` em HTTPS) e confirmar que **`localStorage` está vazio** (nenhum JWT exposto ao navegador).
5. Clicar em **Área administrativa (`/admin`)** → **HTTP 200** (`role=admin`).
6. Clicar em **Sair** (`POST /logout` com `csrf_token`) e tentar acessar `/admin` novamente → **HTTP 401**.

### Bloco 3 — Autorização por `role` e Vínculo por `sub` (`4:15 – 5:30`)
1. Fazer novo login usando a conta `usuario` (`role=user`, `sub=1000000002`).
2. Clicar em **Área administrativa (`/admin`)** → mostrar **HTTP 403 Forbidden** aplicado no servidor (`app/routes.py:161-162`).
3. Comentar rapidamente a política adotada quando `sub` não está na tabela local `users`: **recusa explícita (HTTP 403, fail-closed, sem auto-provisionamento)**.

### Bloco 4 — Execução dos 15 Testes Negativos e Demonstrações no Terminal (`5:30 – 8:45`)

No **Terminal 3**, executar a suíte automatizada completa (24 testes — os 15 negativos obrigatórios + 9 testes complementares):

```powershell
# Executar toda a suite de seguranca (24 testes)
.\.venv\Scripts\python.exe -m pytest -v
```

Caso queira destacar apenas os **15 testes negativos obrigatórios da Seção 5**:

```powershell
.\.venv\Scripts\python.exe -m pytest -v -k "test_neg_"
```

Comandos rápidos para executar casos isolados sob demanda do professor:

```powershell
# #1 e #2: alg=none e confusao de algoritmo HS256 com chave publica
.\.venv\Scripts\python.exe -m pytest -v -k "test_neg_01 or test_neg_02"

# #9: reutilizacao de authorization_code + revogacao imediata dos tokens
.\.venv\Scripts\python.exe -m pytest -v -k "test_neg_09"

# #11: redirect_uri com barra extra, parametro extra ou subcaminho
.\.venv\Scripts\python.exe -m pytest -v -k "test_neg_11"

# #12: 1 byte alterado na assinatura RS256
.\.venv\Scripts\python.exe -m pytest -v -k "test_neg_12"

# #15: forca bruta bloqueada por rate limiting (HTTP 429 + Retry-After)
.\.venv\Scripts\python.exe -m pytest -v -k "test_neg_15"
```

*(Opcional, se sobrar 30 segundos)* Demonstrar rapidamente com `curl.exe` contra o servidor ativo (troque `http://localhost:8001` por `https://localhost:8443` no modo HTTPS):

```powershell
# NEG #14: /userinfo sem Bearer token -> HTTP 401 + WWW-Authenticate: Bearer
curl.exe -i http://localhost:8001/userinfo

# NEG #11: /authorize com barra final extra -> HTTP 400 sem header Location
curl.exe -i "http://localhost:8001/authorize?response_type=code&client_id=app-cybersecurity-33506&redirect_uri=http://localhost:8000/callback/&scope=openid%20profile%20email&state=s1&nonce=n1&code_challenge=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa&code_challenge_method=S256"

# Rotacao de chave RSA mantendo a chave anterior no /jwks.json
.\.venv\Scripts\python.exe scripts/seed.py --rotate-key
```

### Bloco 5 — Encerramento e Arguição (`8:45 – 10:00`)
- Resumir as decisões de segurança (RS256 em lista fixa, PKCE S256, Argon2id, TTLs curtos, zero segredos no repositório) e abrir para perguntas.

---

## 2. Perguntas Prováveis da Arguição (Guia Rápido)

1. **Por que usar `RS256` em vez de `HS256`? Como o ataque de confusão de algoritmo funciona (Teste #2)?**  
   No `HS256` (HMAC simétrico), quem verifica a assinatura também pode forjar tokens usando o mesmo segredo. No `RS256` (assimétrico), só o OP possui a chave privada RSA; o cliente valida com a chave pública via `/jwks.json`. No ataque de confusão, o invasor troca o cabeçalho para `alg: "HS256"` e assina usando a própria chave pública RSA (que é pública) como segredo HMAC. Mitigamos isso mantendo uma lista fixa `ALLOWED_ID_TOKEN_ALGORITHMS = ("RS256",)` em `app/oidc.py:20`, nunca escolhendo o algoritmo a partir do cabeçalho recebido (RFC 8725 §3.1).

2. **Qual a diferença entre `id_token` e `access_token`?**  
   O `id_token` é a prova de identidade do usuário para a Aplicação Cliente (contém `aud=client_id`, `nonce`, `sub`, `role` e é validado pelo cliente antes de abrir sessão). O `access_token` é a credencial Bearer para consumir recursos protegidos (`/userinfo`, com `aud=<issuer>/userinfo` e `token_use="access"`). Em `auth_server/routes.py:707`, `/userinfo` exige `token_use == "access"` e `jti` ativo no banco, impedindo o uso indevido de um `id_token` como `access_token`.

3. **Qual a função de `state`, `nonce` e PKCE? Um não substitui o outro?**  
   Não. **`state`** protege o cliente contra **CSRF no callback** (amarra a resposta à sessão do navegador que iniciou `/login`). **`nonce`** protege contra **replay de ID Token** (amarra o ID Token assinado àquela requisição específica). **PKCE (`S256`)** protege contra **interceptação do `authorization_code`** (mesmo que alguém roube o `code`, não consegue trocá-lo em `/token` sem o `code_verifier` original mantido no servidor).

4. **Por que o vínculo do usuário local é feito por `(oidc_issuer, oidc_sub)` e não por e-mail?**  
   Conforme OIDC Core §5.7, e-mails podem mudar ou ser reatribuídos entre usuários, enquanto o par `(iss, sub)` é estável e nunca reatribuído pelo provedor. Em `app/storage.py:24` e `:117-122`, a tabela `users` possui `UNIQUE (oidc_issuer, oidc_sub)` e busca estritamente por esse par; `email` é tratado apenas como dado de exibição quando `email_verified = true`.

5. **O que o sistema faz se o `sub` do ID Token válido não existir na tabela `users`?**  
   Adotamos a política **fail-closed (recusa sem auto-provisionamento)**: em `app/routes.py:121-124`, se `store.find_user(identity)` retornar `None`, a aplicação registra o evento em log, não cria usuário nem sessão e retorna **HTTP 403**. Isso evita criação automática de contas não autorizadas.

6. **O que acontece se o mesmo `authorization_code` for enviado duas vezes ao `/token` (Teste #9)?**  
   O código tem uso único (consumo atômico via `UPDATE ... WHERE used_at IS NULL` em `auth_server/storage.py:501-511`) e TTL máximo de 60s. Na reutilização (`auth_server/routes.py:571-580`), o servidor detecta `used_at IS NOT NULL`, **revoga imediatamente todos os `access_tokens` e `refresh_tokens` daquele `grant_id`** (RFC 6749 §4.1.2) e retorna HTTP 400 `invalid_grant`.

7. **Por que `redirect_uri` com barra final extra ou parâmetro adicional é rejeitada sem redirecionar (Teste #11)?**  
   O RFC 9700 §2.1 exige comparação exata de string (sem curingas, prefixos ou normalização) para evitar vazamento do `code` para rotas vulneráveis a *open redirect*. E o RFC 6749 §4.1.2.1 proíbe redirecionar quando `client_id` ou `redirect_uri` são inválidos, pois isso transformaria `/authorize` em um vetor de redirecionamento aberto.

8. **Por que o `session_id` não é o JWT e por que há rotação no login?**  
   Guardar JWT no navegador ou `localStorage` expõe tokens a XSS e dificulta revogação imediata no logout. Usamos um `session_id` opaco de 256 bits (`secrets.token_urlsafe(32)`) em cookie `HttpOnly`, `SameSite=Lax` (e `Secure` em HTTPS), com expiração de 30 min por inatividade e 8 h absoluta. A rotação no login (`app/storage.py:130-150`, deletando `previous_id`) mitiga *session fixation*.

9. **Como funciona a rotação de chave RSA no `/jwks.json`?**  
   O comando `scripts/seed.py --rotate-key` (`auth_server/keys.py:66-76`) gera um novo par RSA-2048 com novo `kid` e o marca como `active_kid`, mantendo o `kid` anterior na lista `published_kids` do `/jwks.json`. Assim, tokens novos já saem assinados com a nova chave, enquanto tokens ainda vigentes assinados com a chave antiga continuam sendo validados durante a janela de transição.

10. **Por que ROPC (`grant_type=password`) e Implicit (`response_type=token`) são proibidos?**  
    No ROPC, a aplicação cliente recebe e manipula a senha do usuário, violando o princípio de delegação do OAuth 2.0 e ampliando a superfície de ataque (RFC 9700). No Implicit, tokens trafegam no fragmento da URL do navegador, sujeitos a vazamento em histórico, logs e scripts. Ambos são rejeitados explicitamente (`unsupported_grant_type` em `/token` e `invalid_request` em `/authorize`).
