# Autenticação e autorização com OAuth 2.0 e OpenID Connect

Esqueleto em Python para a avaliação A1/3 de Cyber Security (33506, 2026). Este repositório contém a base da aplicação cliente (Relying Party), comum ao provedor próprio da opção 1 e ao Google da opção 2. A escolha do provedor continua aberta.

## Executar localmente

Requer Python 3.11 ou superior e SQLite 3.35 ou superior, usado pelo módulo `sqlite3` do Python. No PowerShell, execute a partir da raiz do projeto.

```powershell
python -m venv .venv
./.venv/Scripts/python.exe -m pip install -r requirements.txt
Copy-Item .env.example .env
$env:ALLOW_LOCAL_HTTP = 'true'
./.venv/Scripts/python.exe -m flask --app app run --host 127.0.0.1 --port 8000
```

Abra [http://localhost:8000](http://localhost:8000). A primeira execução cria `instance/app.sqlite3`. Sem configuração do provedor, a página inicial abre, `GET /login` retorna `503`, `GET /callback` sem fluxo iniciado retorna `400` e `GET /admin` sem sessão retorna `401`. O Flask CLI carrega `.env` por meio de `python-dotenv`. Variáveis definidas no shell têm precedência.

Em uma execução HTTPS, deixe `ALLOW_LOCAL_HTTP=false` e use uma URI de callback HTTPS que corresponda exatamente ao cadastro no provedor. Com TLS no próprio Flask para desenvolvimento, forneça `--cert` e `--key` com os caminhos do certificado e da chave. As rotas exigem HTTPS por padrão e os cookies de uma conexão HTTPS têm o atributo `Secure`.

| Variável | Uso |
| --- | --- |
| `OIDC_ISSUER` | Emissor esperado e ponto de partida para a futura descoberta OIDC. |
| `OIDC_AUTHORIZATION_ENDPOINT` | Destino do redirecionamento de login, configurado manualmente no esqueleto. |
| `OIDC_CLIENT_ID` | Identificador cadastrado no provedor. |
| `OIDC_CLIENT_SECRET` | Segredo do cliente, lido do ambiente para uso futuro na troca do código. |
| `OIDC_REDIRECT_URI` | URI absoluta e exata do callback, incluindo a porta quando aplicável. |
| `ALLOW_LOCAL_HTTP` | Com `true`, permite HTTP apenas para desenvolvimento local em `localhost` ou `127.0.0.1`. |

## Estrutura e decisões

| Módulo | Responsabilidade |
| --- | --- |
| `app/__init__.py` | Fábrica Flask, inicialização do banco e política de transporte e cache. |
| `app/config.py` | Configuração do cliente OIDC pelo ambiente e checagem das URLs. |
| `app/oidc.py` | Geração de `state`, `nonce` e PKCE `S256`, montagem da URL e ponto de integração `authenticate()`. |
| `app/storage.py` | Tabelas SQLite, consumo único da tentativa de login e persistência de usuários e sessões. |
| `app/routes.py` | Login, callback, autorização da área administrativa e logout. |
| `app/templates/` | Páginas HTML renderizadas no servidor. |

1. `GET /login` gera `state`, `nonce` e `code_verifier` com 256 bits de aleatoriedade. O banco guarda esses dados por até cinco minutos. Um cookie com identificador aleatório vincula o navegador à tentativa. A requisição ao provedor usa `response_type=code`, `S256` e os escopos `openid profile email`.
2. `GET /callback` consome a tentativa uma única vez e confere `state` antes de chamar `authenticate()`. O callback válido retorna `501` enquanto a troca do código e a validação do ID Token estiverem pendentes. Erros do provedor recebem uma mensagem genérica e o log registra apenas o tipo de evento.
3. O caminho de sucesso espera uma identidade verificada. O cadastro local será prévio e o callback recusa identidades desconhecidas com `403`. A chave única do vínculo combina `oidc_issuer` e `oidc_sub`, conforme a regra de identidade `iss` + `sub` do item 1.2. O campo `user_name` é único e serve para exibição.
4. A sessão guarda o ID interno do usuário no servidor e recebe um identificador novo após o login. Ela expira após 30 minutos de inatividade ou oito horas no total. `POST /logout` valida um token CSRF e invalida a sessão no banco. `GET /admin` consulta o papel local a cada acesso e devolve `403` para um usuário autenticado com `role=user`. O papel local é a base para a integração com Google. Para a opção 1, resta definir como o `role` do ID Token validado será aplicado ao cadastro local.

## Verificações realizadas no esqueleto

Validação local com Python 3.13 e o cliente de teste do Flask. O resultado de PKCE correspondeu ao vetor do apêndice B da RFC 7636. O callback rejeitou `state` divergente antes de chamar a integração e rejeitou a repetição de uma tentativa consumida. Uma identidade fictícia fornecida pelo teste permitiu verificar a rotação, a expiração e a invalidação da sessão, a proteção CSRF do logout e a mudança da resposta de `/admin` de `403` para `200` após atualizar o perfil no banco. A integração real com um provedor e a validação criptográfica seguem pendentes.

## Continuação da avaliação

- Completar `authenticate()` com descoberta do emissor configurado, troca do código com timeout e sem repetição automática, e validação do ID Token com JWKS e lista fixa `RS256`. `httpx` pode atender as chamadas HTTP e `PyJWT[crypto]` pode verificar o JWT. O retorno deve conter apenas uma identidade cuja assinatura e claims foram verificados.
- Usar o checklist do item 4.3 para registrar as verificações de `kid` e assinatura, algoritmo, `iss`, `aud`, `azp`, `exp`, `iat` e `nonce`, e a busca local por `sub`. Se houver chamada a UserInfo, conferir também que seu `sub` é o mesmo do ID Token. Tratar o access token como credencial Bearer, independentemente do formato.
- Se o grupo optar pelo Google, cadastrar o cliente web e a URI de callback no Google Cloud. Se optar pelo provedor próprio, construir um segundo serviço Python para Discovery, `/authorize`, `/token`, `/userinfo`, JWKS e logout, além de autenticação, consentimento e proteção do formulário. `argon2-cffi` é uma opção para hash de senhas no provedor próprio.
- Produzir as evidências do item 5 em ambiente controlado, incluindo o `400` por falha de `state`, o `403` em `/admin` com perfil comum e as rejeições do validador de tokens assim que estiver implementado. Para o relatório, guardar o diagrama do fluxo, a justificativa de algoritmo e prazos, as três partes de um ID Token de demonstração com dados fictícios e a coleção de requisições dos endpoints efetivamente implementados. Configurar os logs de acesso para omitir a query do callback antes de usar credenciais reais.

## Referências

- Geração do verificador e desafio PKCE. [RFC 7636, seção 4](https://www.rfc-editor.org/rfc/rfc7636.html#section-4)
- Validação do ID Token e vínculo da identidade. [OpenID Connect Core 1.0](https://openid.net/specs/openid-connect-core-1_0.html)
- Execução da fábrica Flask e carregamento de variáveis de ambiente. [Flask CLI](https://flask.palletsprojects.com/en/stable/cli/)
