# A01 · 认证中心侧注册 client

> 加载时机：阶段 1 动手前。以及任何"授权页报 `invalid_redirect_uri` / `unauthorized_client`"排查时。

## 认证中心暴露的全部端点

以 issuer 为前缀（当前线上 issuer = `http://47.110.80.47:8082`，**执行前必须实测确认**，见下）：

| 端点 | 用途 |
| --- | --- |
| `GET /.well-known/openid-configuration` | 发现文档；`issuer` 字段是判定"地址填对没有"的唯一依据 |
| `GET /.well-known/jwks.json` | RS256 公钥集，`kid=idp-key-1` |
| `GET /oauth2/auth` | 授权端点（浏览器 302）。注意**不是** `/authorize` |
| `POST /oauth2/token` | 令牌端点（表单）。`grant_type` 支持 `authorization_code` / `refresh_token`。**认证中心提供 `refresh_token` 不等于客户端该持有它**——按 A02"会话与续期"，业务侧拿到后应就地丢弃 |
| `GET /oauth2/userinfo` | Bearer 可走 header 或 `?access_token=` |
| `POST /oauth2/revoke` | RFC 7009 |
| `GET /oauth2/logout` | RP 发起登出；按 `idp_session` 销毁会话，`id_token_hint` 收了但不参与判定 |
| `POST /api/login` `GET /api/me` `POST /api/logout` `POST /api/register` | 认证中心自己的 SPA 接口 |
| `GET/POST /api/consent` | 授权确认页；**POST 才是签发授权码的地方** |
| `POST /api/admin/clients` 等 | 管理端，需管理员会话 |

三条容易踩的格式事实：

- **`/api/consent` 返回裸 `{"redirect_to": "..."}`，没有 `{code,data}` 信封。** 按统一信封去取
  `.data.redirect_to` 会拿到 undefined，误判成"认证中心没发码"。两种形状都要吃。
- `response_type` 只接受 `code`，其它值 302 带 `unsupported_response_type` 回跳。
- `scope` 必须含 `openid`，否则 302 带 `invalid_scope`。少了 `email` 就没法按邮箱接管老账号。

## 先确认 issuer，再谈注册

`issuer` 填错是接入失败的头号原因，而且失败点很晚才暴露（浏览器跳转才 404）。**实测三件事**：

```bash
IDP=http://47.110.80.47:8082          # 候选：对外入口，不是后端端口
# 1) 发现文档里声明的 issuer 必须与你要写进配置的值逐字一致
curl -s "$IDP/.well-known/openid-configuration" | grep -o '"issuer":"[^"]*"'
# 2) 浏览器可达性：登录页要能 200（SPA 由 nginx 提供，不在后端镜像里）
curl -s -o /dev/null -w '%{http_code}\n' "$IDP/login"
# 3) 后端直连端口也可能返回发现文档，但里面的 issuer 指的是 nginx —— 那个才是能用的
curl -s "http://47.110.80.47:18080/.well-known/openid-configuration" | grep -o '"issuer":"[^"]*"'
```

第 3 条最能骗人：后端端口也能返回合法 JSON，于是配置"看起来通了"，但
`authorization_endpoint` 拼出来指向 8082，浏览器从 18080 过去就是 404。

## 注册为公共客户端

`POST /api/admin/clients`，字段名是 snake_case：

```json
{
  "client_id": "my-platform",
  "client_name": "我的平台",
  "redirect_uris": ["https://app.example.com/oidc/callback",
                    "http://127.0.0.1:*/oidc/callback"],
  "scopes": ["openid", "profile", "email"],
  "is_public": true,
  "pkce_required": true,
  "enabled": true,
  "post_logout_uris": ["https://app.example.com/"]
}
```

要点：

- **公共客户端不要 `client_secret`。** 认证中心 token 端点读了 `client_id`（form → query → Basic）
  但**从不校验 secret**，PKCE 是唯一凭据。配了 secret 只会给人一种"有密钥保护"的错觉，
  还得担心它下发到哪里。
- `is_public` / `pkce_required` / `enabled` 三个字段是 `*bool`，**不传等于 true**。别指望默认值帮你。
- 非公共客户端会生成 `cs_<random>`，只在创建响应里明文返回一次。库里存明文（注释写明"生产应存哈希"）。
- 管理端读取接口 `AdminClientView` 永不回传 secret，只给 `has_secret`。

## `redirect_uris` 的匹配语义（报错都出在这）

存储是**空格分隔的单个字符串**，API 层收发数组。匹配规则：

- 默认**精确匹配，包含 path**。`http://host:8988/static/oidc-login.html` 与
  `http://host:8988/oidc/callback` 是两个不同值，少写路径段直接 400。
- 唯一例外是 loopback 通配：`http(s)://127.0.0.1:*/path` 与 `http(s)://localhost:*/path`
  —— host 锁死回环、**端口任意**、path 必须匹配（RFC 8252）。本地联调就靠这条，
  不必为每个临时端口改注册。
- 未命中白名单的 `redirect_uri` → **400，绝不回跳**（防开放重定向）。
- `post_logout_uris` 只接受精确匹配，没有通配。

所以注册时**一次把两类地址都写进去**：线上对外地址（精确）+ 本地回环（通配）。

## 不依赖管理端凭据，证明注册真的生效

管理端凭据会被重置、也不该在脚本里落盘。验证 client 是否注册成功，用白名单探测法——
它同时验证了"client 存在"、"enabled"、"白名单生效"、"拒绝逻辑生效"四件事：

```bash
probe() {   # $1 = redirect_uri
  printf '%-58s ' "$1"
  curl -s -o /dev/null -D - -m 10 -G "http://47.110.80.47:8082/oauth2/auth" \
    --data-urlencode "response_type=code" --data-urlencode "client_id=my-platform" \
    --data-urlencode "redirect_uri=$1" --data-urlencode "scope=openid profile email" \
    --data-urlencode "state=x" \
    --data-urlencode "code_challenge=E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM" \
    --data-urlencode "code_challenge_method=S256" \
    | grep -iE '^(HTTP/|location:)' | tr -d '\r' | paste -sd' '
}
probe "https://app.example.com/oidc/callback"    # 期望 302 → /login?return_to=…
probe "http://127.0.0.1:9999/oidc/callback"      # 期望 302（回环通配）
probe "https://evil.example.com/callback"        # 期望 400 未在白名单内
```

只放行该放行的、拒掉该拒的，才算通过。第三行尤其重要：全 302 说明白名单根本没生效。

## 用 sql-harness 核对落库结果

```bash
sql-harness <<'PY'
use_workspace("<认证中心所在连接名>")
print(query("""SELECT id, client_id, client_name, is_public, pkce_required, enabled,
                      has_secret_or_empty, redirect_uris
               FROM auth_hub.o_auth_clients ORDER BY id"""))
PY
```

顺手确认一件容易忽略的事：认证中心与业务平台常常**共用一个 PG 实例、分处不同 schema**
（`auth_hub` / `public`）。任何按表名查的操作都要带 schema，否则 `users` 这种同名表会命中
错误的哪一张（本仓库就发生过：`auth_hub.users` 与 `public.users` 列完全不同）。

## 内置客户端保护

`template-web-client`、`gs-ac`、`oidc-cli`、`fr-app` 是 seed 出来的。管理端禁止删除内置客户端；
`gs-ac` 的回调白名单**每次启动都会用环境变量重新同步进库**——所以手改它的 DB 行会被下次
部署覆盖，要改就改它的 env。

## 移动端客户端为什么也走回环通配（`fr-app`）

`fr-app` 是 Flutter App 的 client，注册的是
`http://127.0.0.1:*/callback http://localhost:*/callback` —— 与 CLI 同一套形态。

不是偷懒，是因为**另外两条路当前都不可用**：

| 形态 | 为什么不行 |
|---|---|
| 自定义 scheme `com.example.app:/cb` | `ValidRedirectURIs` 只放 http/https，要改白名单校验逻辑 |
| Universal Link / App Links | 强制公网 HTTPS + `apple-app-site-association` / `assetlinks.json`，而本平台部署是 http 明文 |
| 回环端口通配 | ✅ Android 上 App 在自己进程监听 127.0.0.1 可行（浏览器与 App 同机） |

而实际上 App 内嵌 WebView 授权时**连监听都不需要**：在 `onNavigationRequest` 里认出回调
地址、直接从 URL 取走 `code` 并 prevent 这次导航即可。白名单要的是"地址形状合法"，
不是"真有人在听"。

**不要为了移动端放宽白名单校验** —— 那 60 行是整个 OIDC 实现里最不能出错的地方，
多一种形状就多一分风险。

> 内置客户端清单在 `db_integration_test.go` 的 `presetClientIDs` 里，
> 与"是否都就位""种子幂等后的行数"两处断言共用同一份来源。
> 加内置客户端只改这一处 —— 原先计数是硬编码的 3，忘了改不会漏掉真实故障，
> 只会让 CI 红在一次纯粹的计数变化上。
