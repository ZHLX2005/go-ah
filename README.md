# go-ah（auth-hub）· 统一认证中心与单点登录参考实现

**go-ah** = **Go** + **A**uth **H**ub —— 一套用 Go 编写的、可端到端运行的 **OIDC 1.0 / OAuth 2.0 PKCE 授权码模式** 单点登录（SSO）完整参考实现。

> 认证中心（IdP）签发身份，业务应用与命令行客户端通过标准 OIDC 协议接入，一次登录、多处通行。

仓库包含三个可独立运行的模块：

| 模块 | 角色 | 说明 |
|---|---|---|
| **auth-hub** | 认证中心（IdP） | 统一登录平台，提供登录 / 授权 / 令牌 / 登出 / JWKS / 发现文档 / 管理后台（Go + Gin + PostgreSQL + React） |
| **template-business-server** | 业务接入模板 | 业务 SPA 接入 OIDC 的**参考脚手架**，演示后端保管 token + 加密存储 + 后台自动续期 |
| **template-oidc-cli** | 命令行客户端 | 原生 / CLI 应用接入范例：本机回环回调 + PKCE，不持有 client_secret（独立 Go module） |

前后端分离架构（部署方案A）：React 打包静态资源由各自 Go 后端托管，`go run` 即同时提供 API + 页面。

---

## 1. 技术栈

| 层 | 技术 |
|---|---|
| 后端 | Go 1.25+、Gin、GORM(PostgreSQL)、golang-jwt(RS256)、argon2id、coreos/go-oidc、oauth2 |
| 前端 | Vite + React 18 + TypeScript、TailwindCSS(CDN)、openid-client v5（浏览器侧 PKCE） |
| 数据库 | **auth-hub 用 PostgreSQL**（`IDP_DSN` 指定，默认落在独立 schema `auth_hub`，与业务库共享同一实例互不干扰）；template-business-server 仍用 SQLite 嵌入式（`template.db`） |

## 2. 目录结构

```
go-ah/
├── auth-hub/                      # 认证中心（IdP）
│   ├── main.go                    # 入口：API路由 + 静态资源托管
│   ├── db/                        # 表模型 / 初始化 / argon2id / 密钥
│   ├── api/                       # 登录、授权、token、登出、JWKS、管理后台
│   └── web/idp-web/               # React 前端（/login /consent /logout /admin）
├── template-business-server/      # 模板业务平台（接入 Demo）
│   ├── main.go
│   ├── db/                        # business_users / business_sessions
│   ├── cryptox/                   # AES-256-GCM + PBKDF2 Token 加密（Task4）
│   ├── api/                       # 回调换token、profile、登出、刷新、加密存储、后台续期
│   └── web/template-web/          # React 前端（/ 与 /oauth/callback）
├── template-oidc-cli/                      # 命令行 OIDC 客户端（本机回环回调 + PKCE）
│   ├── main.go
│   ├── cmd/                       # login / whoami / logout
│   └── internal/                  # PKCE、浏览器唤起、回环回调、加密存储、后台续期
├── e2e/                           # Playwright 端到端测试
├── docs/screenshots/              # 端到端页面截图
├── .github/workflows/             # CI：测试 / 代码检查 / 多平台构建 + 发布
└── README.md
```

## 3. 一键启动

```bash
# ① 构建并启动认证中心 auth-hub（127.0.0.1:8080）
#    IDP_DSN 指向 PostgreSQL；search_path 决定 auth-hub 落在哪个 schema。
#    不设置时会回落到内置默认连接串（开发用），生产必须显式注入。
export IDP_DSN='postgres://postgres:pw@127.0.0.1:5432/postgres?sslmode=disable&search_path=auth_hub'
cd auth-hub/web/idp-web && npm install && npm run build
cd ../../ && go run main.go
#    auth-hub 首次启动会自动建 schema、建表、写入种子（预置账号与客户端）

# ② 新开终端：构建并启动模板业务平台（127.0.0.1:8081）
export BIZ_TOKEN_SECRET=$(openssl rand -hex 32)   # 必填：Token 加密密钥
cd template-business-server/web/template-web && npm install && npm run build
cd ../../ && go run main.go
```

> ⚠️ **`BIZ_TOKEN_SECRET` 是必填项**：业务平台启动时会校验该变量，未配置或长度不足 16 字符将**拒绝启动**（宁可不可用，也不把 refresh_token 明文落库）。生产环境请从密钥管理系统注入，不要写进代码或镜像。

| 入口 | 地址 |
|---|---|
| **模板业务平台（从这里开始测试）** | http://127.0.0.1:8081 |
| auth-hub 认证中心 | http://127.0.0.1:8080 |
| OIDC 发现文档 | http://127.0.0.1:8080/.well-known/openid-configuration |
| JWKS 公钥 | http://127.0.0.1:8080/.well-known/jwks.json |

**预置账号：`test / test123456`**（首次启动自动种子生成）

> 开发阶段（部署方案B）：前端可在各自 web 目录 `npm run dev`（5173/5174 端口，已配代理），生产再 `npm run build` 交给 Go 托管。

## 4. 端到端测试步骤（浏览器可视化）

1. 浏览器访问 **http://127.0.0.1:8081** → 检测无登录态，自动生成 `state / code_verifier / code_challenge(S256)`，302 跳转 auth-hub 登录页
2. 输入 `test / test123456` 登录（可试错密码，页面提示「账号不存在 / 密码错误」）
3. 进入 **授权确认页**，展示应用名「模板业务平台」与 `openid / profile / email` 权限，点【同意授权】
4. 302 携带 `code & state` 回调 `/oauth/callback` → 前端校验 state → 提交 `code + code_verifier` 给业务后端 → 后端调 auth-hub `/oauth2/token` 换取令牌 → SDK 校验 `id_token`（iss/aud/exp/RS256签名）→ 建立业务会话
5. 回到首页，展示 `sub / username / nickname / email` 与令牌保管状态
6. 【刷新用户信息】【刷新 Token】可分别验证受保护接口与 refresh_token 链路
7. 【统一登出】→ 业务会话销毁 → 跳 auth-hub 销毁全局会话 + **吊销全部 refresh_token** → 回到业务首页（未登录态）

页面截图见 `docs/screenshots/`。

## 5. OIDC 端点（auth-hub）

| 端点 | 说明 |
|---|---|
| `GET /oauth2/auth` | 授权端点：校验 client/redirect_uri/PKCE，未登录→登录页，已登录→授权页 |
| `POST /oauth2/token` | 令牌端点：`authorization_code`（PKCE 强制）与 `refresh_token` |
| `GET /oauth2/logout` | RP-Initiated Logout：销毁全局会话、吊销 refresh_token、回跳 |
| `GET /oauth2/userinfo` | 用户信息端点（需 Bearer access_token，校验 DB 记录） |
| `POST /oauth2/revoke` | RFC 7009 令牌吊销 |
| `GET /.well-known/openid-configuration` | 发现文档 |
| `GET /.well-known/jwks.json` | RSA 公钥（id_token RS256 验签） |
| `POST /api/login` `GET /api/me` `POST /api/logout` `GET/POST /api/consent` | auth-hub 前端页面配套 API |

### 5.1 管理后台 API（需管理员会话）

访问路径 `/admin`（前端）→ 后端 `/api/admin/*`，统一由 `RequireAdmin` 中间件保护：未登录返回 **401**，已登录但非管理员返回 **403**。预置账号 `test` 为管理员。

| 接口 | 说明 |
|---|---|
| `GET /api/admin/me` | 当前管理员信息 |
| `GET /api/admin/users` | 用户列表（含会话数、令牌数） |
| `GET /api/admin/users/:id/sessions` | 指定用户的活跃会话 |
| `GET /api/admin/users/:id/tokens` | 指定用户的 refresh_token |
| `GET /api/admin/clients` | OIDC 客户端列表（client_secret 掩码） |
| `POST /api/admin/clients` | 新建客户端（**自动生成 `cs_` 前缀 secret**、PKCE 开关、多 redirect_uri） |
| `PUT /api/admin/clients/:id` | 更新客户端 |
| `DELETE /api/admin/clients/:id` | 删除客户端（内置客户端受保护，禁止删除） |
| `GET /api/admin/refresh-tokens` | 全量 refresh_token 列表 |
| `POST /api/admin/revoke-token` | 吊销指定令牌 |

### 5.2 template-oidc-cli 命令行客户端

独立 Go module，模拟原生/命令行应用接入：临时回环 HTTP 服务接收回调 + PKCE，**不持有 client_secret**。

```bash
cd template-oidc-cli && go build -o oidc-cli .

./oidc-cli login     # 唤起浏览器完成授权，令牌加密存入 ~/.oidc-cli/store.enc
./oidc-cli whoami    # 展示当前登录主体（自动按需续期）
./oidc-cli logout    # 吊销 refresh_token 并删除本地加密存储
```

| 安全约束 | 实现 |
|---|---|
| 回调地址 | **仅绑定 `127.0.0.1`**，随机端口，拿到 token 后**立即关闭**临时服务 |
| PKCE | 强制 S256，不使用 client_secret |
| 存储 | AES-256-GCM 加密，密钥由 **本机指纹 + 可选口令** 经 PBKDF2 派生，权限 `0600`，目录 `0700` |
| 自动续期 | 登录后常驻协程，距过期 < 2 分钟自动续期；失败则清空本地会话并登出 |

## 6. 业务平台接口

| 接口 | 说明 |
|---|---|
| `GET /api/config` | 下发 OIDC 公共配置（**不含 client_secret**），前端据此生成 PKCE |
| `POST /api/auth/callback` | 接收 `code + state + code_verifier`，后端换 token、验 id_token、建会话 |
| `GET /api/profile` | 受保护接口（会话 Cookie 鉴权） |
| `GET /api/session` | 轻量登录态探测 |
| `POST /api/refresh` | 用 refresh_token 刷新 id_token（内部解密 → 换 token → 加密回写） |
| `POST /api/logout` | 销毁业务会话，返回携带 `id_token_hint` 的 IDP 登出地址 |
| `GET /api/security-status` | 暴露加密算法与续期参数（不含密钥），便于验收 |

## 7. 数据表

**auth-hub（PostgreSQL schema `auth_hub`）**：`users`、`oauth_clients`、`oauth_authorization_codes`（一次性，5分钟）、`oauth_refresh_tokens`（7天，登出全吊销）、`oauth_access_tokens`（10分钟，userinfo 鉴权）、`user_sessions`（8小时）、`signing_key_records`（id_token 的 RSA 私钥，**持久化**——否则每次重启换密钥，客户端缓存的 JWKS 会失配、已签发 token 全部验签失败）

> schema 由 `IDP_DSN` 的 `search_path` 决定，默认 `auth_hub`。共享 PG 实例上务必保持独立 schema：`public` 下很可能已有同名的 `users` 表，串了 AutoMigrate 会去改别人的表。

**业务（template.db）**：`business_users`（按 auth-hub `sub` 关联，首次登录自动建档）、`business_sessions`（token 后端保管且**加密存储**，含 `encrypted` 标记与 access/refresh 过期时间）

## 8. 安全设计要点

- **SPA 公共客户端**：不保存 `client_secret`，强制 PKCE(S256)；token 端点认证方式 `none`
- **方案1（后端保管 token）**：code+verifier 提交业务后端换 token，token 存后端数据库（模板模块用 SQLite，auth-hub 侧用 PostgreSQL），浏览器只持 HttpOnly Cookie —— 规避 localStorage XSS 风险
- **JWT 校验全部在后端**（go-oidc 校验 iss/aud/exp/nonce/RS256 签名），前端不验签
- **state 防 CSRF**：前端生成存 sessionStorage，回调时强校验
- **authorization code 一次性**：重复使用返回 `invalid_grant`
- **redirect_uri 白名单**：未注册的回调地址直接 400；**原生/CLI 客户端支持回环通配**（`http://127.0.0.1:*/callback`，RFC 8252）
- **密码 argon2id** 哈希存储，常量时间比较
- **统一登出**：全局会话 + 业务会话 + 全部 refresh_token 三清
- **Token 加密持久化（Task4）**（详见 §9）
- **后台自动续期（Task4）**（详见 §9）

## 9. Token 加密持久化与自动续期（Task4）

### 9.1 加密方案

| 项 | 取值 |
|---|---|
| 算法 | **AES-256-GCM**（认证加密，防篡改） |
| 密钥派生 | **PBKDF2-HMAC-SHA256**，120000 轮，32 字节输出 |
| 存储格式 | `base64( salt(16) ‖ nonce(12) ‖ ciphertext+tag )` |
| 盐值 | 每条记录随机生成，随密文一同保存（无需额外列） |
| AAD | salt 参与认证，密文被搬运到其他记录时解密失败 |
| 密钥来源 | **环境变量 `BIZ_TOKEN_SECRET`**（不落库、不硬编码、不入镜像） |

**全库无明文**：`business_sessions` 的 `id_token / access_token / refresh_token` 三列均为密文，全库扫描不存在任何 `eyJ` 开头的 JWT 明文；解密失败统一归一为「密钥不匹配或数据被篡改」，不泄漏底层细节。

**平滑迁移**：`business_sessions.encrypted` 标记该行是否已加密。历史明文行读取时直接返回原值，不做解密尝试，可在不停机的情况下逐步迁移。

> 注：**auth-hub 侧不加密 `refresh_token`**——按设计，auth-hub 只维护吊销状态（删除/标记记录），不持有需要回传的可逆凭据，因此加密对它没有收益。

### 9.2 后台自动续期

| 参数 | 取值 |
|---|---|
| access_token TTL | 10 分钟 |
| refresh_token TTL | 7 天 |
| 续期触发阈值 | 距 access_token 过期 **< 2 分钟** |
| 巡检间隔 | 30 秒 |

**业务平台**采用「单例巡检协程 + 会话级判定」：进程启动拉起一个 ticker，每轮扫描所有未过期会话，命中阈值的执行续期；续期成功则加密回写新 token 并滑动延长会话，**续期失败（refresh_token 被吊销/过期）则直接删除该业务会话**，前端下次请求 `/api/profile` 即得 401，自然回到登录页。

之所以不是「每会话一个 goroutine」：会话数随用户增长，逐会话协程会导致协程数量不可控；巡检方式成本只与轮询间隔相关。

**CLI** 采用常驻单会话模型，登录成功后启动一个 `Refresher` 协程（30s 检查），续期成功回写加密存储，失败则清空 `~/.oidc-cli/store.enc` 并触发登出回调。

### 9.3 验证结果

| # | 用例 | 结果 |
|---|---|---|
| 1 | 三个 token 落库均为 `salt+nonce+ct` 密文，全库无 `eyJ` 明文 | ✅ |
| 2 | 空密钥 / 弱密钥（<16 字符）拒绝启动并给出明确提示 | ✅ |
| 3 | 错误密钥解密失败、密文篡改被检测（GCM tag 校验） | ✅ |
| 4 | 同一明文两次加密结果不同（salt/nonce 随机） | ✅ |
| 5 | 距过期 < 2 分钟时自动续期，access_token 密文变化、过期时间推后至 ~10 分钟 | ✅ |
| 6 | 吊销 refresh_token 后续期失败，业务会话被自动销毁（触发登出） | ✅ |

## 10. 测试

### 10.0 验收结论速览

| # | 验收项 | 结果 |
|---|---|---|
| 1 | 访问业务首页自动跳转 auth-hub React 登录页 | ✅ |
| 2 | test/test123456 登录进入授权确认页；错误密码提示 | ✅ |
| 3 | 同意授权回调业务平台，首页展示用户信息 | ✅ |
| 4 | 受保护接口 `/api/profile` 鉴权 200 | ✅ |
| 5 | 统一登出后业务接口 401、`/oauth2/auth` 重新要求登录 | ✅ |
| 6 | refresh_token 刷新成功；吊销后刷新返回 `invalid_grant` | ✅ |
| 7 | code 重复使用 / 错误 verifier / 非法 redirect_uri 均被拒 | ✅ |
| 8 | auth-hub 管理后台：未登录 401 → 跳登录；非管理员 403 | ✅ |
| 9 | 管理后台客户端 CRUD、自动生成 client_secret、PKCE 开关生效 | ✅ |
| 10 | CLI `login → whoami → logout` 全链路，本地存储无明文 JWT | ✅ |
| 11 | 业务/CLI token 全部 AES-256-GCM 加密落库，全库无明文 JWT | ✅ |
| 12 | 距过期 < 2 分钟自动续期；吊销后自动销毁会话并登出 | ✅ |

### 10.1 Go 单元测试

auth-hub 的测试需要一个**真实 PostgreSQL**：每个测试会在库里建一个随机命名的一次性 schema，跑完立即 `DROP`（见 `auth-hub/internal/testpg`），因此彼此隔离、也不会污染库里其它内容。未配置 `AUTH_HUB_TEST_DSN` 时这些测试会**跳过**（而不是失败）——本地没配库的人不该看到一片红。

```bash
# auth-hub：需要 PG（连接串不能带 search_path，测试要自建 schema）
export AUTH_HUB_TEST_DSN='postgres://postgres:pw@127.0.0.1:5432/postgres?sslmode=disable'
cd auth-hub && go test ./... -v

# 另外两个模块不需要外部依赖
cd template-business-server && go test ./... -v
cd template-oidc-cli && go test ./... -v
```

| 模块 | 覆盖内容 |
|---|---|
| `auth-hub/api` | PKCE S256（含 RFC 7636 官方测试向量）、redirect_uri 精确/回环通配匹配、argon2id 哈希往返与畸形输入、RS256 id_token 签发与验签（错误密钥/篡改拒绝）、JWKS 模数一致性、授权码一次性与过期、refresh_token 吊销与过期、TTL 常量、**GORM 显式 `false` 持久化回归**、client_secret 生成、token 掩码、`clientView` 不泄漏密钥 |
| `auth-hub/db` | 种子数据（`test` 管理员、三个预置客户端）、重复 Init 幂等、旧库自动提权、表结构完整性、回环通配回调注册、**schema 隔离**（防止落到 public 撞别人的表）、**签名密钥跨重启持久化**、PEM 编解码往返、`IDP_SIGNING_KEY_PEM` 优先采用、DSN 解析与非法 schema 名拒绝（SQL 注入防护）、日志密码脱敏 |
| `template-business-server/cryptox` | 密钥强度校验、加解密往返、盐/nonce 随机性、错误密钥与篡改（GCM tag）拒绝、明文零泄漏、`IsCiphertext` 判定、PBKDF2 派生确定性 |
| `template-business-server/api` | 加密落库（库中无明文 JWT）、读取还原、存量明文平滑迁移、密钥不匹配、续期阈值全边界（9 个 case）、续期协程启停幂等、吊销回调、解密失败自动销毁会话 |

覆盖率：

```
auth-hub/api                       15.6%   （大量 Gin handler 由 E2E 覆盖）
auth-hub/db                        71.8%
template-business-server/api       33.0%
template-business-server/cryptox   78.9%   （核心加密逻辑）
```

> 说明：handler 层（HTTP 编排）通过下面的 Playwright E2E 做真实浏览器验证，
> 单元测试聚焦在**纯函数、加密、数据持久化与状态机**这些"抛错也难发现"的地方。

### 10.2 Playwright E2E

```bash
cd e2e && npm install
npm test                     # 24 个用例，串行约 1.5 分钟
```

前置条件：两个服务已启动（见 §3）。离线环境可用 `CHROMIUM_PATH` 复用已缓存的浏览器。

| 套件 | 用例数 | 覆盖 |
|---|---|---|
| `oidc-pkce-flow.spec.ts` | 6 | 授权请求参数完整性、错误密码、完整登录链路、会话持久化、未授权 401、统一登出 |
| `admin-panel.spec.ts` | 10 | 未登录跳转、管理员鉴权、用户/客户端/令牌三面板、客户端 CRUD、内置客户端保护、secret 不下发 |
| `token-revoke.spec.ts` | 8 | TTL 与加密标记、手动刷新、管理员吊销、`invalid_grant` 三处（刷新/授权码/未知令牌）、userinfo 鉴权、安全状态接口 |

**当前结果：`24 passed`**。详细设计与排错见 [`e2e/README.md`](e2e/README.md)。

## 11. 案例代码：三步接入 go-ah 单点登录

以下是从零接入的**最小可运行**示例，覆盖三种典型客户端形态。

### 11.1 在认证中心注册客户端（管理后台）

访问 `http://127.0.0.1:8080/admin`，用 `test / test123456` 登录，在「客户端管理」新建：

| 字段 | 值 | 说明 |
|---|---|---|
| `client_id` | `my-app` | 唯一标识 |
| 回调地址 | `http://127.0.0.1:9000/callback` | 支持多个，逐个换行 |
| PKCE | **开启** | 公共客户端必须开启 |
| client_secret | 留空 / 自动生成 | SPA / CLI 走 PKCE，**不需要** secret |

### 11.2 案例一：Web 应用（Go 后端 + PKCE）

```go
package main

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"net/http"

	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"
)

const (
	issuer      = "http://127.0.0.1:8080"
	clientID    = "my-app"
	redirectURI = "http://127.0.0.1:9000/callback"
)

var (
	provider *oidc.Provider
	verifier *oidc.IDTokenVerifier
	oauth2Cfg *oauth2.Config
)

func main() {
	ctx := context.Background()

	// ① 拉取发现文档，构建 Provider（自动获取 jwks_uri / endpoints）
	p, err := oidc.NewProvider(ctx, issuer)
	if err != nil {
		log.Fatalf("无法连接认证中心 %s: %v", issuer, err)
	}
	provider = p
	verifier = provider.Verifier(&oidc.Config{ClientID: clientID})

	// ② 公共客户端：AuthStyle 设为 InParams，凭 code_verifier 换 token
	oauth2Cfg = &oauth2.Config{
		ClientID:    clientID,
		RedirectURL: redirectURI,
		Endpoint:    provider.Endpoint(),
		Scopes:      []string{oidc.ScopeOpenID, "profile", "email"},
	}

	http.HandleFunc("/login", handleLogin)
	http.HandleFunc("/callback", handleCallback)

	fmt.Println("示例应用已启动：http://127.0.0.1:9000/login")
	log.Fatal(http.ListenAndServe("127.0.0.1:9000", nil))
}

// 生成 PKCE 的 code_verifier 与 code_challenge(S256)
func pkcePair() (verifier, challenge string) {
	b := make([]byte, 32)
	_, _ = rand.Read(b)
	verifier = base64.RawURLEncoding.EncodeToString(b)
	h := sha256.Sum256([]byte(verifier))
	challenge = base64.RawURLEncoding.EncodeToString(h[:])
	return
}

func handleLogin(w http.ResponseWriter, r *http.Request) {
	verifier, challenge := pkcePair()

	// state 防 CSRF；生产环境请存入会话/Cookie 而非内存
	state := base64.RawURLEncoding.EncodeToString([]byte(verifier))
	http.SetCookie(w, &http.Cookie{Name: "pkce_state", Value: state, HttpOnly: true, Path: "/"})

	url := oauth2Cfg.AuthCodeURL(state,
		oauth2.SetAuthURLParam("code_challenge", challenge),
		oauth2.SetAuthURLParam("code_challenge_method", "S256"),
	)
	http.Redirect(w, r, url, http.StatusFound)
}

func handleCallback(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	// ③ 校验 state 防 CSRF
	stateCookie, err := r.Cookie("pkce_state")
	if err != nil || stateCookie.Value != r.URL.Query().Get("state") {
		http.Error(w, "state 校验失败（疑似 CSRF）", http.StatusBadRequest)
		return
	}

	// ④ 用 code + code_verifier 换取 token
	token, err := oauth2Cfg.Exchange(ctx, r.URL.Query().Get("code"),
		oauth2.SetAuthURLParam("code_verifier", stateCookie.Value))
	if err != nil {
		http.Error(w, "换取 token 失败: "+err.Error(), http.StatusBadRequest)
		return
	}

	// ⑤ 校验 id_token 签名与声明（iss / aud / exp / RS256 全部由 SDK 完成）
	rawIDToken, ok := token.Extra("id_token").(string)
	if !ok {
		http.Error(w, "响应缺少 id_token", http.StatusBadRequest)
		return
	}
	idToken, err := verifier.Verify(ctx, rawIDToken)
	if err != nil {
		http.Error(w, "id_token 校验失败: "+err.Error(), http.StatusUnauthorized)
		return
	}

	var claims struct {
		Sub      string `json:"sub"`
		Username string `json:"preferred_username"`
		Email    string `json:"email"`
	}
	_ = idToken.Claims(&claims)

	// ⑥ 建立自己的业务会话（此处仅演示，实际应写 Cookie/Session）
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"sub":      claims.Sub,
		"username": claims.Username,
		"email":    claims.Email,
		"scope":    token.Type(),
	})
}
```

### 11.3 案例二：前端 SPA（浏览器侧 PKCE，推荐 `openid-client`）

```ts
import { Issuer, generators } from 'openid-client'

const IDP = 'http://127.0.0.1:8080'
const CLIENT_ID = 'my-app'
const REDIRECT_URI = 'http://127.0.0.1:9000/callback'

// ① 发现认证中心元数据
const issuer = await Issuer.discover(IDP)
const client = new issuer.Client({
  client_id: CLIENT_ID,
  redirect_uris: [REDIRECT_URI],
  response_types: ['code'],
  token_endpoint_auth_method: 'none', // 公共客户端，不持有 secret
})

// ② 发起授权：生成 PKCE 参数
export async function login() {
  const codeVerifier = generators.codeVerifier()
  const codeChallenge = generators.codeChallenge(codeVerifier) // S256
  const state = generators.state()

  sessionStorage.setItem('pkce_verifier', codeVerifier)
  sessionStorage.setItem('pkce_state', state)

  location.href = client.authorizationUrl({
    scope: 'openid profile email',
    code_challenge: codeChallenge,
    code_challenge_method: 'S256',
    state,
  })
}

// ③ 回调页：校验 state 后换取 token
export async function handleCallback() {
  const params = client.callbackParams(location.href)
  const codeVerifier = sessionStorage.getItem('pkce_verifier')!
  const state = sessionStorage.getItem('pkce_state')!

  const tokenSet = await client.callback(REDIRECT_URI, params, {
    code_verifier: codeVerifier,
    state,
  })

  sessionStorage.clear()
  console.log('登录成功，sub =', tokenSet.claims().sub)
  return tokenSet
}
```

> **为什么不把 token 放在 localStorage？** 见 §8 —— localStorage 可被 XSS 读取。
> 生产实践推荐 §6 的「后端保管 token」方案：前端只持有 HttpOnly Cookie。

### 11.4 案例三：命令行 / 原生应用（回环重定向）

原生应用无法接收 HTTPS 回调，按 **RFC 8252** 使用本机回环地址：

```go
// 1) 启动临时回环服务，端口交给操作系统分配（避免冲突）
ln, _ := net.Listen("tcp", "127.0.0.1:0")
port := ln.Addr().(*net.TCPAddr).Port
redirectURI := fmt.Sprintf("http://127.0.0.1:%d/callback", port)

// 2) 注册到认证中心的回调白名单：http://127.0.0.1:*/callback
//    （go-ah 支持回环通配匹配，无论端口如何变化都无需重新注册）

// 3) 拿到 code 后立刻关闭回环服务，缩小暴露窗口
go func() {
	code := <-codeCh
	_ = ln.Close()
	// ... 用 code + code_verifier 换 token
}()

// 4) 唤起系统浏览器（不要在应用内嵌浏览器里输入密码——OAuth 2.0 安全最佳实践）
_ = browser.OpenURL(authURL)
```

完整可运行版本见本仓库 [`template-oidc-cli/`](template-oidc-cli/) —— 包含回环回调、AES-256-GCM 加密存储、后台自动续期。

### 11.5 案例四：调用受保护接口（验证 access_token）

```bash
# 认证中心提供 /oauth2/userinfo，用 access_token 换取用户信息
curl -H "Authorization: Bearer $ACCESS_TOKEN" \
     http://127.0.0.1:8080/oauth2/userinfo
```

```go
// 业务侧校验 access_token（本地验签，无需每次回源认证中心）
provider, _ := oidc.NewProvider(ctx, issuer)
verifier := provider.Verifier(&oidc.Config{ClientID: clientID})

idToken, err := verifier.Verify(ctx, rawToken)
if err != nil {
	// 签名错误 / 过期 / aud 不匹配 → 401
	http.Error(w, "unauthorized", http.StatusUnauthorized)
	return
}
```

---

## 12. 环境变量（可选覆盖）

| 服务 | 变量 | 默认 |
|---|---|---|
| auth-hub | `IDP_DSN` **（生产必填）** | 无默认时回落内置开发连接串（`search_path=auth_hub`）；生产必须显式注入 |
| auth-hub | `IDP_ADDR` `IDP_WEB_DIST` | `127.0.0.1:8080` `./web/idp-web/dist` |
| auth-hub | `IDP_ISSUER` **（生产必填）** | `http://127.0.0.1:8080`；本地 `go run` 时就是本机地址。**生产部署后必须改成前端 nginx 的对外地址**（例如 `http://<服务器IP>:8082`），原因见下方部署小节 |
| auth-hub | `GSAC_REDIRECT_URI` `GSAC_POST_LOGOUT_URI` | 本地开发默认值；生产须设成 gs-ac 前端的真实地址（空格分隔多个，任一命中即通过） |
| auth-hub | `IDP_SIGNING_KEY_PEM` | 空。填入固定 RSA 私钥（PKCS#8 PEM）后密钥不落库；**多副本部署必须设置**，否则各副本各自生成、互相验签失败 |
| 业务 | `BIZ_ADDR` `BIZ_DB` `BIZ_WEB_DIST` `IDP_ISSUER` `OIDC_CLIENT_ID` `OIDC_REDIRECT_URI` `OIDC_POST_LOGOUT_URI` | `127.0.0.1:8081` `template.db` `./web/template-web/dist` `http://127.0.0.1:8080` `template-web-client` `http://127.0.0.1:8081/oauth/callback` `http://127.0.0.1:8081/` |
| 业务 | **`BIZ_TOKEN_SECRET`**（**必填**，≥16 字符） | 无默认，缺失即拒绝启动 |
| CLI | `OIDC_CLI_ISSUER` `OIDC_CLI_CLIENT_ID` `OIDC_CLI_STORE` `OIDC_CLI_PASSPHRASE` | `http://127.0.0.1:8080` `oidc-cli` `~/.oidc-cli/store.enc` 空 |

## 13. CI / CD

| 工作流 | 触发 | 内容 |
|---|---|---|
| [`ci.yml`](.github/workflows/ci.yml) | push / PR / 手动 | ① `gofmt` + `go vet`（三模块矩阵）② `go test -race` + 覆盖率（带 PostgreSQL service container，测试自建一次性 schema）③ 两个 React 工程 `npm ci && npm run build` ④ Playwright E2E 真实浏览器跑通 SSO 全链路 |
| [`release.yml`](.github/workflows/release.yml) | tag `v*.*.*` / 手动 | 验证 → 构建前端 → Linux amd64/arm64 二进制 + 源码包 → 自动创建 GitHub Release（template-business-server 仍依赖 sqlite 的 cgo，故需交叉工具链） |
| [`deploy.yml`](.github/workflows/deploy.yml) | push 到 `main` / 手动 | 构建**两个**镜像（auth-hub 纯 Go + auth-hub-web nginx）→ `docker save` → SCP → 服务器 `docker load` → 共享网络 `idp-net` 上重启两容器 → 发现文档健康检查 + **issuer 注入断言** + **SPA 路由与反代贯通断言**。存储已外置到 PG，容器无状态、不挂数据卷 |

**部署 auth-hub 需要配置的 secrets**：`HOST` `USERNAME` `SSH_KEY` `IDP_DSN` `IDP_ISSUER` `GSAC_REDIRECT_URI` `GSAC_POST_LOGOUT_URI`（可选 `PORT` `APP_PORT` `API_PORT` `IDP_SIGNING_KEY_PEM`）。

> `IDP_ISSUER` 与 gs-ac 侧的 `OIDC_ISSUER` 必须**逐字一致**，`GSAC_REDIRECT_URI`/`GSAC_POST_LOGOUT_URI` 与 gs-ac 侧的 `OIDC_REDIRECT_URI`/`OIDC_POST_LOGOUT_URI` 也必须一致 —— 这是两个仓库之间唯一的强耦合点，配歪的症状只有一个「登录回调失败」，很难反推。两个 deploy.yml 都做了前置校验尽量提前拦住。

### 部署拓扑：为什么生产用 nginx 托管前端

本地开发是「Go 直接把 `web/idp-web/dist` 一起托管」（一条 `go run` 就能跑通 SSO 全链路）；
生产则是**两个容器**：

| 容器 | 角色 | 宿主端口 |
|---|---|---|
| `auth-hub-web`（nginx） | 托管 SPA，并把 `/api`、`/oauth2`、`/.well-known` 反代到后端 | **8082**（公网入口） |
| `auth-hub`（Go） | 只提供 API 与 OIDC 端点，**镜像内不含前端** | 8080（直连调试用） |

两边共享 docker 网络 `idp-net`，nginx 靠容器名 `auth-hub` 解析后端。

> ⚠️ **这一改动会连带改变 `IDP_ISSUER` 的取值**：必须从后端端口 `8080` 改成前端 nginx 的 `8082`。
> 因为发现文档里的 `authorization_endpoint` / `end_session_endpoint` 是「issuer + 路径」拼出来的，
> 而这两个端点**由浏览器访问**；issuer 若仍写 8080，浏览器会绕过 nginx 直连后端容器 ——
> 而 SPA 已不在后端镜像里，登录会 404。`deploy.yml` 第 9 步用「取 `${IDP_ISSUER}/login` 必须返回 200」
> 专门断言这一点，因为这个错误在别处极难定位。
>
> nginx 配置里 `.well-known` 的反代**最容易被漏**：漏了之后所有依赖方的 OIDC 初始化都会失败，
> 而报错只出现在调用方的日志里，从认证中心这边看还以为一切正常。

**发布新版本：**

```bash
git tag v1.0.0 && git push origin v1.0.0
```

## 14. 非目标（本次不实现）

管理后台之外的后台功能、HTTPS、MFA/短信、细粒度 RBAC、分布式会话/集群。

