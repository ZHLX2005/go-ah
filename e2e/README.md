# E2E 端到端测试（Playwright）

统一登录平台（IDP）+ 模板业务平台 的浏览器级端到端测试，共 **28 个用例**。

## 前置条件

1. **两个服务已启动**（测试不会自动拉起服务）：

```bash
# 终端 1：IDP
cd auth-hub && go run main.go

# 终端 2：业务平台（需注入加密密钥）
cd template-business-server
export BIZ_TOKEN_SECRET=$(openssl rand -hex 32)
go run main.go
```

2. **浏览器**：默认使用 Playwright 自带的 Chromium。干净环境首次运行需安装：

```bash
npx playwright install chromium
```

> **离线 / 内网环境**：若环境已缓存其它版本的 Chromium，可直接复用，无需重复下载：
>
> ```bash
> CHROMIUM_PATH=/root/.cache/ms-playwright/chromium-1208/chrome-linux64/chrome npx playwright test
> ```
>
> 配置会自动检测该路径是否存在，不存在时回落到 Playwright 默认解析。

## 运行

```bash
cd e2e
npm install

npm test                 # 全部 28 个用例
npm run test:oidc        # 仅 OIDC PKCE 流程（7 个）
npm run test:admin       # 仅管理后台（10 个）
npm run test:invite      # 仅邀请码注册（3 个）
npm run test:token       # 仅令牌刷新与吊销（8 个）
npm run test:headed      # 有头模式，便于观察
npm run report           # 查看 HTML 报告
```

当前状态：**28 passed**（串行约 2 分钟）。

## 用例清单

### `oidc-pkce-flow.spec.ts` — OIDC PKCE 授权码流程（7）

| # | 用例 | 断言要点 |
|---|---|---|
| 1 | 未登录访问业务首页自动跳转 IDP | 从 `return_to` 还原授权 URL；带 `code_challenge`(43位)、`code_challenge_method=S256`、`state`、`nonce`；**URL 中无 `client_secret`** |
| 2 | 错误密码登录 | 停留在 `/login` 并显示错误提示 |
| 3 | 账号栏填邮箱登录 | 用 `TEST_USER.email` 走完整 PKCE 流程进业务首页，业务 `/api/profile` 200（管理员身份由邮箱配置，登录不能只认账号名） |
| 4 | 完整 PKCE 登录 | 登录→授权→回调→`/api/profile` 200；`has_id_token`/`has_refresh_token` 为 true；**页面无 JS 错误** |
| 5 | 登录后刷新页面 | 会话保持，不被踢回 IDP |
| 6 | 未登录访问受保护接口 | `/api/profile` 401；`/api/session` 返回 `data: null` |
| 7 | 统一登出 | 业务接口 401；IDP 重新要求登录且 `return_to` 指向 `/oauth2/auth` |

### `admin-panel.spec.ts` — IDP 管理后台（10）

| # | 用例 | 断言要点 |
|---|---|---|
| 1 | 未登录访问 `/admin/users` | 跳 `/login` 且 `return_to` 保留原路径 |
| 2 | 管理员访问用户管理 | `/api/admin/me` 200；页面列出管理员账号 |
| 3 | 用户详情 | 展示活跃会话与 refresh_token 信息 |
| 4 | 管理 API 未授权 | `/api/admin/*` 四个端点均 **401** |
| 5 | 客户端管理页 | 列出 `template-web-client`、`oidc-cli`，"必需"PKCE 标记 |
| 6 | 客户端列表接口 | **不返回 `client_secret` 明文** |
| 7 | 令牌管理页 | 含 REVOKED 列/令牌表 |
| 8 | 侧边栏导航 | 用户/客户端/令牌三页可切换 |
| 9 | 新建客户端 | 自动生成 secret，创建成功且可删除 |
| 10 | 内置客户端保护 | 删除 `template-web-client` 返回 4xx |

### `token-revoke.spec.ts` — 令牌刷新与吊销（8）

| # | 用例 | 断言要点 |
|---|---|---|
| 1 | 登录后 TTL 与加密标记 | `token_encrypted=true`；access TTL≈10min；refresh TTL≈7d |
| 2 | 手动刷新 | `/api/refresh` 200，`access_token_expires_at` 推后，仍为密文 |
| 3 | 管理员吊销 | 吊销 refresh_token → IDP 返回 400 `invalid_grant` |
| 4 | 不存在的 refresh_token | 400 `invalid_grant` |
| 5 | userinfo 鉴权 | 无 Bearer / 伪造 Bearer 均 401 |
| 6 | 授权码重复使用 | 400 `invalid_grant` |
| 7 | 安全状态接口 | 返回加密算法/续期参数，**不含密钥** |
| 8 | 登出 | `/api/profile` 401 |

### `invite-register.spec.ts` — 邀请码注册（3）

本平台**没有开放的注册入口**：自助注册必须携带一张此刻仍能核销的邀请码，码只由管理员生成。

| # | 用例 | 断言要点 |
|---|---|---|
| 1 | 生成码 → 凭码注册 → 注册即登录 → 配额与明细可追溯 | 管理页生成 1 次性码（状态「可用」、`1 / 1`、未使用）；**全新上下文**从业务站点出发 → IDP 登录页 → 「用邀请码注册」（`return_to` 带回授权请求）→ 提交 → 自动登录并完成授权确认回到业务首页；业务 `/api/profile` 与 IDP `/api/me` 都指向新账号；返回管理页 `used_count=1`、`remaining=0`、状态「已用完」，明细只有一条且指向该账号；`/admin/users` 该账号**不显示「从未登录」** |
| 2 | 码已用完不再放行第二个人 | 第一个人用掉后，第二个人拿同一张码被拒并提示「可用次数已用完」，**停在注册页**；`used_count` 仍为 1（被拒的那次不消耗配额） |
| 3 | 停用/启用/删除立即生效 + 账号占用提示 | 停用后立刻提示「已被停用」；重新启用后可用；拿已存在的管理员账号注册提示「该账号已被占用」且**不扣次数**；删除走二次确认并从列表消失 |

> 主用例刻意走**完整 OIDC 流程**而不是只打一次 `/api/register`：注册唯一的目的是让一个新身份进入业务系统，只断言「接口返回 200」会漏掉「注册完回不到授权流程」这类只有把链路走完才暴露的问题。


## 测试设计要点

- **跨域请求不走 `page.evaluate`**：IDP(8080) 与业务(8081) 是不同源，浏览器内的 `fetch` 会被 CORS 拦截。因此纯协议层断言（token / userinfo / 安全状态）统一用 Playwright 的 `request` / `context.request` 上下文发起，天然不受同源策略限制。
- **避免与 SPA 整页跳转竞态**：未登录时业务首页会自动发起授权跳转，`page.evaluate` 的执行上下文会被销毁。涉及"未登录"的断言改为直接打接口，不先渲染页面。
- **登出链路用 `context.request` 校验**：登出是「业务接口 → IDP 整页跳转 → 回跳」的多跳流程，页面会重建上下文；改用带 Cookie 的 API 请求上下文校验 401，避免竞态。
- **授权确认按钮用角色+精确文本定位**：页面上「拒绝授权」在 DOM 中先于「同意授权」，用 `getByRole('button', { name: '同意授权', exact: true })` 避免误点拒绝。
- **新用户注册要换一个浏览器上下文**：IDP 的会话 Cookie 是按域共享的，在一个已有管理员会话的页面上注册，会把管理员会话顶成新用户的，后半段「回管理页看配额与明细」就直接 403 了。受邀者路径统一用 `browser.newContext()` 起一个干净上下文。

## 产物

- `screenshots/` — 关键步骤截图（用于人工复核与文档）
- `playwright-report/` — HTML 测试报告（`npm run report` 打开）
- `test-results/` — 失败用例的 trace / 截图

## 常见问题

**用例卡在等待跳转**
确认两个服务端口分别为 `8080`（IDP）与 `8081`（业务）。测试中所有地址均硬编码为这两个回环端口，与客户端注册的 `redirect_uri` 必须一致。

**`/api/refresh` 返回 500 `token_decrypt_failed`**
说明业务平台的 `BIZ_TOKEN_SECRET` 与写库时不一致（密钥轮换后旧会话无法解密）。清空 `template.db` 后重新登录即可。

**管理后台用例 403**
`users.is_admin` 为 false。种子逻辑会在启动时把 `test` 提升为管理员；若是旧库，重启一次 IDP 服务即可。

**报 `Executable doesn't exist at .../chromium_headless_shell-XXXX`**
Playwright 版本与本地缓存的浏览器版本不一致。二选一：`npx playwright install chromium`，或用 `CHROMIUM_PATH` 指向已缓存的可执行文件（见上文）。

**报 `Failed to fetch` / `TypeError: Failed to execute 'fetch'`**
在 `page.evaluate` 里请求了不同源的地址（IDP 与业务平台跨域）。改用 Playwright 的 `request` 上下文发起请求。
