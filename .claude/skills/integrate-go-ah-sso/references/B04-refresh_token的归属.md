# B04 · refresh_token 的归属

> 业务服务平台要"长期调用"业务接口，到底怎么搞？是持久化 refresh_token 后做静默续期，还是用 IdP 会话/App 状态让用户重新走一次？CLI 在这里面到底"桥"了什么——还是说"CLI 桥接"这个想法本身就是错的？

## 加载时机

- 设计一个 RP 的"长期登录"机制：用户长期不输密码也能用，那枚令牌放哪儿
- 看到有人准备写"持久化 refresh_token + 后台刷新"的代码——这是要拦的
- 给同事解释"为什么我们不让服务发 refresh_token 给客户端"
- 看懂 fr 凭据存储里的 `_legacyKeys` 列表到底删的是什么历史包袱

## 一句话结论

> **CLI / App / 业务服务端 三方都不持久化 refresh_token；谁都不持久化 access_token；长期身份与长期业务调用是两件互不依赖的事——一个走 IdP 全局会话，一个走 RP 自签的长期令牌。**
>
> **CLI 不是桥。桥接这个思路从一开始就是错的：refresh_token 是 IdP 颁发的，客户端拿到它就是"替 IdP 维护一条 7 天有效期的可兑换凭据"——只要这个凭据落到客户端，本平台就丢失了"统一登出 / 周期性重新确认身份 / 认证策略变更生效"这三件事。**

## 为什么本平台不存 refresh_token

这是本 skill 的硬约束（详 A02「会话与续期」）。两条平台事实叠加：

| 平台事实 | 来源 |
|---|---|
| 5 个内置客户端都是 public 且无 secret | `auth-hub/internal/consts/consts.go:227-237` + `db.go` |
| token 端点读了 client_id 但**从不校验 secret**；代码无 DPoP / mTLS | `auth-hub/internal/controller/oidc/oidc.go` (Token) |

凭这两条：任何一枚 refresh_token 即便被 RSA 加密落库，它本身**没有任何 sender-constraint**——"谁拿到谁可用 7 天"。加密只改变"可读性"，不改变"可兑换性"。所以本平台一律**不持久化**。

补充三个不准混淆的独立理由：

| 理由 | 适用范围 | 失效条件 |
|---|---|---|
| refresh_token 长期落库 + 静默续期 = 用户永远不再回到 IdP | 任何平台 | 上 mTLS / DPoP / 机密客户端后减弱 |
| 滑动会话让过期永远不发生 | 任何平台 | 上线"周期性重新确认身份"机制 |
| 把 10 分钟 access_token 拿来做长期业务调用 | 一枚 token 两用是错 | 改成"登录态 vs 业务 JWT 各一"即可消除 |

## 三个角色到底各持什么

### CLI 端（PC，mn-rt client）

```
持：mn-rt 自签设备令牌（HS256，365 天）+ sessionKey
不持：任何 IdP access_token / refresh_token
```

证据：

- `client/lib/auth.js` 顶部注释（30-33 行）：
  > 换到的 refresh_token 直接丢弃。CLI 真正需要长期持有的是第 ⑤ 步服务端签发的设备令牌——它可被服务端吊销，而 refresh_token 一旦落到每台 PC 的磁盘上，就是把"谁拿到谁可用 7 天"的凭据复制到 N 台机器。
- `client/lib/auth.js:236-244`：换 token 时拿到 access_token，仅用在第 ⑤ 步 `/auth/verify` 的 Bearer header 里一次
- `client/lib/config.js:116-168`（saveConnectionConfig / clearAuthCredentials）：持久化清单里**根本没有 access_token / refresh_token**字段，只有 deviceToken、sessionKey、authUser（身份快照，非凭据）

### App 端（手机，fr）

```
持：mn-rt 自签用户令牌（HS256，365 天，cid=""）+ idp_session cookie（30 天，活跃滑动）
不持：任何 IdP access_token / refresh_token
```

证据：

- `fr/lib/api/remotetype/remotetype_endpoint.dart:63-95`（exchangeCode）：拿 `code+codeVerifier` POST 给 mn-rt 服务器；**App 自己不接触 token**
- `fr/lib/api/remotetype/remotetype_grant_store.dart:21-33`：
  ```dart
  static const _legacyKeys = [
    'remotetype_refresh_token',  // ← 旧版本曾写过的，**只删不写**
    'remotetype_idp_token',
    'remotetype_session_key',
  ];
  ```
  历史版本曾把 refresh_token / IdP token 写进 SharedPreferences——直接放进 `_legacyKeys` 只删不写，注释说："它不该存在于客户端是个结论，不该依赖用户做某个动作才成立"
- `fr/lib/services/auth/unified_auth_service.dart:160-164`（signOut）：idp_session + 业务 token 一并清；refresh_token 早就不在这里

### 业务服务端（mn-rt server）

```
持：自签设备令牌签名密钥 RT_AUTH_JWT_SECRET + 设备注册表 devices.json（clientId ↔ sub）
      一份 IdP access_token 仅在单次 HTTP 请求的内存里存在
不持：任何 IdP access_token / refresh_token
```

证据：

- `server/src/auth.js:23-26` 注释：
  > 换到的 access_token / refresh_token 只在这一次请求的内存里用于取身份，用完即弃、不落库不落盘。
- `server/src/auth.js:168-173`（exchange 内部）：调 `/oauth2/userinfo` 用的 access_token 没有落到任何 Map / 全局变量；函数返回后即释放
- `server/src/auth.js:185-203`（verifyBearer 内部）：同上，单次请求内使用
- 设备注册表 `devices.json`（`auth-hub/internal/db/db.go` 之外的本地卷 `mn_rt_data`）只存 `clientId → {userId, email, deviceName, sessionKey, ownerBoundAt, registeredAt, lastSeenAt}` 与 `revoked` 名单，**没有任何 token**

### App 静默续期的真相

App 在 `fr/lib/services/remotetype/remotetype_service.dart:150-161`（myComputers）里看起来像在做"静默续期"：

```dart
try {
  return await _endpoint.myComputers();
} on RemoteTypeException catch (e) {
  if (e.kind != RemoteTypeErrorKind.unauthorized) rethrow;
  final fresh = await ensureGrant(force: true);
  if (fresh == null) rethrow;
  return _endpoint.myComputers();
}
```

实际过程：

1. 旧的 mn-rt 用户令牌被服务端判定无效（401）→ 抛 RemoteTypeException
2. `ensureGrant(force: true)` → 检查 `idp_session` 是否还活着（30 天内，活跃滑动）
3. 如果在，App **走一遍完整的 OAuth authorize + 自动 consent**（`mintCodeForClient`），从 IdP 拿新 code，POST 给 mn-rt 服务器换新用户令牌
4. 新令牌落盘，继续用

**没有 refresh_token 参与**——这条"看起来是续期"的链路其实是**重新授权**。每次"续期"都过一遍完整的 OIDC dance，UI 看起来无感只是因为：
- 用户已经在 IdP 上登录过，session 没死，浏览器/WebView 不弹
- consent 自动同意（同管理域第一方客户端，详 B02）

## 那长期业务调用到底怎么搞

如果你想要"业务后端能在用户不在场时长期调用业务接口"——比如 mn-rt 自己的后台脚本或定时任务——这跟用户身份无关，应该用 **service-to-service** 凭据：

```
      ┌────────────────────────────────────────┐
      │ 业务后端互调 = 业务内部 RBAC，不混 OIDC │
      └────────────────────────────────────────┘
```

具体而言：

- 用户身份的 token（access_token / 自签设备令牌 / 用户令牌）**不应**被"复用"去做后台任务；它的属主是个人，超时/换岗/吊销都会卡住
- 后台任务用独立的 service account（机密客户端、有 secret、专用 scope），不在用户授权链路里混
- 本平台当前未启用 service account（所有 5 个内置 client 都是 public）——**真要做就自建一对 client（机密 + secret + service-only scope），不混进用户令牌**

## 一个常见的错思路：CLI "替"业务桥出 refresh_token

> "如果 CLI 帮忙把 refresh_token 拿回来再分发给业务后端，业务后端就能长期调用了"

这条错在哪：

| 步骤 | 错在哪 |
|---|---|
| CLI 用授权码换 access_token + refresh_token | 协议本身允许拿 refresh_token；问题在拿到之后怎么处理 |
| CLI 把 refresh_token 落盘 | 即便加密落，"谁拿到谁可用 7 天"的属性不变；CLI 上同时跑输入法模拟器、svchost 之类高权限上下文，被抓的风险远高于 PC 闲置 |
| CLI 把 refresh_token 转给业务后端 | 业务后端拿到的也是无 sender-constraint 的 7 天凭据；它跟"业务后端自己直连 IdP"是完全等价的事，少了 CLI 这个中间层还更安全 |
| 业务后端用 refresh_token 静默续期 | 跟 CLI 静默续期是同一个问题：用户永远不回 IdP、统一登出失效 |

**替代方案**：业务后端拿到的应该是它**自己的**、**自签**的、不依赖 IdP 的短期访问令牌；它的刷新由 CLI 端发起（CLI 用设备令牌调业务后端 /refresh 之类，提示用户重新授权）。这条路径用户**看得见**重新授权，但每次不超过 1 分钟（自动 consent + 浏览器不弹），成本可控。

## 卸载这套设计的判据（什么时候可以打破）

| 现象 | 说明可以打破 | 说明仍应坚持 |
|---|---|---|
| 上 mTLS / DPoP / sender-constrained token | refresh_token 持久化安全边际升高（但 IdP 要重写） | 用户回 IdP 频率问题仍存在 |
| 加入"周期性重新确认身份"机制（如每月强制 MFA） | 滑动会话让用户面对每次提示 | 用户永远不回 IdP 仍是个 UX 风险 |
| 引入机密客户端（用 client_secret + 服务端持久化） | 服务端持久化 refresh_token 是通行做法 | 此非 client 端长期登录，而是后台 service-to-service；走的是 B 序列里"service account"那条分支，不混 |

## 完整证据链（无遗漏锚点）

| 文件 | 行号 | 内容 |
|---|---|---|
| `auth-hub/internal/consts/consts.go` | 227-237 | ClientMnRT 注释"ClientID 是审计与吊销的单位"，确认 5 个公共客户端无 secret |
| `auth-hub/internal/controller/oidc/oidc.go` | 256+ (Token handler) | token 端点接收 client_id，但**不**校验 secret |
| `mn-rt/server/src/auth.js` | 23-27 | "认证中心的 token 一律不持久化" 注释 |
| `mn-rt/server/src/auth.js` | 168-173 | exchange 内部 userinfo Bearer 单次使用 |
| `mn-rt/server/src/auth.js` | 185-203 | verifyBearer 内部 userinfo Bearer 单次使用 |
| `mn-rt/client/lib/auth.js` | 1-33 | 顶部"换到的 refresh_token 直接丢弃" |
| `mn-rt/client/lib/auth.js` | 236-244 | token 交换的 form，无落地 |
| `mn-rt/client/lib/config.js` | 116-168 | 持久化字段无 access_token / refresh_token |
| `fr/lib/api/remotetype/remotetype_endpoint.dart` | 63-95 | App 用 code+verifier POST 给 mn-rt；不接触 IdP token |
| `fr/lib/api/remotetype/remotetype_grant_store.dart` | 21-33 | `_legacyKeys` 只删不写（refresh_token、idp_token、session_key） |
| `fr/lib/services/remotetype/remotetype_service.dart` | 150-161 | "看起来续期" 实际是 401 → ensureGrant(force) → 走完整 OAuth dance |
| `fr/lib/services/auth/unified_auth_service.dart` | 160-164 | signOut 清 idp_session + token，不存在 refresh_token 字段 |

## 关联引用

- A02 · 业务侧代码骨架（"凭据不落 String 形参" 的硬纪律源起于此）
- A04 · 一次性验收（"refresh_token 重放" 不是断言项——因为没人持有）
- A05 · 扫码登录与移动端批准（App 静默同意的第一方豁免）
- B01 · 完整链路（看 refresh_token 在哪一跳被"拒绝落库"）
- B02 · 服务自提供（如果真要做后台 service-to-service，自建机密客户端）