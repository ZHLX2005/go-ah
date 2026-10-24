# 安全加固上线须知（hardening-rollout）

本文配套 2026-10 的一批安全修复：client_secret 强制校验、授权码抢占式消费
与重放吊销、登录/令牌端点限流与错误码合并、四表过期清理、管理员默认口令
启动闸门、`/healthz`、JWKS 缓存头。**上线前必须过一遍第 1、2 节**，
否则线上客户端会在升级后的第一次续期被打断。

## 1. 机密客户端：升级前先发 secret

token 端点开始强制校验 `client_secret`（public 客户端豁免，无感知）。
管理后台手工创建的 **confidential 客户端**（`is_public=false`）此前从未被
要求发送 secret，升级后它们必须带上正确 secret 才能换令牌。

上线顺序：

1. 在线上库预检影响面（谁在活跃续期）：

   ```sql
   SELECT client_id, is_public FROM auth_hub.o_auth_clients ORDER BY id;
   SELECT client_id, count(*) FROM auth_hub.o_auth_refresh_tokens
   WHERE revoked_at IS NULL AND expires_at > now() GROUP BY client_id;
   ```

2. 给每个 `is_public=false` 且有活跃令牌的客户端配好 secret：
   模板业务服务器走 `OIDC_CLIENT_SECRET` env（代码已留好，不用改代码）；
   dev_ctr_hello 走 `DEV_CTR_OIDC_CLIENT_SECRET`。
3. 确认 `dev-ctr-hello` 客户端注册为 `is_public=true`（它不在种子列表，
   是手工注册的，靠这条预检兜底）。
4. 再升级 IdP。

种子五客户端（template-web-client / gs-ac / oidc-cli / fr-app / mn-rt）
全部是 public + PKCE，不受影响（已按四个客户端仓库逐一核实，见
「go-ah客户端」调研结论：fr 不直连 token 端点、gs-ac 与 dev_ctr_hello
换完即弃、mn-rt CLI 与 server 均不发 secret）。

## 2. 管理员口令闸门：部署 env 自检

连接**非本机**数据库（host 不是 127.0.0.1/localhost/::1）且
`IDP_ADMIN_PASSWORD` 仍是公开默认值时，**拒绝启动**。忘配 env 的部署
会在升级后起不来——这是刻意的：唯一管理员能发邀请码，是全平台权限根。
已存在的管理员账号不会被新口令覆盖（seed 只在新建时写口令）。

## 3. 行为变化清单（对客户端）

| 端点 | 变化 | 影响 |
|---|---|---|
| `/oauth2/token` | 机密客户端强制 secret；禁用客户端拒绝；IP 限流 20/min（突发 60） | 见第 1 节 |
| `/oauth2/token` | 授权码并发重放单方成功，**且重放触发该 code 已发令牌全量吊销**（RFC 6749 §4.1.2） | 正常客户端无感 |
| `/api/login` | `user_not_found`/`wrong_password` 合并为 `invalid_credentials`（真实原因进服务端日志）；IP 限流 5/min（突发 10） | 前端文案统一为"账号或密码错误" |
| `/api/register` | IP 限流 3/min（突发 6） | 正常注册无感 |
| `/.well-known/jwks.json` | `Cache-Control: public, max-age=300`（覆盖全局 no-store） | 验签方拉取频率显著下降；密钥轮换至多 5 分钟收敛 |
| `/healthz` | 新增：DB 可达返回 200，否则 503 | 供 LB/K8s 探活 |
| 令牌四表 | janitor 每小时分批清理过期行（保留期见 consts.TokenPurge*） | 首次上线可能清掉大量积压行（分批 5000 行/批，无长事务） |

## 4. 遗留项（本次未做）

- **users.email 唯一索引**：盲加会让有重复数据的线上库启动失败。先跑
  `SELECT email, count(*) FROM auth_hub.users GROUP BY email HAVING count(*)>1`
  确认为零，再手工 `CREATE UNIQUE INDEX CONCURRENTLY`。
- **refresh_token 轮换、密钥轮换路径、Back-Channel Logout**：协议债，
  客户端侧成本已调研（见「go-ah客户端」看板对应报告），留待下一轮。
- **client_secret 明文存储**（管理端历史决定）：本轮靠常数时间比较缓解，
  哈希化 + 登录时 opportunistic rehash 留待下一轮。
