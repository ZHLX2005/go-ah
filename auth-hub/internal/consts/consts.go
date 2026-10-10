// Package consts 收敛全平台的常量：表名、Cookie 名、有效期、表字段名。
//
// 表名与字段名集中在这里，是为了让「拼字符串写 SQL」这件事只发生在一处：
// 业务代码里出现裸的表名/字段名，改表结构时就会漏改，而且漏改不会报错，
// 只会在运行期变成一个查不到数据的空结果。
package consts

import "time"

// ── 表名 ────────────────────────────────────────────────────────────────────
//
// 表名沿用 GORM 时代生成的实际库表名（复数化 + OAuth 被拆成 o_auth），
// **不要"顺手改成漂亮名字"**：线上 auth_hub schema 里这些表已有数据
// （用户、客户端、签名密钥），改名意味着一次数据迁移，收益为零、风险全是。
// 需要可读性的地方，用 Go 侧的实体名（OAuthClient）而不是表名。
const (
	TableUser                   = "users"
	TableOAuthClient            = "o_auth_clients"
	TableOAuthAuthorizationCode = "o_auth_authorization_codes"
	TableOAuthRefreshToken      = "o_auth_refresh_tokens"
	TableOAuthAccessToken       = "o_auth_access_tokens"
	TableUserSession            = "user_sessions"
	TableSigningKey             = "signing_key_records"

	// 邀请码相关（自助注册的门槛）。表名是本项目新加的，没有历史包袱，
	// 因此用复数蛇形（与 users 一致），不必像 o_auth_* 那样迁就 GORM 的命名。
	TableInvitationCode      = "invitation_codes"
	TableInvitationCodeUsage = "invitation_code_usages"
)

// ── Cookie / 会话 ───────────────────────────────────────────────────────────
const (
	// SessionCookieName 全局会话 Cookie 名（IdP 侧 SSO 会话）
	SessionCookieName = "idp_session"
	// CtxKeyAdminUser 管理后台中间件把当前管理员放进请求上下文用的键。
	//
	// 用字符串键而不是私有类型键，是为了与迁移前的实现保持同一观测口径
	// （旧实现在 gin.Context 上用 "admin_user" 存同一个对象）；
	// 键名在这里单点定义，避免中间件与控制器各写一份字面量而写歪。
	CtxKeyAdminUser = "admin_user"
	// SigningKeyEnv 用固定密钥启动的环境变量名（多副本部署共用同一把）
	SigningKeyEnv = "IDP_SIGNING_KEY_PEM"
	// DefaultKeyID 写入 JWT 头的 kid
	DefaultKeyID = "idp-key-1"
)

// ── 有效期 ──────────────────────────────────────────────────────────────────
const (
	// AccessTokenTTL access_token 有效期 10 分钟
	AccessTokenTTL = 10 * time.Minute
	// RefreshTokenTTL refresh_token 有效期 7 天
	RefreshTokenTTL = 7 * 24 * time.Hour
	// AuthCodeTTL 授权码有效期 5 分钟
	AuthCodeTTL = 5 * time.Minute
	// SessionTTL 全局会话有效期 8 小时
	SessionTTL = 8 * time.Hour
	// IDTokenTTL id_token 有效期 1 小时
	IDTokenTTL = 1 * time.Hour
)

// ── 数据库 ──────────────────────────────────────────────────────────────────
const (
	// DefaultSchema auth-hub 的表统一落在独立 schema 里。
	//
	// 为什么不能直接用 public：这台 PG 是共享实例，public 下已经有别人的
	// 同名 users 表。不隔离的话建表会去动那张表、或被它的结构卡住 ——
	// 两种结果都很难查。
	DefaultSchema = "auth_hub"

	// DefaultDSN 共享 PG（与 gs-ac 同一实例，不同 schema）。
	// 生产应通过 IDP_DSN 覆盖，不要把连接串固化进镜像。
	DefaultDSN = "pgsql:postgres:REDACTED@tcp(47.110.80.47:5432)/postgres?sslmode=disable&search_path=" + DefaultSchema
)

// ── 邀请码 ──────────────────────────────────────────────────────────────────
//
// 邀请码是自助注册的**唯一门槛**：没有它就无法注册。所以它的生成强度与
// 校验严格程度，直接等于注册入口的安全强度 —— 这里没有"够用就行"。
const (
	// InvitationCodePrefix 邀请码前缀。
	//
	// 加前缀不是为了好看，而是让它**在日志与截图里一眼可辨**：
	// 运维排查时看到 inv_ 开头的串就知道该去邀请码表查，而不是当成
	// 某个 token 或会话 ID 去找；用户把它贴进工单时也不会被误认成密码。
	InvitationCodePrefix = "inv_"
	// InvitationCodeBytes 邀请码随机部分的字节数。
	//
	// 12 字节 = 96 bit，base64url 编码后 16 字符。邀请码与 token 不同：
	// token 藏在 HttpOnly Cookie 或 SDK 里，而邀请码是**会被转述、粘贴、
	// 截图**的短凭据，被枚举的风险更高。96 bit 让暴力枚举在成本上不可行，
	// 同时长度还在人能念出来的范围内。
	InvitationCodeBytes = 12
	// DefaultInvitationMaxUses 新建邀请码时的默认可用次数（一人一码是常态）
	DefaultInvitationMaxUses = 1
	// MaxInvitationUses 单张邀请码允许配置的最大次数。
	//
	// 设上限是为了挡住"手滑多打几个零"：一个 999999999 次的邀请码，
	// 效果上等于把注册入口完全敞开 —— 那正是邀请制要防的事。
	MaxInvitationUses = 1000
	// MaxInvitationValidDays 单张邀请码允许配置的最长有效期（天）
	MaxInvitationValidDays = 3650
)

// ── 注册校验 ────────────────────────────────────────────────────────────────
//
// 长度上下限集中在常量里，是为了让"前端提示"与"后端拒绝"引用同一组数字。
// 两处各写一份的下场是前端放过去、后端拒掉，用户在表单上反复改却看不出
// 问题出在哪一位。
const (
	// MinUsernameLength 账号最短长度
	MinUsernameLength = 3
	// MaxUsernameLength 账号最长长度（表列为 VARCHAR(64)，这里留足余量）
	MaxUsernameLength = 32
	// MinPasswordLength 口令最短长度
	MinPasswordLength = 8
	// MaxPasswordLength 口令最长长度。
	//
	// 上限是防御：网关、访问日志、哈希前的拷贝都会先被这个体积拖住，
	// 而"把一兆文本当口令提交"从来不是正常用户会做的事。
	MaxPasswordLength = 128
	// MaxEmailLength 邮箱最长长度（与 users.email 的 VARCHAR(128) 对齐）
	MaxEmailLength = 128
)

// ── 唯一核心管理员 ──────────────────────────────────────────────────────────
//
// 平台**只有一个**管理员账号：它由 seed 保证存在，其余账号一律不是管理员
// （见 db.seed 的收敛逻辑）。管理权限是"发邀请码"的前置能力，而邀请码
// 又是账号进入本平台的唯一入口，所以这一项等于全平台的权限根。
//
// 这三个值只是**开发/CI 的默认值**，真实部署必须用 IDP_ADMIN_USERNAME /
// IDP_ADMIN_EMAIL / IDP_ADMIN_PASSWORD 覆盖：本仓库是公开的，
// 写在这里的口令等于公开的口令。默认值故意保留 test 系列，
// 是为了让本地 go run 与 CI 的既有用例不必改配置就能跑。
const (
	// SeedAdminUsername 唯一核心管理员的账号名
	SeedAdminUsername = "test"
	// SeedAdminEmail 唯一核心管理员的邮箱，也是它的登录名
	SeedAdminEmail = "test@example.com"
	// SeedAdminPassword 唯一核心管理员的初始口令（仅在新建账号时写入）
	SeedAdminPassword = "test123456"
)

// ── 预置数据 ────────────────────────────────────────────────────────────────
const (
	// ClientTemplateWeb 模板业务平台的 client_id
	ClientTemplateWeb = "template-web-client"
	// ClientGSAC gs-ac 权限管理平台的 client_id
	ClientGSAC = "gs-ac"
	// ClientCLI 命令行客户端的 client_id
	ClientCLI = "oidc-cli"
)
