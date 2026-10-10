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

	// TableQRLoginSession 扫码登录票据表（同上，本项目新表，用复数蛇形）。
	//
	// 它是全平台写入频率最高的表：每次登录尝试一行，过期没领走的也是一行。
	// 所以它的清理是硬性要求，见 cmd.startJanitor。
	TableQRLoginSession = "qr_login_sessions"
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

	// QRTicketTTL 扫码票据有效期 2 分钟。
	//
	// 比授权码的 5 分钟紧得多，因为这张票据的语义是"某台浏览器正在等着登录"：
	// 它一旦过期就该彻底作废，而不是留着一个可能被人翻出来领取会话的入口。
	// 2 分钟是"掏出手机 → 解锁 → 打开 App → 看清设备信息 → 点确认"的经验上限；
	// 压到 60 秒会让相当比例的正常用户还没确认完就看到二维码过期。
	QRTicketTTL = 2 * time.Minute

	// QRRetainAfterExpiry 过期票据在库里再留 7 天才清。
	//
	// 清理不是为了省空间，是为了让"这次扫码是谁批的"事后能查：
	// 票据表是扫码登录唯一的审计轨迹，随过随删等于把线索一起烧掉。
	QRRetainAfterExpiry = 7 * 24 * time.Hour
)

// ── 数据库 ──────────────────────────────────────────────────────────────────
const (
	// DefaultSchema auth-hub 的表统一落在独立 schema 里。
	//
	// 为什么不能直接用 public：这台 PG 是共享实例，public 下已经有别人的
	// 同名 users 表。不隔离的话建表会去动那张表、或被它的结构卡住 ——
	// 两种结果都很难查。
	DefaultSchema = "auth_hub"

	// DefaultDSN 本机开发用的默认连接串。
	//
	// ⚠️ 这里**故意不写真实地址和口令**。本仓库是公开的，任何写进源码的
	// 连接串都等于公开的连接串 —— 它同时泄露主机、账号、口令三样东西，
	// 而且换口令要改代码重新发版才能生效。所以默认值指向本机、口令用
	// postgres 这种"一看就是占位"的值：它在本机 docker 里能跑，
	// 在别处跑不了，恰好是正确的默认语义。
	//
	// 真实环境（含 CI）一律用 IDP_DSN 覆盖：CI 用它的 PG service container，
	// 部署用 GitHub secret。部署脚本的 Preflight 会校验 IDP_DSN 非空。
	DefaultDSN = "pgsql:postgres:postgres@tcp(127.0.0.1:5432)/postgres?sslmode=disable&search_path=" + DefaultSchema
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

// ── 扫码登录 ────────────────────────────────────────────────────────────────
//
// 扫码登录的整套设计见 docs/design/qr-login.md。这里只放"必须跨包共用"的量：
// Cookie 名、票据格式、给前端的节奏参数。状态取值在 entity 包里定义
// （它跟着读出来的行走），控制器与前端都从那一处取。
const (
	// QRCtxCookieName 把票据与"发起创建它的那台浏览器"绑死的 Cookie。
	//
	// 这是整个扫码功能的安全支点。没有它，二维码就是一个"谁扫都能用"的凭据：
	// 攻击者把 PC 上的二维码截图发给任意一个已登录的受害者，受害者一扫，
	// 攻击者的浏览器就拿到了受害者的会话 —— 票据的熵在这个场景里一点用没有，
	// 因为扫描者是自愿扫的。有了它，领取会话必须由当初那张二维码所在的
	// 浏览器亲自发起，转发攻击在协议层就不成立。
	QRCtxCookieName = "qr_ctx"
	// QRCtxCookiePath 收敛到 /api/qr：这个 Cookie 只在轮询与领取时有用，
	// 没必要让它出现在全站每一个请求上。
	QRCtxCookiePath = "/api/qr"
	// QRCtxBytes qr_ctx 随机部分的字节数（128 bit，只需不可猜，不落库明文）
	QRCtxBytes = 16

	// QRTicketPrefix 票据前缀，同邀请码：让日志里一眼认得出这是什么
	QRTicketPrefix = "qrt_"
	// QRTicketBytes 票据随机部分的字节数。
	//
	// 32 字节 = 256 bit，比邀请码的 96 bit 宽得多，因为它比邀请码更"廉价"
	// 却更危险：邀请码泄露顶多多放一个人注册进来，票据一旦被猜中并且攻击者
	// 恰好能触发领取，那就是别人的账号。二维码还会被拍照、截图、转发，
	// 暴露面比任何 token 都大，所以这里不给它省那一点长度。
	QRTicketBytes = 32

	// QRPollIntervalMS 建议前端采用的轮询间隔。
	//
	// 由服务端下发而不是前端硬编码：将来换 SSE 或调节奏时，只要改这一处，
	// 老版本前端也会跟着变，不必等用户刷新到新版。
	QRPollIntervalMS = 1500
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
