// Package v1 声明模板业务平台对外 HTTP 接口的请求与响应形状。
//
// 这些结构体就是**契约**：前端 web/template-web 与 e2e 用例都按这里的字段名
// 解析。迁移底层框架（gin → GoFrame）时逐个字段照抄，包括几个看起来不一致、
// 但前端已经依赖的细节：
//
//   - 成功响应用 {code:0, data:...} 信封，但失败响应**没有 code**，只有
//     {error, message}；
//   - /api/config、/api/health、/api/security-status 是**裸对象**，没有信封；
//   - /api/session 未登录时返回 200 + {code:0, data:null}，靠 data 判断，
//     不是 401（首页要用它来决定显示登录入口还是用户名）；
//   - /api/logout 的响应既有 code 又有 message，还带两个扁平字段。
//
// 这些不是随手写的形状，是前端已经按它们解析的结果。迁移期间"顺手统一"
// 就是破坏兼容。
package v1

import "time"

// ── 通用于失败响应 ──────────────────────────────────────────────────────────

// ErrorRes 失败响应：只有 error（与可选 message），没有 code 信封
type ErrorRes struct {
	Error   string `json:"error"`
	Message string `json:"message,omitempty"`
}

// ── GET /api/config ────────────────────────────────────────────────────────
//
// 裸对象：前端启动时直接读字段，用来在浏览器侧生成 PKCE 参数。
// client_secret 绝不下发，这里也没有它的位置。

// PublicConfigRes OIDC 公共配置
type PublicConfigRes struct {
	ClientID      string `json:"client_id"`
	RedirectURI   string `json:"redirect_uri"`
	Scope         string `json:"scope"`
	PostLogoutURI string `json:"post_logout_uri"`
	IDPIssuer     string `json:"idp_issuer"`

	AuthorizationEndpoint string `json:"authorization_endpoint"`
	// TokenEndpoint 仅在成功连上 IDP 时才有值：连不上时前端拿不到它，
	// 也就不该以为自己能换 token。omitempty 保留这个语义。
	TokenEndpoint      string `json:"token_endpoint,omitempty"`
	EndSessionEndpoint string `json:"end_session_endpoint"`

	IDPAvailable bool `json:"idp_available"`
	// IDPError 只在 IDP 不可用时出现，直接展示给排障的人
	IDPError string `json:"idp_error,omitempty"`
}

// ── POST /api/auth/callback ────────────────────────────────────────────────

// AuthCallbackReq 回调页提交的 PKCE 授权码
type AuthCallbackReq struct {
	Code         string `json:"code"`
	State        string `json:"state"`
	CodeVerifier string `json:"code_verifier"`
	// RedirectURI 非空时覆盖配置里的回调地址，保证与授权请求时一致
	RedirectURI string `json:"redirect_uri"`
}

// UserData 业务用户的对外字段（登录成功后回给前端）
type UserData struct {
	Sub      string `json:"sub"`
	Username string `json:"username"`
	Nickname string `json:"nickname"`
	Email    string `json:"email"`
}

// AuthCallbackRes 建会话成功的业务信封
type AuthCallbackRes struct {
	Code int      `json:"code"`
	Data UserData `json:"data"`
}

// ── GET /api/session ───────────────────────────────────────────────────────

// SessionData 轻量登录态
type SessionData struct {
	Sub       string    `json:"sub"`
	ExpiresAt time.Time `json:"expires_at"`
}

// SessionRes 未登录时 Data 为 nil → 序列化成 null（前端按 data 判空）
type SessionRes struct {
	Code int          `json:"code"`
	Data *SessionData `json:"data"`
}

// ── GET /api/profile ───────────────────────────────────────────────────────

// ProfileData 受保护的用户资料 + 会话/令牌状态
//
// token 本身绝不下发，只给 has_* 布尔标记：前端要展示"续期是否生效"，
// 但没有任何理由拿到 JWT。
type ProfileData struct {
	Sub         string    `json:"sub"`
	Username    string    `json:"username"`
	Nickname    string    `json:"nickname"`
	Email       string    `json:"email"`
	LastLoginAt time.Time `json:"last_login_at"`

	SessionExpiresAt time.Time `json:"session_expires_at"`
	HasIDToken       bool      `json:"has_id_token"`
	HasRefreshToken  bool      `json:"has_refresh_token"`

	TokenEncrypted        bool      `json:"token_encrypted"`
	AccessTokenExpiresAt  time.Time `json:"access_token_expires_at"`
	RefreshTokenExpiresAt time.Time `json:"refresh_token_expires_at"`
}

// ProfileRes 资料响应
type ProfileRes struct {
	Code int         `json:"code"`
	Data ProfileData `json:"data"`
}

// ── POST /api/refresh ──────────────────────────────────────────────────────

// RefreshRes 主动续期的结果
type RefreshRes struct {
	Code                 int       `json:"code"`
	Message              string    `json:"message"`
	AccessTokenExpiresAt time.Time `json:"access_token_expires_at"`
}

// ── POST /api/logout ───────────────────────────────────────────────────────

// LogoutRes 业务会话已销毁 + 需要浏览器跳转的 IDP 登出地址
//
// idp_logout 恒为 true：单点登出必须由前端跳转 IDP 完成，
// 业务侧删掉自己的会话只是第一步。
type LogoutRes struct {
	Code      int    `json:"code"`
	Message   string `json:"message"`
	LogoutURL string `json:"logout_url"`
	IDPLogout bool   `json:"idp_logout"`
}

// ── GET /api/health ────────────────────────────────────────────────────────

// HealthRes 存活探测（裸对象）
type HealthRes struct {
	Status  string `json:"status"`
	Service string `json:"service"`
}

// ── GET /api/security-status ───────────────────────────────────────────────

// TokenEncryption 加密能力状态（不泄漏密钥本身）
type TokenEncryption struct {
	Algorithm  string `json:"algorithm"`
	KDF        string `json:"kdf"`
	Iterations int    `json:"iterations"`
	KeySource  string `json:"key_source"`
	Ready      bool   `json:"ready"`
}

// AutoRefresh 后台续期能力状态
type AutoRefresh struct {
	Enabled        bool   `json:"enabled"`
	AccessTokenTTL string `json:"access_token_ttl"`
	RefreshTTL     string `json:"refresh_ttl"`
	Threshold      string `json:"threshold"`
}

// SecurityStatusRes 安全相关能力总览（裸对象）
type SecurityStatusRes struct {
	TokenEncryption TokenEncryption `json:"token_encryption"`
	AutoRefresh     AutoRefresh     `json:"auto_refresh"`
}
