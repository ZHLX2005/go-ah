// Package entity 是数据库表的 Go 侧映射（一行 = 一个实体）。
//
// 与 do 的分工：entity 用于**读出**（查询结果落进来的形状，字段齐全），
// do 用于**写入**（只带要写的那几个字段，nil 的字段不参与 INSERT/UPDATE）。
// 混用是数据库写入事故的常见来源：拿一个读出来的实体的零值字段去写，
// 会把没打算改的列覆盖成零值。
package entity

import "time"

// User 统一登录平台的用户账号
type User struct {
	Id           int64     `json:"id"           description:"用户ID"`
	Username     string    `json:"username"     description:"登录账号"`
	PasswordHash string    `json:"-"            description:"argon2id 密码哈希"`
	Email        string    `json:"email"        description:"邮箱"`
	Nickname     string    `json:"nickname"     description:"昵称"`
	IsAdmin      bool      `json:"is_admin"     description:"是否管理员"`
	CreatedAt    time.Time `json:"created_at"   description:"创建时间"`
	UpdatedAt    time.Time `json:"updated_at"   description:"更新时间"`
}

// OAuthClient 注册在 IdP 的 OIDC 客户端（业务方）
//
// 三个布尔开关用 *bool：数据库列可空，nil 表示"未显式设置"，
// 语义上按 true 处理（见 IsXxx 方法）。用 bool 的话无法区分
// "没设置"与"显式关掉"，管理后台就没法把开关关掉。
type OAuthClient struct {
	Id             int64     `json:"id"               description:"主键"`
	ClientID       string    `json:"client_id"        description:"客户端ID"`
	ClientSecret   string    `json:"-"               description:"客户端密钥（公共客户端为空）"`
	ClientName     string    `json:"client_name"      description:"客户端名称"`
	RedirectURIs   string    `json:"redirect_uris"    description:"回调白名单，空格分隔"`
	Scopes         string    `json:"scopes"           description:"授权范围，空格分隔"`
	IsPublic       *bool     `json:"is_public"        description:"是否公共客户端"`
	PKCERequired   *bool     `json:"pkce_required"    description:"是否强制 PKCE"`
	Enabled        *bool     `json:"enabled"          description:"是否启用"`
	PostLogoutURIs string    `json:"post_logout_uris" description:"登出回跳白名单，空格分隔"`
	CreatedAt      time.Time `json:"created_at"       description:"创建时间"`
	UpdatedAt      time.Time `json:"updated_at"       description:"更新时间"`
}

// IsPublicClient 安全读取 IsPublic（nil 视为 true）
func (c *OAuthClient) IsPublicClient() bool { return c.IsPublic == nil || *c.IsPublic }

// PKCENeeded 安全读取 PKCERequired（nil 视为 true）
func (c *OAuthClient) PKCENeeded() bool { return c.PKCERequired == nil || *c.PKCERequired }

// IsEnabled 安全读取 Enabled（nil 视为 true）
func (c *OAuthClient) IsEnabled() bool { return c.Enabled == nil || *c.Enabled }

// OAuthAuthorizationCode 一次性授权码
type OAuthAuthorizationCode struct {
	Id                  int64      `json:"id"                      description:"主键"`
	Code                string     `json:"code"                    description:"授权码"`
	ClientID            string     `json:"client_id"               description:"客户端ID"`
	UserID              int64      `json:"user_id"                 description:"用户ID"`
	RedirectURI         string     `json:"redirect_uri"            description:"回调地址"`
	Scope               string     `json:"scope"                   description:"授权范围"`
	Nonce               string     `json:"nonce"                   description:"OIDC nonce"`
	CodeChallenge       string     `json:"code_challenge"          description:"PKCE challenge"`
	CodeChallengeMethod string     `json:"code_challenge_method"   description:"PKCE 方法"`
	ExpiresAt           time.Time  `json:"expires_at"              description:"过期时间"`
	UsedAt              *time.Time `json:"used_at"                 description:"使用时间（非空即已用过）"`
	CreatedAt           time.Time  `json:"created_at"              description:"创建时间"`
}

// OAuthRefreshToken 刷新令牌
type OAuthRefreshToken struct {
	Id        int64      `json:"id"         description:"主键"`
	Token     string     `json:"token"      description:"令牌"`
	ClientID  string     `json:"client_id"  description:"客户端ID"`
	UserID    int64      `json:"user_id"    description:"用户ID"`
	Scope     string     `json:"scope"      description:"授权范围"`
	ExpiresAt time.Time  `json:"expires_at" description:"过期时间"`
	RevokedAt *time.Time `json:"revoked_at" description:"吊销时间（非空即已吊销）"`
	CreatedAt time.Time  `json:"created_at" description:"创建时间"`
}

// OAuthAccessToken 访问令牌（供 /oauth2/userinfo 的 Bearer 鉴权）
type OAuthAccessToken struct {
	Id        int64     `json:"id"         description:"主键"`
	Token     string    `json:"token"      description:"令牌"`
	ClientID  string    `json:"client_id"  description:"客户端ID"`
	UserID    int64     `json:"user_id"    description:"用户ID"`
	Scope     string    `json:"scope"      description:"授权范围"`
	ExpiresAt time.Time `json:"expires_at" description:"过期时间"`
	CreatedAt time.Time `json:"created_at" description:"创建时间"`
}

// UserSession 全局登录会话（IdP 侧 SSO 会话）
type UserSession struct {
	Id        int64     `json:"id"         description:"主键"`
	SessionID string    `json:"session_id" description:"会话ID"`
	UserID    int64     `json:"user_id"    description:"用户ID"`
	ExpiresAt time.Time `json:"expires_at" description:"过期时间"`
	CreatedAt time.Time `json:"created_at" description:"创建时间"`
}

// SigningKeyRecord 持久化的 id_token 签名密钥（RSA 私钥，PKCS#8 PEM）
type SigningKeyRecord struct {
	Id        int64     `json:"id"         description:"主键"`
	KeyID     string    `json:"key_id"     description:"密钥ID（写入 JWT 头的 kid）"`
	Pem       string    `json:"-"          description:"PKCS#8 PEM 私钥，绝不外发"`
	CreatedAt time.Time `json:"created_at" description:"创建时间"`
}
