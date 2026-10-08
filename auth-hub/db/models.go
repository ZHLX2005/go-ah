package db

import (
	"time"
)

// User 统一登录平台的用户账号
type User struct {
	ID           uint   `gorm:"primaryKey" json:"id"`
	Username     string `gorm:"uniqueIndex;size:64;not null" json:"username"`
	PasswordHash string `gorm:"size:255;not null" json:"-"`
	Email        string `gorm:"size:128" json:"email"`
	Nickname     string `gorm:"size:64" json:"nickname"`
	// IsAdmin 管理员标记，可访问 /admin 管理后台
	IsAdmin   bool      `gorm:"default:false" json:"is_admin"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

// OAuthClient 注册在 IDP 的 OIDC 客户端（业务方）
// 本项目为 SPA 公共客户端，使用 PKCE，不保存 client_secret
//
// 注意：布尔字段使用 *bool + 默认值写入 seed，避免 GORM 的
// `default:true` 标签把显式的 false 当成零值而忽略，导致无法关闭开关。
type OAuthClient struct {
	ID           uint   `gorm:"primaryKey" json:"id"`
	ClientID     string `gorm:"uniqueIndex;size:64;not null" json:"client_id"`
	ClientSecret string `gorm:"size:255" json:"-"` // 公共客户端可为空
	ClientName   string `gorm:"size:128" json:"client_name"`
	RedirectURIs string `gorm:"type:text" json:"redirect_uris"` // 多个用换行/空格分隔
	Scopes       string `gorm:"type:text" json:"scopes"`
	// IsPublic 是否为公共客户端(PKCE 无密钥)
	IsPublic *bool `json:"is_public"`
	// PKCERequired 是否强制 PKCE（公共客户端建议始终开启）
	PKCERequired *bool `json:"pkce_required"`
	// Enabled 是否启用；禁用后授权端点直接拒绝
	Enabled        *bool     `json:"enabled"`
	PostLogoutURIs string    `gorm:"type:text" json:"post_logout_uris"`
	CreatedAt      time.Time `json:"created_at"`
	UpdatedAt      time.Time `json:"updated_at"`
}

// IsPublicClient 安全读取 IsPublic（nil 视为 true）
func (c *OAuthClient) IsPublicClient() bool {
	return c.IsPublic == nil || *c.IsPublic
}

// PKCENeeded 安全读取 PKCERequired（nil 视为 true）
func (c *OAuthClient) PKCENeeded() bool {
	return c.PKCERequired == nil || *c.PKCERequired
}

// IsEnabled 安全读取 Enabled（nil 视为 true）
func (c *OAuthClient) IsEnabled() bool {
	return c.Enabled == nil || *c.Enabled
}

// BoolPtr 返回布尔指针，便于赋值
func BoolPtr(b bool) *bool { return &b }

// OAuthAuthorizationCode 一次性授权码
type OAuthAuthorizationCode struct {
	ID                  uint       `gorm:"primaryKey"`
	Code                string     `gorm:"uniqueIndex;size:128;not null"`
	ClientID            string     `gorm:"index;size:64;not null"`
	UserID              uint       `gorm:"index;not null"`
	RedirectURI         string     `gorm:"size:255"`
	Scope               string     `gorm:"size:255"`
	Nonce               string     `gorm:"size:128"`
	CodeChallenge       string     `gorm:"size:128"`
	CodeChallengeMethod string     `gorm:"size:16"`
	ExpiresAt           time.Time  `gorm:"index"`
	UsedAt              *time.Time // 非空表示已被使用（一次性）
	CreatedAt           time.Time
}

// OAuthRefreshToken 刷新令牌
type OAuthRefreshToken struct {
	ID        uint       `gorm:"primaryKey"`
	Token     string     `gorm:"uniqueIndex;size:128;not null"`
	ClientID  string     `gorm:"index;size:64"`
	UserID    uint       `gorm:"index"`
	Scope     string     `gorm:"size:255"`
	ExpiresAt time.Time  `gorm:"index"`
	RevokedAt *time.Time // 非空表示已吊销
	CreatedAt time.Time
}

// OAuthAccessToken 访问令牌
// 用于 /oauth2/userinfo 的 Bearer 鉴权；TTL 10 分钟（Task4 续期规则）
type OAuthAccessToken struct {
	ID        uint      `gorm:"primaryKey"`
	Token     string    `gorm:"uniqueIndex;size:128;not null"`
	ClientID  string    `gorm:"index;size:64"`
	UserID    uint      `gorm:"index"`
	Scope     string    `gorm:"size:255"`
	ExpiresAt time.Time `gorm:"index"`
	CreatedAt time.Time
}

// UserSession 全局登录会话（IDP 侧 SSO 会话）
type UserSession struct {
	ID        uint      `gorm:"primaryKey"`
	SessionID string    `gorm:"uniqueIndex;size:128;not null"`
	UserID    uint      `gorm:"index"`
	ExpiresAt time.Time `gorm:"index"`
	CreatedAt time.Time
}
