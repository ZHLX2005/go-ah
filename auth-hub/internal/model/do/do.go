// Package do 是**写入**用的数据对象：只带本次要写的列，未赋值的列不参与 SQL。
//
// 与 entity 的分工见 entity 包注释。字段类型统一用 interface{} 是 GoFrame 的
// 惯例 —— 只有这样才区分得开「没赋值」与「赋了零值」：
// 想把 is_admin 改成 false，用 entity 的 bool 字段写法会得到「零值不写入」，
// 于是关不掉管理员；interface{} 里放 false 则是一次真实的 SET is_admin=false。
package do

import "github.com/gogf/gf/v2/frame/g"

// User users 表的可写列
type User struct {
	g.Meta       `orm:"table:users, do:true"`
	Id           interface{} `orm:"id"`
	Username     interface{} `orm:"username"`
	PasswordHash interface{} `orm:"password_hash"`
	Email        interface{} `orm:"email"`
	Nickname     interface{} `orm:"nickname"`
	IsAdmin      interface{} `orm:"is_admin"`
	CreatedAt    interface{} `orm:"created_at"`
	UpdatedAt    interface{} `orm:"updated_at"`
}

// OAuthClient o_auth_clients 表的可写列
type OAuthClient struct {
	g.Meta         `orm:"table:o_auth_clients, do:true"`
	Id             interface{} `orm:"id"`
	ClientID       interface{} `orm:"client_id"`
	ClientSecret   interface{} `orm:"client_secret"`
	ClientName     interface{} `orm:"client_name"`
	RedirectURIs   interface{} `orm:"redirect_uris"`
	Scopes         interface{} `orm:"scopes"`
	IsPublic       interface{} `orm:"is_public"`
	PKCERequired   interface{} `orm:"pkce_required"`
	Enabled        interface{} `orm:"enabled"`
	PostLogoutURIs interface{} `orm:"post_logout_uris"`
	CreatedAt      interface{} `orm:"created_at"`
	UpdatedAt      interface{} `orm:"updated_at"`
}

// OAuthAuthorizationCode o_auth_authorization_codes 表的可写列
type OAuthAuthorizationCode struct {
	g.Meta              `orm:"table:o_auth_authorization_codes, do:true"`
	Id                  interface{} `orm:"id"`
	Code                interface{} `orm:"code"`
	ClientID            interface{} `orm:"client_id"`
	UserID              interface{} `orm:"user_id"`
	RedirectURI         interface{} `orm:"redirect_uri"`
	Scope               interface{} `orm:"scope"`
	Nonce               interface{} `orm:"nonce"`
	CodeChallenge       interface{} `orm:"code_challenge"`
	CodeChallengeMethod interface{} `orm:"code_challenge_method"`
	ExpiresAt           interface{} `orm:"expires_at"`
	UsedAt              interface{} `orm:"used_at"`
	CreatedAt           interface{} `orm:"created_at"`
}

// OAuthRefreshToken o_auth_refresh_tokens 表的可写列
type OAuthRefreshToken struct {
	g.Meta    `orm:"table:o_auth_refresh_tokens, do:true"`
	Id        interface{} `orm:"id"`
	Token     interface{} `orm:"token"`
	ClientID  interface{} `orm:"client_id"`
	UserID    interface{} `orm:"user_id"`
	Scope     interface{} `orm:"scope"`
	ExpiresAt interface{} `orm:"expires_at"`
	RevokedAt interface{} `orm:"revoked_at"`
	CreatedAt interface{} `orm:"created_at"`
}

// OAuthAccessToken o_auth_access_tokens 表的可写列
type OAuthAccessToken struct {
	g.Meta    `orm:"table:o_auth_access_tokens, do:true"`
	Id        interface{} `orm:"id"`
	Token     interface{} `orm:"token"`
	ClientID  interface{} `orm:"client_id"`
	UserID    interface{} `orm:"user_id"`
	Scope     interface{} `orm:"scope"`
	ExpiresAt interface{} `orm:"expires_at"`
	CreatedAt interface{} `orm:"created_at"`
}

// UserSession user_sessions 表的可写列
type UserSession struct {
	g.Meta    `orm:"table:user_sessions, do:true"`
	Id        interface{} `orm:"id"`
	SessionID interface{} `orm:"session_id"`
	UserID    interface{} `orm:"user_id"`
	ExpiresAt interface{} `orm:"expires_at"`
	CreatedAt interface{} `orm:"created_at"`
}

// SigningKey o_auth_signing 表的可写列
type SigningKey struct {
	g.Meta    `orm:"table:signing_key_records, do:true"`
	Id        interface{} `orm:"id"`
	KeyID     interface{} `orm:"key_id"`
	Pem       interface{} `orm:"pem"`
	CreatedAt interface{} `orm:"created_at"`
}
