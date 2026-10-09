// Package internal 存放 dao 的底层定义：表名与列名常量。
//
// 列名集中成结构体，是为了让「拼字段名」这件事有唯一的来源：
// 业务代码里出现裸字符串 "oidc_sub" 这类写法时，改表结构必然漏改，
// 而且漏改不报错 —— 只会变成一个恒假的过滤条件，静默返回错误结果。
package internal

// UserColumns users 表列名
type UserColumns struct {
	Id           string
	Username     string
	PasswordHash string
	Email        string
	Nickname     string
	IsAdmin      string
	CreatedAt    string
	UpdatedAt    string
}

// UserColumnsOf 返回 users 表的列名集合
func UserColumnsOf() UserColumns {
	return UserColumns{
		Id: "id", Username: "username", PasswordHash: "password_hash",
		Email: "email", Nickname: "nickname", IsAdmin: "is_admin",
		CreatedAt: "created_at", UpdatedAt: "updated_at",
	}
}

// OAuthClientColumns o_auth_clients 表列名
type OAuthClientColumns struct {
	Id             string
	ClientID       string
	ClientSecret   string
	ClientName     string
	RedirectURIs   string
	Scopes         string
	IsPublic       string
	PKCERequired   string
	Enabled        string
	PostLogoutURIs string
	CreatedAt      string
	UpdatedAt      string
}

// OAuthClientColumnsOf 返回 o_auth_clients 表的列名集合
func OAuthClientColumnsOf() OAuthClientColumns {
	return OAuthClientColumns{
		Id: "id", ClientID: "client_id", ClientSecret: "client_secret",
		ClientName: "client_name", RedirectURIs: "redirect_uris", Scopes: "scopes",
		IsPublic: "is_public", PKCERequired: "pkce_required", Enabled: "enabled",
		PostLogoutURIs: "post_logout_uris", CreatedAt: "created_at", UpdatedAt: "updated_at",
	}
}

// OAuthAuthorizationCodeColumns o_auth_authorization_codes 表列名
type OAuthAuthorizationCodeColumns struct {
	Id                  string
	Code                string
	ClientID            string
	UserID              string
	RedirectURI         string
	Scope               string
	Nonce               string
	CodeChallenge       string
	CodeChallengeMethod string
	ExpiresAt           string
	UsedAt              string
	CreatedAt           string
}

// OAuthAuthorizationCodeColumnsOf 返回 o_auth_authorization_codes 表的列名集合
func OAuthAuthorizationCodeColumnsOf() OAuthAuthorizationCodeColumns {
	return OAuthAuthorizationCodeColumns{
		Id: "id", Code: "code", ClientID: "client_id", UserID: "user_id",
		RedirectURI: "redirect_uri", Scope: "scope", Nonce: "nonce",
		CodeChallenge: "code_challenge", CodeChallengeMethod: "code_challenge_method",
		ExpiresAt: "expires_at", UsedAt: "used_at", CreatedAt: "created_at",
	}
}

// OAuthRefreshTokenColumns o_auth_refresh_tokens 表列名
type OAuthRefreshTokenColumns struct {
	Id        string
	Token     string
	ClientID  string
	UserID    string
	Scope     string
	ExpiresAt string
	RevokedAt string
	CreatedAt string
}

// OAuthRefreshTokenColumnsOf 返回 o_auth_refresh_tokens 表的列名集合
func OAuthRefreshTokenColumnsOf() OAuthRefreshTokenColumns {
	return OAuthRefreshTokenColumns{
		Id: "id", Token: "token", ClientID: "client_id", UserID: "user_id",
		Scope: "scope", ExpiresAt: "expires_at", RevokedAt: "revoked_at", CreatedAt: "created_at",
	}
}

// OAuthAccessTokenColumns o_auth_access_tokens 表列名
type OAuthAccessTokenColumns struct {
	Id        string
	Token     string
	ClientID  string
	UserID    string
	Scope     string
	ExpiresAt string
	CreatedAt string
}

// OAuthAccessTokenColumnsOf 返回 o_auth_access_tokens 表的列名集合
func OAuthAccessTokenColumnsOf() OAuthAccessTokenColumns {
	return OAuthAccessTokenColumns{
		Id: "id", Token: "token", ClientID: "client_id", UserID: "user_id",
		Scope: "scope", ExpiresAt: "expires_at", CreatedAt: "created_at",
	}
}

// UserSessionColumns user_sessions 表列名
type UserSessionColumns struct {
	Id        string
	SessionID string
	UserID    string
	ExpiresAt string
	CreatedAt string
}

// UserSessionColumnsOf 返回 user_sessions 表的列名集合
func UserSessionColumnsOf() UserSessionColumns {
	return UserSessionColumns{
		Id: "id", SessionID: "session_id", UserID: "user_id",
		ExpiresAt: "expires_at", CreatedAt: "created_at",
	}
}

// SigningKeyColumns signing_key_records 表列名
type SigningKeyColumns struct {
	Id        string
	KeyID     string
	Pem       string
	CreatedAt string
}

// SigningKeyColumnsOf 返回 signing_key_records 表的列名集合
func SigningKeyColumnsOf() SigningKeyColumns {
	return SigningKeyColumns{
		Id: "id", KeyID: "key_id", Pem: "pem", CreatedAt: "created_at",
	}
}
