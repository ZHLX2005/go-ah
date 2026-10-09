// Package v1 定义 OIDC 端点的请求与响应结构。
//
// 这里的字段名就是**对外协议**：前端与业务方（gs-ac）按它取值，
// 改动等于破坏兼容。因此每个字段都写了说明，且一律用 snake_case ——
// OIDC 是公开标准，字段名不能自创。
package v1

import "github.com/gogf/gf/v2/frame/g"

// ── 发现文档 ────────────────────────────────────────────────────────────────

// DiscoveryReq GET /.well-known/openid-configuration
type DiscoveryReq struct {
	g.Meta `path:"/.well-known/openid-configuration" method:"get" tags:"OIDC" summary:"OIDC 发现文档"`
}

// DiscoveryRes 发现文档内容（字段由 OIDC Discovery 1.0 规定）
type DiscoveryRes struct {
	Issuer                            string   `json:"issuer"`
	AuthorizationEndpoint             string   `json:"authorization_endpoint"`
	TokenEndpoint                     string   `json:"token_endpoint"`
	UserinfoEndpoint                  string   `json:"userinfo_endpoint"`
	JwksURI                           string   `json:"jwks_uri"`
	EndSessionEndpoint                string   `json:"end_session_endpoint"`
	RevocationEndpoint                string   `json:"revocation_endpoint"`
	ResponseTypesSupported            []string `json:"response_types_supported"`
	GrantTypesSupported               []string `json:"grant_types_supported"`
	SubjectTypesSupported             []string `json:"subject_types_supported"`
	IDTokenSigningAlgValuesSupported  []string `json:"id_token_signing_alg_values_supported"`
	ScopesSupported                   []string `json:"scopes_supported"`
	TokenEndpointAuthMethodsSupported []string `json:"token_endpoint_auth_methods_supported"`
	CodeChallengeMethodsSupported     []string `json:"code_challenge_methods_supported"`
}

// ── JWKS ────────────────────────────────────────────────────────────────────

// JwksReq GET /.well-known/jwks.json
type JwksReq struct {
	g.Meta `path:"/.well-known/jwks.json" method:"get" tags:"OIDC" summary:"签名公钥集"`
}

// JwkKey 单个公钥（RSA）
type JwkKey struct {
	Kty string `json:"kty"`
	Use string `json:"use"`
	Alg string `json:"alg"`
	Kid string `json:"kid"`
	N   string `json:"n"` // modulus，base64url
	E   string `json:"e"` // exponent，base64url
}

// JwksRes 公钥集
type JwksRes struct {
	Keys []JwkKey `json:"keys"`
}

// ── 授权端点 ────────────────────────────────────────────────────────────────

// AuthorizeReq GET /oauth2/auth（浏览器跳转，无响应体）
type AuthorizeReq struct {
	g.Meta              `path:"/oauth2/auth" method:"get" tags:"OIDC" summary:"授权端点"`
	ClientID            string `json:"client_id"            in:"query"`
	RedirectURI         string `json:"redirect_uri"         in:"query"`
	ResponseType        string `json:"response_type"        in:"query"`
	Scope               string `json:"scope"                in:"query"`
	State               string `json:"state"                in:"query"`
	CodeChallenge       string `json:"code_challenge"       in:"query"`
	CodeChallengeMethod string `json:"code_challenge_method" in:"query"`
	Nonce               string `json:"nonce"                in:"query"`
}

// ConsentInfoReq GET /api/consent
type ConsentInfoReq struct {
	g.Meta   `path:"/api/consent" method:"get" tags:"OIDC" summary:"授权确认页信息"`
	ClientID string `json:"client_id" in:"query"`
	Scope    string `json:"scope"     in:"query"`
}

// ConsentUser 授权确认页展示的用户信息
type ConsentUser struct {
	Username string `json:"username"`
	Nickname string `json:"nickname"`
	Email    string `json:"email"`
}

// ConsentInfoRes 授权确认页信息
type ConsentInfoRes struct {
	ClientName string      `json:"client_name"`
	ClientID   string      `json:"client_id"`
	Scopes     []string    `json:"scopes"`
	User       ConsentUser `json:"user"`
}

// ConsentReq POST /api/consent
type ConsentReq struct {
	g.Meta              `path:"/api/consent" method:"post" tags:"OIDC" summary:"同意/拒绝授权"`
	ClientID            string `json:"client_id"`
	RedirectURI         string `json:"redirect_uri"`
	Scope               string `json:"scope"`
	State               string `json:"state"`
	Nonce               string `json:"nonce"`
	CodeChallenge       string `json:"code_challenge"`
	CodeChallengeMethod string `json:"code_challenge_method"`
	Decision            string `json:"decision"` // allow / deny
}

// ConsentRes 授权结果：给出前端要跳转的地址（由前端执行跳转）
type ConsentRes struct {
	RedirectTo string `json:"redirect_to"`
}

// ── 令牌端点 ────────────────────────────────────────────────────────────────

// TokenReq POST /oauth2/token（表单编码，支持 Basic 客户端认证）
type TokenReq struct {
	g.Meta       `path:"/oauth2/token" method:"post" tags:"OIDC" summary:"令牌端点"`
	GrantType    string `json:"grant_type"    in:"form"`
	ClientID     string `json:"client_id"     in:"form"`
	Code         string `json:"code"          in:"form"`
	RedirectURI  string `json:"redirect_uri"  in:"form"`
	CodeVerifier string `json:"code_verifier" in:"form"`
	RefreshToken string `json:"refresh_token" in:"form"`
}

// TokenRes 令牌响应
type TokenRes struct {
	AccessToken  string `json:"access_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int    `json:"expires_in"`
	RefreshToken string `json:"refresh_token"`
	IDToken      string `json:"id_token"`
	Scope        string `json:"scope"`
}

// ── userinfo ────────────────────────────────────────────────────────────────

// UserInfoReq GET /oauth2/userinfo（Bearer access_token）
type UserInfoReq struct {
	g.Meta      `path:"/oauth2/userinfo" method:"get" tags:"OIDC" summary:"用户信息端点"`
	AccessToken string `json:"access_token" in:"query"`
}

// ── 令牌吊销 ────────────────────────────────────────────────────────────────

// RevokeReq POST /oauth2/revoke（RFC 7009）
type RevokeReq struct {
	g.Meta        `path:"/oauth2/revoke" method:"post" tags:"OIDC" summary:"令牌吊销"`
	Token         string `json:"token"           in:"form"`
	ClientID      string `json:"client_id"       in:"form"`
	TokenTypeHint string `json:"token_type_hint" in:"form"`
}

// RevokeRes 按 RFC 7009 恒返回该结构
type RevokeRes struct {
	Status string `json:"status"`
}

// ── 统一登出 ────────────────────────────────────────────────────────────────

// LogoutReq GET /oauth2/logout
type LogoutReq struct {
	g.Meta                `path:"/oauth2/logout" method:"get" tags:"OIDC" summary:"RP 发起单点登出"`
	PostLogoutRedirectURI string `json:"post_logout_redirect_uri" in:"query"`
	ClientID              string `json:"client_id" in:"query"`
	State                 string `json:"state"     in:"query"`
}

// LogoutRes 未指定回跳地址时返回
type LogoutRes struct {
	Status string `json:"status"`
}
