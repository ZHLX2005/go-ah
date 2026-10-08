package api

import (
	"encoding/base64"
	"encoding/json"
	"log"
	"math/big"
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"

	"github.com/ZHLX2005/go-ah/auth-hub/db"
)

// ============ OIDC 发现与 JWKS ============

// OpenIDConfiguration GET /.well-known/openid-configuration
func OpenIDConfiguration(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{
		"issuer":                                Issuer,
		"authorization_endpoint":                Issuer + "/oauth2/auth",
		"token_endpoint":                        Issuer + "/oauth2/token",
		"userinfo_endpoint":                     Issuer + "/oauth2/userinfo",
		"jwks_uri":                              Issuer + "/.well-known/jwks.json",
		"end_session_endpoint":                  Issuer + "/oauth2/logout",
		"revocation_endpoint":                   Issuer + "/oauth2/revoke",
		"response_types_supported":              []string{"code"},
		"grant_types_supported":                 []string{"authorization_code", "refresh_token"},
		"subject_types_supported":               []string{"public"},
		"id_token_signing_alg_values_supported": []string{"RS256"},
		"scopes_supported":                      []string{"openid", "profile", "email"},
		"token_endpoint_auth_methods_supported": []string{"none", "client_secret_post", "client_secret_basic"},
		"code_challenge_methods_supported":      []string{"S256", "plain"},
	})
}

// JWKS GET /.well-known/jwks.json —— 暴露 RSA 公钥
func JWKS(c *gin.Context) {
	pub := db.SigningKey.PublicKey
	c.JSON(http.StatusOK, gin.H{
		"keys": []gin.H{{
			"kty": "RSA",
			"use": "sig",
			"alg": "RS256",
			"kid": db.KeyID,
			"n":   base64.RawURLEncoding.EncodeToString(pub.N.Bytes()),
			"e":   base64.RawURLEncoding.EncodeToString(big.NewInt(int64(pub.E)).Bytes()),
		}},
	})
}

// ============ /oauth2/auth 授权端点 ============

// Authorize GET /oauth2/auth
// 1) 校验 client / redirect_uri / response_type / PKCE 参数
// 2) 未登录 -> 302 到 React 登录页，并带上原始参数以便登录后续接
// 3) 已登录 -> 302 到 React 授权确认页 /consent
func Authorize(c *gin.Context) {
	clientID := c.Query("client_id")
	redirectURI := c.Query("redirect_uri")
	responseType := c.Query("response_type")
	scope := c.DefaultQuery("scope", "openid")
	state := c.Query("state")
	challenge := c.Query("code_challenge")
	method := c.DefaultQuery("code_challenge_method", "S256")

	var client db.OAuthClient
	if err := db.DB.Where("client_id = ?", clientID).First(&client).Error; err != nil {
		c.String(http.StatusBadRequest, "invalid client_id")
		return
	}
	// 客户端被禁用则拒绝授权
	if !client.IsEnabled() {
		c.String(http.StatusBadRequest, "该客户端已被禁用（请联系管理员在管理后台启用）")
		return
	}
	if !clientAllowsRedirect(&client, redirectURI) {
		c.String(http.StatusBadRequest, "redirect_uri 未在客户端注册白名单内")
		return
	}
	if responseType != "code" {
		errorRedirect(c, redirectURI, state, "unsupported_response_type", "仅支持 code 模式")
		return
	}
	if !strings.Contains(scope, "openid") {
		errorRedirect(c, redirectURI, state, "invalid_scope", "必须包含 openid scope")
		return
	}
	// 要求 PKCE 的客户端必须携带 code_challenge
	if client.PKCENeeded() && challenge == "" {
		errorRedirect(c, redirectURI, state, "invalid_request", "缺少 code_challenge（该客户端要求 PKCE）")
		return
	}
	// 仅支持 S256
	if challenge != "" && method != "S256" && method != "plain" {
		errorRedirect(c, redirectURI, state, "invalid_request", "仅支持 S256 / plain 的 code_challenge_method")
		return
	}
	// 将原始请求参数串透传给前端页面，登录/授权完成后原样回提
	orig := c.Request.URL.RawQuery

	if user := currentUser(c); user == nil {
		// 未登录：跳转 React 登录页，携带 return_to 指向真正的授权地址
		loginURL := "/login?return_to=" + urlEncode("/oauth2/auth?"+orig)
		c.Redirect(http.StatusFound, loginURL)
		return
	}
	// 已登录：跳转 React 授权确认页
	c.Redirect(http.StatusFound, "/consent?"+orig)
}

// ============ 授权确认 ============

// ConsentInfo GET /api/consent —— 供 React 授权确认页渲染展示信息
func ConsentInfo(c *gin.Context) {
	user := currentUser(c)
	if user == nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "not_authenticated"})
		return
	}
	clientID := c.Query("client_id")
	var client db.OAuthClient
	if err := db.DB.Where("client_id = ?", clientID).First(&client).Error; err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid_client"})
		return
	}
	c.JSON(http.StatusOK, gin.H{
		"client_name": client.ClientName,
		"client_id":   client.ClientID,
		"scopes":      strings.Fields(c.DefaultQuery("scope", "openid")),
		"user": gin.H{
			"username": user.Username,
			"nickname": user.Nickname,
			"email":    user.Email,
		},
	})
}

// Consent POST /api/consent —— 同意 / 拒绝授权
// 同意：生成一次性 authorization code，302 回调 redirect_uri?code=...&state=...
// 拒绝：302 回调 redirect_uri?error=access_denied&state=...
func Consent(c *gin.Context) {
	user := currentUser(c)
	if user == nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "not_authenticated"})
		return
	}
	var req struct {
		ClientID            string `json:"client_id"`
		RedirectURI         string `json:"redirect_uri"`
		Scope               string `json:"scope"`
		State               string `json:"state"`
		Nonce               string `json:"nonce"`
		CodeChallenge       string `json:"code_challenge"`
		CodeChallengeMethod string `json:"code_challenge_method"`
		Decision            string `json:"decision"` // allow / deny
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid_request", "message": err.Error()})
		return
	}

	var client db.OAuthClient
	if err := db.DB.Where("client_id = ?", req.ClientID).First(&client).Error; err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid_client"})
		return
	}
	if !clientAllowsRedirect(&client, req.RedirectURI) {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid_redirect_uri"})
		return
	}

	if req.Decision != "allow" {
		c.JSON(http.StatusOK, gin.H{
			"redirect_to": withQuery(req.RedirectURI, map[string]string{
				"error":             "access_denied",
				"error_description": "用户拒绝授权",
				"state":             req.State,
			}),
		})
		return
	}

	code := db.RandomToken(32)
	db.DB.Create(&db.OAuthAuthorizationCode{
		Code:                code,
		ClientID:            req.ClientID,
		UserID:              user.ID,
		RedirectURI:         req.RedirectURI,
		Scope:               req.Scope,
		Nonce:               req.Nonce,
		CodeChallenge:       req.CodeChallenge,
		CodeChallengeMethod: req.CodeChallengeMethod,
		ExpiresAt:           time.Now().Add(AuthCodeTTL),
	})

	c.JSON(http.StatusOK, gin.H{
		"redirect_to": withQuery(req.RedirectURI, map[string]string{
			"code":  code,
			"state": req.State,
		}),
	})
}

// ============ /oauth2/token 令牌端点 ============

// Token POST /oauth2/token
// 支持 grant_type=authorization_code（PKCE 校验）与 refresh_token
func Token(c *gin.Context) {
	grantType := c.PostForm("grant_type")
	clientID := c.PostForm("client_id")
	if clientID == "" {
		clientID = c.Query("client_id")
	}
	if u, p, ok := c.Request.BasicAuth(); ok {
		clientID = u
		_ = p
	}

	var client db.OAuthClient
	if err := db.DB.Where("client_id = ?", clientID).First(&client).Error; err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid_client"})
		return
	}

	switch grantType {
	case "authorization_code":
		handleAuthCodeGrant(c, &client)
	case "refresh_token":
		handleRefreshGrant(c, &client)
	default:
		c.JSON(http.StatusBadRequest, gin.H{"error": "unsupported_grant_type"})
	}
}

func handleAuthCodeGrant(c *gin.Context, client *db.OAuthClient) {
	code := c.PostForm("code")
	redirectURI := c.PostForm("redirect_uri")
	verifier := c.PostForm("code_verifier")

	var ac db.OAuthAuthorizationCode
	if err := db.DB.Where("code = ?", code).First(&ac).Error; err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid_grant", "error_description": "code 不存在"})
		return
	}
	if ac.ClientID != client.ClientID || ac.RedirectURI != redirectURI {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid_grant", "error_description": "client/redirect_uri 不匹配"})
		return
	}
	if ac.UsedAt != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid_grant", "error_description": "code 已被使用"})
		return
	}
	if time.Now().After(ac.ExpiresAt) {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid_grant", "error_description": "code 已过期"})
		return
	}
	if !verifyPKCE(verifier, ac.CodeChallenge, ac.CodeChallengeMethod) {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid_grant", "error_description": "PKCE 校验失败"})
		return
	}
	// 标记一次性使用
	used := time.Now()
	ac.UsedAt = &used
	db.DB.Save(&ac)

	var user db.User
	db.DB.First(&user, ac.UserID)

	idToken, err := signIDToken(&user, client.ClientID, ac.Nonce, ac.Scope)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "server_error"})
		return
	}
	accessToken := db.RandomToken(32)
	refreshToken := db.RandomToken(40)
	// access_token 落库，供 /oauth2/userinfo 做 Bearer 鉴权（TTL 10 分钟）
	db.DB.Create(&db.OAuthAccessToken{
		Token:     accessToken,
		ClientID:  client.ClientID,
		UserID:    user.ID,
		Scope:     ac.Scope,
		ExpiresAt: time.Now().Add(AccessTokenTTL),
	})
	db.DB.Create(&db.OAuthRefreshToken{
		Token:     refreshToken,
		ClientID:  client.ClientID,
		UserID:    user.ID,
		Scope:     ac.Scope,
		ExpiresAt: time.Now().Add(RefreshTokenTTL),
	})

	c.JSON(http.StatusOK, gin.H{
		"access_token":  accessToken,
		"token_type":    "Bearer",
		"expires_in":    int(AccessTokenTTL.Seconds()),
		"refresh_token": refreshToken,
		"id_token":      idToken,
		"scope":         ac.Scope,
	})
}

func handleRefreshGrant(c *gin.Context, client *db.OAuthClient) {
	rt := c.PostForm("refresh_token")
	var rec db.OAuthRefreshToken
	// 注意：refresh_token 不存在/已吊销/已过期一律返回 400 invalid_grant。
	// RFC 6749 §5.2 规定 invalid_grant 对应 HTTP 400（而非 401）；
	// 401 保留给"客户端自身认证失败"（如 Basic 凭据错误）的场景。
	if err := db.DB.Where("token = ?", rt).First(&rec).Error; err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid_grant", "error_description": "refresh_token 不存在"})
		return
	}
	if rec.RevokedAt != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid_grant", "error_description": "refresh_token 已吊销"})
		return
	}
	if time.Now().After(rec.ExpiresAt) {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid_grant", "error_description": "refresh_token 已过期"})
		return
	}
	if rec.ClientID != client.ClientID {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid_grant", "error_description": "client 不匹配"})
		return
	}

	var user db.User
	db.DB.First(&user, rec.UserID)
	idToken, err := signIDToken(&user, client.ClientID, "", rec.Scope)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "server_error"})
		return
	}
	// 新 access_token 同样落库
	newAccess := db.RandomToken(32)
	db.DB.Create(&db.OAuthAccessToken{
		Token:     newAccess,
		ClientID:  client.ClientID,
		UserID:    user.ID,
		Scope:     rec.Scope,
		ExpiresAt: time.Now().Add(AccessTokenTTL),
	})

	c.JSON(http.StatusOK, gin.H{
		"access_token":  newAccess,
		"token_type":    "Bearer",
		"expires_in":    int(AccessTokenTTL.Seconds()),
		"refresh_token": rec.Token,
		"id_token":      idToken,
		"scope":         rec.Scope,
	})
}

// ============ /oauth2/userinfo ============

// UserInfo GET /oauth2/userinfo —— 基于 Bearer access_token 返回用户信息
func UserInfo(c *gin.Context) {
	// 从 Authorization: Bearer <token> 或 access_token 参数读取
	token := ""
	if h := c.GetHeader("Authorization"); strings.HasPrefix(h, "Bearer ") {
		token = strings.TrimPrefix(h, "Bearer ")
	} else if q := c.Query("access_token"); q != "" {
		token = q
	}
	if token == "" {
		c.Header("WWW-Authenticate", `Bearer realm="idp"`)
		c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid_token", "error_description": "缺少 access_token"})
		return
	}

	var at db.OAuthAccessToken
	if err := db.DB.Where("token = ?", token).First(&at).Error; err != nil {
		c.Header("WWW-Authenticate", `Bearer realm="idp", error="invalid_token"`)
		c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid_token", "error_description": "access_token 无效"})
		return
	}
	if time.Now().After(at.ExpiresAt) {
		c.Header("WWW-Authenticate", `Bearer realm="idp", error="invalid_token"`)
		c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid_token", "error_description": "access_token 已过期"})
		return
	}

	var user db.User
	if err := db.DB.First(&user, at.UserID).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "user_not_found"})
		return
	}

	// 按 scope 决定返回字段
	resp := gin.H{"sub": itoa(user.ID)}
	if strings.Contains(at.Scope, "profile") {
		resp["preferred_username"] = user.Username
		resp["name"] = user.Nickname
	}
	if strings.Contains(at.Scope, "email") {
		resp["email"] = user.Email
		resp["email_verified"] = true
	}
	c.JSON(http.StatusOK, resp)
}

// ============ /oauth2/revoke 令牌吊销（RFC 7009） ============

// RevokeToken POST /oauth2/revoke
// 吊销 refresh_token / access_token。按 RFC 7009，无论令牌是否存在均返回 200，
// 避免泄露令牌有效性信息。
func RevokeToken(c *gin.Context) {
	token := c.PostForm("token")
	clientID := c.PostForm("client_id")
	hint := c.PostForm("token_type_hint")

	if token == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid_request", "error_description": "缺少 token"})
		return
	}

	// 校验客户端存在（公共客户端仅凭 client_id）
	if clientID != "" {
		var client db.OAuthClient
		if err := db.DB.Where("client_id = ?", clientID).First(&client).Error; err != nil {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid_client"})
			return
		}
	}

	// 支持按令牌值匹配；hint 仅为优化提示，不强制
	now := time.Now()
	revoked := int64(0)

	// 吊销 refresh_token
	res := db.DB.Model(&db.OAuthRefreshToken{}).
		Where("token = ? AND revoked_at IS NULL", token).
		Update("revoked_at", now)
	revoked += res.RowsAffected

	// 若传入的是 access_token，直接删除以便 userinfo 立即失效
	res2 := db.DB.Where("token = ?", token).Delete(&db.OAuthAccessToken{})
	revoked += res2.RowsAffected

	if revoked > 0 {
		log.Printf("[IDP] 已吊销令牌（hint=%s, client=%s）", hint, clientID)
	}

	// RFC 7009：即使令牌无效也返回 200
	c.JSON(http.StatusOK, gin.H{"status": "ok"})
}

// ============ /oauth2/logout 统一登出 ============

// Logout GET /oauth2/logout —— RP 发起单点登出
// 销毁全局会话 + 吊销该用户全部 refresh_token，然后回跳 post_logout_redirect_uri
func Logout(c *gin.Context) {
	if sid, err := c.Cookie(sessionCookie); err == nil && sid != "" {
		var s db.UserSession
		if err := db.DB.Where("session_id = ?", sid).First(&s).Error; err == nil {
			// 吊销该用户所有刷新令牌
			nw := time.Now()
			db.DB.Model(&db.OAuthRefreshToken{}).
				Where("user_id = ? AND revoked_at IS NULL", s.UserID).
				Update("revoked_at", nw)
			// 同时清空该用户全部 access_token，使 userinfo 立即失效
			db.DB.Where("user_id = ?", s.UserID).Delete(&db.OAuthAccessToken{})
			db.DB.Where("session_id = ?", sid).Delete(&db.UserSession{})
		}
	}
	c.SetCookie(sessionCookie, "", -1, "/", "", false, true)

	postLogout := c.Query("post_logout_redirect_uri")
	state := c.Query("state")
	if postLogout == "" {
		c.JSON(http.StatusOK, gin.H{"status": "logged_out"})
		return
	}

	// 回跳地址必须在客户端注册的 post_logout_uris 白名单内。
	// 缺了这一步,/oauth2/logout 就是一个开放重定向:任何人构造
	// /oauth2/logout?post_logout_redirect_uri=https://evil.com
	// 都能借认证中心的域名把用户带去任意站点。
	// client_id 随之成为必填 —— 否则校验无从谈起。
	clientID := c.Query("client_id")
	if clientID == "" {
		c.JSON(http.StatusBadRequest, gin.H{
			"error":             "invalid_request",
			"error_description": "携带 post_logout_redirect_uri 时必须提供 client_id",
		})
		return
	}
	var logoutClient db.OAuthClient
	if err := db.DB.Where("client_id = ?", clientID).First(&logoutClient).Error; err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error":             "invalid_client",
			"error_description": "未知的 client_id: " + clientID,
		})
		return
	}
	if !clientAllowsPostLogout(&logoutClient, postLogout) {
		c.JSON(http.StatusBadRequest, gin.H{
			"error":             "invalid_request",
			"error_description": "post_logout_redirect_uri 未在该客户端注册",
		})
		return
	}

	params := map[string]string{}
	if state != "" {
		params["state"] = state
	}
	redirectWith(c, postLogout, params)
}

// ============ 辅助函数 ============

func urlEncode(s string) string {
	return strings.ReplaceAll(strings.ReplaceAll(s, "%", "%25"), "&", "%26")
}

func withQuery(base string, params map[string]string) string {
	sep := "?"
	if strings.Contains(base, "?") {
		sep = "&"
	}
	parts := []string{}
	for k, v := range params {
		if v == "" {
			continue
		}
		parts = append(parts, k+"="+queryEscape(v))
	}
	if len(parts) == 0 {
		return base
	}
	return base + sep + strings.Join(parts, "&")
}

func queryEscape(s string) string {
	var b strings.Builder
	for _, r := range []byte(s) {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') ||
			r == '-' || r == '_' || r == '.' || r == '~' {
			b.WriteByte(r)
		} else {
			const hex = "0123456789ABCDEF"
			b.WriteByte('%')
			b.WriteByte(hex[r>>4])
			b.WriteByte(hex[r&0x0f])
		}
	}
	return b.String()
}

var _ = json.Marshal
