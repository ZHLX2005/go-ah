package api

import (
	"crypto/sha256"
	"encoding/base64"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"

	"github.com/ZHLX2005/go-ah/auth-hub/db"
)

// Issuer IDP 的签发者标识（与 .well-known 保持一致）
const Issuer = "http://127.0.0.1:8080"

// sessionCookie 全局会话 Cookie 名
const sessionCookie = "idp_session"

// 令牌有效期（Task4 统一规则）
const (
	// AccessTokenTTL access_token 有效期 10 分钟
	AccessTokenTTL = 10 * time.Minute
	// RefreshTokenTTL refresh_token 有效期 7 天
	RefreshTokenTTL = 7 * 24 * time.Hour
	// AuthCodeTTL 授权码有效期 5 分钟
	AuthCodeTTL = 5 * time.Minute
	// SessionTTL 全局会话有效期 8 小时
	SessionTTL = 8 * time.Hour
)

// now 统一时间
func now() time.Time { return time.Now() }

// issueSession 创建全局会话并设置 Cookie
func issueSession(c *gin.Context, userID uint) string {
	sid := db.RandomToken(32)
	db.DB.Create(&db.UserSession{
		SessionID: sid,
		UserID:    userID,
		ExpiresAt: now().Add(SessionTTL),
	})
	c.SetCookie(sessionCookie, sid, int(SessionTTL.Seconds()), "/", "", false, true)
	return sid
}

// currentUser 根据全局会话返回当前登录用户
func currentUser(c *gin.Context) *db.User {
	sid, err := c.Cookie(sessionCookie)
	if err != nil || sid == "" {
		return nil
	}
	var s db.UserSession
	if err := db.DB.Where("session_id = ? AND expires_at > ?", sid, now()).First(&s).Error; err != nil {
		return nil
	}
	var u db.User
	if err := db.DB.First(&u, s.UserID).Error; err != nil {
		return nil
	}
	return &u
}

// signIDToken 使用 RS256 签发 id_token
func signIDToken(user *db.User, clientID, nonce, scope string) (string, error) {
	claims := jwt.MapClaims{
		"iss":       Issuer,
		"sub":       itoa(user.ID),
		"aud":       clientID,
		"exp":       now().Add(1 * time.Hour).Unix(),
		"iat":       now().Unix(),
		"auth_time": now().Unix(),
	}
	if nonce != "" {
		claims["nonce"] = nonce
	}
	if strings.Contains(scope, "profile") {
		claims["name"] = user.Nickname
		claims["preferred_username"] = user.Username
	}
	if strings.Contains(scope, "email") {
		claims["email"] = user.Email
		claims["email_verified"] = true
	}
	tok := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	tok.Header["kid"] = db.KeyID
	return tok.SignedString(db.SigningKey)
}

func itoa(u uint) string {
	if u == 0 {
		return "0"
	}
	var b [20]byte
	i := len(b)
	for u > 0 {
		i--
		b[i] = byte('0' + u%10)
		u /= 10
	}
	return string(b[i:])
}

// verifyPKCE 校验 code_verifier 与 code_challenge 是否匹配
//
// 按 RFC 7636，code_challenge_method 只有 "S256" 与 "plain" 两个合法值。
// 这里采用白名单语义：只有当 method 显式等于 "plain" 时才走明文比较，
// 其余任何取值（含大小写变体、拼写错误、空值）一律按 S256 处理。
// 这样对客户端更严格（S256 比 plain 更安全），也避免把未知 method
// 静默降级成 plain 比较而削弱校验。
func verifyPKCE(verifier, challenge, method string) bool {
	if verifier == "" || challenge == "" {
		return false
	}
	if method == "plain" {
		return verifier == challenge
	}
	h := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(h[:]) == challenge
}

// clientAllowsRedirect 校验 redirect_uri 是否在客户端注册白名单内
//
// 支持两种注册形式：
//  1. 精确匹配：http://127.0.0.1:8081/oauth/callback
//  2. 回环通配：http://127.0.0.1:*/callback
//     仅允许 127.0.0.1 / localhost，用于 CLI 等自动分配临时端口的本机客户端。
//     RFC 8252（OAuth 2.0 for Native Apps）推荐本机应用使用回环地址重定向，
//     端口号由系统动态分配，因此这里放开端口但严格锁定主机为回环地址。
func clientAllowsRedirect(client *db.OAuthClient, uri string) bool {
	if uri == "" {
		return false
	}
	for _, u := range strings.Fields(client.RedirectURIs) {
		if matchRedirectPattern(u, uri) {
			return true
		}
	}
	return false
}

// matchRedirectPattern 匹配单个注册项
func matchRedirectPattern(pattern, uri string) bool {
	if pattern == uri {
		return true
	}
	// 通配形式：仅允许 loopback 主机 + 端口通配
	wildCard := ""
	switch {
	case strings.Contains(pattern, "://127.0.0.1:*"):
		wildCard = "127.0.0.1"
	case strings.Contains(pattern, "://localhost:*"):
		wildCard = "localhost"
	default:
		return false
	}

	scheme := "http"
	if strings.HasPrefix(pattern, "https://") {
		scheme = "https"
	}
	// 仅匹配同一 scheme 且主机为回环地址的 uri
	prefix := scheme + "://" + wildCard + ":"
	if !strings.HasPrefix(uri, prefix) {
		return false
	}
	rest := strings.TrimPrefix(uri, prefix)
	slash := strings.Index(rest, "/")
	if slash <= 0 {
		return false
	}
	port, path := rest[:slash], rest[slash:]
	if !isAllDigits(port) {
		return false
	}
	// 注册项的路径部分：从 "://" 之后的首个 "/" 开始
	restPat := pattern[strings.Index(pattern, "://")+3:]
	pSlash := strings.Index(restPat, "/")
	if pSlash < 0 {
		return false
	}
	registeredPath := restPat[pSlash:]
	return registeredPath == path
}

func isAllDigits(s string) bool {
	if s == "" {
		return false
	}
	for _, r := range s {
		if r < '0' || r > '9' {
			return false
		}
	}
	return true
}

func clientAllowsPostLogout(client *db.OAuthClient, uri string) bool {
	if uri == "" {
		return true
	}
	for _, u := range strings.Fields(client.PostLogoutURIs) {
		if u == uri {
			return true
		}
	}
	return false
}

// redirectWith 附加 query 参数并 302 跳转
func redirectWith(c *gin.Context, base string, params map[string]string) {
	u, err := url.Parse(base)
	if err != nil {
		c.String(http.StatusBadRequest, "invalid redirect_uri")
		return
	}
	q := u.Query()
	for k, v := range params {
		q.Set(k, v)
	}
	u.RawQuery = q.Encode()
	c.Redirect(http.StatusFound, u.String())
}

// errorRedirect 按 OAuth2 规范回传错误
func errorRedirect(c *gin.Context, redirectURI, state, code, desc string) {
	redirectWith(c, redirectURI, map[string]string{
		"error":             code,
		"error_description": desc,
		"state":             state,
	})
}
