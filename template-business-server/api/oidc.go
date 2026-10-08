package api

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/gin-gonic/gin"
	"golang.org/x/oauth2"

	"github.com/ZHLX2005/go-ah/template-business-server/db"
)

// ============================================================
// 业务平台 OIDC 接入配置（业务接入参考脚手架）
// ============================================================

// OIDC 相关配置，均可用环境变量覆盖，便于部署到不同环境
var (
	IDPIssuer       = db.Env("IDP_ISSUER", "http://127.0.0.1:8080")
	ClientID        = db.Env("OIDC_CLIENT_ID", "template-web-client")
	ClientSecret    = db.Env("OIDC_CLIENT_SECRET", "") // 公共客户端(PKCE)无需 secret
	RedirectURI     = db.Env("OIDC_REDIRECT_URI", "http://127.0.0.1:8081/oauth/callback")
	PostLogoutURI   = db.Env("OIDC_POST_LOGOUT_URI", "http://127.0.0.1:8081/")
	BusinessAddr    = db.Env("BIZ_ADDR", "127.0.0.1:8081")
	SessionCookie   = "biz_session"
	SessionLifetime = 8 * time.Hour
)

var (
	provider    *oidc.Provider
	verifier    *oidc.IDTokenVerifier
	oauth2Cfg   *oauth2.Config
	initOnce    sync.Once
	initErr     error
	EndpointSet oauth2.Endpoint
)

// SetupOIDC 连接 IDP，拉取 .well-known 发现文档，初始化校验器
// 注意：IDP 未启动时会失败，main 中会重试
func SetupOIDC() error {
	initOnce.Do(func() {
		// 允许 http（本地开发环境，非 HTTPS）
		ctx := oidc.InsecureIssuerURLContext(context.Background(), IDPIssuer)
		p, err := oidc.NewProvider(ctx, IDPIssuer)
		if err != nil {
			initErr = fmt.Errorf("连接 IDP 失败: %w", err)
			return
		}
		provider = p
		// 关键：由 SDK 校验 id_token 的 iss / aud / exp / 签名（RS256 + JWKS）
		verifier = provider.Verifier(&oidc.Config{ClientID: ClientID})
		oauth2Cfg = &oauth2.Config{
			ClientID:     ClientID,
			ClientSecret: ClientSecret,
			RedirectURL:  RedirectURI,
			Endpoint:     provider.Endpoint(),
			Scopes:       []string{oidc.ScopeOpenID, "profile", "email"},
		}
		EndpointSet = provider.Endpoint()
		log.Printf("[BIZ] 已连接 IDP: %s (issuer=%s)", IDPIssuer, p.Endpoint().AuthURL)
	})
	return initErr
}

// ============================================================
// 接口 1：POST /api/auth/callback
// 前端回调页把 code + state + code_verifier 提交给业务后端，
// 由后端完成 token 交换 + id_token 校验 + 建立业务会话。
// 这就是"方案1"（推荐）：token 不落地浏览器 localStorage。
// ============================================================

func AuthCallback(c *gin.Context) {
	if err := SetupOIDC(); err != nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "idp_unavailable", "message": err.Error()})
		return
	}

	var req struct {
		Code         string `json:"code"`
		State        string `json:"state"`
		CodeVerifier string `json:"code_verifier"`
		RedirectURI  string `json:"redirect_uri"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid_request", "message": err.Error()})
		return
	}
	if req.Code == "" || req.CodeVerifier == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid_request", "message": "缺少 code 或 code_verifier"})
		return
	}

	now := time.Now()

	// ---- 1) 用 code + code_verifier 向 IDP 换取 token（PKCE） ----
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// 若前端传入 redirect_uri 则使用，保证与授权请求一致
	cfg := *oauth2Cfg
	if req.RedirectURI != "" {
		cfg.RedirectURL = req.RedirectURI
	}

	token, err := cfg.Exchange(ctx, req.Code,
		oauth2.SetAuthURLParam("code_verifier", req.CodeVerifier),
	)
	if err != nil {
		log.Printf("[BIZ] token 交换失败: %v", err)
		c.JSON(http.StatusBadRequest, gin.H{
			"error":   "token_exchange_failed",
			"message": "code 换取 token 失败：" + err.Error(),
		})
		return
	}

	// ---- 2) SDK 校验 id_token（签名/iss/aud/exp） ----
	rawIDToken, ok := token.Extra("id_token").(string)
	if !ok || rawIDToken == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "no_id_token", "message": "IDP 未返回 id_token"})
		return
	}
	idToken, err := verifier.Verify(ctx, rawIDToken)
	if err != nil {
		log.Printf("[BIZ] id_token 校验失败: %v", err)
		c.JSON(http.StatusUnauthorized, gin.H{
			"error":   "invalid_id_token",
			"message": "id_token 校验失败：" + err.Error(),
		})
		return
	}

	// ---- 3) 解析 claims ----
	var claims struct {
		Sub               string `json:"sub"`
		Name              string `json:"name"`
		PreferredUsername string `json:"preferred_username"`
		Email             string `json:"email"`
	}
	if err := idToken.Claims(&claims); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid_claims", "message": err.Error()})
		return
	}

	// ---- 4) 根据 sub 查询/新建业务用户 ----
	var bu db.BusinessUser
	if err := db.DB.Where("sub = ?", claims.Sub).First(&bu).Error; err != nil {
		bu = db.BusinessUser{
			Sub:      claims.Sub,
			Username: claims.PreferredUsername,
			Nickname: claims.Name,
			Email:    claims.Email,
		}
		db.DB.Create(&bu)
		log.Printf("[BIZ] 新建业务用户 sub=%s username=%s", bu.Sub, bu.Username)
	} else {
		// 同步最新资料
		bu.Username = claims.PreferredUsername
		bu.Nickname = claims.Name
		bu.Email = claims.Email
	}
	bu.LastLoginAt = time.Now()
	db.DB.Save(&bu)

	// ---- 5) 建立业务会话，token 加密后保存在后端（SQLite） ----
	sid := randomToken(32)
	sess := &db.BusinessSession{
		SessionID:             sid,
		UserSub:               claims.Sub,
		IDToken:               rawIDToken,
		AccessToken:           token.AccessToken,
		RefreshToken:          token.RefreshToken,
		AccessTokenExpiresAt:  now.Add(AccessTokenTTL),
		RefreshTokenExpiresAt: now.Add(RefreshTokenTTL),
		ExpiresAt:             now.Add(SessionLifetime),
	}
	// saveSession 内部完成 AES-256-GCM 加密，落库内容不含明文 JWT
	if err := saveSession(sess); err != nil {
		log.Printf("[BIZ] 保存加密会话失败: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{
			"error":   "session_save_failed",
			"message": "会话保存失败：" + err.Error(),
		})
		return
	}
	c.SetCookie(SessionCookie, sid, int(SessionLifetime.Seconds()), "/", "", false, true)

	c.JSON(http.StatusOK, gin.H{
		"code": 0,
		"data": gin.H{
			"sub":      claims.Sub,
			"username": bu.Username,
			"nickname": bu.Nickname,
			"email":    bu.Email,
		},
	})
}

// ============================================================
// 接口 2：GET /api/config
// 前端启动时拉取 OIDC 公共配置，用于在浏览器侧生成 PKCE 参数并发起授权跳转
// （client_secret 绝不下发；仅下发公共信息）
// ============================================================
func PublicConfig(c *gin.Context) {
	cfg := gin.H{
		"client_id":       ClientID,
		"redirect_uri":    RedirectURI,
		"scope":           "openid profile email",
		"post_logout_uri": PostLogoutURI,
		"idp_issuer":      IDPIssuer,
	}
	if err := SetupOIDC(); err == nil {
		cfg["authorization_endpoint"] = EndpointSet.AuthURL
		cfg["token_endpoint"] = EndpointSet.TokenURL
		cfg["end_session_endpoint"] = strings.TrimSuffix(IDPIssuer, "/") + "/oauth2/logout"
		cfg["idp_available"] = true
	} else {
		// IDP 暂不可用时的兜底地址（仍允许前端构造授权 URL）
		cfg["authorization_endpoint"] = strings.TrimSuffix(IDPIssuer, "/") + "/oauth2/auth"
		cfg["end_session_endpoint"] = strings.TrimSuffix(IDPIssuer, "/") + "/oauth2/logout"
		cfg["idp_available"] = false
		cfg["idp_error"] = err.Error()
	}
	c.JSON(http.StatusOK, cfg)
}

// ============================================================
// 接口 3：GET /api/profile  —— 受保护接口
// 通过业务 session cookie 鉴权，返回用户信息
// ============================================================
func Profile(c *gin.Context) {
	sess := currentSession(c)
	if sess == nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "unauthorized", "message": "未登录或会话已过期"})
		return
	}
	var bu db.BusinessUser
	if err := db.DB.Where("sub = ?", sess.UserSub).First(&bu).Error; err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "user_not_found"})
		return
	}

	// 读取解密后的 token 元信息，仅返回布尔标记，绝不把 token 内容下发给前端
	tokens, err := ReadTokens(sess)
	if err != nil {
		log.Printf("[BIZ] 会话 %s token 解密失败: %v", sess.SessionID, err)
		c.JSON(http.StatusInternalServerError, gin.H{
			"error":   "token_decrypt_failed",
			"message": "会话 token 解密失败，可能需要重新登录",
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"code": 0,
		"data": gin.H{
			"sub":           bu.Sub,
			"username":      bu.Username,
			"nickname":      bu.Nickname,
			"email":         bu.Email,
			"last_login_at": bu.LastLoginAt,
			// 展示会话有效期，便于测试用例验证
			"session_expires_at": sess.ExpiresAt,
			"has_id_token":       tokens.IDToken != "",
			"has_refresh_token":  tokens.RefreshToken != "",
			// Task4：暴露加密与续期状态，便于验证"落库无明文 + 自动续期"
			"token_encrypted":          sess.Encrypted,
			"access_token_expires_at":  sess.AccessTokenExpiresAt,
			"refresh_token_expires_at": sess.RefreshTokenExpiresAt,
		},
	})
}

// ============================================================
// 接口 4：GET /api/session —— 轻量登录态查询（供前端首页判断）
// ============================================================
func SessionInfo(c *gin.Context) {
	sess := currentSession(c)
	if sess == nil {
		c.JSON(http.StatusOK, gin.H{"code": 0, "data": nil})
		return
	}
	c.JSON(http.StatusOK, gin.H{
		"code": 0,
		"data": gin.H{"sub": sess.UserSub, "expires_at": sess.ExpiresAt},
	})
}

// ============================================================
// 接口 5：POST /api/logout —— 统一登出
// 1) 清空业务会话
// 2) 返回 IDP 登出地址（携带 id_token_hint），由前端跳转完成单点登出
// ============================================================
func Logout(c *gin.Context) {
	sess := currentSession(c)
	idTokenHint := ""
	if sess != nil {
		// id_token 为密文存储，登出回调需要明文，因此先解密
		if tokens, err := ReadTokens(sess); err == nil {
			idTokenHint = tokens.IDToken
		} else {
			log.Printf("[BIZ] 登出时解密 id_token 失败: %v", err)
		}
		db.DB.Where("session_id = ?", sess.SessionID).Delete(&db.BusinessSession{})
	}
	c.SetCookie(SessionCookie, "", -1, "/", "", false, true)

	logoutURL := strings.TrimSuffix(IDPIssuer, "/") + "/oauth2/logout"
	params := url.Values{}
	if idTokenHint != "" {
		params.Set("id_token_hint", idTokenHint)
	}
	params.Set("post_logout_redirect_uri", PostLogoutURI)
	params.Set("client_id", ClientID)

	c.JSON(http.StatusOK, gin.H{
		"code":       0,
		"message":    "业务会话已销毁",
		"logout_url": logoutURL + "?" + params.Encode(),
		"idp_logout": true,
	})
}

// ============================================================
// 接口 6：POST /api/refresh —— 用 refresh_token 刷新 id_token
// 用于测试用例 6（token 刷新链路）
// ============================================================
func Refresh(c *gin.Context) {
	sess := currentSession(c)
	if sess == nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
		return
	}
	// refresh_token 为密文存储，续期前先解密
	tokens, err := ReadTokens(sess)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "token_decrypt_failed", "message": err.Error()})
		return
	}
	if tokens.RefreshToken == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "no_refresh_token"})
		return
	}
	tok, err := refreshIDToken(tokens.RefreshToken)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "refresh_failed", "message": err.Error()})
		return
	}
	sess.IDToken = tok.IDToken
	sess.AccessToken = tok.AccessToken
	if tok.RefreshToken != "" {
		sess.RefreshToken = tok.RefreshToken
	}
	sess.AccessTokenExpiresAt = time.Now().Add(AccessTokenTTL)
	sess.ExpiresAt = time.Now().Add(SessionLifetime)
	// 加密回写
	if err := saveSession(sess); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "session_save_failed", "message": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{
		"code":                    0,
		"message":                 "token 刷新成功",
		"access_token_expires_at": sess.AccessTokenExpiresAt,
	})
}

type refreshedTokens struct {
	IDToken      string
	AccessToken  string
	RefreshToken string
}

// refreshIDToken 直接调用 IDP /oauth2/token (grant_type=refresh_token)
func refreshIDToken(refreshToken string) (*refreshedTokens, error) {
	form := url.Values{}
	form.Set("grant_type", "refresh_token")
	form.Set("refresh_token", refreshToken)
	form.Set("client_id", ClientID)

	req, _ := http.NewRequest("POST", strings.TrimSuffix(IDPIssuer, "/")+"/oauth2/token",
		strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("IDP 返回 %d: %s", resp.StatusCode, string(body))
	}
	var out struct {
		IDToken      string `json:"id_token"`
		AccessToken  string `json:"access_token"`
		RefreshToken string `json:"refresh_token"`
	}
	if err := json.Unmarshal(body, &out); err != nil {
		return nil, err
	}
	return &refreshedTokens{out.IDToken, out.AccessToken, out.RefreshToken}, nil
}

// currentSession 读取业务 session cookie 并校验有效期
func currentSession(c *gin.Context) *db.BusinessSession {
	sid, err := c.Cookie(SessionCookie)
	if err != nil || sid == "" {
		return nil
	}
	var s db.BusinessSession
	if err := db.DB.Where("session_id = ? AND expires_at > ?", sid, time.Now()).First(&s).Error; err != nil {
		return nil
	}
	return &s
}
