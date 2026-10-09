// Package api 是模板业务平台的 HTTP 层：OIDC 接入、业务会话、后台续期。
//
// 它是"业务方如何接入统一登录"的参考实现，因此这里刻意不做抽象 ——
// 每个接口的响应形状都直接写在代码里，接入方照抄即可。
package api

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/gogf/gf/v2/frame/g"
	"golang.org/x/oauth2"

	v1 "github.com/ZHLX2005/go-ah/template-business-server/api/v1"
	"github.com/ZHLX2005/go-ah/template-business-server/db"
)

// ============================================================
// 业务平台 OIDC 接入配置（业务接入参考脚手架）
// ============================================================

// 全部可用环境变量覆盖，便于部署到不同环境；默认值对齐本地开发
var (
	IDPIssuer     = db.Env("IDP_ISSUER", "http://127.0.0.1:8080")
	ClientID      = db.Env("OIDC_CLIENT_ID", "template-web-client")
	ClientSecret  = db.Env("OIDC_CLIENT_SECRET", "") // 公共客户端(PKCE)无需 secret
	RedirectURI   = db.Env("OIDC_REDIRECT_URI", "http://127.0.0.1:8081/oauth/callback")
	PostLogoutURI = db.Env("OIDC_POST_LOGOUT_URI", "http://127.0.0.1:8081/")

	// SessionCookie 业务会话 Cookie 名。与 IDP 的会话 Cookie 是两回事：
	// 业务侧持有的是"我们自己的会话 ID"，不是 IDP 的登录态。
	SessionCookie = "biz_session"
	// SessionLifetime 业务会话有效期（滑动续期）
	SessionLifetime = 8 * time.Hour
)

var (
	provider  *oidc.Provider
	verifier  *oidc.IDTokenVerifier
	oauth2Cfg *oauth2.Config
	// initMu 保护下面这组"一次性但允许重试"的初始化结果
	initMu sync.Mutex
	// EndpointSet IDP 的端点集合（PublicConfig 下发给前端）
	EndpointSet oauth2.Endpoint
)

// Controller 模板业务平台的 HTTP 控制器。
//
// 所有方法都是 func(ctx, ...) error：响应由方法自己写出，路由层的适配器只
// 负责解析入参与兜底。理由与 auth-hub 相同 —— 本服务的响应有四种形状，
// 交给框架统一渲染就没法逐接口对齐。
type Controller struct{}

// New 构造控制器
func New() *Controller { return &Controller{} }

// ============================================================
// OIDC 客户端自举
// ============================================================

// SetupOIDC 连接 IDP，拉取 .well-known 发现文档，初始化校验器。
//
// 与迁移前的实现有一处**有意的差别**：失败结果不再被永久缓存。
// 原实现用 sync.Once 包住整个初始化，于是"首次失败"会被记住，之后每个接口
// 都返回同一个错误，直到人工重启 —— 而容器编排下业务平台先于 IDP 启动是
// 常见情况，那样单点登录会一直不可用。
//
// 这里改成：只有**成功**才固定下来，失败则允许下一次请求重试。
// 成功之后走的是同一个"provider 非 nil 就返回"的快速路径。
func SetupOIDC() error {
	initMu.Lock()
	defer initMu.Unlock()

	if provider != nil {
		return nil
	}

	// 允许 http（本地开发，非 HTTPS）；带上超时，避免 IDP 卡住时把
	// /api/config 一起拖死
	base := oidc.InsecureIssuerURLContext(context.Background(), IDPIssuer)
	base = oidc.ClientContext(base, &http.Client{Timeout: 10 * time.Second})

	p, err := oidc.NewProvider(base, IDPIssuer)
	if err != nil {
		return fmt.Errorf("连接 IDP 失败: %w", err)
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
	return nil
}

// ============================================================
// 接口 1：GET /api/config
//
// 前端启动时拉取 OIDC 公共配置，用于在浏览器侧生成 PKCE 参数并发起授权跳转。
// 公共客户端的 client_secret 绝不下发（本服务默认也没有）。
// ============================================================

// PublicConfig 下发前端发起授权所需的公共配置
func (c *Controller) PublicConfig(ctx context.Context) error {
	r := g.RequestFromCtx(ctx)

	res := &v1.PublicConfigRes{
		ClientID:      ClientID,
		RedirectURI:   RedirectURI,
		Scope:         "openid profile email",
		PostLogoutURI: PostLogoutURI,
		IDPIssuer:     IDPIssuer,
	}
	if err := SetupOIDC(); err == nil {
		res.AuthorizationEndpoint = EndpointSet.AuthURL
		res.TokenEndpoint = EndpointSet.TokenURL
		res.EndSessionEndpoint = strings.TrimSuffix(IDPIssuer, "/") + "/oauth2/logout"
		res.IDPAvailable = true
	} else {
		// IDP 暂不可用时的兜底地址：仍允许前端构造出授权 URL，
		// 让用户看到的失败发生在 IDP 侧而不是"配置缺失"
		res.AuthorizationEndpoint = strings.TrimSuffix(IDPIssuer, "/") + "/oauth2/auth"
		res.EndSessionEndpoint = strings.TrimSuffix(IDPIssuer, "/") + "/oauth2/logout"
		res.IDPAvailable = false
		res.IDPError = err.Error()
	}
	writeJSON(r, http.StatusOK, res)
	return nil
}

// ============================================================
// 接口 2：POST /api/auth/callback
//
// 前端回调页把 code + state + code_verifier 提交给业务后端，由后端完成
// token 交换 + id_token 校验 + 建立业务会话。
// 这就是"方案1"：token 不落地浏览器 localStorage。
// ============================================================

// AuthCallback 用授权码换令牌并建立业务会话
func (c *Controller) AuthCallback(ctx context.Context, req *v1.AuthCallbackReq) error {
	r := g.RequestFromCtx(ctx)

	if err := SetupOIDC(); err != nil {
		writeError(r, http.StatusServiceUnavailable, "idp_unavailable", err.Error())
		return nil
	}
	if req.Code == "" || req.CodeVerifier == "" {
		writeError(r, http.StatusBadRequest, "invalid_request", "缺少 code 或 code_verifier")
		return nil
	}

	now := time.Now()

	// ---- 1) 用 code + code_verifier 向 IDP 换取 token（PKCE） ----
	exCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// 前端传了 redirect_uri 就用它，保证与授权请求时的一致
	cfg := *oauth2Cfg
	if req.RedirectURI != "" {
		cfg.RedirectURL = req.RedirectURI
	}

	token, err := cfg.Exchange(exCtx, req.Code,
		oauth2.SetAuthURLParam("code_verifier", req.CodeVerifier),
	)
	if err != nil {
		log.Printf("[BIZ] token 交换失败: %v", err)
		writeError(r, http.StatusBadRequest, "token_exchange_failed", "code 换取 token 失败："+err.Error())
		return nil
	}

	// ---- 2) SDK 校验 id_token（签名 / iss / aud / exp） ----
	rawIDToken, ok := token.Extra("id_token").(string)
	if !ok || rawIDToken == "" {
		writeError(r, http.StatusBadRequest, "no_id_token", "IDP 未返回 id_token")
		return nil
	}
	idToken, err := verifier.Verify(exCtx, rawIDToken)
	if err != nil {
		log.Printf("[BIZ] id_token 校验失败: %v", err)
		writeError(r, http.StatusUnauthorized, "invalid_id_token", "id_token 校验失败："+err.Error())
		return nil
	}

	// ---- 3) 解析 claims ----
	var claims struct {
		Sub               string `json:"sub"`
		Name              string `json:"name"`
		PreferredUsername string `json:"preferred_username"`
		Email             string `json:"email"`
	}
	if err := idToken.Claims(&claims); err != nil {
		writeError(r, http.StatusBadRequest, "invalid_claims", err.Error())
		return nil
	}

	// ---- 4) 根据 sub 查询/新建业务用户 ----
	//
	// 新建与更新合并成一次写入（迁移前是 Create 后再 Save，写两遍）：
	// 新建时资料本来就是最新的，紧接着再 UPDATE 一遍纯属多余。
	bu, err := db.UserBySub(ctx, claims.Sub)
	switch {
	case err != nil:
		writeError(r, http.StatusInternalServerError, "db_error", err.Error())
		return nil

	case bu == nil:
		bu = &db.BusinessUser{
			Sub:         claims.Sub,
			Username:    claims.PreferredUsername,
			Nickname:    claims.Name,
			Email:       claims.Email,
			LastLoginAt: now,
		}
		if err := db.CreateUser(ctx, bu); err != nil {
			writeError(r, http.StatusInternalServerError, "db_error", err.Error())
			return nil
		}
		log.Printf("[BIZ] 新建业务用户 sub=%s username=%s", bu.Sub, bu.Username)

	default:
		// 同步 IDP 侧的最新资料：业务侧不是资料的权威来源
		bu.Username = claims.PreferredUsername
		bu.Nickname = claims.Name
		bu.Email = claims.Email
		bu.LastLoginAt = now
		if err := db.SyncUserProfile(ctx, bu); err != nil {
			writeError(r, http.StatusInternalServerError, "db_error", err.Error())
			return nil
		}
	}

	// ---- 5) 建立业务会话，token 加密后保存在后端 ----
	sess := &db.BusinessSession{
		SessionID:             randomToken(32),
		UserSub:               claims.Sub,
		IDToken:               rawIDToken,
		AccessToken:           token.AccessToken,
		RefreshToken:          token.RefreshToken,
		AccessTokenExpiresAt:  now.Add(AccessTokenTTL),
		RefreshTokenExpiresAt: now.Add(RefreshTokenTTL),
		ExpiresAt:             now.Add(SessionLifetime),
	}
	// saveSession 内部完成 AES-256-GCM 加密，落库内容不含明文 JWT
	if err := saveSession(ctx, sess); err != nil {
		log.Printf("[BIZ] 保存加密会话失败: %v", err)
		writeError(r, http.StatusInternalServerError, "session_save_failed", "会话保存失败："+err.Error())
		return nil
	}
	setSessionCookie(r, sess.SessionID, int(SessionLifetime.Seconds()))

	writeJSON(r, http.StatusOK, &v1.AuthCallbackRes{
		Code: 0,
		Data: v1.UserData{
			Sub:      claims.Sub,
			Username: bu.Username,
			Nickname: bu.Nickname,
			Email:    bu.Email,
		},
	})
	return nil
}
