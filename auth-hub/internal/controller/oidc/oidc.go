// Package oidc 是 OIDC 端点的 HTTP 处理层：解析参数、组装响应、决定状态码。
//
// 协议判断全在 internal/logic/oidc，这里不做业务决策 —— 只有一件事必须
// 在这里做对：**不同失败走不同响应形状**。授权端点直接与人打交道，
// 参数错按历史行为回纯文本；令牌与 userinfo 是给程序看的，回标准协议错误。
//
// 本包所有方法都是同一形状：func(ctx, *Req) error，并**自行写响应**。
// 统一成这一形状不是为了好看——gf 的对象注册只接受 (ctx, *Req) (*Res, error)
// 或 func(*ghttp.Request)，而本包有「纯文本 / 302 跳转 / 裸对象」三类
// 非信封响应，塞进 (*Res, error) 就会被迫去改响应形状。让控制器自己写，
// 路由层只负责「解析入参 → 调用 → 兜底 500」。
package oidc

import (
	"context"
	"encoding/base64"
	"math/big"
	"net/http"
	"strings"

	"github.com/gogf/gf/v2/frame/g"
	"github.com/gogf/gf/v2/net/ghttp"

	v1 "github.com/ZHLX2005/go-ah/auth-hub/api/oidc/v1"
	"github.com/ZHLX2005/go-ah/auth-hub/internal/config"
	"github.com/ZHLX2005/go-ah/auth-hub/internal/consts"
	"github.com/ZHLX2005/go-ah/auth-hub/internal/controller/response"
	"github.com/ZHLX2005/go-ah/auth-hub/internal/logic/oidc"
	"github.com/ZHLX2005/go-ah/auth-hub/internal/logic/session"
	"github.com/ZHLX2005/go-ah/auth-hub/internal/logic/signing"
	"github.com/ZHLX2005/go-ah/auth-hub/internal/logic/user"
	"github.com/ZHLX2005/go-ah/auth-hub/internal/model/entity"
)

// Controller OIDC 端点控制器
type Controller struct{}

// New 构造控制器
func New() *Controller { return &Controller{} }

// Discovery GET /.well-known/openid-configuration
func (c *Controller) Discovery(ctx context.Context, req *v1.DiscoveryReq) error {
	r := g.RequestFromCtx(ctx)

	iss := config.Get().Issuer
	response.Write(r, http.StatusOK, &v1.DiscoveryRes{
		Issuer:                            iss,
		AuthorizationEndpoint:             iss + "/oauth2/auth",
		TokenEndpoint:                     iss + "/oauth2/token",
		UserinfoEndpoint:                  iss + "/oauth2/userinfo",
		JwksURI:                           iss + "/.well-known/jwks.json",
		EndSessionEndpoint:                iss + "/oauth2/logout",
		RevocationEndpoint:                iss + "/oauth2/revoke",
		ResponseTypesSupported:            []string{"code"},
		GrantTypesSupported:               []string{"authorization_code", "refresh_token"},
		SubjectTypesSupported:             []string{"public"},
		IDTokenSigningAlgValuesSupported:  []string{"RS256"},
		ScopesSupported:                   []string{"openid", "profile", "email"},
		TokenEndpointAuthMethodsSupported: []string{"none", "client_secret_post", "client_secret_basic"},
		CodeChallengeMethodsSupported:     []string{"S256", "plain"},
	})
	return nil
}

// Jwks GET /.well-known/jwks.json
func (c *Controller) Jwks(ctx context.Context, req *v1.JwksReq) error {
	r := g.RequestFromCtx(ctx)

	pub, err := signing.PublicKey(ctx)
	if err != nil {
		return err
	}
	response.Write(r, http.StatusOK, &v1.JwksRes{Keys: []v1.JwkKey{{
		Kty: "RSA",
		Use: "sig",
		Alg: "RS256",
		Kid: signing.KeyID(),
		N:   base64.RawURLEncoding.EncodeToString(pub.N.Bytes()),
		E:   base64.RawURLEncoding.EncodeToString(big.NewInt(int64(pub.E)).Bytes()),
	}}})
	return nil
}

// Authorize GET /oauth2/auth
//
// 1) 校验 client / redirect_uri / response_type / PKCE 参数
// 2) 未登录 → 302 到前端登录页，并把原始参数透传进 return_to，登录后接着走
// 3) 已登录 → 302 到前端授权确认页，参数原样透传
//
// 注意：这里的参数校验失败**不能**都跳回 redirect_uri ——
// 客户端身份或回调地址本身不可信时（前三条），跳过去等于把用户
// 送到未验证的地址；这类失败只能就地报错。
func (c *Controller) Authorize(ctx context.Context, req *v1.AuthorizeReq) error {
	r := g.RequestFromCtx(ctx)

	scope := req.Scope
	if scope == "" {
		scope = "openid"
	}
	method := req.CodeChallengeMethod
	if method == "" {
		method = "S256"
	}

	client, err := oidc.FindClient(ctx, req.ClientID)
	if err != nil {
		response.Plain(r, http.StatusInternalServerError, "查询客户端失败")
		return nil
	}
	if client == nil {
		response.Plain(r, http.StatusBadRequest, "invalid client_id")
		return nil
	}
	// 客户端被禁用则拒绝授权
	if !client.IsEnabled() {
		response.Plain(r, http.StatusBadRequest, "该客户端已被禁用（请联系管理员在管理后台启用）")
		return nil
	}
	if !oidc.ClientAllowsRedirect(client, req.RedirectURI) {
		response.Plain(r, http.StatusBadRequest, "redirect_uri 未在客户端注册白名单内")
		return nil
	}
	if req.ResponseType != "code" {
		errorRedirect(r, req.RedirectURI, req.State, "unsupported_response_type", "仅支持 code 模式")
		return nil
	}
	if !strings.Contains(scope, "openid") {
		errorRedirect(r, req.RedirectURI, req.State, "invalid_scope", "必须包含 openid scope")
		return nil
	}
	// 要求 PKCE 的客户端必须携带 code_challenge
	if client.PKCENeeded() && req.CodeChallenge == "" {
		errorRedirect(r, req.RedirectURI, req.State, "invalid_request", "缺少 code_challenge（该客户端要求 PKCE）")
		return nil
	}
	// 仅支持 S256 / plain
	if req.CodeChallenge != "" && method != "S256" && method != "plain" {
		errorRedirect(r, req.RedirectURI, req.State, "invalid_request", "仅支持 S256 / plain 的 code_challenge_method")
		return nil
	}

	// 原始请求参数串：登录/确认完成后原样回提，避免中途丢参数
	orig := r.Request.URL.RawQuery

	user, err := SessionUser(ctx, r)
	if err != nil {
		response.Plain(r, http.StatusInternalServerError, "查询登录态失败")
		return nil
	}
	if user == nil {
		response.Redirect(r, "/login?return_to="+urlEncode("/oauth2/auth?"+orig))
		return nil
	}
	response.Redirect(r, "/consent?"+orig)
	return nil
}

// ConsentInfo GET /api/consent —— 供授权确认页渲染
func (c *Controller) ConsentInfo(ctx context.Context, req *v1.ConsentInfoReq) error {
	r := g.RequestFromCtx(ctx)

	user, err := SessionUser(ctx, r)
	if err != nil {
		return err
	}
	if user == nil {
		response.Write(r, http.StatusUnauthorized, map[string]interface{}{"error": "not_authenticated"})
		return nil
	}

	client, err := oidc.FindClient(ctx, req.ClientID)
	if err != nil {
		return err
	}
	if client == nil {
		response.Write(r, http.StatusBadRequest, map[string]interface{}{"error": "invalid_client"})
		return nil
	}

	scope := req.Scope
	if scope == "" {
		scope = "openid"
	}
	response.Write(r, http.StatusOK, &v1.ConsentInfoRes{
		ClientName: client.ClientName,
		ClientID:   client.ClientID,
		Scopes:     strings.Fields(scope),
		User: v1.ConsentUser{
			Username: user.Username,
			Nickname: user.Nickname,
			Email:    user.Email,
		},
	})
	return nil
}

// Consent POST /api/consent —— 同意 / 拒绝授权
//
// 同意：生成一次性授权码，返回带 code 的回调地址
// 拒绝：返回带 error=access_denied 的回调地址
// 两种情况都只返回地址、由前端执行跳转（跳转由浏览器发起，才能命中 SSO 会话）
func (c *Controller) Consent(ctx context.Context, req *v1.ConsentReq) error {
	r := g.RequestFromCtx(ctx)

	user, err := SessionUser(ctx, r)
	if err != nil {
		return err
	}
	if user == nil {
		response.Write(r, http.StatusUnauthorized, map[string]interface{}{"error": "not_authenticated"})
		return nil
	}

	client, err := oidc.FindClient(ctx, req.ClientID)
	if err != nil {
		return err
	}
	if client == nil {
		response.Write(r, http.StatusBadRequest, map[string]interface{}{"error": "invalid_client"})
		return nil
	}
	if !oidc.ClientAllowsRedirect(client, req.RedirectURI) {
		response.Write(r, http.StatusBadRequest, map[string]interface{}{"error": "invalid_redirect_uri"})
		return nil
	}

	if req.Decision != "allow" {
		response.Write(r, http.StatusOK, &v1.ConsentRes{RedirectTo: withQuery(req.RedirectURI, map[string]string{
			"error":             "access_denied",
			"error_description": "用户拒绝授权",
			"state":             req.State,
		})})
		return nil
	}

	code, err := oidc.CreateAuthorizationCode(ctx, oidc.AuthCodeInput{
		ClientID:            req.ClientID,
		UserID:              user.Id,
		RedirectURI:         req.RedirectURI,
		Scope:               req.Scope,
		Nonce:               req.Nonce,
		CodeChallenge:       req.CodeChallenge,
		CodeChallengeMethod: req.CodeChallengeMethod,
	})
	if err != nil {
		return err
	}

	response.Write(r, http.StatusOK, &v1.ConsentRes{RedirectTo: withQuery(req.RedirectURI, map[string]string{
		"code":  code,
		"state": req.State,
	})})
	return nil
}

// Token POST /oauth2/token
func (c *Controller) Token(ctx context.Context, req *v1.TokenReq) error {
	r := g.RequestFromCtx(ctx)

	// 读取顺序与历史实现一致：表单主，query 兜底，Basic 认证覆盖
	grantType := req.GrantType
	clientID := req.ClientID
	if clientID == "" {
		clientID = r.GetQuery("client_id").String()
	}
	if u, _, ok := basicAuth(r); ok {
		clientID = u
	}

	client, err := oidc.FindClient(ctx, clientID)
	if err != nil {
		return err
	}
	if client == nil {
		response.ProtocolError(r, oidc.NewProtocolError(http.StatusUnauthorized, "invalid_client", "未知的 client_id"))
		return nil
	}

	switch grantType {
	case "authorization_code":
		return c.handleAuthCodeGrant(ctx, r, client, req)
	case "refresh_token":
		return c.handleRefreshGrant(ctx, r, client, req)
	default:
		response.ProtocolError(r, oidc.NewProtocolError(http.StatusBadRequest, "unsupported_grant_type", "仅支持 authorization_code 与 refresh_token"))
		return nil
	}
}

func (c *Controller) handleAuthCodeGrant(
	ctx context.Context, r *ghttp.Request, client *entity.OAuthClient, req *v1.TokenReq,
) error {
	ac, err := oidc.ConsumeAuthorizationCode(ctx, req.Code, client.ClientID, req.RedirectURI, req.CodeVerifier)
	if err != nil {
		if pe, ok := err.(*oidc.ProtocolError); ok {
			response.ProtocolError(r, pe)
			return nil
		}
		return err
	}

	user, err := findUserByID(ctx, ac.UserID)
	if err != nil {
		return err
	}
	if user == nil {
		response.ProtocolError(r, oidc.NewProtocolError(http.StatusBadRequest, "invalid_grant", "code 对应用户不存在"))
		return nil
	}

	set, err := oidc.IssueTokenSet(ctx, client.ClientID, user, ac.Scope, ac.Nonce)
	if err != nil {
		return err
	}
	response.Write(r, http.StatusOK, &v1.TokenRes{
		AccessToken:  set.AccessToken,
		TokenType:    "Bearer",
		ExpiresIn:    set.ExpiresIn,
		RefreshToken: set.RefreshToken,
		IDToken:      set.IDToken,
		Scope:        set.Scope,
	})
	return nil
}

func (c *Controller) handleRefreshGrant(
	ctx context.Context, r *ghttp.Request, client *entity.OAuthClient, req *v1.TokenReq,
) error {
	set, err := oidc.RefreshTokenSet(ctx, client.ClientID, req.RefreshToken)
	if err != nil {
		if pe, ok := err.(*oidc.ProtocolError); ok {
			response.ProtocolError(r, pe)
			return nil
		}
		return err
	}
	response.Write(r, http.StatusOK, &v1.TokenRes{
		AccessToken:  set.AccessToken,
		TokenType:    "Bearer",
		ExpiresIn:    set.ExpiresIn,
		RefreshToken: set.RefreshToken,
		IDToken:      set.IDToken,
		Scope:        set.Scope,
	})
	return nil
}

// UserInfo GET /oauth2/userinfo
func (c *Controller) UserInfo(ctx context.Context, req *v1.UserInfoReq) error {
	r := g.RequestFromCtx(ctx)

	token := ""
	if h := r.Header.Get("Authorization"); strings.HasPrefix(h, "Bearer ") {
		token = strings.TrimPrefix(h, "Bearer ")
	} else if req.AccessToken != "" {
		token = req.AccessToken
	}
	if token == "" {
		r.Response.Header().Set("WWW-Authenticate", `Bearer realm="idp"`)
		response.ProtocolError(r, oidc.NewProtocolError(http.StatusUnauthorized, "invalid_token", "缺少 access_token"))
		return nil
	}

	res, err := oidc.UserInfo(ctx, token)
	if err != nil {
		if pe, ok := err.(*oidc.ProtocolError); ok {
			if pe.Status == http.StatusUnauthorized {
				r.Response.Header().Set("WWW-Authenticate", `Bearer realm="idp", error="invalid_token"`)
			}
			response.ProtocolError(r, pe)
			return nil
		}
		return err
	}

	// 按 scope 决定返回字段：没申请就没有该字段（不是返回空值）
	out := map[string]interface{}{"sub": oidc.Sub(res.User.Id)}
	if strings.Contains(res.Scope, "profile") {
		out["preferred_username"] = res.User.Username
		out["name"] = res.User.Nickname
	}
	if strings.Contains(res.Scope, "email") {
		out["email"] = res.User.Email
		out["email_verified"] = true
	}
	response.Write(r, http.StatusOK, out)
	return nil
}

// Revoke POST /oauth2/revoke（RFC 7009）
//
// 无论令牌是否存在都返回 200：否则这个端点就成了"令牌是否有效"的探测接口。
func (c *Controller) Revoke(ctx context.Context, req *v1.RevokeReq) error {
	r := g.RequestFromCtx(ctx)

	if req.Token == "" {
		response.ProtocolError(r, oidc.NewProtocolError(http.StatusBadRequest, "invalid_request", "缺少 token"))
		return nil
	}
	if _, err := oidc.Revoke(ctx, req.Token, req.ClientID); err != nil {
		if pe, ok := err.(*oidc.ProtocolError); ok {
			response.ProtocolError(r, pe)
			return nil
		}
		return err
	}
	response.Write(r, http.StatusOK, &v1.RevokeRes{Status: "ok"})
	return nil
}

// Logout GET /oauth2/logout —— RP 发起的单点登出
//
// 销毁全局会话 + 吊销该用户全部令牌，再回跳 post_logout_redirect_uri。
// 回跳地址必须在客户端注册的白名单内，且因此 client_id 成为必填 ——
// 少了这一步，本端点就是任意站点可用的开放重定向。
func (c *Controller) Logout(ctx context.Context, req *v1.LogoutReq) error {
	r := g.RequestFromCtx(ctx)

	if sid := r.Cookie.Get(consts.SessionCookieName).String(); sid != "" {
		if err := session.Destroy(ctx, sid); err != nil {
			return err
		}
	}
	response.ClearSessionCookie(r)

	if req.PostLogoutRedirectURI == "" {
		response.Write(r, http.StatusOK, &v1.LogoutRes{Status: "logged_out"})
		return nil
	}

	if req.ClientID == "" {
		response.ProtocolError(r, oidc.NewProtocolError(http.StatusBadRequest, "invalid_request",
			"携带 post_logout_redirect_uri 时必须提供 client_id"))
		return nil
	}
	client, err := oidc.FindClient(ctx, req.ClientID)
	if err != nil {
		return err
	}
	if client == nil {
		response.ProtocolError(r, oidc.NewProtocolError(http.StatusBadRequest, "invalid_client",
			"未知的 client_id: "+req.ClientID))
		return nil
	}
	if !oidc.ClientAllowsPostLogout(client, req.PostLogoutRedirectURI) {
		response.ProtocolError(r, oidc.NewProtocolError(http.StatusBadRequest, "invalid_request",
			"post_logout_redirect_uri 未在该客户端注册"))
		return nil
	}

	params := map[string]string{}
	if req.State != "" {
		params["state"] = req.State
	}
	response.Redirect(r, withQuery(req.PostLogoutRedirectURI, params))
	return nil
}

// SessionUser 取当前会话用户（未登录返回 nil, nil）。控制器与中间件共用。
func SessionUser(ctx context.Context, r *ghttp.Request) (*entity.User, error) {
	return session.CurrentUser(ctx, r.Cookie.Get(consts.SessionCookieName).String())
}

// findUserByID 取用户（避免 controller 直接依赖 dao）
func findUserByID(ctx context.Context, id int64) (*entity.User, error) {
	return user.FindByID(ctx, id)
}

// basicAuth 解析 Authorization: Basic 里的客户端凭据。
//
// 不用 gf 的 r.BasicAuth(user, pass)：那个方法的语义是"校验给定口令是否匹配"，
// 返回 bool，拿不到凭据本身；而令牌端点需要的是「客户端声称自己是谁」。
func basicAuth(r *ghttp.Request) (clientID, clientSecret string, ok bool) {
	const prefix = "Basic "
	h := r.Header.Get("Authorization")
	if len(h) <= len(prefix) || !strings.EqualFold(h[:len(prefix)], prefix) {
		return "", "", false
	}
	raw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(h[len(prefix):]))
	if err != nil {
		return "", "", false
	}
	i := strings.IndexByte(string(raw), ':')
	if i < 0 {
		return "", "", false
	}
	return string(raw[:i]), string(raw[i+1:]), true
}

// ── 跳转地址工具 ────────────────────────────────────────────────────────────

// errorRedirect 按 OAuth2 规范把错误回传给客户端（302 到 redirect_uri）
//
// 只有在 redirect_uri 已通过白名单校验之后才能用 —— 否则等于
// 把用户重定向到一个未经验证的地址。
func errorRedirect(r *ghttp.Request, redirectURI, state, code, desc string) {
	response.Redirect(r, withQuery(redirectURI, map[string]string{
		"error":             code,
		"error_description": desc,
		"state":             state,
	}))
}

// urlEncode 只转义会破坏 query 结构的两个字符（与历史实现一致）
func urlEncode(s string) string {
	return strings.ReplaceAll(strings.ReplaceAll(s, "%", "%25"), "&", "%26")
}

// withQuery 在 base 上追加/覆盖参数
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

// queryEscape 按 RFC 3986 对 query 值做百分号编码
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
