package internal

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// ============================================================
// OIDC 客户端：发现文档、token 交换、userinfo、revoke
// ============================================================

// OIDCClient 与 IDP 交互的最小客户端
type OIDCClient struct {
	Issuer      string
	ClientID    string
	RedirectURI string
	HTTP        *http.Client

	// 发现文档缓存
	authEndpoint  string
	tokenEndpoint string
	userInfoEP    string
	revokeEP      string
	endSessionEP  string
}

// Discovery IDP 发现文档（按需取字段）
type Discovery struct {
	Issuer                string `json:"issuer"`
	AuthorizationEndpoint string `json:"authorization_endpoint"`
	TokenEndpoint         string `json:"token_endpoint"`
	UserinfoEndpoint      string `json:"userinfo_endpoint"`
	EndSessionEndpoint    string `json:"end_session_endpoint"`
	RevocationEndpoint    string `json:"revocation_endpoint"`
}

// NewOIDCClient 创建客户端，issuer 为空则使用默认本地地址
func NewOIDCClient(issuer, clientID, redirectURI string) *OIDCClient {
	if issuer == "" {
		issuer = "http://127.0.0.1:8080"
	}
	return &OIDCClient{
		Issuer:      strings.TrimSuffix(issuer, "/"),
		ClientID:    clientID,
		RedirectURI: redirectURI,
		HTTP:        &http.Client{Timeout: 15 * time.Second},
	}
}

// Discover 拉取 /.well-known/openid-configuration
func (c *OIDCClient) Discover(ctx context.Context) (*Discovery, error) {
	req, _ := http.NewRequestWithContext(ctx, "GET", c.Issuer+"/.well-known/openid-configuration", nil)
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return nil, fmt.Errorf("连接 IDP 失败（%s）：%w\n请确认 auth-hub 已启动", c.Issuer, err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("获取发现文档失败，状态码 %d", resp.StatusCode)
	}
	var d Discovery
	if err := json.Unmarshal(body, &d); err != nil {
		return nil, fmt.Errorf("解析发现文档失败: %w", err)
	}
	c.authEndpoint = d.AuthorizationEndpoint
	c.tokenEndpoint = d.TokenEndpoint
	c.userInfoEP = d.UserinfoEndpoint
	c.endSessionEP = d.EndSessionEndpoint
	// 兼容：IDP 未声明 revocation_endpoint 时，回退到本地既定路径
	if d.RevocationEndpoint != "" {
		c.revokeEP = d.RevocationEndpoint
	} else {
		c.revokeEP = c.Issuer + "/oauth2/revoke"
	}
	return &d, nil
}

// WeMustDiscover 确保已完成发现（失败则返回错误）
func (c *OIDCClient) ensureDiscovered(ctx context.Context) error {
	if c.tokenEndpoint != "" {
		return nil
	}
	_, err := c.Discover(ctx)
	return err
}

// AuthorizationURL 构造授权地址，携带全部 PKCE 参数
func (c *OIDCClient) AuthorizationURL(p *PKCE) (string, error) {
	if c.authEndpoint == "" {
		return "", fmt.Errorf("尚未获取授权端点，请先调用 Discover")
	}
	u, err := url.Parse(c.authEndpoint)
	if err != nil {
		return "", err
	}
	q := u.Query()
	q.Set("client_id", c.ClientID)
	q.Set("redirect_uri", c.RedirectURI)
	q.Set("response_type", "code")
	q.Set("scope", "openid profile email")
	q.Set("state", p.State)
	q.Set("nonce", p.Nonce)
	q.Set("code_challenge", p.CodeChallenge)
	q.Set("code_challenge_method", p.Method)
	u.RawQuery = q.Encode()
	return u.String(), nil
}

// TokenResponse /oauth2/token 响应
type TokenResponse struct {
	AccessToken  string `json:"access_token"`
	IDToken      string `json:"id_token"`
	RefreshToken string `json:"refresh_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int    `json:"expires_in"`
	Scope        string `json:"scope"`
	Error        string `json:"error"`
	ErrorDesc    string `json:"error_description"`
}

// ExchangeCode 用 code + code_verifier 换取 token（PKCE，无 client_secret）
func (c *OIDCClient) ExchangeCode(ctx context.Context, code, verifier string) (*TokenResponse, error) {
	if err := c.ensureDiscovered(ctx); err != nil {
		return nil, err
	}
	form := url.Values{}
	form.Set("grant_type", "authorization_code")
	form.Set("code", code)
	form.Set("client_id", c.ClientID)
	form.Set("redirect_uri", c.RedirectURI)
	form.Set("code_verifier", verifier)

	body, status, err := c.postForm(ctx, c.tokenEndpoint, form)
	if err != nil {
		return nil, err
	}
	var tr TokenResponse
	if err := json.Unmarshal(body, &tr); err != nil {
		return nil, fmt.Errorf("解析 token 响应失败: %w", err)
	}
	if status != 200 || tr.Error != "" {
		return nil, fmt.Errorf("换取 token 失败（%d）：%s %s", status, tr.Error, tr.ErrorDesc)
	}
	return &tr, nil
}

// Refresh 使用 refresh_token 续期
func (c *OIDCClient) Refresh(ctx context.Context, refreshToken string) (*TokenResponse, error) {
	if err := c.ensureDiscovered(ctx); err != nil {
		return nil, err
	}
	form := url.Values{}
	form.Set("grant_type", "refresh_token")
	form.Set("refresh_token", refreshToken)
	form.Set("client_id", c.ClientID)

	body, status, err := c.postForm(ctx, c.tokenEndpoint, form)
	if err != nil {
		return nil, err
	}
	var tr TokenResponse
	if err := json.Unmarshal(body, &tr); err != nil {
		return nil, fmt.Errorf("解析刷新响应失败: %w", err)
	}
	if status != 200 || tr.Error != "" {
		return nil, fmt.Errorf("刷新失败（%d）：%s %s", status, tr.Error, tr.ErrorDesc)
	}
	return &tr, nil
}

// Revoke 吊销 refresh_token（RFC 7009）
func (c *OIDCClient) Revoke(ctx context.Context, token, tokenTypeHint string) error {
	if err := c.ensureDiscovered(ctx); err != nil {
		return err
	}
	form := url.Values{}
	form.Set("token", token)
	form.Set("client_id", c.ClientID)
	if tokenTypeHint != "" {
		form.Set("token_type_hint", tokenTypeHint)
	}
	_, status, err := c.postForm(ctx, c.revokeEP, form)
	if err != nil {
		return err
	}
	if status != 200 {
		return fmt.Errorf("吊销令牌失败，状态码 %d", status)
	}
	return nil
}

// UserInfo 调用 /oauth2/userinfo 获取用户信息
func (c *OIDCClient) UserInfo(ctx context.Context, accessToken string) (map[string]any, error) {
	if err := c.ensureDiscovered(ctx); err != nil {
		return nil, err
	}
	req, _ := http.NewRequestWithContext(ctx, "GET", c.userInfoEP, nil)
	if accessToken != "" {
		req.Header.Set("Authorization", "Bearer "+accessToken)
	}
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("获取用户信息失败（%d）：%s", resp.StatusCode, string(body))
	}
	var out map[string]any
	if err := json.Unmarshal(body, &out); err != nil {
		return nil, err
	}
	return out, nil
}

// postForm 发送表单请求并读取响应
func (c *OIDCClient) postForm(ctx context.Context, endpoint string, form url.Values) ([]byte, int, error) {
	req, err := http.NewRequestWithContext(ctx, "POST", endpoint, strings.NewReader(form.Encode()))
	if err != nil {
		return nil, 0, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return nil, 0, fmt.Errorf("请求 %s 失败: %w", endpoint, err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	return body, resp.StatusCode, nil
}

// EndSessionEndpoint 返回登出端点（供展示）
func (c *OIDCClient) EndSessionEndpoint() string { return c.endSessionEP }

// ============================================================
// id_token 载荷解析（仅用于本地展示；签名校验由服务端负责）
// ============================================================

// ParseIDTokenClaims 无验签解析 id_token payload
// 说明：CLI 不做签名校验是安全的取舍——token 由本机浏览器直接经 IDP 换回，
// 且所有受保护操作仍由服务端重新鉴权；此处仅用于展示 subject/username。
func ParseIDTokenClaims(idToken string) (map[string]any, error) {
	parts := strings.Split(idToken, ".")
	if len(parts) != 3 {
		return nil, fmt.Errorf("id_token 格式不正确")
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, fmt.Errorf("解析 id_token 载荷失败: %w", err)
	}
	var m map[string]any
	if err := json.Unmarshal(payload, &m); err != nil {
		return nil, err
	}
	return m, nil
}
