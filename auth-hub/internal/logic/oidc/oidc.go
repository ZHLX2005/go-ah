// Package oidc 实现 OIDC / OAuth2 授权码流程的协议逻辑：PKCE 校验、
// 回调地址白名单匹配、授权码一次性消费、令牌签发与吊销、userinfo。
//
// 这一层的每个判断都直接决定认证是否可信，因此：
//   - 所有拒绝都返回带状态码与 OAuth 错误码的 ProtocolError，
//     让表示层不必自己猜该回 400 还是 401；
//   - 校验顺序固定（客户端存在 → 白名单 → 参数 → 一次性 → 过期 → PKCE），
//     先做能确定性失败的检查，避免把"码不存在"和"PKCE 错"混成一个错误；
//   - 任何"未知取值"都按更严格的分支处理，不静默降级。
package oidc

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/gogf/gf/v2/frame/g"

	"github.com/ZHLX2005/go-ah/auth-hub/internal/consts"
	"github.com/ZHLX2005/go-ah/auth-hub/internal/dao"
	"github.com/ZHLX2005/go-ah/auth-hub/internal/db"
	"github.com/ZHLX2005/go-ah/auth-hub/internal/logic/signing"
	"github.com/ZHLX2005/go-ah/auth-hub/internal/model/entity"
	"github.com/ZHLX2005/go-ah/auth-hub/internal/utility"
)

// ProtocolError OIDC 端点的失败响应：状态码 + OAuth 错误码 + 可读原因
type ProtocolError struct {
	Status int
	Code   string
	Desc   string
}

// Error 实现 error 接口
func (e *ProtocolError) Error() string { return e.Desc }

// NewProtocolError 构造协议错误
func NewProtocolError(status int, code, desc string) *ProtocolError {
	return &ProtocolError{Status: status, Code: code, Desc: desc}
}

// 常用错误构造（集中在这里，保证同类失败的状态码与错误码始终一致）
func errInvalidGrant(desc string) *ProtocolError {
	return NewProtocolError(http.StatusBadRequest, "invalid_grant", desc)
}

func errInvalidToken(desc string) *ProtocolError {
	return NewProtocolError(http.StatusUnauthorized, "invalid_token", desc)
}

// ── PKCE ────────────────────────────────────────────────────────────────────

// VerifyPKCE 校验 code_verifier 与 code_challenge 是否匹配。
//
// 按 RFC 7636，code_challenge_method 只有 "S256" 与 "plain" 两个合法值。
// 这里采用白名单语义：只有显式等于 "plain" 才走明文比较，其余任何取值
// （大小写变体、拼写错误、空值）一律按 S256 处理 —— 对客户端更严格，
// 也避免把未知 method 静默降级成 plain 比较从而削弱校验。
func VerifyPKCE(verifier, challenge, method string) bool {
	if verifier == "" || challenge == "" {
		return false
	}
	if method == "plain" {
		return verifier == challenge
	}
	h := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(h[:]) == challenge
}

// ── 回调地址白名单 ──────────────────────────────────────────────────────────

// ClientAllowsRedirect 校验 redirect_uri 是否在客户端注册白名单内。
//
// 支持两种注册形式：
//  1. 精确匹配：http://127.0.0.1:8081/oauth/callback
//  2. 回环通配：http://127.0.0.1:*/callback
//     仅允许 127.0.0.1 / localhost，用于 CLI 等自动分配临时端口的本机客户端。
//     RFC 8252（OAuth 2.0 for Native Apps）推荐本机应用使用回环地址重定向、
//     端口由系统动态分配，因此这里放开端口但严格锁定主机为回环地址。
func ClientAllowsRedirect(client *entity.OAuthClient, uri string) bool {
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

// ClientAllowsPostLogout 校验登出回跳地址是否在白名单内。
//
// 不做这层校验，/oauth2/logout 就是一个开放重定向：任何人构造
// /oauth2/logout?post_logout_redirect_uri=https://evil.com
// 都能借认证中心的域名把用户带去任意站点。
func ClientAllowsPostLogout(client *entity.OAuthClient, uri string) bool {
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
	return restPat[pSlash:] == path
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

// ValidRedirectURIs 校验注册回调地址的格式。
// 允许：完整 http/https URL；端口通配仅限回环地址。
func ValidRedirectURIs(uris []string) bool {
	for _, u := range uris {
		u = strings.TrimSpace(u)
		if u == "" {
			return false
		}
		if !strings.HasPrefix(u, "http://") && !strings.HasPrefix(u, "https://") {
			return false
		}
		// 端口通配必须为回环地址
		if strings.Contains(u, ":*") {
			if !strings.Contains(u, "://127.0.0.1:*") && !strings.Contains(u, "://localhost:*") {
				return false
			}
		}
	}
	return true
}

// ── 客户端查询 ──────────────────────────────────────────────────────────────

// FindClient 按 client_id 查客户端；不存在返回 (nil, nil)
func FindClient(ctx context.Context, clientID string) (*entity.OAuthClient, error) {
	if clientID == "" {
		return nil, nil
	}
	var c entity.OAuthClient
	found, err := db.ScanOne(ctx, dao.OAuthClient.Ctx(ctx).Where("client_id", clientID), &c)
	if err != nil {
		return nil, err
	}
	if !found {
		return nil, nil
	}
	return &c, nil
}

// VerifyClientAuth 校验令牌端点的客户端身份。
//
// 规则按 token_endpoint_auth_method 语义收口：
//   - public 客户端（is_public=true，即 method=none）：不要求 secret，
//     带了也不比对——它没有可比对的东西。PKCE 才是它的身份证明。
//   - confidential 客户端：必须携带 secret 且与库中一致（常数时间比较）。
//     库里没存 secret 视为配置残缺，按拒绝处理（fail-closed）：
//     一个"声称机密却没配密钥"的客户端，放行等于把机密当公共用。
//
// 历史包袱说明：本端点曾长期不校验 secret（发现文档却声明支持
// client_secret_post/basic）。线上已有接入方全部注册为 public 客户端，
// 因此本函数对它们是 no-op；真正受影响的只有管理后台手工创建的
// confidential 客户端——它们上线时从没被要求发过 secret，切换到强制
// 校验的那一刻会在下次续期时收到 401 invalid_client，需要先配好
// OIDC_CLIENT_SECRET 再升级（见 docs 的迁移说明）。
func VerifyClientAuth(client *entity.OAuthClient, clientSecret string) error {
	if client.IsPublicClient() {
		return nil
	}
	if client.ClientSecret == "" {
		return NewProtocolError(http.StatusUnauthorized, "invalid_client",
			"机密客户端未配置 client_secret（请联系管理员重新下发）")
	}
	if clientSecret == "" ||
		subtle.ConstantTimeCompare([]byte(clientSecret), []byte(client.ClientSecret)) != 1 {
		return NewProtocolError(http.StatusUnauthorized, "invalid_client", "客户端认证失败")
	}
	return nil
}

// ── 授权码 ──────────────────────────────────────────────────────────────────

// AuthCodeInput 生成授权码所需的上下文
type AuthCodeInput struct {
	ClientID            string
	UserID              int64
	RedirectURI         string
	Scope               string
	Nonce               string
	CodeChallenge       string
	CodeChallengeMethod string
}

// CreateAuthorizationCode 生成一次性授权码
func CreateAuthorizationCode(ctx context.Context, in AuthCodeInput) (string, error) {
	code := utility.RandomToken(32)
	now := time.Now()
	if _, err := dao.OAuthAuthorizationCode.Ctx(ctx).Data(g.Map{
		"code":                  code,
		"client_id":             in.ClientID,
		"user_id":               in.UserID,
		"redirect_uri":          in.RedirectURI,
		"scope":                 in.Scope,
		"nonce":                 in.Nonce,
		"code_challenge":        in.CodeChallenge,
		"code_challenge_method": in.CodeChallengeMethod,
		"expires_at":            now.Add(consts.AuthCodeTTL),
		"created_at":            now,
	}).Insert(); err != nil {
		return "", err
	}
	return code, nil
}

// ConsumeAuthorizationCode 校验并消费授权码，返回其内容。
//
// 校验顺序不可打乱：不匹配/不存在这类"确定性拒绝"放前面，
// 用的是同一个 invalid_grant 错误码但原因各不相同 —— 排查时
// 原因文本就是唯一线索，不能糊成一个"授权失败"。
//
// 一次性消费用**条件 UPDATE 抢占**（WHERE used_at IS NULL），不是读后写：
// 同一个 code 的两次并发兑换会双双通过 SELECT 校验，但只有一次 UPDATE
// 能抢到 affected=1，另一次进入重放分支。曾经这里是"先读再无条件 UPDATE"，
// 并发重放会各自签出一套令牌——单实例低并发下测试永远全绿，
// 恰恰是攻击者最会利用的窗口（口径同 logic/qr 对票据迁移的纪律）。
//
// 重放分支按 RFC 6749 §4.1.2 吊销该 code 已签发的全部令牌：
// 重放本身就是凭据泄露的信号，此时"保留已发令牌"没有任何正当场景。
func ConsumeAuthorizationCode(
	ctx context.Context, code, clientID, redirectURI, verifier string,
) (*entity.OAuthAuthorizationCode, error) {
	var ac entity.OAuthAuthorizationCode
	found, err := db.ScanOne(ctx, dao.OAuthAuthorizationCode.Ctx(ctx).Where("code", code), &ac)
	if err != nil {
		return nil, err
	}
	if !found {
		return nil, errInvalidGrant("code 不存在")
	}
	if ac.ClientID != clientID || ac.RedirectURI != redirectURI {
		return nil, errInvalidGrant("client/redirect_uri 不匹配")
	}
	if time.Now().After(ac.ExpiresAt) {
		return nil, errInvalidGrant("code 已过期")
	}
	if !VerifyPKCE(verifier, ac.CodeChallenge, ac.CodeChallengeMethod) {
		return nil, errInvalidGrant("PKCE 校验失败")
	}
	// 顺带的确定性拒绝：非并发的重放直接在这里暴露（SELECT 已见 used_at 非空），
	// 与抢占失败走同一条吊销路径，行为不分先后。
	if ac.UsedAt != nil {
		if rerr := revokeTokensForCode(ctx, ac.Id); rerr != nil {
			return nil, rerr
		}
		return nil, errInvalidGrant("code 已被使用")
	}

	// 抢占：必须放在所有校验之后——PKCE 失败的请求不该烧掉这张 code
	// （攻击者拿不到 verifier，但也不该让他用错误 verifier 把合法者的 code 打废）。
	now := time.Now()
	res, err := dao.OAuthAuthorizationCode.Ctx(ctx).
		Where("id", ac.Id).
		Where("used_at IS NULL").
		Data(g.Map{"used_at": now}).
		Update()
	if err != nil {
		return nil, err
	}
	n, err := res.RowsAffected()
	if err != nil {
		return nil, err
	}
	if n == 0 {
		// 并发重放：校验全部通过，但另一个请求先抢到了。
		if rerr := revokeTokensForCode(ctx, ac.Id); rerr != nil {
			return nil, rerr
		}
		return nil, errInvalidGrant("code 已被使用")
	}
	ac.UsedAt = &now
	return &ac, nil
}

// revokeTokensForCode 吊销某授权码签发过的全部令牌（code 重放的对策）。
//
// 吊销失败会连同本次兑换一起失败：与其"记了重放却放任令牌存活"，
// 不如让调用方收到错误重试——重放检测漏一次的代价是令牌多活一段，
// 而静默漏掉的代价是"重放对策存在但不生效"这种错觉。
func revokeTokensForCode(ctx context.Context, codeID int64) error {
	now := time.Now()
	if _, err := dao.OAuthRefreshToken.Ctx(ctx).
		Where("authorization_code_id", codeID).
		Where("revoked_at IS NULL").
		Data(g.Map{"revoked_at": now}).
		Update(); err != nil {
		return err
	}
	if _, err := dao.OAuthAccessToken.Ctx(ctx).
		Where("authorization_code_id", codeID).
		Delete(); err != nil {
		return err
	}
	g.Log().Warningf(ctx, "[auth-hub] 授权码被重放，已吊销其签发的令牌: code_row=%d", codeID)
	return nil
}

// ── 令牌集 ──────────────────────────────────────────────────────────────────

// TokenSet 一次令牌签发的产出
type TokenSet struct {
	AccessToken  string
	RefreshToken string
	IDToken      string
	Scope        string
	ExpiresIn    int
}

// IssueTokenSet 为授权码流程签发一整套令牌。
//
// codeID 是签发来源的授权码行 id：重放检测要按它精确吊销（见
// revokeTokensForCode），没有它就只能"code 被重放了但不知道该吊销谁"。
func IssueTokenSet(ctx context.Context, clientID string, user *entity.User, scope, nonce string, codeID int64) (*TokenSet, error) {
	idToken, err := signing.IDToken(ctx, user, clientID, nonce, scope)
	if err != nil {
		return nil, err
	}
	accessToken := utility.RandomToken(32)
	refreshToken := utility.RandomToken(40)
	now := time.Now()

	if _, err := dao.OAuthAccessToken.Ctx(ctx).Data(g.Map{
		"token":                 accessToken,
		"client_id":             clientID,
		"user_id":               user.Id,
		"scope":                 scope,
		"expires_at":            now.Add(consts.AccessTokenTTL),
		"created_at":            now,
		"authorization_code_id": codeID,
	}).Insert(); err != nil {
		return nil, err
	}
	if _, err := dao.OAuthRefreshToken.Ctx(ctx).Data(g.Map{
		"token":                 refreshToken,
		"client_id":             clientID,
		"user_id":               user.Id,
		"scope":                 scope,
		"expires_at":            now.Add(consts.RefreshTokenTTL),
		"created_at":            now,
		"authorization_code_id": codeID,
	}).Insert(); err != nil {
		return nil, err
	}

	return &TokenSet{
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
		IDToken:      idToken,
		Scope:        scope,
		ExpiresIn:    int(consts.AccessTokenTTL.Seconds()),
	}, nil
}

// RefreshTokenSet 用 refresh_token 换新令牌。
//
// 注意：refresh_token 不存在/已吊销/已过期一律返回 400 invalid_grant。
// RFC 6749 §5.2 规定 invalid_grant 对应 HTTP 400（而非 401）；
// 401 保留给"客户端自身认证失败"的场景。
func RefreshTokenSet(ctx context.Context, clientID, refreshToken string) (*TokenSet, error) {
	var rec entity.OAuthRefreshToken
	found, err := db.ScanOne(ctx, dao.OAuthRefreshToken.Ctx(ctx).Where("token", refreshToken), &rec)
	if err != nil {
		return nil, err
	}
	if !found {
		return nil, errInvalidGrant("refresh_token 不存在")
	}
	if rec.RevokedAt != nil {
		return nil, errInvalidGrant("refresh_token 已吊销")
	}
	if time.Now().After(rec.ExpiresAt) {
		return nil, errInvalidGrant("refresh_token 已过期")
	}
	if rec.ClientID != clientID {
		return nil, errInvalidGrant("client 不匹配")
	}

	var user entity.User
	found, err = db.ScanOne(ctx, dao.User.Ctx(ctx).Where("id", rec.UserID), &user)
	if err != nil {
		return nil, err
	}
	if !found {
		return nil, errInvalidGrant("refresh_token 对应用户不存在")
	}

	idToken, err := signing.IDToken(ctx, &user, clientID, "", rec.Scope)
	if err != nil {
		return nil, err
	}
	newAccess := utility.RandomToken(32)
	if _, err := dao.OAuthAccessToken.Ctx(ctx).Data(g.Map{
		"token":      newAccess,
		"client_id":  clientID,
		"user_id":    user.Id,
		"scope":      rec.Scope,
		"expires_at": time.Now().Add(consts.AccessTokenTTL),
		"created_at": time.Now(),
	}).Insert(); err != nil {
		return nil, err
	}

	return &TokenSet{
		AccessToken:  newAccess,
		RefreshToken: rec.Token,
		IDToken:      idToken,
		Scope:        rec.Scope,
		ExpiresIn:    int(consts.AccessTokenTTL.Seconds()),
	}, nil
}

// ── 吊销 ────────────────────────────────────────────────────────────────────

// Revoke 吊销 refresh_token（标记 revoked_at）或删除 access_token。
// 返回受影响的行数；调用方按 RFC 7009 无论是否存在都回 200。
func Revoke(ctx context.Context, token, clientID string) (int64, error) {
	if clientID != "" {
		c, err := FindClient(ctx, clientID)
		if err != nil {
			return 0, err
		}
		if c == nil {
			return 0, NewProtocolError(http.StatusUnauthorized, "invalid_client", "未知的 client_id: "+clientID)
		}
	}

	now := time.Now()
	var revoked int64
	res, err := dao.OAuthRefreshToken.Ctx(ctx).
		Where("token", token).
		Where("revoked_at IS NULL").
		Data(g.Map{"revoked_at": now}).
		Update()
	if err != nil {
		return 0, err
	}
	if n, e := res.RowsAffected(); e == nil {
		revoked += n
	}

	// 传入的是 access_token 时直接删除，让 userinfo 立即失效
	res2, err := dao.OAuthAccessToken.Ctx(ctx).Where("token", token).Delete()
	if err != nil {
		return 0, err
	}
	if n, e := res2.RowsAffected(); e == nil {
		revoked += n
	}
	if revoked > 0 {
		g.Log().Infof(ctx, "[auth-hub] 已吊销令牌 client=%s", clientID)
	}
	return revoked, nil
}

// ── userinfo ────────────────────────────────────────────────────────────────

// UserInfoResult userinfo 端点的结果
type UserInfoResult struct {
	User  *entity.User
	Scope string
}

// UserInfo 按 Bearer access_token 取用户信息。
func UserInfo(ctx context.Context, accessToken string) (*UserInfoResult, error) {
	if accessToken == "" {
		return nil, errInvalidToken("缺少 access_token")
	}
	var at entity.OAuthAccessToken
	found, err := db.ScanOne(ctx, dao.OAuthAccessToken.Ctx(ctx).Where("token", accessToken), &at)
	if err != nil {
		return nil, err
	}
	if !found {
		return nil, errInvalidToken("access_token 无效")
	}
	if time.Now().After(at.ExpiresAt) {
		return nil, errInvalidToken("access_token 已过期")
	}
	var user entity.User
	found, err = db.ScanOne(ctx, dao.User.Ctx(ctx).Where("id", at.UserID), &user)
	if err != nil {
		return nil, err
	}
	if !found {
		return nil, NewProtocolError(http.StatusNotFound, "user_not_found", "用户不存在")
	}
	return &UserInfoResult{User: &user, Scope: at.Scope}, nil
}

// Sub 用户 ID 对应的 OIDC sub
func Sub(userID int64) string { return fmt.Sprintf("%d", userID) }

// ── 过期清理（janitor 调度）──────────────────────────────────────────────────

// PurgeExpiredAuthCodes 删除过期已超过保留期的授权码行。
//
// 授权码行只在登录时产生（一张一行、5 分钟 TTL），量级天然小，
// 但从不清理依然无限累积；保留 7 天与 QR 票据同口径——
// "这次登录发生在什么时候"是它唯一的审计价值。
func PurgeExpiredAuthCodes(ctx context.Context) (int64, error) {
	return db.DeleteOlderThan(ctx, consts.TableOAuthAuthorizationCode,
		time.Now().Add(-consts.TokenPurgeCodeRetain))
}

// PurgeExpiredAccessTokens 删除已过期的 access_token 行。
//
// 这是全平台**积压速度最快**的表：每 10 分钟 TTL 一行，业务方后台续期
// 还会持续放大。它也是清理任务存在的首要理由——没有这一条，
// 库会先于任何水平扩展问题被撑爆。
func PurgeExpiredAccessTokens(ctx context.Context) (int64, error) {
	return db.DeleteOlderThan(ctx, consts.TableOAuthAccessToken,
		time.Now().Add(-consts.TokenPurgeAccessRetain))
}

// PurgeGoneRefreshTokens 删除过期/吊销已超过保留期的 refresh_token 行。
//
// 吊销行与过期行同等清理：revoked_at 只是"令牌死了"的另一种死法，
// 死了的令牌不留 7 天以上的尸位。
func PurgeGoneRefreshTokens(ctx context.Context) (int64, error) {
	cutoff := time.Now().Add(-consts.TokenPurgeRefreshRetain)
	return db.DeleteRefreshTokensGone(ctx, cutoff, cutoff)
}
