// Package admin 管理后台的业务逻辑：用户、会话、令牌、OIDC 客户端。
//
// 与 protocol 层的分工：这里只做"取数 + 校验 + 写库"，
// 权限判断（是否管理员）属于横切关注点，在 middleware 里统一做，
// 不散落到每个方法里 —— 散落的权限判断必然漏掉某一处。
package admin

import (
	"context"
	"strings"
	"time"

	"github.com/gogf/gf/v2/frame/g"

	"github.com/ZHLX2005/go-ah/auth-hub/internal/consts"
	"github.com/ZHLX2005/go-ah/auth-hub/internal/dao"
	"github.com/ZHLX2005/go-ah/auth-hub/internal/db"
	"github.com/ZHLX2005/go-ah/auth-hub/internal/logic/oidc"
	"github.com/ZHLX2005/go-ah/auth-hub/internal/model/entity"
	"github.com/ZHLX2005/go-ah/auth-hub/internal/utility"
)

// ── 用户 ────────────────────────────────────────────────────────────────────

// UserRow 用户列表行（附带会话/令牌计数，便于排查）
type UserRow struct {
	Id            int64
	Username      string
	Email         string
	Nickname      string
	IsAdmin       bool
	CreatedAt     time.Time
	SessionCount  int64
	RefreshCount  int64
	ActiveRefresh int64
}

// ListUsers 用户列表
func ListUsers(ctx context.Context) ([]UserRow, error) {
	var users []entity.User
	if err := dao.User.Ctx(ctx).Order("id asc").Scan(&users); err != nil {
		return nil, err
	}
	now := time.Now()
	out := make([]UserRow, 0, len(users))
	for _, u := range users {
		sessCount, err := dao.UserSession.Ctx(ctx).
			Where("user_id", u.Id).Where("expires_at >", now).Count()
		if err != nil {
			return nil, err
		}
		rtCount, err := dao.OAuthRefreshToken.Ctx(ctx).Where("user_id", u.Id).Count()
		if err != nil {
			return nil, err
		}
		activeCount, err := dao.OAuthRefreshToken.Ctx(ctx).
			Where("user_id", u.Id).
			Where("revoked_at IS NULL").
			Where("expires_at >", now).
			Count()
		if err != nil {
			return nil, err
		}
		out = append(out, UserRow{
			Id: u.Id, Username: u.Username, Email: u.Email, Nickname: u.Nickname,
			IsAdmin: u.IsAdmin, CreatedAt: u.CreatedAt,
			SessionCount: int64(sessCount), RefreshCount: int64(rtCount), ActiveRefresh: int64(activeCount),
		})
	}
	return out, nil
}

// SessionRow 活跃会话行
type SessionRow struct {
	SessionID string
	ExpiresAt time.Time
	CreatedAt time.Time
}

// UserSessions 指定用户的活跃会话
func UserSessions(ctx context.Context, userID int64) ([]SessionRow, error) {
	var sessions []entity.UserSession
	if err := dao.UserSession.Ctx(ctx).
		Where("user_id", userID).
		Where("expires_at >", time.Now()).
		Order("created_at desc").
		Scan(&sessions); err != nil {
		return nil, err
	}
	out := make([]SessionRow, 0, len(sessions))
	for _, s := range sessions {
		out = append(out, SessionRow{
			SessionID: MaskToken(s.SessionID),
			ExpiresAt: s.ExpiresAt,
			CreatedAt: s.CreatedAt,
		})
	}
	return out, nil
}

// MaskToken 令牌脱敏：保留前 8 位
func MaskToken(t string) string {
	if len(t) <= 8 {
		return t
	}
	return t[:8] + "••••••••"
}

// ── 令牌 ────────────────────────────────────────────────────────────────────

// RefreshRow 刷新令牌列表行
type RefreshRow struct {
	Id        int64
	Token     string
	UserID    int64
	Username  string
	ClientID  string
	Scope     string
	ExpiresAt time.Time
	Revoked   bool
	RevokedAt *time.Time
	CreatedAt time.Time
	Expired   bool
}

// tokenRows 组装令牌行（批量取用户名，避免 N+1）
func tokenRows(ctx context.Context, tokens []entity.OAuthRefreshToken) ([]RefreshRow, error) {
	userNames := map[int64]string{}
	ids := make([]int64, 0, len(tokens))
	for _, t := range tokens {
		ids = append(ids, t.UserID)
	}
	if len(ids) > 0 {
		var users []entity.User
		if err := dao.User.Ctx(ctx).WhereIn("id", ids).Scan(&users); err != nil {
			return nil, err
		}
		for _, u := range users {
			userNames[u.Id] = u.Username
		}
	}
	now := time.Now()
	out := make([]RefreshRow, 0, len(tokens))
	for _, t := range tokens {
		out = append(out, RefreshRow{
			Id: t.Id, Token: MaskToken(t.Token), UserID: t.UserID,
			Username: userNames[t.UserID], ClientID: t.ClientID, Scope: t.Scope,
			ExpiresAt: t.ExpiresAt, Revoked: t.RevokedAt != nil, RevokedAt: t.RevokedAt,
			CreatedAt: t.CreatedAt, Expired: now.After(t.ExpiresAt),
		})
	}
	return out, nil
}

// UserTokens 指定用户的刷新令牌
func UserTokens(ctx context.Context, userID int64) ([]RefreshRow, error) {
	var tokens []entity.OAuthRefreshToken
	if err := dao.OAuthRefreshToken.Ctx(ctx).
		Where("user_id", userID).
		Order("created_at desc").
		Scan(&tokens); err != nil {
		return nil, err
	}
	return tokenRows(ctx, tokens)
}

// ListRefreshTokens 全量刷新令牌。status: all | active | revoked
func ListRefreshTokens(ctx context.Context, status string) ([]RefreshRow, error) {
	m := dao.OAuthRefreshToken.Ctx(ctx).Order("created_at desc")
	switch status {
	case "active":
		m = m.Where("revoked_at IS NULL").Where("expires_at >", time.Now())
	case "revoked":
		m = m.Where("revoked_at IS NOT NULL")
	}
	var tokens []entity.OAuthRefreshToken
	if err := m.Limit(500).Scan(&tokens); err != nil {
		return nil, err
	}
	return tokenRows(ctx, tokens)
}

// RevokeRefreshToken 吊销刷新令牌（按 id 或按 token 值），返回受影响行数
func RevokeRefreshToken(ctx context.Context, id *int64, token string) (int64, error) {
	now := time.Now()
	m := dao.OAuthRefreshToken.Ctx(ctx).Where("revoked_at IS NULL")
	switch {
	case id != nil:
		m = m.Where("id", *id)
	case token != "":
		m = m.Where("token", token)
	default:
		return 0, errInvalid("需要提供 id 或 token")
	}
	res, err := m.Data(g.Map{"revoked_at": now}).Update()
	if err != nil {
		return 0, err
	}
	n, err := res.RowsAffected()
	return n, err
}

// ── OIDC 客户端 ─────────────────────────────────────────────────────────────

// ListClients 客户端列表
func ListClients(ctx context.Context) ([]entity.OAuthClient, error) {
	var clients []entity.OAuthClient
	if err := dao.OAuthClient.Ctx(ctx).Order("id asc").Scan(&clients); err != nil {
		return nil, err
	}
	return clients, nil
}

// CreateClientInput 创建客户端入参
type CreateClientInput struct {
	ClientID       string
	ClientName     string
	RedirectURIs   []string
	Scopes         []string
	IsPublic       *bool
	PKCERequired   *bool
	Enabled        *bool
	PostLogoutURIs []string
}

// CreateClient 创建客户端，返回实体与"仅此一次"的明文密钥（公共客户端为空）
func CreateClient(ctx context.Context, in CreateClientInput) (*entity.OAuthClient, string, error) {
	clientID := strings.TrimSpace(in.ClientID)
	if clientID == "" {
		return nil, "", errInvalid("client_id 不能为空")
	}
	if len(in.RedirectURIs) == 0 {
		return nil, "", errInvalid("至少需要配置一个回调地址")
	}
	if !oidc.ValidRedirectURIs(in.RedirectURIs) {
		return nil, "", errInvalid("回调地址必须为完整 URL（http/https）；端口通配仅支持 127.0.0.1 / localhost")
	}
	exists, err := oidc.FindClient(ctx, clientID)
	if err != nil {
		return nil, "", err
	}
	if exists != nil {
		return nil, "", errConflict("该 client_id 已存在")
	}

	isPublic := true
	if in.IsPublic != nil {
		isPublic = *in.IsPublic
	}
	// 公共客户端强制 PKCE：无密钥的客户端只靠 PKCE 防授权码拦截
	pkce := true
	if in.PKCERequired != nil {
		pkce = *in.PKCERequired
	}
	if isPublic {
		pkce = true
	}
	enabled := true
	if in.Enabled != nil {
		enabled = *in.Enabled
	}
	scopes := in.Scopes
	if len(scopes) == 0 {
		scopes = []string{"openid", "profile", "email"}
	}

	secret, plainSecret := "", ""
	if !isPublic {
		plainSecret = generateClientSecret()
		secret = plainSecret // 与历史实现一致：演示用途存明文，生产应存哈希
	}

	now := time.Now()
	id, err := dao.OAuthClient.Ctx(ctx).Data(g.Map{
		"client_id":        clientID,
		"client_secret":    secret,
		"client_name":      in.ClientName,
		"redirect_uris":    strings.Join(in.RedirectURIs, " "),
		"scopes":           strings.Join(scopes, " "),
		"is_public":        isPublic,
		"pkce_required":    pkce,
		"enabled":          enabled,
		"post_logout_uris": strings.Join(in.PostLogoutURIs, " "),
		"created_at":       now,
		"updated_at":       now,
	}).InsertAndGetId()
	if err != nil {
		return nil, "", err
	}

	created, err := findClientByID(ctx, id)
	if err != nil {
		return nil, "", err
	}
	return created, plainSecret, nil
}

// UpdateClientInput 更新客户端入参（nil 表示不改该项）
type UpdateClientInput struct {
	ClientName     *string
	RedirectURIs   []string
	Scopes         []string
	PKCERequired   *bool
	Enabled        *bool
	PostLogoutURIs []string
}

// UpdateClient 更新客户端
func UpdateClient(ctx context.Context, id int64, in UpdateClientInput) (*entity.OAuthClient, error) {
	cur, err := findClientByID(ctx, id)
	if err != nil {
		return nil, err
	}
	if cur == nil {
		return nil, errNotFound("客户端不存在")
	}

	data := g.Map{"updated_at": time.Now()}
	if len(in.RedirectURIs) > 0 {
		if !oidc.ValidRedirectURIs(in.RedirectURIs) {
			return nil, errInvalid("回调地址格式不正确")
		}
		data["redirect_uris"] = strings.Join(in.RedirectURIs, " ")
	}
	if in.ClientName != nil {
		data["client_name"] = *in.ClientName
	}
	if len(in.Scopes) > 0 {
		data["scopes"] = strings.Join(in.Scopes, " ")
	}
	if in.PKCERequired != nil {
		// 公共客户端不允许关闭 PKCE
		if cur.IsPublicClient() {
			data["pkce_required"] = true
		} else {
			data["pkce_required"] = *in.PKCERequired
		}
	}
	if in.Enabled != nil {
		data["enabled"] = *in.Enabled
	}
	if in.PostLogoutURIs != nil {
		data["post_logout_uris"] = strings.Join(in.PostLogoutURIs, " ")
	}

	if _, err := dao.OAuthClient.Ctx(ctx).Where("id", id).Data(data).Update(); err != nil {
		return nil, err
	}
	return findClientByID(ctx, id)
}

// DeleteClient 删除客户端，并级联清理其授权码与令牌
func DeleteClient(ctx context.Context, id int64) error {
	cur, err := findClientByID(ctx, id)
	if err != nil {
		return err
	}
	if cur == nil {
		return errNotFound("客户端不存在")
	}
	// 保护内置客户端，避免误删导致平台不可用
	if cur.ClientID == consts.ClientTemplateWeb || cur.ClientID == consts.ClientCLI {
		return errProtected("内置客户端不可删除（template-web-client / oidc-cli）")
	}
	if _, err := dao.OAuthAuthorizationCode.Ctx(ctx).Where("client_id", cur.ClientID).Delete(); err != nil {
		return err
	}
	if _, err := dao.OAuthRefreshToken.Ctx(ctx).Where("client_id", cur.ClientID).Delete(); err != nil {
		return err
	}
	if _, err := dao.OAuthAccessToken.Ctx(ctx).Where("client_id", cur.ClientID).Delete(); err != nil {
		return err
	}
	_, err = dao.OAuthClient.Ctx(ctx).Where("id", id).Delete()
	return err
}

func findClientByID(ctx context.Context, id int64) (*entity.OAuthClient, error) {
	var c entity.OAuthClient
	found, err := db.ScanOne(ctx, dao.OAuthClient.Ctx(ctx).Where("id", id), &c)
	if err != nil {
		return nil, err
	}
	if !found {
		return nil, nil
	}
	return &c, nil
}

// generateClientSecret 生成随机 client_secret
func generateClientSecret() string {
	return "cs_" + utility.RandomToken(32)
}

// ── 错误类型 ────────────────────────────────────────────────────────────────
//
// 管理接口的失败要能区分 400 / 404 / 409 三种状态码，靠 message 文本
// 反推状态码是脆弱做法（改一句话就换了语义）。这里让错误自带种类，
// 由表示层决定状态码 —— 顺序是：种类在业务层确定，状态码在表示层确定。

// ErrKind 失败种类
type ErrKind int

// 失败种类枚举
const (
	// KindInvalid 参数或取值非法 → 400
	KindInvalid ErrKind = iota
	// KindNotFound 目标不存在 → 404
	KindNotFound
	// KindConflict 与既有数据冲突 → 409
	KindConflict
	// KindProtected 内置对象受保护，不可操作 → 400
	KindProtected
)

// Error 带种类的业务错误
type Error struct {
	Kind ErrKind
	Msg  string
}

// Error 实现 error 接口
func (e *Error) Error() string { return e.Msg }

func errInvalid(msg string) error   { return &Error{Kind: KindInvalid, Msg: msg} }
func errNotFound(msg string) error  { return &Error{Kind: KindNotFound, Msg: msg} }
func errConflict(msg string) error  { return &Error{Kind: KindConflict, Msg: msg} }
func errProtected(msg string) error { return &Error{Kind: KindProtected, Msg: msg} }
