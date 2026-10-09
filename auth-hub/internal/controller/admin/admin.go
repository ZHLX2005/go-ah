// Package admin 是管理后台的 HTTP 处理层：把 internal/logic/admin 的结果
// 映射成管理前端约定的响应形状与状态码。
//
// 与逻辑层的分工：逻辑层只回答"哪一类失败"（KindInvalid / KindNotFound /
// KindConflict / KindProtected），**状态码在这里定**。反向依赖（逻辑层去猜
// HTTP 状态码）会把协议细节焊进业务代码，改一次协议就要动一遍业务。
//
// 失败响应**没有 code 字段**，成功响应才有 —— 这是迁移前的既有契约，
// 迁移期间原样保留：前端是按这两种形状分别解析的，顺手"统一"就是破坏兼容。
package admin

import (
	"context"
	"errors"
	"net/http"
	"strings"

	"github.com/gogf/gf/v2/frame/g"
	"github.com/gogf/gf/v2/net/ghttp"

	v1 "github.com/ZHLX2005/go-ah/auth-hub/api/admin/v1"
	"github.com/ZHLX2005/go-ah/auth-hub/internal/controller/response"
	"github.com/ZHLX2005/go-ah/auth-hub/internal/logic/admin"
	"github.com/ZHLX2005/go-ah/auth-hub/internal/logic/oidc"
	"github.com/ZHLX2005/go-ah/auth-hub/internal/middleware"
	"github.com/ZHLX2005/go-ah/auth-hub/internal/model/entity"
)

// Controller 管理后台控制器
type Controller struct{}

// New 构造控制器
func New() *Controller { return &Controller{} }

// ── 当前管理员 ──────────────────────────────────────────────────────────────

// Me GET /api/admin/me —— 前端据此判断"当前登录者是不是管理员"
//
// 用户对象由 RequireAdmin 中间件放进上下文，这里只做映射。
// 若取不到，说明中间件没挂在本路由上（装配错误），按未登录返回 ——
// 宁可让前端跳登录页，也不能回一个空的管理员对象让它以为已登录。
func (c *Controller) Me(ctx context.Context, req *v1.AdminMeReq) error {
	r := g.RequestFromCtx(ctx)

	u := middleware.CurrentAdmin(r)
	if u == nil {
		response.Write(r, http.StatusUnauthorized, map[string]interface{}{"error": "not_authenticated"})
		return nil
	}
	response.Write(r, http.StatusOK, &v1.AdminMeRes{
		Code: 0,
		Data: v1.AdminMeData{
			ID:       u.Id,
			Username: u.Username,
			Nickname: u.Nickname,
			Email:    u.Email,
			IsAdmin:  u.IsAdmin,
		},
	})
	return nil
}

// ── 用户 ────────────────────────────────────────────────────────────────────

// Users GET /api/admin/users —— 用户列表，附带会话数与令牌数，便于排查
func (c *Controller) Users(ctx context.Context, req *v1.AdminUsersReq) error {
	r := g.RequestFromCtx(ctx)

	rows, err := admin.ListUsers(ctx)
	if err != nil {
		writeAdminError(r, err)
		return nil
	}
	out := make([]v1.AdminUserRow, 0, len(rows))
	for _, u := range rows {
		out = append(out, v1.AdminUserRow{
			ID:            u.Id,
			Username:      u.Username,
			Email:         u.Email,
			Nickname:      u.Nickname,
			IsAdmin:       u.IsAdmin,
			CreatedAt:     u.CreatedAt,
			SessionCount:  u.SessionCount,
			RefreshCount:  u.RefreshCount,
			ActiveRefresh: u.ActiveRefresh,
		})
	}
	response.Write(r, http.StatusOK, &v1.AdminUsersRes{Code: 0, Data: out})
	return nil
}

// UserSessions GET /api/admin/users/{id}/sessions —— 指定用户的活跃会话
func (c *Controller) UserSessions(ctx context.Context, req *v1.AdminUserSessionsReq) error {
	r := g.RequestFromCtx(ctx)

	rows, err := admin.UserSessions(ctx, req.ID)
	if err != nil {
		writeAdminError(r, err)
		return nil
	}
	out := make([]v1.AdminSessionRow, 0, len(rows))
	for _, s := range rows {
		out = append(out, v1.AdminSessionRow{
			SessionID: s.SessionID,
			ExpiresAt: s.ExpiresAt,
			CreatedAt: s.CreatedAt,
		})
	}
	response.Write(r, http.StatusOK, &v1.AdminUserSessionsRes{Code: 0, Data: out})
	return nil
}

// UserTokens GET /api/admin/users/{id}/tokens —— 指定用户关联的刷新令牌
func (c *Controller) UserTokens(ctx context.Context, req *v1.AdminUserTokensReq) error {
	r := g.RequestFromCtx(ctx)

	rows, err := admin.UserTokens(ctx, req.ID)
	if err != nil {
		writeAdminError(r, err)
		return nil
	}
	response.Write(r, http.StatusOK, &v1.AdminUserTokensRes{Code: 0, Data: tokenRows(rows)})
	return nil
}

// ── OIDC 客户端 ─────────────────────────────────────────────────────────────

// Clients GET /api/admin/clients
func (c *Controller) Clients(ctx context.Context, req *v1.AdminClientsReq) error {
	r := g.RequestFromCtx(ctx)

	clients, err := admin.ListClients(ctx)
	if err != nil {
		writeAdminError(r, err)
		return nil
	}
	out := make([]v1.AdminClientView, 0, len(clients))
	for _, cl := range clients {
		out = append(out, clientView(cl))
	}
	response.Write(r, http.StatusOK, &v1.AdminClientsRes{Code: 0, Data: out})
	return nil
}

// CreateClient POST /api/admin/clients
//
// 非公共客户端的明文密钥**仅在本次响应里返回一次**，库里只留哈希/明文本身，
// 之后任何接口都不再回传（见 clientView：结构体里根本没有 secret 字段）。
func (c *Controller) CreateClient(ctx context.Context, req *v1.AdminCreateClientReq) error {
	r := g.RequestFromCtx(ctx)

	created, plainSecret, err := admin.CreateClient(ctx, admin.CreateClientInput{
		ClientID:       req.ClientID,
		ClientName:     req.ClientName,
		RedirectURIs:   req.RedirectURIs,
		Scopes:         req.Scopes,
		IsPublic:       req.IsPublic,
		PKCERequired:   req.PKCERequired,
		Enabled:        req.Enabled,
		PostLogoutURIs: req.PostLogoutURIs,
	})
	if err != nil {
		writeAdminError(r, err)
		return nil
	}

	res := &v1.AdminCreateClientRes{Code: 0, Data: clientView(*created)}
	if plainSecret != "" {
		res.ClientSecret = plainSecret
		res.Notice = "client_secret 仅在创建时显示一次，请妥善保存"
	}
	response.Write(r, http.StatusOK, res)
	return nil
}

// UpdateClient PUT /api/admin/clients/{id}
func (c *Controller) UpdateClient(ctx context.Context, req *v1.AdminUpdateClientReq) error {
	r := g.RequestFromCtx(ctx)

	updated, err := admin.UpdateClient(ctx, req.ID, admin.UpdateClientInput{
		ClientName:     req.ClientName,
		RedirectURIs:   req.RedirectURIs,
		Scopes:         req.Scopes,
		PKCERequired:   req.PKCERequired,
		Enabled:        req.Enabled,
		PostLogoutURIs: req.PostLogoutURIs,
	})
	if err != nil {
		if isNotFound(err) {
			// 迁移前该端点的 404 不带 message，保持原样
			writeFail(r, http.StatusNotFound, "not_found", "")
			return nil
		}
		writeAdminError(r, err)
		return nil
	}
	response.Write(r, http.StatusOK, &v1.AdminUpdateClientRes{Code: 0, Data: clientView(*updated)})
	return nil
}

// DeleteClient DELETE /api/admin/clients/{id}
//
// 内置客户端（template-web-client / oidc-cli）不可删除：删掉会让参考实现
// 与命令行客户端直接不可用，而这通常不是操作者的本意。
func (c *Controller) DeleteClient(ctx context.Context, req *v1.AdminDeleteClientReq) error {
	r := g.RequestFromCtx(ctx)

	if err := admin.DeleteClient(ctx, req.ID); err != nil {
		if isNotFound(err) {
			writeFail(r, http.StatusNotFound, "not_found", "")
			return nil
		}
		writeAdminError(r, err)
		return nil
	}
	response.Write(r, http.StatusOK, &v1.AdminDeleteClientRes{Code: 0, Message: "客户端已删除"})
	return nil
}

// ── 令牌管理 ────────────────────────────────────────────────────────────────

// RefreshTokens GET /api/admin/refresh-tokens?status=all|active|revoked
func (c *Controller) RefreshTokens(ctx context.Context, req *v1.AdminRefreshTokensReq) error {
	r := g.RequestFromCtx(ctx)

	status := req.Status
	if status == "" {
		status = "all"
	}
	rows, err := admin.ListRefreshTokens(ctx, status)
	if err != nil {
		writeAdminError(r, err)
		return nil
	}
	response.Write(r, http.StatusOK, &v1.AdminRefreshTokensRes{Code: 0, Data: tokenRows(rows)})
	return nil
}

// RevokeToken POST /api/admin/revoke-token
//
// 只打吊销标记，不删行：令牌记录本身就是审计线索，
// 删掉之后"这个令牌曾被签发过、后来被谁吊销"就查不出来了。
func (c *Controller) RevokeToken(ctx context.Context, req *v1.AdminRevokeTokenReq) error {
	r := g.RequestFromCtx(ctx)

	if req.ID == nil && req.Token == "" {
		writeFail(r, http.StatusBadRequest, "invalid_request", "需要提供 id 或 token")
		return nil
	}
	affected, err := admin.RevokeRefreshToken(ctx, req.ID, req.Token)
	if err != nil {
		writeAdminError(r, err)
		return nil
	}
	if affected == 0 {
		writeFail(r, http.StatusNotFound, "not_found", "未找到对应的有效 refresh_token（可能已吊销）")
		return nil
	}
	response.Write(r, http.StatusOK, &v1.AdminRevokeTokenRes{
		Code:     0,
		Message:  "已吊销",
		Affected: affected,
	})
	return nil
}

// ── 视图映射 ────────────────────────────────────────────────────────────────

// clientView 把客户端实体映射成管理端视图。
//
// 结构体里没有 client_secret 字段，这是"密钥不外泄"的强保证：
// 不是靠"记得别赋值"，而是靠"根本没有地方可以放"。
func clientView(cl entity.OAuthClient) v1.AdminClientView {
	return v1.AdminClientView{
		ID:             cl.Id,
		ClientID:       cl.ClientID,
		ClientName:     cl.ClientName,
		RedirectURIs:   strings.Fields(cl.RedirectURIs),
		Scopes:         strings.Fields(cl.Scopes),
		IsPublic:       cl.IsPublicClient(),
		PKCERequired:   cl.PKCENeeded(),
		Enabled:        cl.IsEnabled(),
		PostLogoutURIs: strings.Fields(cl.PostLogoutURIs),
		CreatedAt:      cl.CreatedAt,
		HasSecret:      cl.ClientSecret != "",
	}
}

// tokenRows 把令牌行映射成管理端视图（脱敏后的 token + 派生的 sub）
func tokenRows(rows []admin.RefreshRow) []v1.AdminTokenRow {
	out := make([]v1.AdminTokenRow, 0, len(rows))
	for _, t := range rows {
		out = append(out, v1.AdminTokenRow{
			ID:        t.Id,
			Token:     t.Token,
			UserID:    t.UserID,
			UserSub:   oidc.Sub(t.UserID),
			Username:  t.Username,
			ClientID:  t.ClientID,
			Scope:     t.Scope,
			ExpiresAt: t.ExpiresAt,
			Revoked:   t.Revoked,
			RevokedAt: t.RevokedAt,
			CreatedAt: t.CreatedAt,
			Expired:   t.Expired,
		})
	}
	return out
}

// ── 失败响应 ────────────────────────────────────────────────────────────────

// writeAdminError 把带种类的业务错误映射成状态码。
//
// 唯一映射点：改协议只改这里，业务层不必知道 HTTP。
func writeAdminError(r *ghttp.Request, err error) {
	var ae *admin.Error
	if !errors.As(err, &ae) {
		// 非业务错误（数据库故障、驱动报错等）按 500 兜底
		writeFail(r, http.StatusInternalServerError, "db_error", err.Error())
		return
	}
	switch ae.Kind {
	case admin.KindInvalid:
		writeFail(r, http.StatusBadRequest, "invalid_request", ae.Msg)
	case admin.KindProtected:
		// error 码与"参数非法"分开，前端才能给出针对性提示
		writeFail(r, http.StatusBadRequest, "protected_client", ae.Msg)
	case admin.KindConflict:
		writeFail(r, http.StatusConflict, "conflict", ae.Msg)
	case admin.KindNotFound:
		writeFail(r, http.StatusNotFound, "not_found", ae.Msg)
	default:
		writeFail(r, http.StatusInternalServerError, "db_error", ae.Msg)
	}
}

// writeFail 管理后台的失败响应：只有 error（与可选 message），没有 code 信封。
// message 为空时整个字段省略，与迁移前的字面量保持一致。
func writeFail(r *ghttp.Request, status int, errCode, message string) {
	response.Write(r, status, &v1.AdminErrorRes{Error: errCode, Message: message})
}

// isNotFound 判断是否属于"目标不存在"
func isNotFound(err error) bool {
	var ae *admin.Error
	return errors.As(err, &ae) && ae.Kind == admin.KindNotFound
}
