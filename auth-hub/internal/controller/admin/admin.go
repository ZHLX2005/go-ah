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
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/gogf/gf/v2/frame/g"
	"github.com/gogf/gf/v2/net/ghttp"
	"github.com/gogf/gf/v2/os/gtime"

	v1 "github.com/ZHLX2005/go-ah/auth-hub/api/admin/v1"
	"github.com/ZHLX2005/go-ah/auth-hub/internal/controller/response"
	"github.com/ZHLX2005/go-ah/auth-hub/internal/logic/admin"
	"github.com/ZHLX2005/go-ah/auth-hub/internal/logic/invite"
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
			LastLoginAt:   u.LastLoginAt,
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

// ── 注册邀请码 ──────────────────────────────────────────────────────────────

// Invites GET /api/admin/invites?status=active|disabled|expired|exhausted|all
//
// 状态过滤与 Status/Remaining 都由后端算：这两个派生值必须与注册接口的
// 放行规则同源，前端各算一份的结果是"列表说可用、注册却被拒"。
func (c *Controller) Invites(ctx context.Context, req *v1.AdminInvitesReq) error {
	r := g.RequestFromCtx(ctx)

	rows, err := invite.ListByStatus(ctx, req.Status)
	if err != nil {
		writeInviteError(r, err)
		return nil
	}
	now := time.Now()
	out := make([]v1.AdminInviteView, 0, len(rows))
	for _, row := range rows {
		out = append(out, inviteView(row, now))
	}
	response.Write(r, http.StatusOK, &v1.AdminInvitesRes{Code: 0, Data: out})
	return nil
}

// CreateInvite POST /api/admin/invites
//
// 创建者取自中间件放进上下文的当前管理员（与 /api/admin/me 同一个来源），
// 不信任请求体里传来的 created_by —— 那是个客户端可以随便填的值，
// 用它做审计等于让被审计者自己签名。
func (c *Controller) CreateInvite(ctx context.Context, req *v1.AdminCreateInviteReq) error {
	r := g.RequestFromCtx(ctx)

	expiresAt, err := parseExpiry(req.ExpiresAt)
	if err != nil {
		writeFail(r, http.StatusBadRequest, "invalid_request", err.Error())
		return nil
	}

	var createdBy int64
	if u := middleware.CurrentAdmin(r); u != nil {
		createdBy = u.Id
	}

	created, err := invite.Generate(ctx, invite.GenerateInput{
		MaxUses:   req.MaxUses,
		ExpiresAt: expiresAt,
		Note:      req.Note,
		CreatedBy: createdBy,
	})
	if err != nil {
		writeInviteError(r, err)
		return nil
	}
	response.Write(r, http.StatusOK, &v1.AdminCreateInviteRes{
		Code: 0,
		Data: inviteView(*created, time.Now()),
	})
	return nil
}

// UpdateInvite PUT /api/admin/invites/{id}
//
// 未给出的字段不改；ExpiresAt 传空串表示"改为长期有效"（置 NULL）。
func (c *Controller) UpdateInvite(ctx context.Context, req *v1.AdminUpdateInviteReq) error {
	r := g.RequestFromCtx(ctx)

	in := invite.UpdateInput{MaxUses: req.MaxUses, Enabled: req.Enabled, Note: req.Note}
	if req.ExpiresAt != nil {
		if strings.TrimSpace(*req.ExpiresAt) == "" {
			in.ClearExpires = true
		} else {
			t, err := parseExpiry(*req.ExpiresAt)
			if err != nil {
				writeFail(r, http.StatusBadRequest, "invalid_request", err.Error())
				return nil
			}
			in.ExpiresAt = t
		}
	}

	updated, err := invite.Update(ctx, req.ID, in)
	if err != nil {
		writeInviteError(r, err)
		return nil
	}
	response.Write(r, http.StatusOK, &v1.AdminUpdateInviteRes{
		Code: 0,
		Data: inviteView(*updated, time.Now()),
	})
	return nil
}

// DeleteInvite DELETE /api/admin/invites/{id}
//
// 只删邀请码本身，**使用明细保留**：明细里冗余存了码，删码之后仍然查得出
// "这个账号当初是用哪张码注册的" —— 那是事后追责时唯一想查的东西。
func (c *Controller) DeleteInvite(ctx context.Context, req *v1.AdminDeleteInviteReq) error {
	r := g.RequestFromCtx(ctx)

	if err := invite.Delete(ctx, req.ID); err != nil {
		writeInviteError(r, err)
		return nil
	}
	response.Write(r, http.StatusOK, &v1.AdminDeleteInviteRes{Code: 0, Message: "邀请码已删除"})
	return nil
}

// InviteUsages GET /api/admin/invites/{id}/usages
//
// 先确认邀请码存在再返回明细：不存在时回一个空数组会让界面显示
// "还没有人使用"，而事实是这张码根本不存在 —— 两件事的处置完全不同。
func (c *Controller) InviteUsages(ctx context.Context, req *v1.AdminInviteUsagesReq) error {
	r := g.RequestFromCtx(ctx)

	cur, err := invite.FindByID(ctx, req.ID)
	if err != nil {
		writeInviteError(r, err)
		return nil
	}
	if cur == nil {
		writeFail(r, http.StatusNotFound, "not_found", "邀请码不存在")
		return nil
	}

	rows, err := invite.Usages(ctx, req.ID)
	if err != nil {
		writeInviteError(r, err)
		return nil
	}
	out := make([]v1.AdminInviteUsageRow, 0, len(rows))
	for _, u := range rows {
		out = append(out, v1.AdminInviteUsageRow{
			ID:       u.Id,
			Code:     u.Code,
			UserID:   u.UserID,
			Username: u.Username,
			Email:    u.Email,
			UsedAt:   u.UsedAt,
		})
	}
	response.Write(r, http.StatusOK, &v1.AdminInviteUsagesRes{Code: 0, Data: out})
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

// inviteView 把邀请码实体映射成管理端视图。
//
// Remaining 与 Status 在这里算好：它们的规则在 entity 上（与注册接口共用），
// 前端只负责显示。让前端自己从 max_uses/used_count/expires_at 推状态的话，
// "已停用但也没过期"这类组合会出现两种解释。
func inviteView(row entity.InvitationCode, now time.Time) v1.AdminInviteView {
	return v1.AdminInviteView{
		ID:        row.Id,
		Code:      row.Code,
		MaxUses:   row.MaxUses,
		UsedCount: row.UsedCount,
		Remaining: row.Remaining(),
		Status:    row.Status(now),
		ExpiresAt: row.ExpiresAt,
		Enabled:   row.Enabled,
		Note:      row.Note,
		CreatedAt: row.CreatedAt,
		UpdatedAt: row.UpdatedAt,
	}
}

// parseExpiry 解析管理端传来的过期时间；空串表示长期有效（返回 nil）。
//
// 用 gtime 的宽松解析而不是只认 RFC3339：管理界面用的是 datetime-local 输入，
// 浏览器给出的是 "2006-01-02T15:04"（没有秒、没有时区）。只认 RFC3339 的话，
// 前端就得自己补秒和时区 —— 那是把后端的解析责任推给浏览器，而且每个调用方
// 都要推一遍。
func parseExpiry(s string) (*time.Time, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return nil, nil
	}
	t, err := gtime.StrToTime(s)
	if err != nil {
		return nil, fmt.Errorf("过期时间格式不正确: %q", s)
	}
	out := t.Time
	return &out, nil
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

// writeInviteError 把邀请码的业务错误映射成状态码。
//
// 与 writeAdminError 职责相同、类型不同（invite.Error 而不是 admin.Error）：
// 逻辑层的失败词汇表是按**业务域**定义的，让 invite 反过来依赖 admin 只为
// 共用四个常量，等于把两个正交的概念焊死。代价就是这里多一个 switch，
// 换来的是"邀请码的失败语义"能独立演进。
//
// error 字段沿用管理端既有取值（invalid_request / not_found / conflict），
// 具体原因放在 message 里：管理后台前端已经按这三个值判分支，新造一套
// invite_* 会需要前端同步改，而信息量并没有增加（原因在 message 里）。
func writeInviteError(r *ghttp.Request, err error) {
	var ie *invite.Error
	if !errors.As(err, &ie) {
		writeFail(r, http.StatusInternalServerError, "db_error", err.Error())
		return
	}
	switch ie.Kind {
	case invite.KindNotFound:
		writeFail(r, http.StatusNotFound, "not_found", ie.Msg)
	case invite.KindConflict:
		writeFail(r, http.StatusConflict, "conflict", ie.Msg)
	case invite.KindInvalid:
		writeFail(r, http.StatusBadRequest, "invalid_request", ie.Msg)
	default:
		writeFail(r, http.StatusInternalServerError, "db_error", ie.Msg)
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
