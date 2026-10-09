// Package v1 定义管理后台接口的请求与响应结构。
//
// 全部响应用 {code, data} 信封；失败时 code 非 0 并给出 error/message。
// 字段名与迁移前逐字保持一致 —— 管理后台前端按这些名字取值。
package v1

import (
	"time"

	"github.com/gogf/gf/v2/frame/g"
)

// AdminMeReq GET /api/admin/me
type AdminMeReq struct {
	g.Meta `path:"/api/admin/me" method:"get" tags:"Admin" summary:"当前管理员"`
}

// AdminMeData 管理员信息
type AdminMeData struct {
	ID       int64  `json:"id"`
	Username string `json:"username"`
	Nickname string `json:"nickname"`
	Email    string `json:"email"`
	IsAdmin  bool   `json:"is_admin"`
}

// AdminMeRes 管理员信息响应
type AdminMeRes struct {
	Code int         `json:"code"`
	Data AdminMeData `json:"data"`
}

// ── 用户 ────────────────────────────────────────────────────────────────────

// AdminUsersReq GET /api/admin/users
type AdminUsersReq struct {
	g.Meta `path:"/api/admin/users" method:"get" tags:"Admin" summary:"用户列表"`
}

// AdminUserRow 用户列表行
type AdminUserRow struct {
	ID            int64      `json:"id"`
	Username      string     `json:"username"`
	Email         string     `json:"email"`
	Nickname      string     `json:"nickname"`
	IsAdmin       bool       `json:"is_admin"`
	CreatedAt     time.Time  `json:"created_at"`
	LastLoginAt   *time.Time `json:"last_login_at"`
	SessionCount  int64      `json:"session_count"`
	RefreshCount  int64      `json:"refresh_token_count"`
	ActiveRefresh int64      `json:"active_refresh_count"`
}

// AdminUsersRes 用户列表响应
type AdminUsersRes struct {
	Code int            `json:"code"`
	Data []AdminUserRow `json:"data"`
}

// AdminUserSessionsReq GET /api/admin/users/{id}/sessions
type AdminUserSessionsReq struct {
	g.Meta `path:"/api/admin/users/{id}/sessions" method:"get" tags:"Admin" summary:"用户活跃会话"`
	ID     int64 `json:"id" in:"path" v:"required"`
}

// AdminSessionRow 会话行
type AdminSessionRow struct {
	SessionID string    `json:"session_id"`
	ExpiresAt time.Time `json:"expires_at"`
	CreatedAt time.Time `json:"created_at"`
}

// AdminUserSessionsRes 会话列表响应
type AdminUserSessionsRes struct {
	Code int               `json:"code"`
	Data []AdminSessionRow `json:"data"`
}

// AdminUserTokensReq GET /api/admin/users/{id}/tokens
type AdminUserTokensReq struct {
	g.Meta `path:"/api/admin/users/{id}/tokens" method:"get" tags:"Admin" summary:"用户的刷新令牌"`
	ID     int64 `json:"id" in:"path" v:"required"`
}

// AdminTokenRow 刷新令牌行
type AdminTokenRow struct {
	ID        int64      `json:"id"`
	Token     string     `json:"token"`
	UserID    int64      `json:"user_id"`
	UserSub   string     `json:"user_sub"`
	Username  string     `json:"username"`
	ClientID  string     `json:"client_id"`
	Scope     string     `json:"scope"`
	ExpiresAt time.Time  `json:"expires_at"`
	Revoked   bool       `json:"revoked"`
	RevokedAt *time.Time `json:"revoked_at"`
	CreatedAt time.Time  `json:"created_at"`
	Expired   bool       `json:"expired"`
}

// AdminUserTokensRes 令牌列表响应
type AdminUserTokensRes struct {
	Code int             `json:"code"`
	Data []AdminTokenRow `json:"data"`
}

// ── 客户端 ──────────────────────────────────────────────────────────────────

// AdminClientsReq GET /api/admin/clients
type AdminClientsReq struct {
	g.Meta `path:"/api/admin/clients" method:"get" tags:"Admin" summary:"客户端列表"`
}

// AdminClientView 客户端视图（不回传明文密钥）
type AdminClientView struct {
	ID             int64     `json:"id"`
	ClientID       string    `json:"client_id"`
	ClientName     string    `json:"client_name"`
	RedirectURIs   []string  `json:"redirect_uris"`
	Scopes         []string  `json:"scopes"`
	IsPublic       bool      `json:"is_public"`
	PKCERequired   bool      `json:"pkce_required"`
	Enabled        bool      `json:"enabled"`
	PostLogoutURIs []string  `json:"post_logout_uris"`
	CreatedAt      time.Time `json:"created_at"`
	HasSecret      bool      `json:"has_secret"`
}

// AdminClientsRes 客户端列表响应
type AdminClientsRes struct {
	Code int               `json:"code"`
	Data []AdminClientView `json:"data"`
}

// AdminCreateClientReq POST /api/admin/clients
type AdminCreateClientReq struct {
	g.Meta         `path:"/api/admin/clients" method:"post" tags:"Admin" summary:"创建客户端"`
	ClientID       string   `json:"client_id"`
	ClientName     string   `json:"client_name"`
	RedirectURIs   []string `json:"redirect_uris"`
	Scopes         []string `json:"scopes"`
	IsPublic       *bool    `json:"is_public"`
	PKCERequired   *bool    `json:"pkce_required"`
	Enabled        *bool    `json:"enabled"`
	PostLogoutURIs []string `json:"post_logout_uris"`
}

// AdminCreateClientRes 创建结果；非公共客户端额外返回一次明文密钥
type AdminCreateClientRes struct {
	Code         int             `json:"code"`
	Data         AdminClientView `json:"data"`
	ClientSecret string          `json:"client_secret,omitempty"`
	Notice       string          `json:"notice,omitempty"`
}

// AdminUpdateClientReq PUT /api/admin/clients/{id}
type AdminUpdateClientReq struct {
	g.Meta         `path:"/api/admin/clients/{id}" method:"put" tags:"Admin" summary:"更新客户端"`
	ID             int64    `json:"id" in:"path" v:"required"`
	ClientName     *string  `json:"client_name"`
	RedirectURIs   []string `json:"redirect_uris"`
	Scopes         []string `json:"scopes"`
	PKCERequired   *bool    `json:"pkce_required"`
	Enabled        *bool    `json:"enabled"`
	PostLogoutURIs []string `json:"post_logout_uris"`
}

// AdminUpdateClientRes 更新结果
type AdminUpdateClientRes struct {
	Code int             `json:"code"`
	Data AdminClientView `json:"data"`
}

// AdminDeleteClientReq DELETE /api/admin/clients/{id}
type AdminDeleteClientReq struct {
	g.Meta `path:"/api/admin/clients/{id}" method:"delete" tags:"Admin" summary:"删除客户端"`
	ID     int64 `json:"id" in:"path" v:"required"`
}

// AdminDeleteClientRes 删除结果
type AdminDeleteClientRes struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

// ── 令牌管理 ────────────────────────────────────────────────────────────────

// AdminRefreshTokensReq GET /api/admin/refresh-tokens
type AdminRefreshTokensReq struct {
	g.Meta `path:"/api/admin/refresh-tokens" method:"get" tags:"Admin" summary:"刷新令牌列表"`
	Status string `json:"status" in:"query"` // all | active | revoked
}

// AdminRefreshTokensRes 令牌列表响应
type AdminRefreshTokensRes struct {
	Code int             `json:"code"`
	Data []AdminTokenRow `json:"data"`
}

// AdminRevokeTokenReq POST /api/admin/revoke-token
type AdminRevokeTokenReq struct {
	g.Meta `path:"/api/admin/revoke-token" method:"post" tags:"Admin" summary:"吊销刷新令牌"`
	ID     *int64 `json:"id"`
	Token  string `json:"token"`
}

// AdminRevokeTokenRes 吊销结果
type AdminRevokeTokenRes struct {
	Code     int    `json:"code"`
	Message  string `json:"message"`
	Affected int64  `json:"affected"`
}

// ── 注册邀请码 ──────────────────────────────────────────────────────────────

// AdminInvitesReq GET /api/admin/invites
type AdminInvitesReq struct {
	g.Meta `path:"/api/admin/invites" method:"get" tags:"Admin" summary:"邀请码列表"`
	// Status 按状态过滤：active | disabled | expired | exhausted；留空/ all 为全部。
	// 过滤放在后端做：状态是由 enabled/expires_at/used_count 三者算出来的，
	// 交给前端过滤意味着"哪些算过期"要在两处各判断一次。
	Status string `json:"status" in:"query"`
}

// AdminInviteView 邀请码视图。
//
// Remaining 与 Status 都是后端算好的派生值，不指望前端自己算：
// 列表上显示的"还剩 2 次""已过期"必须与注册接口的放行规则**同源**，
// 否则会出现"列表说可用、注册却被拒"这种自相矛盾的现象。
type AdminInviteView struct {
	ID        int64      `json:"id"`
	Code      string     `json:"code"`
	MaxUses   int        `json:"max_uses"`
	UsedCount int        `json:"used_count"`
	Remaining int        `json:"remaining"`
	Status    string     `json:"status"`
	ExpiresAt *time.Time `json:"expires_at"`
	Enabled   bool       `json:"enabled"`
	Note      string     `json:"note"`
	CreatedAt time.Time  `json:"created_at"`
	UpdatedAt time.Time  `json:"updated_at"`
}

// AdminInvitesRes 邀请码列表响应
type AdminInvitesRes struct {
	Code int               `json:"code"`
	Data []AdminInviteView `json:"data"`
}

// AdminCreateInviteReq POST /api/admin/invites
type AdminCreateInviteReq struct {
	g.Meta `path:"/api/admin/invites" method:"post" tags:"Admin" summary:"生成邀请码"`
	// MaxUses 可用次数；留空或 <=0 取默认值（1 次）
	MaxUses int `json:"max_uses"`
	// ExpiresAt 过期时间，接受 gtime 能识别的多种写法（RFC3339、
	// "2006-01-02 15:04:05"、"2006-01-02" 等）；留空表示长期有效。
	ExpiresAt string `json:"expires_at"`
	// Note 备注：发给谁、做什么用。邀请码列表里唯一能区分两张码的信息。
	Note string `json:"note"`
}

// AdminCreateInviteRes 生成结果（返回完整行，便于前端直接插入列表）
type AdminCreateInviteRes struct {
	Code int             `json:"code"`
	Data AdminInviteView `json:"data"`
}

// AdminUpdateInviteReq PUT /api/admin/invites/{id}
//
// 指针字段语义是"不改"：可写字段里有 max_uses，若用值类型，客户端漏传
// 就会被解释成"改成 0"→ 配额被悄悄重置。ExpiresAt 用 *string 而不是
// *time.Time，是为了区分"没传"（nil，不改）与"传了空串"（改成长期有效）。
type AdminUpdateInviteReq struct {
	g.Meta    `path:"/api/admin/invites/{id}" method:"put" tags:"Admin" summary:"修改邀请码"`
	ID        int64   `json:"id" in:"path" v:"required"`
	MaxUses   *int    `json:"max_uses"`
	ExpiresAt *string `json:"expires_at"`
	Enabled   *bool   `json:"enabled"`
	Note      *string `json:"note"`
}

// AdminUpdateInviteRes 修改结果
type AdminUpdateInviteRes struct {
	Code int             `json:"code"`
	Data AdminInviteView `json:"data"`
}

// AdminDeleteInviteReq DELETE /api/admin/invites/{id}
type AdminDeleteInviteReq struct {
	g.Meta `path:"/api/admin/invites/{id}" method:"delete" tags:"Admin" summary:"删除邀请码"`
	ID     int64 `json:"id" in:"path" v:"required"`
}

// AdminDeleteInviteRes 删除结果
type AdminDeleteInviteRes struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

// AdminInviteUsagesReq GET /api/admin/invites/{id}/usages
type AdminInviteUsagesReq struct {
	g.Meta `path:"/api/admin/invites/{id}/usages" method:"get" tags:"Admin" summary:"邀请码使用明细"`
	ID     int64 `json:"id" in:"path" v:"required"`
}

// AdminInviteUsageRow 使用明细行：一条 = 某次注册用掉了某张码
type AdminInviteUsageRow struct {
	ID       int64     `json:"id"`
	Code     string    `json:"code"`
	UserID   int64     `json:"user_id"`
	Username string    `json:"username"`
	Email    string    `json:"email"`
	UsedAt   time.Time `json:"used_at"`
}

// AdminInviteUsagesRes 使用明细响应
type AdminInviteUsagesRes struct {
	Code int                   `json:"code"`
	Data []AdminInviteUsageRow `json:"data"`
}

// ── 失败响应 ────────────────────────────────────────────────────────────────

// AdminErrorRes 管理接口失败响应（HTTP 状态码非 200 时使用）。
//
// **没有 code 字段**：管理后台前端按 error 判定分支，code 是业务成功信封的
// 字段，混进来会改变它的判断路径。message 为空时整个字段省略 —— 迁移前
// 各端点的 404 有的带 message 有的不带，这里如实保留。
type AdminErrorRes struct {
	Error   string `json:"error"`
	Message string `json:"message,omitempty"`
}
