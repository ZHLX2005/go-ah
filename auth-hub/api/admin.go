// Package api 管理后台接口：全部需要管理员会话鉴权
//
// 权限模型：IDP 全局会话(currentUser) + users.is_admin = true
// 非管理员访问返回 403；未登录返回 401
package api

import (
	"crypto/rand"
	"encoding/base64"
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"

	"github.com/ZHLX2005/go-ah/auth-hub/db"
)

// requireAdmin 管理员鉴权中间件
func requireAdmin(c *gin.Context) {
	user := currentUser(c)
	if user == nil {
		c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{
			"error":   "not_authenticated",
			"message": "未登录，请先登录 IDP",
		})
		return
	}
	if !user.IsAdmin {
		c.AbortWithStatusJSON(http.StatusForbidden, gin.H{
			"error":   "forbidden",
			"message": "需要管理员权限",
		})
		return
	}
	c.Set("admin_user", user)
	c.Next()
}

// ============================================================
// 用户管理
// ============================================================

// AdminListUsers GET /api/admin/users
// 返回用户列表，并附带会话数与 refresh_token 数，便于排查
func AdminListUsers(c *gin.Context) {
	var users []db.User
	db.DB.Order("id asc").Find(&users)

	type row struct {
		ID            uint      `json:"id"`
		Username      string    `json:"username"`
		Email         string    `json:"email"`
		Nickname      string    `json:"nickname"`
		IsAdmin       bool      `json:"is_admin"`
		CreatedAt     time.Time `json:"created_at"`
		SessionCount  int64     `json:"session_count"`
		RefreshCount  int64     `json:"refresh_token_count"`
		ActiveRefresh int64     `json:"active_refresh_count"`
	}

	out := make([]row, 0, len(users))
	for _, u := range users {
		var sessCount, rtCount, activeCount int64
		db.DB.Model(&db.UserSession{}).Where("user_id = ? AND expires_at > ?", u.ID, time.Now()).Count(&sessCount)
		db.DB.Model(&db.OAuthRefreshToken{}).Where("user_id = ?", u.ID).Count(&rtCount)
		db.DB.Model(&db.OAuthRefreshToken{}).
			Where("user_id = ? AND revoked_at IS NULL AND expires_at > ?", u.ID, time.Now()).
			Count(&activeCount)

		out = append(out, row{
			ID: u.ID, Username: u.Username, Email: u.Email, Nickname: u.Nickname,
			IsAdmin: u.IsAdmin, CreatedAt: u.CreatedAt,
			SessionCount: sessCount, RefreshCount: rtCount, ActiveRefresh: activeCount,
		})
	}
	c.JSON(http.StatusOK, gin.H{"code": 0, "data": out})
}

// AdminUserSessions GET /api/admin/users/:id/sessions
// 查看指定用户的活跃会话
func AdminUserSessions(c *gin.Context) {
	id := c.Param("id")
	var sessions []db.UserSession
	db.DB.Where("user_id = ? AND expires_at > ?", id, time.Now()).Order("created_at desc").Find(&sessions)

	type row struct {
		SessionID string    `json:"session_id"`
		ExpiresAt time.Time `json:"expires_at"`
		CreatedAt time.Time `json:"created_at"`
	}
	out := make([]row, 0, len(sessions))
	for _, s := range sessions {
		out = append(out, row{
			SessionID: maskToken(s.SessionID),
			ExpiresAt: s.ExpiresAt,
			CreatedAt: s.CreatedAt,
		})
	}
	c.JSON(http.StatusOK, gin.H{"code": 0, "data": out})
}

// AdminUserTokens GET /api/admin/users/:id/tokens
// 查看指定用户关联的 refresh_token
func AdminUserTokens(c *gin.Context) {
	id := c.Param("id")
	var tokens []db.OAuthRefreshToken
	db.DB.Where("user_id = ?", id).Order("created_at desc").Find(&tokens)
	c.JSON(http.StatusOK, gin.H{"code": 0, "data": refreshTokenRows(tokens)})
}

// ============================================================
// OIDC 客户端管理
// ============================================================

// clientView 客户端输出结构（含明文 client_secret 控制）
type clientView struct {
	ID             uint      `json:"id"`
	ClientID       string    `json:"client_id"`
	ClientName     string    `json:"client_name"`
	RedirectURIs   []string  `json:"redirect_uris"`
	Scopes         []string  `json:"scopes"`
	IsPublic       bool      `json:"is_public"`
	PKCERequired   bool      `json:"pkce_required"`
	Enabled        bool      `json:"enabled"`
	PostLogoutURIs []string  `json:"post_logout_uris"`
	CreatedAt      time.Time `json:"created_at"`
	// HasSecret 是否已配置密钥（不回传明文）
	HasSecret bool `json:"has_secret"`
}

func toClientView(cl db.OAuthClient) clientView {
	return clientView{
		ID:             cl.ID,
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

// AdminListClients GET /api/admin/clients
func AdminListClients(c *gin.Context) {
	var clients []db.OAuthClient
	db.DB.Order("id asc").Find(&clients)
	out := make([]clientView, 0, len(clients))
	for _, cl := range clients {
		out = append(out, toClientView(cl))
	}
	c.JSON(http.StatusOK, gin.H{"code": 0, "data": out})
}

// AdminCreateClient POST /api/admin/clients
// 创建客户端；非公共客户端自动生成 client_secret 并仅本次返回明文
func AdminCreateClient(c *gin.Context) {
	var req struct {
		ClientID       string   `json:"client_id"`
		ClientName     string   `json:"client_name"`
		RedirectURIs   []string `json:"redirect_uris"`
		Scopes         []string `json:"scopes"`
		IsPublic       *bool    `json:"is_public"`
		PKCERequired   *bool    `json:"pkce_required"`
		Enabled        *bool    `json:"enabled"`
		PostLogoutURIs []string `json:"post_logout_uris"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid_request", "message": err.Error()})
		return
	}
	req.ClientID = strings.TrimSpace(req.ClientID)
	if req.ClientID == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid_request", "message": "client_id 不能为空"})
		return
	}
	if len(req.RedirectURIs) == 0 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid_request", "message": "至少需要配置一个回调地址"})
		return
	}
	if !validRedirectURIs(req.RedirectURIs) {
		c.JSON(http.StatusBadRequest, gin.H{
			"error":   "invalid_request",
			"message": "回调地址必须为完整 URL（http/https）；端口通配仅支持 127.0.0.1 / localhost",
		})
		return
	}
	// 唯一性校验
	var exists db.OAuthClient
	if err := db.DB.Where("client_id = ?", req.ClientID).First(&exists).Error; err == nil {
		c.JSON(http.StatusConflict, gin.H{"error": "conflict", "message": "该 client_id 已存在"})
		return
	}

	isPublic := true
	if req.IsPublic != nil {
		isPublic = *req.IsPublic
	}
	// 公共客户端强制 PKCE
	pkce := true
	if req.PKCERequired != nil {
		pkce = *req.PKCERequired
	}
	if isPublic {
		pkce = true
	}
	enabled := true
	if req.Enabled != nil {
		enabled = *req.Enabled
	}
	scopes := req.Scopes
	if len(scopes) == 0 {
		scopes = []string{"openid", "profile", "email"}
	}

	secret := ""
	plainSecret := ""
	if !isPublic {
		plainSecret = generateClientSecret()
		secret = plainSecret // Demo 存储明文；生产应使用哈希
	}

	cl := db.OAuthClient{
		ClientID:       req.ClientID,
		ClientSecret:   secret,
		ClientName:     req.ClientName,
		RedirectURIs:   strings.Join(req.RedirectURIs, " "),
		Scopes:         strings.Join(scopes, " "),
		IsPublic:       db.BoolPtr(isPublic),
		PKCERequired:   db.BoolPtr(pkce),
		Enabled:        db.BoolPtr(enabled),
		PostLogoutURIs: strings.Join(req.PostLogoutURIs, " "),
	}
	if err := db.DB.Create(&cl).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "db_error", "message": err.Error()})
		return
	}

	resp := gin.H{"code": 0, "data": toClientView(cl)}
	// 明文密钥仅创建时返回一次
	if plainSecret != "" {
		resp["client_secret"] = plainSecret
		resp["notice"] = "client_secret 仅在创建时显示一次，请妥善保存"
	}
	c.JSON(http.StatusOK, resp)
}

// AdminUpdateClient PUT /api/admin/clients/:id
func AdminUpdateClient(c *gin.Context) {
	id := c.Param("id")
	var cl db.OAuthClient
	if err := db.DB.First(&cl, id).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "not_found"})
		return
	}
	var req struct {
		ClientName     *string  `json:"client_name"`
		RedirectURIs   []string `json:"redirect_uris"`
		Scopes         []string `json:"scopes"`
		PKCERequired   *bool    `json:"pkce_required"`
		Enabled        *bool    `json:"enabled"`
		PostLogoutURIs []string `json:"post_logout_uris"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid_request", "message": err.Error()})
		return
	}
	if len(req.RedirectURIs) > 0 {
		if !validRedirectURIs(req.RedirectURIs) {
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid_request", "message": "回调地址格式不正确"})
			return
		}
		cl.RedirectURIs = strings.Join(req.RedirectURIs, " ")
	}
	if req.ClientName != nil {
		cl.ClientName = *req.ClientName
	}
	if len(req.Scopes) > 0 {
		cl.Scopes = strings.Join(req.Scopes, " ")
	}
	if req.PKCERequired != nil {
		// 公共客户端不允许关闭 PKCE
		if cl.IsPublicClient() {
			cl.PKCERequired = db.BoolPtr(true)
		} else {
			cl.PKCERequired = req.PKCERequired
		}
	}
	if req.Enabled != nil {
		cl.Enabled = req.Enabled
	}
	if req.PostLogoutURIs != nil {
		cl.PostLogoutURIs = strings.Join(req.PostLogoutURIs, " ")
	}

	if err := db.DB.Save(&cl).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "db_error", "message": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"code": 0, "data": toClientView(cl)})
}

// AdminDeleteClient DELETE /api/admin/clients/:id
func AdminDeleteClient(c *gin.Context) {
	id := c.Param("id")
	var cl db.OAuthClient
	if err := db.DB.First(&cl, id).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "not_found"})
		return
	}
	// 保护内置客户端，避免误删导致 Demo 不可用
	if cl.ClientID == "template-web-client" || cl.ClientID == "oidc-cli" {
		c.JSON(http.StatusBadRequest, gin.H{
			"error":   "protected_client",
			"message": "内置客户端不可删除（template-web-client / oidc-cli）",
		})
		return
	}
	// 级联清理该客户端的授权码与令牌
	db.DB.Where("client_id = ?", cl.ClientID).Delete(&db.OAuthAuthorizationCode{})
	db.DB.Where("client_id = ?", cl.ClientID).Delete(&db.OAuthRefreshToken{})
	db.DB.Where("client_id = ?", cl.ClientID).Delete(&db.OAuthAccessToken{})
	db.DB.Delete(&cl)
	c.JSON(http.StatusOK, gin.H{"code": 0, "message": "客户端已删除"})
}

// ============================================================
// Token 管理
// ============================================================

type refreshTokenRow struct {
	ID        uint       `json:"id"`
	Token     string     `json:"token"` // 脱敏后的令牌
	UserID    uint       `json:"user_id"`
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

func refreshTokenRows(tokens []db.OAuthRefreshToken) []refreshTokenRow {
	// 批量取用户名，避免 N+1
	userNames := map[uint]string{}
	var ids []uint
	for _, t := range tokens {
		ids = append(ids, t.UserID)
	}
	if len(ids) > 0 {
		var users []db.User
		db.DB.Where("id in ?", ids).Find(&users)
		for _, u := range users {
			userNames[u.ID] = u.Username
		}
	}
	now := time.Now()
	out := make([]refreshTokenRow, 0, len(tokens))
	for _, t := range tokens {
		out = append(out, refreshTokenRow{
			ID:        t.ID,
			Token:     maskToken(t.Token),
			UserID:    t.UserID,
			UserSub:   itoa(t.UserID),
			Username:  userNames[t.UserID],
			ClientID:  t.ClientID,
			Scope:     t.Scope,
			ExpiresAt: t.ExpiresAt,
			Revoked:   t.RevokedAt != nil,
			RevokedAt: t.RevokedAt,
			CreatedAt: t.CreatedAt,
			Expired:   now.After(t.ExpiresAt),
		})
	}
	return out
}

// AdminListRefreshTokens GET /api/admin/refresh-tokens
// 查询参数 status: all(默认) | active | revoked
func AdminListRefreshTokens(c *gin.Context) {
	status := c.DefaultQuery("status", "all")
	q := db.DB.Model(&db.OAuthRefreshToken{}).Order("created_at desc")
	switch status {
	case "active":
		q = q.Where("revoked_at IS NULL AND expires_at > ?", time.Now())
	case "revoked":
		q = q.Where("revoked_at IS NOT NULL")
	}
	var tokens []db.OAuthRefreshToken
	if err := q.Limit(500).Find(&tokens).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "db_error"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"code": 0, "data": refreshTokenRows(tokens)})
}

// AdminRevokeToken POST /api/admin/revoke-token
// 请求体：{"id": 1} 或 {"token": "..."}
// 仅修改 revoked 标记，符合"IDP 侧 token 不加密、只做吊销标记"的设计
func AdminRevokeToken(c *gin.Context) {
	var req struct {
		ID    *uint  `json:"id"`
		Token string `json:"token"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid_request", "message": err.Error()})
		return
	}
	now := time.Now()

	var affected int64
	if req.ID != nil {
		res := db.DB.Model(&db.OAuthRefreshToken{}).
			Where("id = ? AND revoked_at IS NULL", *req.ID).
			Update("revoked_at", now)
		affected = res.RowsAffected
	} else if req.Token != "" {
		// 支持传入完整令牌（内部调用）或脱敏前缀匹配
		res := db.DB.Model(&db.OAuthRefreshToken{}).
			Where("token = ? AND revoked_at IS NULL", req.Token).
			Update("revoked_at", now)
		affected = res.RowsAffected
	} else {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid_request", "message": "需要提供 id 或 token"})
		return
	}

	if affected == 0 {
		c.JSON(http.StatusNotFound, gin.H{"error": "not_found", "message": "未找到对应的有效 refresh_token（可能已吊销）"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"code": 0, "message": "已吊销", "affected": affected})
}

// ============================================================
// 辅助函数
// ============================================================

// AdminMe GET /api/admin/me —— 前端判断是否管理员
func AdminMe(c *gin.Context) {
	user := currentUser(c)
	if user == nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "not_authenticated"})
		return
	}
	c.JSON(http.StatusOK, gin.H{
		"code": 0,
		"data": gin.H{
			"id":       user.ID,
			"username": user.Username,
			"nickname": user.Nickname,
			"email":    user.Email,
			"is_admin": user.IsAdmin,
		},
	})
}

// maskToken 令牌脱敏：保留前 8 位
func maskToken(t string) string {
	if len(t) <= 8 {
		return t
	}
	return t[:8] + "••••••••"
}

// generateClientSecret 生成随机 client_secret
func generateClientSecret() string {
	b := make([]byte, 32)
	_, _ = rand.Read(b)
	return "cs_" + base64.RawURLEncoding.EncodeToString(b)
}

// validRedirectURIs 校验回调地址格式
// 允许：完整 http/https URL；端口通配仅限回环地址
func validRedirectURIs(uris []string) bool {
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

// RequireAdmin 导出中间件供 main.go 注册分组使用
func RequireAdmin(c *gin.Context) { requireAdmin(c) }
