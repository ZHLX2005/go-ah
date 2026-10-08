package api

import (
	"net/http"

	"github.com/gin-gonic/gin"

	"github.com/ZHLX2005/go-ah/auth-hub/db"
)

// Login POST /api/login
// 请求体: {"username":"test","password":"test123456"}
// 成功: {code:0, data:{username, nickname, return_to}}
// 失败: {code:1, error:"user_not_found"|"wrong_password"}
func Login(c *gin.Context) {
	var req struct {
		Username string `json:"username"`
		Password string `json:"password"`
		ReturnTo string `json:"return_to"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"code": 1, "error": "invalid_request", "message": "请求参数格式错误"})
		return
	}
	if req.Username == "" || req.Password == "" {
		c.JSON(http.StatusBadRequest, gin.H{"code": 1, "error": "invalid_request", "message": "账号和密码不能为空"})
		return
	}

	var user db.User
	if err := db.DB.Where("username = ?", req.Username).First(&user).Error; err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"code": 1, "error": "user_not_found", "message": "账号不存在"})
		return
	}
	if !db.VerifyPassword(req.Password, user.PasswordHash) {
		c.JSON(http.StatusUnauthorized, gin.H{"code": 1, "error": "wrong_password", "message": "密码错误"})
		return
	}

	issueSession(c, user.ID)

	// 登录成功后回到原 OIDC 授权流程
	returnTo := req.ReturnTo
	if returnTo == "" {
		returnTo = "/oauth2/auth"
	}
	c.JSON(http.StatusOK, gin.H{
		"code": 0,
		"data": gin.H{
			"username":  user.Username,
			"nickname":  user.Nickname,
			"return_to": returnTo,
		},
	})
}

// Me GET /api/me —— 当前登录态（供前端页面判断刷新时使用）
func Me(c *gin.Context) {
	user := currentUser(c)
	if user == nil {
		c.JSON(http.StatusOK, gin.H{"code": 0, "data": nil})
		return
	}
	c.JSON(http.StatusOK, gin.H{
		"code": 0,
		"data": gin.H{
			"id":       user.ID,
			"username": user.Username,
			"nickname": user.Nickname,
			"email":    user.Email,
		},
	})
}

// LogoutAPI POST /api/logout —— React 登出页调用（不重定向，返回跳转地址由前端执行）
func LogoutAPI(c *gin.Context) {
	var req struct {
		PostLogoutRedirectURI string `json:"post_logout_redirect_uri"`
		ClientID              string `json:"client_id"`
		State                 string `json:"state"`
	}
	_ = c.ShouldBindJSON(&req)

	if sid, err := c.Cookie(sessionCookie); err == nil && sid != "" {
		var s db.UserSession
		if err := db.DB.Where("session_id = ?", sid).First(&s).Error; err == nil {
			nw := now()
			db.DB.Model(&db.OAuthRefreshToken{}).
				Where("user_id = ? AND revoked_at IS NULL", s.UserID).
				Update("revoked_at", nw)
			db.DB.Where("user_id = ?", s.UserID).Delete(&db.OAuthAccessToken{})
			db.DB.Where("session_id = ?", sid).Delete(&db.UserSession{})
		}
	}
	c.SetCookie(sessionCookie, "", -1, "/", "", false, true)
	c.JSON(http.StatusOK, gin.H{"code": 0, "message": "已退出全局会话"})
}
