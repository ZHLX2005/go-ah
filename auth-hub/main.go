package main

import (
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strings"

	"github.com/gin-gonic/gin"

	"github.com/ZHLX2005/go-ah/auth-hub/api"
	"github.com/ZHLX2005/go-ah/auth-hub/db"
)

// version 由发布流水线通过 -ldflags "-X main.version=x.y.z" 注入，
// 本地 go run / go build 时保持为 dev。
var version = "dev"

func main() {
	// 1) 初始化 SQLite
	db.Init(db.Env("IDP_DB", "idp.db"))
	// 2) 初始化 RSA 签名密钥
	db.InitKeys()

	log.Printf("[auth-hub] version=%s 启动中…", version)

	r := gin.Default()

	// ============ API / OIDC 路由（优先级高于静态资源） ============
	r.POST("/api/login", api.Login)
	r.GET("/api/me", api.Me)
	r.POST("/api/logout", api.LogoutAPI)
	r.GET("/api/consent", api.ConsentInfo)
	r.POST("/api/consent", api.Consent)

	r.GET("/.well-known/openid-configuration", api.OpenIDConfiguration)
	r.GET("/.well-known/jwks.json", api.JWKS)
	r.GET("/oauth2/auth", api.Authorize)
	r.POST("/oauth2/token", api.Token)
	r.GET("/oauth2/userinfo", api.UserInfo)
	r.GET("/oauth2/logout", api.Logout)
	r.POST("/oauth2/revoke", api.RevokeToken)

	// ============ 管理后台 API（需管理员会话） ============
	admin := r.Group("/api/admin", api.RequireAdmin)
	{
		admin.GET("/me", api.AdminMe)
		// 用户管理
		admin.GET("/users", api.AdminListUsers)
		admin.GET("/users/:id/sessions", api.AdminUserSessions)
		admin.GET("/users/:id/tokens", api.AdminUserTokens)
		// OIDC 客户端管理
		admin.GET("/clients", api.AdminListClients)
		admin.POST("/clients", api.AdminCreateClient)
		admin.PUT("/clients/:id", api.AdminUpdateClient)
		admin.DELETE("/clients/:id", api.AdminDeleteClient)
		// Token 管理
		admin.GET("/refresh-tokens", api.AdminListRefreshTokens)
		admin.POST("/revoke-token", api.AdminRevokeToken)
	}

	// ============ React 静态资源托管（SPA fallback） ============
	distDir := db.Env("IDP_WEB_DIST", "./web/idp-web/dist")
	if _, err := os.Stat(distDir); err == nil {
		r.Static("/assets", filepath.Join(distDir, "assets"))
		r.StaticFile("/favicon.ico", filepath.Join(distDir, "favicon.ico"))
		r.NoRoute(func(c *gin.Context) {
			p := c.Request.URL.Path
			// 未命中的 API 前缀保持 404，其余交给 React Router
			if strings.HasPrefix(p, "/api") || strings.HasPrefix(p, "/oauth2") || strings.HasPrefix(p, "/.well-known") {
				c.JSON(http.StatusNotFound, gin.H{"error": "not_found", "path": p})
				return
			}
			c.File(filepath.Join(distDir, "index.html"))
		})
		log.Printf("[IDP] 静态资源目录: %s", distDir)
	} else {
		log.Printf("[IDP] 未找到 %s，仅提供 API（请先 cd web/idp-web && npm install && npm run build）", distDir)
	}

	addr := db.Env("IDP_ADDR", "127.0.0.1:8080")
	log.Printf("[IDP] 统一登录平台已启动: http://%s", addr)
	if err := r.Run(addr); err != nil {
		log.Fatalf("启动失败: %v", err)
	}
}
