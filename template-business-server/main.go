package main

import (
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/gin-gonic/gin"

	"github.com/ZHLX2005/go-ah/template-business-server/api"
	"github.com/ZHLX2005/go-ah/template-business-server/db"
)

// version 由发布流水线通过 -ldflags "-X main.version=x.y.z" 注入，
// 本地 go run / go build 时保持为 dev。
var version = "dev"

func main() {
	// 1) 初始化业务数据库（SQLite）
	db.Init(db.Env("BIZ_DB", "template.db"))

	log.Printf("[go-ah-template] version=%s 启动中…", version)

	// 2) 初始化 Token 加密引擎（Task4）
	//    密钥来自 BIZ_TOKEN_SECRET，缺失或过弱直接终止启动——
	//    宁可不启动，也不能在没有加密能力的情况下把 refresh_token 明文落库。
	if err := api.InitCrypto(); err != nil {
		log.Fatalf("[BIZ] 加密初始化失败，服务无法安全启动: %v\n"+
			"       请设置环境变量，例如：export %s=$(openssl rand -hex 32)",
			err, "BIZ_TOKEN_SECRET")
	}
	log.Printf("[BIZ] Token 加密引擎已就绪（AES-256-GCM + PBKDF2-SHA256）")

	// 3) 启动后台自动续期巡检协程（Task4）
	refresher := api.NewRefresher(30 * time.Second)
	refresher.OnSessionRevoked = func(sessionID, userSub string, reason error) {
		log.Printf("[BIZ][续期] 会话已失效，用户需重新登录: session=%s sub=%s 原因=%v",
			sessionID, userSub, reason)
	}
	refresher.Start()
	defer refresher.Stop()

	// 4) 尝试连接 IDP（失败不阻塞启动，接口调用时会重试并返回明确错误）
	go func() {
		for i := 0; i < 3; i++ {
			if err := api.SetupOIDC(); err == nil {
				return
			} else if i == 2 {
				log.Printf("[BIZ] 初始化 OIDC 客户端失败（IDP 可能未启动）: %v", err)
			}
			time.Sleep(2 * time.Second)
		}
	}()

	r := gin.Default()

	// ============ 业务 API ============
	r.GET("/api/config", api.PublicConfig)         // 前端读取 OIDC 公共配置
	r.POST("/api/auth/callback", api.AuthCallback) // 回调：code + verifier 换 token
	r.GET("/api/session", api.SessionInfo)         // 轻量登录态
	r.GET("/api/profile", api.Profile)             // 受保护接口
	r.POST("/api/refresh", api.Refresh)            // 刷新 token
	r.POST("/api/logout", api.Logout)              // 统一登出

	r.GET("/api/health", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"status": "ok", "service": "template-business-server"})
	})

	// 健康检查扩展：暴露加密与续期能力状态（不泄漏密钥）
	r.GET("/api/security-status", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{
			"token_encryption": gin.H{
				"algorithm":  "AES-256-GCM",
				"kdf":        "PBKDF2-HMAC-SHA256",
				"iterations": 120000,
				"key_source": "env:BIZ_TOKEN_SECRET",
				"ready":      api.CryptoReady(),
			},
			"auto_refresh": gin.H{
				"enabled":          true,
				"access_token_ttl": "10m",
				"refresh_ttl":      "168h",
				"threshold":        "2m",
			},
		})
	})

	// ============ React 静态资源托管（SPA fallback） ============
	distDir := db.Env("BIZ_WEB_DIST", "./web/template-web/dist")
	if _, err := os.Stat(distDir); err == nil {
		r.Static("/assets", filepath.Join(distDir, "assets"))
		r.StaticFile("/favicon.ico", filepath.Join(distDir, "favicon.ico"))
		r.NoRoute(func(c *gin.Context) {
			p := c.Request.URL.Path
			if strings.HasPrefix(p, "/api") {
				c.JSON(http.StatusNotFound, gin.H{"error": "not_found", "path": p})
				return
			}
			c.File(filepath.Join(distDir, "index.html"))
		})
		log.Printf("[BIZ] 静态资源目录: %s", distDir)
	} else {
		log.Printf("[BIZ] 未找到 %s，仅提供 API（请先 cd web/template-web && npm install && npm run build）", distDir)
	}

	addr := db.Env("BIZ_ADDR", "127.0.0.1:8081")
	log.Printf("[BIZ] 模板业务平台已启动: http://%s", addr)
	if err := r.Run(addr); err != nil {
		log.Fatalf("启动失败: %v", err)
	}
}
