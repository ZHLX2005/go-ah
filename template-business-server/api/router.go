// 本文件是"有哪些入口"的唯一清单：一条路由一行，没有约定式推导。
//
// 为什么不用 gf 的对象注册（group.Bind(controller)）：那条路只接受
// func(*ghttp.Request) 与 func(context.Context, *Req) (*Res, error) 两种签名，
// 且返回值默认由响应中间件包成 {code,message,data} 信封。本服务的响应有四种
// 形状（业务信封 / error+message / 裸对象 / 404），硬塞进单一信封就是改协议。
// 所以用显式注册 + 一层薄适配器：控制器自行写响应，适配器只管解析入参与兜底。
package api

import (
	"context"
	"net/http"
	"os"
	"path/filepath"
	"strings"

	"github.com/gogf/gf/v2/frame/g"
	"github.com/gogf/gf/v2/net/ghttp"

	v1 "github.com/ZHLX2005/go-ah/template-business-server/api/v1"
)

// Register 注册全部路由；webDist 存在时同时托管前端产物。
func Register(ctx context.Context, s *ghttp.Server, webDist string) {
	c := New()
	s.Group("/", func(group *ghttp.RouterGroup) {
		group.GET("/api/config", noParams(c.PublicConfig))

		// 唯一需要解析请求体的接口：code + code_verifier 由前端回调页提交
		group.POST("/api/auth/callback", withBody[v1.AuthCallbackReq](c.AuthCallback))

		group.GET("/api/session", noParams(c.SessionInfo))
		group.GET("/api/profile", noParams(c.Profile))
		group.POST("/api/refresh", noParams(c.Refresh))
		group.POST("/api/logout", noParams(c.Logout))

		group.GET("/api/health", noParams(c.Health))
		group.GET("/api/security-status", noParams(c.SecurityStatus))
	})

	registerWeb(ctx, s, webDist)
}

// noParams 包"没有请求参数"的控制器。
//
// 这类接口**刻意不调用 r.Parse**：gf 在 POST + Content-Type: application/json
// 且 body 为空时会把空体当成 JSON 语法错误，而前端调 /api/refresh、
// /api/logout 就是不带请求体发的。少一次解析就少一类误判。
func noParams(fn func(context.Context) error) ghttp.HandlerFunc {
	return func(r *ghttp.Request) {
		if err := fn(r.Context()); err != nil {
			// 控制器返回 error 只代表"未预期的内部故障"：可预期的失败
			// （未登录、参数错、令牌被吊销）都在控制器里就地写成响应并返回 nil。
			g.Log().Errorf(r.Context(), "[BIZ] %s %s 处理失败: %+v", r.Method, r.URL.Path, err)
			writeError(r, http.StatusInternalServerError, "internal_error", err.Error())
		}
	}
}

// withBody 包"需要解析请求体"的控制器
func withBody[Req any](fn func(context.Context, *Req) error) ghttp.HandlerFunc {
	return func(r *ghttp.Request) {
		var req Req
		if err := r.Parse(&req); err != nil {
			writeError(r, http.StatusBadRequest, "invalid_request", err.Error())
			return
		}
		if err := fn(r.Context(), &req); err != nil {
			g.Log().Errorf(r.Context(), "[BIZ] %s %s 处理失败: %+v", r.Method, r.URL.Path, err)
			writeError(r, http.StatusInternalServerError, "internal_error", err.Error())
		}
	}
}

// registerWeb 托管前端产物（SPA）。
//
// 目录不存在时什么都不注册：容器部署下前端由 nginx 提供，Go 侧只提供 API，
// 此时对任意路径返回 404 才是正确行为（而不是把所有路径都变成 index.html）。
func registerWeb(ctx context.Context, s *ghttp.Server, distDir string) {
	if distDir == "" {
		g.Log().Info(ctx, "[BIZ] 未配置前端目录，仅提供 API")
		return
	}
	if _, err := os.Stat(distDir); err != nil {
		g.Log().Infof(ctx,
			"[BIZ] 未找到 %s，仅提供 API（请先 cd web/template-web && npm install && npm run build）",
			distDir)
		return
	}

	s.SetServerRoot(distDir)
	// 未命中的路径：/api 前缀保持 JSON 404（否则前端会把 404 页当作路由命中，
	// 表现出"接口返回了 HTML"），其余交给前端路由。
	s.BindStatusHandler(http.StatusNotFound, func(r *ghttp.Request) {
		p := r.URL.Path
		if strings.HasPrefix(p, "/api") {
			writeJSON(r, http.StatusNotFound, map[string]interface{}{
				"error": "not_found",
				"path":  p,
			})
			return
		}
		r.Response.ServeFile(filepath.Join(distDir, "index.html"))
	})
	g.Log().Infof(ctx, "[BIZ] 静态资源目录: %s", distDir)
}
