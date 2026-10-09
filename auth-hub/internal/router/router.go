// Package router 注册全部 HTTP 路由，是"有哪些入口"的唯一清单。
//
// 为什么不用 gf 的对象注册（group.Bind(controller)）：那条路只接受两种签名 ——
// func(*ghttp.Request) 与 func(context.Context, *Req) (*Res, error)，且返回值
// 默认由响应中间件包成 {code,message,data} 信封。本服务的响应有**三种形状**
// （业务信封 / OIDC 协议错 / 裸对象 / 纯文本 / 302），硬塞进单一信封就是改协议。
// 所以这里用显式注册 + 一个薄适配器：控制器自行写响应，路由只管解析入参、
// 调用、兜底。路由表因此也是可读的 —— 一条路由一行，没有约定式推导。
package router

import (
	"context"
	"net/http"
	"os"
	"path/filepath"
	"strings"

	"github.com/gogf/gf/v2/frame/g"
	"github.com/gogf/gf/v2/net/ghttp"

	adminapi "github.com/ZHLX2005/go-ah/auth-hub/api/admin/v1"
	authapi "github.com/ZHLX2005/go-ah/auth-hub/api/auth/v1"
	oidcapi "github.com/ZHLX2005/go-ah/auth-hub/api/oidc/v1"
	adminctrl "github.com/ZHLX2005/go-ah/auth-hub/internal/controller/admin"
	authctrl "github.com/ZHLX2005/go-ah/auth-hub/internal/controller/auth"
	oidcctrl "github.com/ZHLX2005/go-ah/auth-hub/internal/controller/oidc"
	"github.com/ZHLX2005/go-ah/auth-hub/internal/controller/response"
	"github.com/ZHLX2005/go-ah/auth-hub/internal/middleware"
)

// Register 注册全部路由；webDist 存在时同时托管前端产物（容器部署下由 nginx
// 托管，这个目录不存在，只提供 API —— 属于预期行为，不算异常）。
func Register(ctx context.Context, s *ghttp.Server, webDist string) {
	oidcC := oidcctrl.New()
	authC := authctrl.New()
	adminC := adminctrl.New()

	// ── 公开端点：OIDC 协议 + 认证入口 + 授权确认页数据 ──────────────────────
	s.Group("/", func(group *ghttp.RouterGroup) {
		// 发现文档与公钥必须匿名可取：客户端与业务方靠它自举
		group.GET("/.well-known/openid-configuration", call[oidcapi.DiscoveryReq](oidcC.Discovery))
		group.GET("/.well-known/jwks.json", call[oidcapi.JwksReq](oidcC.Jwks))

		// 认证入口（IdP 自己的登录态）
		group.POST("/api/login", call[authapi.LoginReq](authC.Login))
		group.GET("/api/me", call[authapi.MeReq](authC.Me))
		group.POST("/api/logout", call[authapi.LogoutReq](authC.Logout))

		// 授权确认页
		group.GET("/api/consent", call[oidcapi.ConsentInfoReq](oidcC.ConsentInfo))
		group.POST("/api/consent", call[oidcapi.ConsentReq](oidcC.Consent))

		// OIDC 协议端点
		group.GET("/oauth2/auth", call[oidcapi.AuthorizeReq](oidcC.Authorize))
		group.POST("/oauth2/token", call[oidcapi.TokenReq](oidcC.Token))
		group.GET("/oauth2/userinfo", call[oidcapi.UserInfoReq](oidcC.UserInfo))
		group.POST("/oauth2/revoke", call[oidcapi.RevokeReq](oidcC.Revoke))
		group.GET("/oauth2/logout", call[oidcapi.LogoutReq](oidcC.Logout))
	})

	// ── 管理后台：整组挂管理员鉴权 ──────────────────────────────────────────
	//
	// 鉴权挂在分组上而不是每个端点上：新增端点自动受保护。
	// 逐个端点加中间件的写法，漏加一个就是一条匿名可用的管理接口。
	s.Group("/", func(group *ghttp.RouterGroup) {
		group.Middleware(middleware.RequireAdmin)

		group.GET("/api/admin/me", adminCall[adminapi.AdminMeReq](adminC.Me))

		group.GET("/api/admin/users", adminCall[adminapi.AdminUsersReq](adminC.Users))
		group.GET("/api/admin/users/{id}/sessions", adminCall[adminapi.AdminUserSessionsReq](adminC.UserSessions))
		group.GET("/api/admin/users/{id}/tokens", adminCall[adminapi.AdminUserTokensReq](adminC.UserTokens))

		group.GET("/api/admin/clients", adminCall[adminapi.AdminClientsReq](adminC.Clients))
		group.POST("/api/admin/clients", adminCall[adminapi.AdminCreateClientReq](adminC.CreateClient))
		group.PUT("/api/admin/clients/{id}", adminCall[adminapi.AdminUpdateClientReq](adminC.UpdateClient))
		group.DELETE("/api/admin/clients/{id}", adminCall[adminapi.AdminDeleteClientReq](adminC.DeleteClient))

		group.GET("/api/admin/refresh-tokens", adminCall[adminapi.AdminRefreshTokensReq](adminC.RefreshTokens))
		group.POST("/api/admin/revoke-token", adminCall[adminapi.AdminRevokeTokenReq](adminC.RevokeToken))
	})

	registerWeb(ctx, s, webDist)
}

// handler 把「按请求结构体解析入参 → 调用控制器 → 兜底」这套样板收敛到一处。
//
// onParseError 由调用方给：业务端点的解析失败要回 {code:1,...} 信封，
// 管理端点的失败响应没有 code 字段 —— 两者不能共用一种形状。
func handler[Req any](
	fn func(context.Context, *Req) error,
	onParseError func(*ghttp.Request, error),
	onInternalErr func(*ghttp.Request, error),
) ghttp.HandlerFunc {
	return func(r *ghttp.Request) {
		var req Req
		if err := r.Parse(&req); err != nil {
			onParseError(r, err)
			return
		}
		if err := fn(r.Context(), &req); err != nil {
			// 控制器返回 error 只代表"未预期的内部故障"：可预期的失败
			// （参数错、未登录、协议错）都在控制器里就地写成响应并返回 nil。
			g.Log().Errorf(r.Context(), "[auth-hub] %s %s 处理失败: %+v", r.Method, r.URL.Path, err)
			onInternalErr(r, err)
		}
	}
}

// call 公开端点的适配器：失败按业务信封返回
func call[Req any](fn func(context.Context, *Req) error) ghttp.HandlerFunc {
	return handler[Req](fn,
		func(r *ghttp.Request, err error) {
			response.BizError(r, http.StatusBadRequest, "invalid_request", "请求参数格式错误")
		},
		func(r *ghttp.Request, err error) {
			response.BizError(r, http.StatusInternalServerError, "internal_error", err.Error())
		},
	)
}

// adminCall 管理端点的适配器：失败响应没有 code 字段（与迁移前一致）
func adminCall[Req any](fn func(context.Context, *Req) error) ghttp.HandlerFunc {
	return handler[Req](fn,
		func(r *ghttp.Request, err error) {
			response.Write(r, http.StatusBadRequest, map[string]interface{}{
				"error":   "invalid_request",
				"message": err.Error(),
			})
		},
		func(r *ghttp.Request, err error) {
			response.Write(r, http.StatusInternalServerError, map[string]interface{}{
				"error":   "db_error",
				"message": err.Error(),
			})
		},
	)
}

// registerWeb 托管前端产物（SPA）。目录不存在时什么都不做 —— 容器部署下
// 前端由 nginx 提供，Go 侧只提供 API。
func registerWeb(ctx context.Context, s *ghttp.Server, distDir string) {
	if _, err := os.Stat(distDir); err != nil {
		g.Log().Infof(ctx, "[auth-hub] 未找到前端目录 %s，仅提供 API", distDir)
		return
	}

	s.SetServerRoot(distDir)
	// 未命中的路径：API/OIDC 前缀保持 404（否则前端会把 404 页当成路由命中），
	// 其余交给前端路由（/login、/consent 等由 React Router 处理）。
	s.BindStatusHandler(http.StatusNotFound, func(r *ghttp.Request) {
		p := r.URL.Path
		if strings.HasPrefix(p, "/api") ||
			strings.HasPrefix(p, "/oauth2") ||
			strings.HasPrefix(p, "/.well-known") {
			response.Write(r, http.StatusNotFound, map[string]interface{}{
				"error": "not_found",
				"path":  p,
			})
			return
		}
		r.Response.ServeFile(filepath.Join(distDir, "index.html"))
	})
	g.Log().Infof(ctx, "[auth-hub] 静态资源目录: %s", distDir)
}
