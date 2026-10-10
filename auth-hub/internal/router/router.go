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
	qrapi "github.com/ZHLX2005/go-ah/auth-hub/api/qr/v1"
	adminctrl "github.com/ZHLX2005/go-ah/auth-hub/internal/controller/admin"
	authctrl "github.com/ZHLX2005/go-ah/auth-hub/internal/controller/auth"
	oidcctrl "github.com/ZHLX2005/go-ah/auth-hub/internal/controller/oidc"
	qrctrl "github.com/ZHLX2005/go-ah/auth-hub/internal/controller/qr"
	"github.com/ZHLX2005/go-ah/auth-hub/internal/controller/response"
	"github.com/ZHLX2005/go-ah/auth-hub/internal/middleware"
)

// Register 注册全部路由；webDist 存在时同时托管前端产物（容器部署下由 nginx
// 托管，这个目录不存在，只提供 API —— 属于预期行为，不算异常）。
func Register(ctx context.Context, s *ghttp.Server, webDist string) {
	oidcC := oidcctrl.New()
	authC := authctrl.New()
	adminC := adminctrl.New()
	qrC := qrctrl.New()

	// ── 公开端点：OIDC 协议 + 认证入口 + 授权确认页数据 ──────────────────────
	s.Group("/", func(group *ghttp.RouterGroup) {
		// 发现文档与公钥必须匿名可取：客户端与业务方靠它自举
		group.GET("/.well-known/openid-configuration", call[oidcapi.DiscoveryReq](oidcC.Discovery))
		group.GET("/.well-known/jwks.json", call[oidcapi.JwksReq](oidcC.Jwks))

		// 认证入口（IdP 自己的登录态）
		group.POST("/api/login", call[authapi.LoginReq](authC.Login))
		group.GET("/api/me", call[authapi.MeReq](authC.Me))
		group.POST("/api/logout", call[authapi.LogoutReq](authC.Logout))

		// 自助注册。它是**唯一**不需要已有身份的写入口，门槛是邀请码：
		// 码的校验与核销都在 logic/invite 里，这里只负责装配。
		//
		// 为什么不放进管理分组：注册不是管理员在做的事，是受邀者自己在做 ——
		// 挂上 RequireAdmin 等于把注册入口关掉。
		//
		// 关于枚举：失败原因确实区分了"不存在/停用/过期/用完"（注册页要靠它
		// 给出可操作的提示），也就是说这个端点会确认"你猜的这串是真码"。
		// 接受这个信息泄露，是因为码有 96 bit 随机性 —— 做成枚举预言机也需要
		// 先猜中一个 2^96 空间里的值，收益为零。真正的防护在这里不是模糊
		// 报错，而是码的熵。
		group.POST("/api/register", call[authapi.RegisterReq](authC.Register))

		// 授权确认页
		group.GET("/api/consent", call[oidcapi.ConsentInfoReq](oidcC.ConsentInfo))
		group.POST("/api/consent", call[oidcapi.ConsentReq](oidcC.Consent))

		// ── 扫码登录（设计见 docs/design/qr-login.md）──────────────────────────
		//
		// 整组放在公开组里，但"公开"对两类端点的含义完全不同，别混着看：
		//
		//   PC 侧（sessions / poll / claim / cancel）匿名可调，授权靠 qr_ctx
		//   Cookie —— 谁创建了这张票据，谁才配领走它换来的会话。
		//
		//   手机侧（preview / scan / confirm / refuse）必须已有身份，
		//   由控制器自查（Cookie 会话或 Bearer access_token 两条路都认）。
		//   不挂 RequireAdmin：扫码确认是普通账号在做的事，挂上等于
		//   把功能只对管理员开放 —— 同 /api/register 不进管理分组的理由。
		//
		// 中间件挂在分组上，所以这四条手机侧端点不能和 PC 侧四条并到同一个
		// 子分组里（那样要么全都得登录、要么全都不校验）。逐个注册，
		// 代价是"新增端点忘了想鉴权"的风险回到人身上；这里用注释把它标出来。
		group.POST("/api/qr/sessions", call[qrapi.CreateReq](qrC.Create))
		group.GET("/api/qr/sessions/{ticket}", call[qrapi.PollReq](qrC.Poll))
		group.POST("/api/qr/sessions/{ticket}/claim", call[qrapi.ClaimReq](qrC.Claim))
		group.POST("/api/qr/sessions/{ticket}/cancel", call[qrapi.CancelReq](qrC.Cancel))
		group.GET("/api/qr/sessions/{ticket}/preview", call[qrapi.PreviewReq](qrC.Preview))
		group.POST("/api/qr/sessions/{ticket}/scan", call[qrapi.ScanReq](qrC.Scan))
		group.POST("/api/qr/sessions/{ticket}/confirm", call[qrapi.ConfirmReq](qrC.Confirm))
		group.POST("/api/qr/sessions/{ticket}/refuse", call[qrapi.RefuseReq](qrC.Refuse))

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

		// 注册邀请码（自助注册的门槛由管理员发放）
		group.GET("/api/admin/invites", adminCall[adminapi.AdminInvitesReq](adminC.Invites))
		group.POST("/api/admin/invites", adminCall[adminapi.AdminCreateInviteReq](adminC.CreateInvite))
		group.PUT("/api/admin/invites/{id}", adminCall[adminapi.AdminUpdateInviteReq](adminC.UpdateInvite))
		group.DELETE("/api/admin/invites/{id}", adminCall[adminapi.AdminDeleteInviteReq](adminC.DeleteInvite))
		group.GET("/api/admin/invites/{id}/usages", adminCall[adminapi.AdminInviteUsagesReq](adminC.InviteUsages))
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
