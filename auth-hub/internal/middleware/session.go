package middleware

import (
	"github.com/gogf/gf/v2/net/ghttp"

	"github.com/ZHLX2005/go-ah/auth-hub/internal/consts"
	"github.com/ZHLX2005/go-ah/auth-hub/internal/controller/response"
)

// TouchSession 全局登录会话的看门狗中间件：每条带 idp_session cookie 的请求
// 都做一次「DB + cookie」同步续期决策（由 response.RefreshSessionCookie 实现）。
//
// 挂这条中间件而不是把续期逻辑散到各控制器，理由和 RequireAdmin 一样 ——
// 新增端点默认会被续期覆盖，漏加一个就是「某条路径不会自动续期」的体感 bug。
//
// 不带 cookie / cookie 无效 = 完全 no-op：登录、注册、扫码创建票据等
// 匿名端点都跑在这条中间件下，**不能因为没有会话就把请求拦下来**。
// 调用 RefreshSessionCookie 是 best-effort，失败也只 log 不报错，
// 因此这条中间件永远要调用 Next —— 哪怕 cookie 已经被 ClearSessionCookie
// 删掉了，下游控制器还要继续按「未登录」逻辑跑完整。
func TouchSession(r *ghttp.Request) {
	sid := r.Cookie.Get(consts.SessionCookieName).String()
	if sid != "" {
		response.RefreshSessionCookie(r.Context(), r, sid)
	}
	r.Middleware.Next()
}