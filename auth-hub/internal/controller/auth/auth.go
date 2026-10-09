// Package auth 处理认证入口：账号口令登录、登录态查询、登出。
//
// 登录成功只做两件事：建全局会话、下发会话 Cookie。业务方能不能拿到
// 身份，走的是 OIDC 授权流程（见 controller/oidc），与本包无关 ——
// 这样"登录 IdP"和"把身份交给某个应用"始终是两件事。
package auth

import (
	"context"
	"net/http"

	"github.com/gogf/gf/v2/frame/g"

	v1 "github.com/ZHLX2005/go-ah/auth-hub/api/auth/v1"
	"github.com/ZHLX2005/go-ah/auth-hub/internal/consts"
	"github.com/ZHLX2005/go-ah/auth-hub/internal/controller/response"
	"github.com/ZHLX2005/go-ah/auth-hub/internal/logic/session"
	"github.com/ZHLX2005/go-ah/auth-hub/internal/logic/user"
)

// Controller 认证控制器
type Controller struct{}

// New 构造控制器
func New() *Controller { return &Controller{} }

// Login POST /api/login
//
// 失败原因分三类且互不混淆：参数问题 400、账号不存在 401、口令错误 401。
// 账号不存在与口令错误返回不同的 error 值，是给管理后台看的可操作提示；
// 若本端点将来面向公网，应在上层把两者合并为同一提示以防账号枚举。
//
// 请求体由路由层统一解析（见 internal/router 的 handler 适配器），
// 这里不再自己 Parse —— 解析只做一次，重复解析只会让失败分支有两份。
func (c *Controller) Login(ctx context.Context, req *v1.LoginReq) error {
	r := g.RequestFromCtx(ctx)

	if req.Username == "" || req.Password == "" {
		response.BizError(r, http.StatusBadRequest, "invalid_request", "账号和密码不能为空")
		return nil
	}

	u, err := user.Authenticate(ctx, req.Username, req.Password)
	if err != nil {
		if ae, ok := err.(*user.AuthError); ok {
			response.BizError(r, http.StatusUnauthorized, ae.ErrorCode, ae.Message)
			return nil
		}
		return err
	}

	sid, ttl, err := session.Issue(ctx, u.Id)
	if err != nil {
		return err
	}
	response.SetSessionCookie(r, sid, int(ttl.Seconds()))

	// 登录成功后回到原 OIDC 授权流程
	returnTo := req.ReturnTo
	if returnTo == "" {
		returnTo = "/oauth2/auth"
	}
	response.Write(r, http.StatusOK, &v1.LoginRes{
		Code: 0,
		Data: v1.LoginData{
			Username: u.Username,
			Nickname: u.Nickname,
			ReturnTo: returnTo,
		},
	})
	return nil
}

// Me GET /api/me —— 当前登录态（前端刷新页面时判断用）
//
// 未登录返回 code=0 + data=null：这是**正常的未登录**，不是错误。
// 用非 0 的 code 会让前端把"还没登录"当成故障弹窗。
func (c *Controller) Me(ctx context.Context, req *v1.MeReq) error {
	r := g.RequestFromCtx(ctx)

	u, err := session.CurrentUser(ctx, r.Cookie.Get(consts.SessionCookieName).String())
	if err != nil {
		return err
	}
	if u == nil {
		response.Write(r, http.StatusOK, &v1.MeRes{Code: 0, Data: nil})
		return nil
	}
	response.Write(r, http.StatusOK, &v1.MeRes{
		Code: 0,
		Data: &v1.MeData{ID: u.Id, Username: u.Username, Nickname: u.Nickname, Email: u.Email},
	})
	return nil
}

// Logout POST /api/logout —— 前端登出页调用（不重定向，跳转由前端执行）
func (c *Controller) Logout(ctx context.Context, req *v1.LogoutReq) error {
	r := g.RequestFromCtx(ctx)

	if sid := r.Cookie.Get(consts.SessionCookieName).String(); sid != "" {
		if err := session.Destroy(ctx, sid); err != nil {
			return err
		}
	}
	response.ClearSessionCookie(r)
	response.Write(r, http.StatusOK, &v1.LogoutAPIRes{Code: 0, Message: "已退出全局会话"})
	return nil
}
