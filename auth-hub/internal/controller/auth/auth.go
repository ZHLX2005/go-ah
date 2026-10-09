// Package auth 处理认证入口：账号口令登录、邀请码注册、登录态查询、登出。
//
// 登录/注册成功都只做两件事：建全局会话、下发会话 Cookie。业务方能不能拿到
// 身份，走的是 OIDC 授权流程（见 controller/oidc），与本包无关 ——
// 这样"登录 IdP"和"把身份交给某个应用"始终是两件事。
package auth

import (
	"context"
	"errors"
	"net/http"
	"strings"

	"github.com/gogf/gf/v2/frame/g"
	"github.com/gogf/gf/v2/net/ghttp"

	v1 "github.com/ZHLX2005/go-ah/auth-hub/api/auth/v1"
	"github.com/ZHLX2005/go-ah/auth-hub/internal/consts"
	"github.com/ZHLX2005/go-ah/auth-hub/internal/controller/response"
	"github.com/ZHLX2005/go-ah/auth-hub/internal/logic/invite"
	"github.com/ZHLX2005/go-ah/auth-hub/internal/logic/session"
	"github.com/ZHLX2005/go-ah/auth-hub/internal/logic/user"
	"github.com/ZHLX2005/go-ah/auth-hub/internal/utility"
)

// Controller 认证控制器
type Controller struct{}

// New 构造控制器
func New() *Controller { return &Controller{} }

// defaultReturnTo 登录/注册成功后没有指定回跳时的落点：
// 回到 OIDC 授权端点，继续原本被打断的授权流程
const defaultReturnTo = "/oauth2/auth"

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

	// 登录成功先记最后登录时间，再建会话：这一笔失败要如实报错。
	// 时间戳是管理端判断"账号还在不在用"的唯一依据，静默跳过它，
	// 数据会变成一条看起来正常、其实早已停更的记录。
	if err := user.TouchLastLogin(ctx, u.Id); err != nil {
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
		returnTo = defaultReturnTo
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

// Register POST /api/register —— 凭邀请码自助注册
//
// 顺序刻意是"先校验输入、再核销邀请码"：邀请码是**消耗品**，一次失败的
// 注册不该浪费它。所有能在核销之前问清楚的问题（账号格式、口令长度、
// 账号是否已被占用）都在前面问完，核销之后只剩"写库"这一件可能失败的事。
//
// 注册成功即登录（下发会话 Cookie 并按 return_to 回到授权流程）：
// 让用户注册完还要再打一遍刚刚设好的口令，是纯粹的刁难。
func (c *Controller) Register(ctx context.Context, req *v1.RegisterReq) error {
	r := g.RequestFromCtx(ctx)

	username := strings.TrimSpace(req.Username)
	email := strings.TrimSpace(req.Email)
	code := strings.TrimSpace(req.InviteCode)

	// 邀请码缺失单独给一条明确的话：这是本项目最常见的"用错接口"——
	// 有人会把它当成普通注册端点直接 POST 账号密码。
	if code == "" {
		response.BizError(r, http.StatusBadRequest, invite.CodeNotFound, "邀请码不能为空")
		return nil
	}
	if err := user.ValidateNewAccount(username, req.Password, email); err != nil {
		writeRegisterError(r, err)
		return nil
	}
	// 占用预检：给出"账号已被占用"这句明确的话。它不是安全边界 ——
	// 真正的保证是 users.username 的唯一索引，见 logic/invite.Redeem。
	if err := invite.CheckUsernameFree(ctx, username); err != nil {
		writeRegisterError(r, err)
		return nil
	}

	u, err := invite.Redeem(ctx, invite.RedeemInput{
		Code:     code,
		Username: username,
		// 明文口令到此为止：往下传的是哈希，业务包里不会出现明文口令，
		// 日志与 panic 栈也就不会把它带出去。
		PasswordHash: utility.HashPassword(req.Password),
		Email:        email,
	})
	if err != nil {
		writeRegisterError(r, err)
		return nil
	}

	sid, ttl, err := session.Issue(ctx, u.Id)
	if err != nil {
		return err
	}
	response.SetSessionCookie(r, sid, int(ttl.Seconds()))
	g.Log().Infof(ctx, "[auth-hub] 邀请码注册成功: user=%s (id=%d)", u.Username, u.Id)

	returnTo := req.ReturnTo
	if returnTo == "" {
		returnTo = defaultReturnTo
	}
	response.Write(r, http.StatusOK, &v1.RegisterRes{
		Code: 0,
		Data: v1.RegisterData{
			Username: u.Username,
			Nickname: u.Nickname,
			ReturnTo: returnTo,
		},
	})
	return nil
}

// writeRegisterError 把注册链路上的业务错误映射成响应。
//
// 状态码按种类分：参数/邀请码不可用 → 400，账号被占用 → 409。
// 具体原因一律走 error 字段（invite_expired / username_taken …），
// 前端据此给文案 —— 注册页要能告诉用户"是码的问题还是账号的问题"，
// 只说"注册失败"的话用户唯一能做的就是把整页重填一遍。
func writeRegisterError(r *ghttp.Request, err error) {
	var ie *invite.Error
	if !errors.As(err, &ie) {
		if ae, ok := err.(*user.AuthError); ok {
			response.BizError(r, http.StatusBadRequest, ae.ErrorCode, ae.Message)
			return
		}
		// 非业务错误（数据库故障等）按 500 兜底，不伪装成"参数不对"
		response.BizError(r, http.StatusInternalServerError, "internal_error", err.Error())
		return
	}
	switch ie.Kind {
	case invite.KindConflict:
		response.BizError(r, http.StatusConflict, ie.Code, ie.Msg)
	case invite.KindNotFound:
		response.BizError(r, http.StatusBadRequest, ie.Code, ie.Msg)
	default:
		response.BizError(r, http.StatusBadRequest, ie.Code, ie.Msg)
	}
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
