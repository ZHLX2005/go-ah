// Package middleware 收敛横切关注点。目前只有管理后台鉴权。
//
// 为什么不把「是不是管理员」写进每个管理端点：散落的权限判断必然漏掉某一处，
// 而漏掉的那一处就是一个匿名可用的管理接口。判断只做一次、挂在分组上，
// 新增端点自动受保护 —— 这是"默认安全"，反之是"默认裸奔"。
package middleware

import (
	"net/http"

	"github.com/gogf/gf/v2/net/ghttp"

	"github.com/ZHLX2005/go-ah/auth-hub/internal/consts"
	"github.com/ZHLX2005/go-ah/auth-hub/internal/controller/response"
	"github.com/ZHLX2005/go-ah/auth-hub/internal/logic/session"
	"github.com/ZHLX2005/go-ah/auth-hub/internal/model/entity"
)

// RequireAdmin 管理员鉴权：未登录 401，非管理员 403，通过则续跑后续处理。
//
// 失败响应与迁移前逐字一致：**只有 error 与 message，没有 code 信封**。
// 管理后台前端按 error 判定分支，多一个 code 字段会改变它的判断路径。
//
// 通过时把用户对象放进请求上下文：控制器拿它即可，不必再查一次同样的会话
// （同一请求里两次查会话，除了多一次往返，还可能拿到不一致的结果）。
func RequireAdmin(r *ghttp.Request) {
	u, err := session.CurrentUser(r.Context(), r.Cookie.Get(consts.SessionCookieName).String())
	if err != nil {
		response.Write(r, http.StatusInternalServerError, map[string]interface{}{
			"error": "internal_error",
		})
		return
	}
	if u == nil {
		response.Write(r, http.StatusUnauthorized, map[string]interface{}{
			"error":   "not_authenticated",
			"message": "未登录，请先登录 IDP",
		})
		return
	}
	if !u.IsAdmin {
		response.Write(r, http.StatusForbidden, map[string]interface{}{
			"error":   "forbidden",
			"message": "需要管理员权限",
		})
		return
	}

	r.SetCtxVar(consts.CtxKeyAdminUser, u)
	// 只有显式调用 Next 才会继续走服务处理器；不调用时链路就地终止，
	// 这正是「鉴权失败即拦下」需要的语义。
	r.Middleware.Next()
}

// CurrentAdmin 取出中间件放进上下文的当前管理员；未登录返回 nil。
//
// 控制器用它而不是自己去查会话，是为了让中间件成为"当前管理员是谁"的
// 唯一判定点：读的一方不用重复实现一遍鉴权逻辑（重复实现就有两份真相）。
func CurrentAdmin(r *ghttp.Request) *entity.User {
	v := r.GetCtxVar(consts.CtxKeyAdminUser).Interface()
	if v == nil {
		return nil
	}
	u, ok := v.(*entity.User)
	if !ok {
		return nil
	}
	return u
}
