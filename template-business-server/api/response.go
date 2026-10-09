package api

import (
	"net/http"

	"github.com/gogf/gf/v2/net/ghttp"

	v1 "github.com/ZHLX2005/go-ah/template-business-server/api/v1"
)

// 这一层存在的理由与 auth-hub 相同：本服务的响应有四种形状，混用一次就是
// 前端解析失败 ——
//
//	① 业务信封     {code:0, data:...}（成功形状由 api/v1 里的结构体直接写出）
//	② 失败响应     {error, message} —— **没有 code**
//	③ 裸对象       /api/config、/api/health、/api/security-status
//	④ 404          {error:"not_found", path:...}
//
// 失败响应为什么没有 code：迁移前的 gin 版本就是这样，前端为这两种形状
// 分别写了分支。迁移期间"顺手统一"就是破坏兼容。

// writeJSON 以指定状态码写出 JSON 并结束请求处理
func writeJSON(r *ghttp.Request, status int, body interface{}) {
	r.Response.WriteHeader(status)
	r.Response.WriteJsonExit(body)
}

// writeError 失败响应：{error, message}。message 为空时整个字段省略。
func writeError(r *ghttp.Request, status int, errCode, message string) {
	writeJSON(r, status, &v1.ErrorRes{Error: errCode, Message: message})
}

// setSessionCookie 下发业务会话 Cookie；maxAge 单位秒，负值表示立即失效。
//
// 用 SetHttpCookie 而不是 gf 的 Cookie.Set：后者没有 MaxAge 字段，
// 会改成输出 Expires，响应头与迁移前不一致。
func setSessionCookie(r *ghttp.Request, value string, maxAge int) {
	r.Cookie.SetHttpCookie(&http.Cookie{
		Name:     SessionCookie,
		Value:    value,
		Path:     "/",
		MaxAge:   maxAge,
		HttpOnly: true,
	})
}
