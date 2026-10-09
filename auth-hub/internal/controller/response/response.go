// Package response 统一构造 HTTP 响应。
//
// 为什么要有这一层：本服务的响应有**四种**互不相同的形状，
// 混用一次就是前端解析失败或 OIDC 客户端报协议错：
//
//	① 业务信封     {code:0, data:...} / {code:1, error:..., message:...}
//	② OIDC 协议错  {"error":"invalid_grant","error_description":"..."}（无 code）
//	③ 裸对象       发现文档、JWKS、令牌响应 —— 标准规定的字段，不能包壳
//	④ 管理后台失败 {"error":"not_found","message":"..."}（无 code）
//
// ① 的成功形状由各端点在 api/*/v1 声明的响应结构体写出（字段名只有一处声明）；
// 本包提供其余三种形状的构造入口，以及 302 与会话 Cookie —— 凡"出口"都走这里，
// 控制器只做"选哪一种 + 传值"。
package response

import (
	"net/http"

	"github.com/gogf/gf/v2/net/ghttp"

	"github.com/ZHLX2005/go-ah/auth-hub/internal/consts"
	"github.com/ZHLX2005/go-ah/auth-hub/internal/logic/oidc"
)

// Write 以指定状态码写出 JSON 并结束请求处理
func Write(r *ghttp.Request, status int, body interface{}) {
	r.Response.WriteHeader(status)
	r.Response.WriteJsonExit(body)
}

// BizError 业务失败信封：{code:1, error:..., message:...}
//
// code 恒为 1（非 0 即失败），原因是前端只判断 code 是否为 0；
// 具体失败原因走 error 字段，供界面给出可操作的提示。
//
// 成功的业务信封（{code:0, data:...}）不在这里构造：它由各端点在
// api/*/v1 里声明的响应结构体直接写出，字段名因此有唯一的声明处。
func BizError(r *ghttp.Request, status int, errCode, message string) {
	Write(r, status, map[string]interface{}{
		"code":    1,
		"error":   errCode,
		"message": message,
	})
}

// ProtocolError 按 OIDC 规范写协议错误：{"error":..., "error_description":...}
func ProtocolError(r *ghttp.Request, pe *oidc.ProtocolError) {
	Write(r, pe.Status, map[string]interface{}{
		"error":             pe.Code,
		"error_description": pe.Desc,
	})
}

// Plain 纯文本错误（授权端点的参数错误按历史行为回纯文本）
func Plain(r *ghttp.Request, status int, text string) {
	r.Response.WriteHeader(status)
	r.Response.WriteExit(text)
}

// Redirect 302 跳转并结束请求处理
func Redirect(r *ghttp.Request, location string) {
	r.Response.Header().Set("Location", location)
	r.Response.WriteHeader(http.StatusFound)
	r.Response.WriteExit("")
}

// ── 会话 Cookie ─────────────────────────────────────────────────────────────
//
// 会话 Cookie 的读写在三个端点（登录、前端登出、RP 发起登出）都要做，
// 统一放这里：三处各写一份的话，属性稍有出入就是一个很难查的登录态问题
// （比如漏了 HttpOnly、或 Path 写成子路径）。

// SetSessionCookie 下发全局会话 Cookie；maxAge 单位秒，负值表示立即失效
func SetSessionCookie(r *ghttp.Request, value string, maxAge int) {
	r.Cookie.SetHttpCookie(&http.Cookie{
		Name:   consts.SessionCookieName,
		Value:  value,
		Path:   "/",
		MaxAge: maxAge,
		// 会话票据绝不暴露给脚本：否则一段 XSS 就能把登录态带走
		HttpOnly: true,
	})
}

// ClearSessionCookie 清除全局会话 Cookie（MaxAge 为负 → 浏览器立即删除）
func ClearSessionCookie(r *ghttp.Request) {
	SetSessionCookie(r, "", -1)
}
