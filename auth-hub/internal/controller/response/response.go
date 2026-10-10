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
		// 显式写 Lax，而不是留着不写给浏览器去默认。
		//
		// 二者今天的**行为**是一样的（浏览器对无 SameSite 属性的 Cookie 按 Lax
		// 处置），但"靠默认"和"写下来"不是一回事：默认值属于浏览器的策略，
		// 会随版本变（Safari 一度对跨站 Cookie 直接默认拒绝），而写下来的
		// 契约不会。本服务多处写操作（登录、登出、授权、扫码领取、扫码确认）
		// 的 CSRF 免疫全都建立在这一点上，不该建在一个没人声明过的默认值上。
		//
		// Secure 仍然没加：当前部署是 HTTP（README §14 把 HTTPS 列为非目标），
		// 加上它本地开发立刻登录不上。等 HTTPS 落地时随配置一起开。
		SameSite: http.SameSiteLaxMode,
	})
}

// ClearSessionCookie 清除全局会话 Cookie（MaxAge 为负 → 浏览器立即删除）
func ClearSessionCookie(r *ghttp.Request) {
	SetSessionCookie(r, "", -1)
}

// SetQRCtxCookie 下发扫码票据的上下文 Cookie。
//
// 三个属性都和"它会被人拿去尝试转发"直接相关，一个都不能省：
//   - HttpOnly：这是领取凭据，脚本能读到就等于把防转发机制关掉；
//   - Path 收敛到 /api/qr：它只在轮询与领取时有用，没必要跟着
//     用户访问的每个页面一起发出去；
//   - 短 MaxAge：与票据同寿，票据没了这把钥匙也该没了。
//
// 不设置 SameSite=Lax 以外的更强值：PC 前端就在 issuer 同源上，
// Lax 足够，而 Strict 会让"从外链点进登录页"这种正常路径丢 Cookie。
func SetQRCtxCookie(r *ghttp.Request, value string, maxAge int) {
	r.Cookie.SetHttpCookie(&http.Cookie{
		Name:     consts.QRCtxCookieName,
		Value:    value,
		Path:     consts.QRCtxCookiePath,
		MaxAge:   maxAge,
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
	})
}

// NoStore 声明响应不可缓存。
//
// 扫码轮询必须带这个：状态查询一旦被中间代理或浏览器缓存住，
// PC 就会反复看到同一个旧状态 —— 症状是"手机明明确认了，电脑上却不动"，
// 而这个症状从代码上看完全正常，只能靠抓包才查得出来。
// 挂在这类"状态在库里、答案在响应里"的端点上，比在网关层统一配要可靠：
// 谁新加一个轮询端点，忘了调这一句就会踩坑，而坑长在端点自己身上。
func NoStore(r *ghttp.Request) {
	h := r.Response.Header()
	h.Set("Cache-Control", "no-store")
	h.Set("Pragma", "no-cache")
}
