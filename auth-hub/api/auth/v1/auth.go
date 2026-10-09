// Package v1 定义认证（登录/登录态/登出）接口的请求与响应结构。
//
// 响应统一是 {code, data} 信封：前端据此判断成败，
// **code 字段不能省**（没有 code 时前端的统一拆包逻辑会把响应当成裸对象）。
package v1

import "github.com/gogf/gf/v2/frame/g"

// LoginReq POST /api/login
type LoginReq struct {
	g.Meta   `path:"/api/login" method:"post" tags:"Auth" summary:"账号口令登录"`
	Username string `json:"username"`
	Password string `json:"password"`
	ReturnTo string `json:"return_to"`
}

// LoginData 登录成功的数据体
type LoginData struct {
	Username string `json:"username"`
	Nickname string `json:"nickname"`
	ReturnTo string `json:"return_to"`
}

// LoginRes 登录响应（code=0 表示成功）
type LoginRes struct {
	Code int       `json:"code"`
	Data LoginData `json:"data"`
}

// MeReq GET /api/me
type MeReq struct {
	g.Meta `path:"/api/me" method:"get" tags:"Auth" summary:"当前登录态"`
}

// MeData 当前用户
type MeData struct {
	ID       int64  `json:"id"`
	Username string `json:"username"`
	Nickname string `json:"nickname"`
	Email    string `json:"email"`
}

// MeRes 登录态响应；未登录时 Data 为 null（前端据此跳登录页）
type MeRes struct {
	Code int     `json:"code"`
	Data *MeData `json:"data"`
}

// LogoutReq POST /api/logout
type LogoutReq struct {
	g.Meta                `path:"/api/logout" method:"post" tags:"Auth" summary:"登出（不重定向）"`
	PostLogoutRedirectURI string `json:"post_logout_redirect_uri"`
	ClientID              string `json:"client_id"`
	State                 string `json:"state"`
}

// LogoutAPIRes 登出响应
type LogoutAPIRes struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}
