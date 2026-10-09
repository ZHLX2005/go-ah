// Package v1 定义认证（登录/注册/登录态/登出）接口的请求与响应结构。
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

// RegisterReq POST /api/register
//
// 唯一的自助注册入口，且**必须**带邀请码。注册是全平台唯一"还没有身份就能
// 创建身份"的动作，邀请码就是它唯一的门槛 —— 所以这个字段不是可选项，
// 缺失一律拒绝，而不是"没有码就当成普通注册放过去"。
type RegisterReq struct {
	g.Meta     `path:"/api/register" method:"post" tags:"Auth" summary:"凭邀请码自助注册"`
	Username   string `json:"username"`
	Password   string `json:"password"`
	Email      string `json:"email"`
	InviteCode string `json:"invite_code"`
	ReturnTo   string `json:"return_to"`
}

// RegisterData 注册成功的数据体。
//
// 与 LoginData 同形（账号/昵称/回跳地址）：注册成功后要接着走登录后同一条
// 链路（回到原 OIDC 授权请求），前端因此可以复用同一段处理逻辑。
type RegisterData struct {
	Username string `json:"username"`
	Nickname string `json:"nickname"`
	ReturnTo string `json:"return_to"`
}

// RegisterRes 注册响应（code=0 表示成功）
type RegisterRes struct {
	Code int          `json:"code"`
	Data RegisterData `json:"data"`
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
