// Package v1 定义扫码登录端点的请求与响应结构。
//
// 这里的字段名就是**对外契约**：PC 前端、手机 H5 页、原生 App、以及仓库里
// 那个模拟端到端的 Python CLI 都按它取值，改名等于同时破坏四方。
// 一律 snake_case，与本服务其余端点一致（Go 字段驼峰、json 标签蛇形）。
//
// 关于"响应为什么都带 code"：本服务的公开端点统一是 {code,data} 信封，
// 前端靠 code 是否为 0 判断成败（见 api/client.ts 的拆包逻辑）。
// 少了 code，裸对象会被当成成功数据，失败反而被吞掉。
package v1

import "github.com/gogf/gf/v2/frame/g"

// ── PC 侧：建票 ────────────────────────────────────────────────────────────

// CreateReq POST /api/qr/sessions —— 创建一张待扫码票据
//
// 没有任何入参：PC 是谁（UA/IP）一律由服务端从请求里读，不接受自报。
// 允许客户端声明"我是 Windows Chrome"，就等于允许攻击者伪造用户在手机上
// 唯一能看到的那条核对信息。
type CreateReq struct {
	g.Meta `path:"/api/qr/sessions" method:"post" tags:"QR" summary:"创建扫码登录票据"`
}

// CreateData 建票结果
type CreateData struct {
	Ticket string `json:"ticket"`
	// QRContent 是**二维码的内容**，即手机扫出来那串东西。
	// 它是一个 https URL 而不是 ticket 本身：同一个 URL 要能同时被
	// 已安装的 App（Universal Link 唤起）和未安装时的手机浏览器接住。
	QRContent string `json:"qr_content"`
	// ExpiresIn 票据存活秒数。前端拿它画倒计时，不自己数 ——
	// 服务端时钟才是唯一裁判，两边各数一份必然在边界处对不上。
	ExpiresIn int `json:"expires_in"`
	// IntervalMS 建议轮询间隔。由服务端下发而不是前端硬编码：
	// 将来调节奏或换 SSE 时不必等用户刷到新版前端。
	IntervalMS int `json:"interval_ms"`
}

// CreateRes 建票响应（201）
type CreateRes struct {
	Code int        `json:"code"`
	Data CreateData `json:"data"`
}

// ── PC 侧：轮询 ────────────────────────────────────────────────────────────

// PollReq GET /api/qr/sessions/{ticket} —— 查状态，**无副作用**
//
// 轮询与领取刻意分成两个端点：手机侧也要查状态，如果查询自带
// "命中 confirmed 就下发会话"的副作用，手机打开确认页时那一次查询
// 就会把会话建立掉，而 Set-Cookie 落在手机上 —— PC 永远领不到。
type PollReq struct {
	g.Meta `path:"/api/qr/sessions/{ticket}" method:"get" tags:"QR" summary:"轮询扫码状态"`
	Ticket string `json:"ticket" in:"path" v:"required"`
}

// PollData 轮询结果。字段极少是刻意的：见 logic/qr.Peek 的防探测说明。
type PollData struct {
	Status    string `json:"status"`
	ExpiresIn int    `json:"expires_in"`
}

// PollRes 轮询响应
type PollRes struct {
	Code int      `json:"code"`
	Data PollData `json:"data"`
}

// ── PC 侧：领取 ────────────────────────────────────────────────────────────

// ClaimReq POST /api/qr/sessions/{ticket}/claim —— 领取登录态
//
// 这是全平台唯一会下发 idp_session 的扫码端点。凭据是 qr_ctx Cookie，
// 不出现在请求体里，因此这个结构体除了路径参数什么都没有。
type ClaimReq struct {
	g.Meta `path:"/api/qr/sessions/{ticket}/claim" method:"post" tags:"QR" summary:"领取扫码登录会话"`
	Ticket string `json:"ticket" in:"path" v:"required"`
}

// ClaimData 领取成功后的账号信息。
//
// 与 LoginData 同形（账号 + 昵称），前端登录成功后的处理逻辑因此可以整段复用。
// **不含 return_to**：服务端从不记录这次登录后要去授权哪个应用（设计文档 §5），
// 回跳地址由 PC 存在自己内存里。
type ClaimData struct {
	Username string `json:"username"`
	Nickname string `json:"nickname"`
}

// ClaimRes 领取响应
type ClaimRes struct {
	Code int       `json:"code"`
	Data ClaimData `json:"data"`
}

// ── PC 侧：作废换码 ────────────────────────────────────────────────────────

// CancelReq POST /api/qr/sessions/{ticket}/cancel —— 作废自己那张码
type CancelReq struct {
	g.Meta `path:"/api/qr/sessions/{ticket}/cancel" method:"post" tags:"QR" summary:"作废并更换二维码"`
	Ticket string `json:"ticket" in:"path" v:"required"`
}

// CancelRes 作废响应
type CancelRes struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

// ── 手机侧：预览 ────────────────────────────────────────────────────────────

// PreviewReq GET /api/qr/sessions/{ticket}/preview —— 确认页取数（需身份）
type PreviewReq struct {
	g.Meta `path:"/api/qr/sessions/{ticket}/preview" method:"get" tags:"QR" summary:"手机侧查看待确认的登录请求"`
	Ticket string `json:"ticket" in:"path" v:"required"`
}

// PCInfo 待被登录那台机器的画像。
//
// 这个结构体是整个扫码功能的安全着力点：用户是否点下"确认"，
// 取决于他能不能从这几项里认出那是自己的机器。所以 UA 必须是服务端
// 解析过的摘要（"Chrome · Windows"）而不是原始串，IP 与来源分类也要给。
type PCInfo struct {
	UA        string `json:"ua"`
	IP        string `json:"ip"`
	Geo       string `json:"geo"`
	CreatedAt string `json:"created_at"`
}

// PreviewData 预览结果
type PreviewData struct {
	Status string `json:"status"`
	PC     PCInfo `json:"pc"`
}

// PreviewRes 预览响应
type PreviewRes struct {
	Code int         `json:"code"`
	Data PreviewData `json:"data"`
}

// ── 手机侧：扫码 / 确认 / 拒绝 ─────────────────────────────────────────────

// ScanReq POST /api/qr/sessions/{ticket}/scan —— 标记已扫码（需身份）
//
// 单独一步是为了让 PC 能显示"已扫码，请在手机上确认"。
// 没有这一步，用户在手机上慢慢看设备信息时，PC 那边只有一张静止的二维码，
// 他无法区分"还没扫上"和"扫上了但卡住了"。
type ScanReq struct {
	g.Meta `path:"/api/qr/sessions/{ticket}/scan" method:"post" tags:"QR" summary:"标记已扫码"`
	Ticket string `json:"ticket" in:"path" v:"required"`
}

// StatusData 只回当前状态，供手机端刷新界面
type StatusData struct {
	Status string `json:"status"`
}

// ScanRes 扫码响应
type ScanRes struct {
	Code int        `json:"code"`
	Data StatusData `json:"data"`
}

// ConfirmReq POST /api/qr/sessions/{ticket}/confirm —— 批准登录（需身份）
//
// **无请求体**：批准者是谁，只认服务端解析出的身份（Cookie 会话或 Bearer
// access_token），绝不接受"我在 body 里声明我替谁批"。
type ConfirmReq struct {
	g.Meta `path:"/api/qr/sessions/{ticket}/confirm" method:"post" tags:"QR" summary:"批准这次扫码登录"`
	Ticket string `json:"ticket" in:"path" v:"required"`
}

// ConfirmRes 批准响应
type ConfirmRes struct {
	Code int        `json:"code"`
	Data StatusData `json:"data"`
}

// RefuseReq POST /api/qr/sessions/{ticket}/refuse —— 不是我操作的要登录
type RefuseReq struct {
	g.Meta `path:"/api/qr/sessions/{ticket}/refuse" method:"post" tags:"QR" summary:"拒绝这次扫码登录"`
	Ticket string `json:"ticket" in:"path" v:"required"`
}

// RefuseRes 拒绝响应
type RefuseRes struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}
