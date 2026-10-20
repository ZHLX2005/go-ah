// Package qr 是扫码登录的 HTTP 层。
//
// 它只做三件事：把请求里的身份信息解析出来、调用 logic/qr 走状态机、
// 把结果写成响应。**任何"能不能放行"的判断都不在这一层** ——
// 状态迁移的判定全在 logic/qr 的条件 UPDATE 里，这里若自己判断一次
// （"先读出来看看是不是 confirmed 再决定要不要发 Cookie"），
// 就把整个设计的并发正确性拆掉了。
//
// 两类调用方共用这一个控制器，鉴权口径完全不同，务必看清：
//
//	PC 侧（Create / Poll / Claim / Cancel）—— 匿名可调。
//	    它们的授权来自 qr_ctx Cookie：谁创建票据，谁才配领取。
//	    不挂 RequireAdmin 是显然的（登录中的人还不是任何人）；
//	    但"匿名"不等于"无主"，领取那一步的 qr_ctx 校验就是它的身份。
//
//	手机侧（Preview / Scan / Confirm / Refuse）—— 必须有身份。
//	    身份可以是手机浏览器的 idp_session Cookie（H5 兜底路径），
//	    也可以是原生 App 的 Bearer access_token。两者都认，见 resolveIdentity。
//	    同样不挂 RequireAdmin：扫码确认是**普通账号**在做的事，
//	    挂上等于把功能只对管理员开放。理由与 /api/register 不进管理分组同构
//	    （见 router.go 里那段注释），差别只在注册是"还没有身份"，
//	    这里是"有身份但不是管理员"。
package qr

import (
	"context"
	"errors"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/gogf/gf/v2/frame/g"
	"github.com/gogf/gf/v2/net/ghttp"

	v1 "github.com/ZHLX2005/go-ah/auth-hub/api/qr/v1"
	"github.com/ZHLX2005/go-ah/auth-hub/internal/config"
	"github.com/ZHLX2005/go-ah/auth-hub/internal/consts"
	"github.com/ZHLX2005/go-ah/auth-hub/internal/controller/response"
	"github.com/ZHLX2005/go-ah/auth-hub/internal/limiter"
	"github.com/ZHLX2005/go-ah/auth-hub/internal/logic/oidc"
	"github.com/ZHLX2005/go-ah/auth-hub/internal/logic/qr"
	"github.com/ZHLX2005/go-ah/auth-hub/internal/logic/session"
	"github.com/ZHLX2005/go-ah/auth-hub/internal/logic/user"
	"github.com/ZHLX2005/go-ah/auth-hub/internal/model/entity"
	"github.com/ZHLX2005/go-ah/auth-hub/internal/utility"
)

// Controller 扫码登录控制器
type Controller struct{}

// New 构造控制器
func New() *Controller { return &Controller{} }

// ── 限流 ──────────────────────────────────────────────────────────────────
//
// 为什么在控制器里逐个端点判，而不走 router 的分组中间件：
// router.go 的既有习惯是"中间件挂在分组上，新增端点自动受保护"，
// 但这里恰好不能这么做 —— /api/qr/* 八条端点的合理频率差着量级：
// 轮询端点正常用法就是每 1.5 秒一次（约 40 次/分钟），
// 而建票一分钟超过 3 次已经是在刷。挂同一个桶要么放过刷票，
// 要么把正常轮询打成 429。所以只能按端点分别设，代价是
// "新增端点忘了设限流"没人兜底，靠下面这段注释和 §11.5 提醒后来的人。
//
// 为什么没有再加一个"全进程总量"桶：听起来能防分布式灌表，实际上
// 是把资源问题换成可用性问题 —— 一个攻击者就能把全局额度打满，
// 让所有正常用户都登录不了。单 IP 桶挡住的正是"一个人无成本刷"这件事，
// 而分布式来源不是进程内限流该负责的范围（那需要网关层）。
var (
	// qrCreateLimit 建票：按来源 IP。
	//
	// 10 次/分钟、突发 20。定这个数的依据是"一张票活 120 秒"：
	// 一分钟内建到第 11 张，意味着前面 10 张一张都没被扫 —— 那已经不是
	// 人在登录。给 20 的突发是为了容纳"刷新几次 + 旁边同事也在这台出口建码"。
	qrCreateLimit = limiter.New(limiter.Spec{Capacity: 20, PerMinute: 10})

	// qrConfirmLimit 批准登录：按批准者账号。
	//
	// 30 次/分钟、突发 60。这是全平台后果最重的一次写操作（一次批准 =
	// 给别人一台机器发会话），所以哪怕它已经天然被"必须先建票"约束住，
	// 仍然单独设一道：账号被脚本驱动时，这一道是最后的刹车。
	qrConfirmLimit = limiter.New(limiter.Spec{Capacity: 60, PerMinute: 30})

	// qrDecodeLimit 二维码图片解码：按来源 IP。
	//
	// 这是全平台唯一一条"**匿名 + CPU 密集**"的端点（图片解码要跑识别算法），
	// 所以必须限流。它不回显任何服务端状态，只回显调用者自己传上来的图里的
	// 内容 —— 没有可探测的信息，但可以被当成免费的公共解码服务白嫖。
	// 10 次/分钟、突发 20：一次扫码批准只需要 1 次。
	qrDecodeLimit = limiter.New(limiter.Spec{Capacity: 20, PerMinute: 10})
)

// errCodeRateLimited 是对外契约里的原因码，前端与 CLI 按它分支。
const errCodeRateLimited = "rate_limited"

// tooManyRequests 写 429 并带 Retry-After。
//
// 429 而不是 400：客户端需要知道"稍后再试可能成功"与"你请求本身不对"
// 的区别，否则它只会把同一个错误重试到永远，或者反过来——看到 4xx
// 就彻底放弃，而这里其实只是慢了一秒。
func tooManyRequests(r *ghttp.Request, retryAfter int, msg string) {
	r.Response.Header().Set("Retry-After", strconv.Itoa(retryAfter))
	response.BizError(r, http.StatusTooManyRequests, errCodeRateLimited, msg)
}

// scanPagePath 手机扫码后打开的路径。
//
// 它与 idp-web 的 /scan 路由必须一致（两边各写一份是这次实现里唯一一处
// 跨语言重复，改路由名时要同时改这里与 main.tsx）。之所以不把路径下发给
// 前端拼：二维码内容必须由**服务端**决定 —— 它是"手机该打开哪里"这个
// 问题的唯一答案，交给客户端拼就等于让任何人都能造出指向别处的二维码。
const scanPagePath = "/scan"

// ── PC 侧 ─────────────────────────────────────────────────────────────────

// Create POST /api/qr/sessions
func (c *Controller) Create(ctx context.Context, req *v1.CreateReq) error {
	r := g.RequestFromCtx(ctx)

	// 设备画像全部取自请求侧，不接受 body 自报（见 utility/useragent.go）。
	rawUA := r.Header.Get("User-Agent")
	ua := utility.SummarizeUserAgent(rawUA)
	ip := r.GetClientIp()
	geo := utility.ClassifyIP(ip)

	// 限流放在建票**之前**：这条端点是全平台唯一"没有任何身份就能写入"的入口，
	// 一次调用就是一行 INSERT。放在之后写出去的行已经落库了，那就不是限流而是记账。
	//
	// 键取 r.GetClientIp()。经 nginx 反代时它来自 X-Real-IP，而 nginx.conf 用
	// $remote_addr 覆写了这个头，所以客户端伪造不了。但**直连后端端口**
	// （容器网络里的 8080）时该头由客户端说了算，限流即可被绕过 ——
	// 部署上 8080 不对外，这是前提而非已验证的保证，改拓扑时要重新确认。
	if !qrCreateLimit.Allow(ip) {
		tooManyRequests(r, qrCreateLimit.RetryAfter(ip),
			"创建二维码过于频繁，请稍后再试")
		return nil
	}

	created, err := qr.Create(ctx, qr.CreateInput{
		PcUA: ua, PcIP: ip, PcGeo: geo,
	})
	if err != nil {
		return err
	}

	// qr_ctx 只在这一刻出现一次：库里只留它的 SHA-256，
	// 所以除了这个响应，任何地方都无法再把它算出来。
	maxAge := int(consts.QRTicketTTL.Seconds())
	response.SetQRCtxCookie(r, created.QRCtx, maxAge)

	iss := strings.TrimRight(config.Get().Issuer, "/")
	response.Write(r, http.StatusCreated, &v1.CreateRes{
		Code: 0,
		Data: v1.CreateData{
			Ticket:     created.Ticket,
			QRContent:  iss + scanPagePath + "?t=" + created.Ticket,
			ExpiresIn:  maxAge,
			IntervalMS: consts.QRPollIntervalMS,
		},
	})
	return nil
}

// Poll GET /api/qr/sessions/{ticket}
//
// 只读、无副作用（领取是 Claim）。见 api/qr/v1 里 PollReq 的说明。
func (c *Controller) Poll(ctx context.Context, req *v1.PollReq) error {
	r := g.RequestFromCtx(ctx)
	response.NoStore(r)

	view, err := qr.Peek(ctx, req.Ticket, callerCtx(r))
	if err != nil {
		writeQRError(r, err)
		return nil
	}
	response.Write(r, http.StatusOK, &v1.PollRes{
		Code: 0,
		Data: v1.PollData{Status: view.Status, ExpiresIn: view.ExpiresIn},
	})
	return nil
}

// Claim POST /api/qr/sessions/{ticket}/claim
//
// 全平台唯一一处"把扫码票据兑换成登录态"的地方。
//
// 顺序是**先领票据、再建会话**，不能反：
// 反过来写的话，两个并发 claim 会各自通过、各自建一条会话，
// 只有其中一条被记进票据行，另一条就成了查不到出处的活会话 ——
// 而它带着一个真实账号的权限。让条件 UPDATE 去排队，多余的请求自然什么都拿不到。
//
// 会话建立失败时票据已经是 consumed：宁可让用户"刷新二维码重来"，
// 也不能把票据倒回 confirmed —— 倒回就等于"验证过一次就可以反复领取"。
func (c *Controller) Claim(ctx context.Context, req *v1.ClaimReq) error {
	r := g.RequestFromCtx(ctx)
	response.NoStore(r)

	userID, err := qr.Claim(ctx, req.Ticket, callerCtx(r))
	if err != nil {
		writeQRError(r, err)
		return nil
	}

	u, err := user.FindByID(ctx, userID)
	if err != nil {
		return err
	}
	if u == nil {
		// 批准后、领取前的这几秒里账号被删了。票据已作废，不会再被领第二次。
		response.BizError(r, http.StatusBadRequest, qr.CodeNotReady, "账号已不存在，请重新登录")
		return nil
	}

	// 与口令登录同一口径：先记最后登录时间，再建会话。
	// 扫码登录如果不在 last_login_at 上留痕，管理端"账号还在不在用"的判断
	// 就会系统性低估所有只用扫码的人。
	if err := user.TouchLastLogin(ctx, u.Id); err != nil {
		return err
	}
	sid, ttl, err := session.Issue(ctx, u.Id)
	if err != nil {
		return err
	}
	response.SetSessionCookie(r, sid, int(ttl.Seconds()))
	g.Log().Infof(ctx, "[auth-hub] 扫码登录成功: user=%s (id=%d) ticket=%s", u.Username, u.Id, req.Ticket)

	response.Write(r, http.StatusOK, &v1.ClaimRes{
		Code: 0,
		Data: v1.ClaimData{Username: u.Username, Nickname: u.Nickname},
	})
	return nil
}

// Cancel POST /api/qr/sessions/{ticket}/cancel
func (c *Controller) Cancel(ctx context.Context, req *v1.CancelReq) error {
	r := g.RequestFromCtx(ctx)
	response.NoStore(r)

	if err := qr.CancelByPC(ctx, req.Ticket, callerCtx(r)); err != nil {
		writeQRError(r, err)
		return nil
	}
	response.Write(r, http.StatusOK, &v1.CancelRes{Code: 0, Message: "二维码已作废"})
	return nil
}

// ── 手机侧 ────────────────────────────────────────────────────────────────

// Preview GET /api/qr/sessions/{ticket}/preview
func (c *Controller) Preview(ctx context.Context, req *v1.PreviewReq) error {
	r := g.RequestFromCtx(ctx)
	response.NoStore(r)

	if _, ok := c.requireIdentity(ctx, r); !ok {
		return nil
	}
	row, err := qr.Preview(ctx, req.Ticket)
	if err != nil {
		writeQRError(r, err)
		return nil
	}
	response.Write(r, http.StatusOK, &v1.PreviewRes{
		Code: 0,
		Data: v1.PreviewData{
			Status: row.EffectiveStatus(time.Now()),
			PC: v1.PCInfo{
				UA: row.PcUA, IP: row.PcIP, Geo: row.PcGeo,
				// RFC3339 而不是本地格式化串：库里读出来的 time.Time 带的是 UTC 偏移，
				// 服务端 Format("2006-01-02 15:04:05") 会把 23:55 印成 15:55 ——
				// 而这一刻正是用户在手机上核对"是不是我刚刚发起的"的依据，
				// 差 8 小时等于让这块最要紧的界面说谎。带上偏移量交给展示层本地化，
				// 也与本服务其余接口的时间字段口径一致。
				CreatedAt: row.CreatedAt.Format(time.RFC3339),
			},
		},
	})
	return nil
}

// Scan POST /api/qr/sessions/{ticket}/scan
func (c *Controller) Scan(ctx context.Context, req *v1.ScanReq) error {
	r := g.RequestFromCtx(ctx)
	response.NoStore(r)

	if _, ok := c.requireIdentity(ctx, r); !ok {
		return nil
	}
	if err := qr.Scan(ctx, req.Ticket, utility.SummarizeUserAgent(r.Header.Get("User-Agent"))); err != nil {
		writeQRError(r, err)
		return nil
	}
	response.Write(r, http.StatusOK, &v1.ScanRes{
		Code: 0, Data: v1.StatusData{Status: entity.QRStatusScanned},
	})
	return nil
}

// Confirm POST /api/qr/sessions/{ticket}/confirm
//
// 批准者身份**只**来自 resolveIdentity 解析出的会话或 Bearer token。
// 请求体里没有任何"我替谁批准"的字段，也不是将来该有：那等于把
// 整个扫码功能的授权面从"手机持有者"转移到"任何会发请求的人"。
func (c *Controller) Confirm(ctx context.Context, req *v1.ConfirmReq) error {
	r := g.RequestFromCtx(ctx)
	response.NoStore(r)

	u, ok := c.requireIdentity(ctx, r)
	if !ok {
		return nil
	}
	// 按批准者限流，且必须放在身份解析**之后** —— 没身份就没有可归因的键，
	// 按 IP 限则会让一个 NAT 后面所有用户互相拖累。
	//
	// 这是全平台后果最重的一次写操作：一次成功批准 = 给别人一台机器发出
	// 一个属于这个账号的会话。它天然已经被"攻击者得先有自己的票"约束住，
	// 但账号一旦被脚本驱动（手机丢了、恶意 App 拿到 access_token），
	// 这一道是最后的刹车。
	if !qrConfirmLimit.Allow(strconv.FormatInt(u.Id, 10)) {
		tooManyRequests(r, qrConfirmLimit.RetryAfter(strconv.FormatInt(u.Id, 10)),
			"批准操作过于频繁，请稍后再试")
		return nil
	}
	if err := qr.Confirm(ctx, req.Ticket, u.Id, utility.SummarizeUserAgent(r.Header.Get("User-Agent"))); err != nil {
		writeQRError(r, err)
		return nil
	}
	g.Log().Infof(ctx, "[auth-hub] 手机侧已批准扫码登录: user=%s ticket=%s", u.Username, req.Ticket)
	response.Write(r, http.StatusOK, &v1.ConfirmRes{
		Code: 0, Data: v1.StatusData{Status: entity.QRStatusConfirmed},
	})
	return nil
}

// Refuse POST /api/qr/sessions/{ticket}/refuse
func (c *Controller) Refuse(ctx context.Context, req *v1.RefuseReq) error {
	r := g.RequestFromCtx(ctx)
	response.NoStore(r)

	if _, ok := c.requireIdentity(ctx, r); !ok {
		return nil
	}
	if err := qr.Refuse(ctx, req.Ticket); err != nil {
		writeQRError(r, err)
		return nil
	}
	response.Write(r, http.StatusOK, &v1.RefuseRes{Code: 0, Message: "已拒绝该登录请求"})
	return nil
}

// ── 二维码图片解码 ────────────────────────────────────────────────────────

// Decode POST /api/qr/decode —— 上传一张二维码照片，服务端解出内容。
//
// 匿名可调（见 api/qr/v1.DecodeReq 的说明）：它不回显任何服务端状态，
// 只回显"调用者自己拍到的图里有什么"。真正的授权在 preview / confirm。
// 但图片解码是 CPU 密集的，所以按来源 IP 限流，且限流放在**读文件之前** ——
// 否则攻击者可以用超大文件把解码开销打满。
func (c *Controller) Decode(ctx context.Context, req *v1.DecodeReq) error {
	r := g.RequestFromCtx(ctx)
	response.NoStore(r)

	ip := r.GetClientIp()
	if !qrDecodeLimit.Allow(ip) {
		tooManyRequests(r, qrDecodeLimit.RetryAfter(ip), "解码过于频繁，请稍后再试")
		return nil
	}

	f := r.GetUploadFile("file")
	if f == nil {
		response.BizError(r, http.StatusBadRequest, "no_file",
			"没有收到图片文件（multipart 字段名固定为 file）")
		return nil
	}
	src, err := f.Open()
	if err != nil {
		response.BizError(r, http.StatusBadRequest, "bad_file", "图片读取失败")
		return nil
	}
	defer src.Close()

	content, err := qr.DecodeImageFrom(src, qr.MaxDecodeImageBytes)
	if err != nil {
		code := "decode_failed"
		if errors.Is(err, qr.ErrImageTooLarge) {
			code = "image_too_large"
		}
		response.BizError(r, http.StatusBadRequest, code, err.Error())
		return nil
	}
	response.Write(r, http.StatusOK, &v1.DecodeRes{
		Code: 0, Data: v1.DecodeData{Content: content},
	})
	return nil
}

// ── 身份解析 ──────────────────────────────────────────────────────────────

// resolveIdentity 解析手机侧身份，支持两种凭证：
//
//	Bearer access_token  → 原生 App（它手里只有 token，没有浏览器 Cookie）
//	idp_session Cookie   → 手机浏览器上的 H5 兜底页
//
// 这是**新写的组合**，不是照抄某个既有端点：userinfo 解析 Bearer 的口径来自
// controller/oidc/oidc.go:353-357，但它没有 Bearer 时回落的是 access_token
// 查询参数（api/oidc/v1/oidc.go:140）而不是 Cookie；Cookie 那条来自
// SessionUser（controller/oidc/oidc.go:460-462）。把两条拼起来才是
// "App 用 token、H5 用 Cookie"都能认。
//
// Bearer 优先：App 一定带着 token，而它的 WebView 里通常没有 idp_session，
// 让 token 先走可以省去一次注定落空的 Cookie 查询。
//
// 返回 (nil, nil) 表示"没有有效身份"，是正常结果而不是错误 —— 与
// session.CurrentUser 的口径一致（那里明确"未登录不是一种失败"）。
func (c *Controller) resolveIdentity(ctx context.Context, r *ghttp.Request) (*entity.User, error) {
	if h := r.Header.Get("Authorization"); strings.HasPrefix(h, "Bearer ") {
		token := strings.TrimSpace(strings.TrimPrefix(h, "Bearer "))
		if token == "" {
			return nil, nil
		}
		res, err := oidc.UserInfo(ctx, token)
		if err != nil {
			// access_token 无效/过期会被 oidc 包成 401 的 ProtocolError，
			// 对扫码确认端点而言这就等于"没登录"，不该冒泡成 500。
			var pe *oidc.ProtocolError
			if errors.As(err, &pe) {
				return nil, nil
			}
			return nil, err
		}
		return res.User, nil
	}
	return session.CurrentUser(ctx, r.Cookie.Get(consts.SessionCookieName).String())
}

// requireIdentity 是"没有身份就当场回 401"的护栏。
//
// 单独抽出来是因为四个手机侧端点都要同一句：各自写一遍的话，
// 漏掉一个就是一个匿名可调的确认接口 —— 而那正是本功能最需要防的东西。
// 返回的布尔值表示"已经写好响应了，控制器该 return nil 了"。
func (c *Controller) requireIdentity(ctx context.Context, r *ghttp.Request) (*entity.User, bool) {
	u, err := c.resolveIdentity(ctx, r)
	if err != nil {
		response.BizError(r, http.StatusInternalServerError, "internal_error", err.Error())
		return nil, false
	}
	if u == nil {
		response.BizError(r, http.StatusUnauthorized, "unauthenticated",
			"需要先登录手机端账号，才能批准这次扫码登录")
		return nil, false
	}
	return u, true
}

// ── 辅助 ──────────────────────────────────────────────────────────────────

// callerCtx 取请求带来的票据上下文（PC 浏览器才有，手机拿不到）
func callerCtx(r *ghttp.Request) string {
	return r.Cookie.Get(consts.QRCtxCookieName).String()
}

// writeQRError 把 logic 层的业务错误映射成响应：Kind 决定状态码，Code 进契约。
//
// 数据库故障之类的非业务错误一律 500 兜底，不伪装成"参数不对" ——
// 口径同 controller/auth 的 writeRegisterError。
func writeQRError(r *ghttp.Request, err error) {
	var qe *qr.Error
	if !errors.As(err, &qe) {
		response.BizError(r, http.StatusInternalServerError, "internal_error", err.Error())
		return
	}
	switch qe.Kind {
	case qr.KindNotFound:
		response.BizError(r, http.StatusNotFound, qe.Code, qe.Msg)
	case qr.KindConflict:
		response.BizError(r, http.StatusConflict, qe.Code, qe.Msg)
	case qr.KindGone:
		response.BizError(r, http.StatusGone, qe.Code, qe.Msg)
	default:
		response.BizError(r, http.StatusBadRequest, qe.Code, qe.Msg)
	}
}
