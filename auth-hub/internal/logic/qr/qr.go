// Package qr 是扫码登录的**票据状态机**，也是这套流程唯一的判定处。
//
// 它管的东西只有一句话：一张二维码现在处于什么状态、谁能把它推到下一个状态。
// 谁批准了登录（手机侧身份）、给谁建立会话（PC 侧 Cookie），都不在这里做 ——
// 那是控制器的事。本包不认识 HTTP。
//
// ── 为什么这个包不用事务 ────────────────────────────────────────────────
//
// 邀请码核销（logic/invite）需要事务，因为它是"扣次数 + 建账号 + 写明细"三件
// 必须同生同灭的事。这里每一步迁移都只有**一条** UPDATE 语句，原子性由数据库
// 单语句天然保证；而"改状态"与"据此建会话"之间不需要原子 —— 恰恰相反，
// 我们必须先确认状态改赢了（affected==1）才去建会话，否则并发下会留下
// 多条只有第一条被记录的僵尸会话。所以这里没有事务是设计，不是漏了。
//
// ── 判定纪律 ────────────────────────────────────────────────────────────
//
// 所有迁移都是 `UPDATE … WHERE <前置状态> AND <未过期>`，然后看 RowsAffected：
// 1 = 我抢到了，0 = 别人抢先了或状态不对。**绝不允许**先 SELECT 出来判断
// 再无条件 UPDATE —— 那样两次并发请求会双双通过判断，把"只放行一次"变成
// "看起来只放行了一次"。
//
// 现有 ConsumeAuthorizationCode（logic/oidc/oidc.go:246-281）正是读后写的形状，
// 它在授权码上问题不大（还有 PKCE 兜底），但票据直接决定谁拿到登录态，
// 不能照抄。这一处的严格程度高于现状，是有意的。
//
// 失败之后确实会再读一次行，但那次读**只用来生成错误信息**，不参与任何放行判定 ——
// 读出来的内容与放行结论没有因果关系，就不构成读后写。
package qr

import (
	"context"
	"database/sql"
	"time"

	"github.com/gogf/gf/v2/frame/g"

	"github.com/ZHLX2005/go-ah/auth-hub/internal/consts"
	"github.com/ZHLX2005/go-ah/auth-hub/internal/dao"
	"github.com/ZHLX2005/go-ah/auth-hub/internal/db"
	"github.com/ZHLX2005/go-ah/auth-hub/internal/model/entity"
	"github.com/ZHLX2005/go-ah/auth-hub/internal/utility"
)

// ── 失败原因 ────────────────────────────────────────────────────────────────

// ErrKind 失败种类，只决定 HTTP 状态码类别，不决定具体原因。
//
// 与 invite 同一套分工：Kind→状态码，Code→前端文案分支。
type ErrKind int

// 失败种类
const (
	// KindInvalid 请求不成立（状态不对、凭据不匹配）→ 400
	KindInvalid ErrKind = iota
	// KindNotFound 票据不存在 → 404
	KindNotFound
	// KindConflict 与既有状态冲突（已被领取/重复批准）→ 409
	KindConflict
	// KindGone 票据已过期作废 → 410
	KindGone
)

// 面向客户端的稳定原因码。前端与 CLI 按它分支，改名等于改接口。
const (
	// CodeInvalid 参数不合法
	CodeInvalid = "invalid_request"
	// CodeNotFound 票据不存在（含已被清理任务删掉）
	CodeNotFound = "qr_not_found"
	// CodeExpired 票据已过期
	CodeExpired = "qr_expired"
	// CodeNotReady 还不能领取：未到 confirmed，**或 qr_ctx 不匹配**
	// （两者故意共用一个码，见 Claim 的说明 —— 不给了探测者区分信号）
	CodeNotReady = "qr_not_ready"
	// CodeUsed 票据已被领取或被批准过（重复动作）
	CodeUsed = "qr_already_used"
	// CodeStateConflict 抢态失败（并发下别人先推进了状态）
	CodeStateConflict = "qr_state_conflict"
)

// Error 带种类与原因码的业务错误。控制器按 Kind 映射状态码、按 Code 输出契约。
type Error struct {
	Kind ErrKind
	Code string
	Msg  string
}

// Error 实现 error 接口
func (e *Error) Error() string { return e.Msg }

func errInvalid(code, msg string) error { return &Error{Kind: KindInvalid, Code: code, Msg: msg} }
func errNotFound() error {
	return &Error{Kind: KindNotFound, Code: CodeNotFound, Msg: "二维码无效或已失效"}
}
func errConflict(code, msg string) error { return &Error{Kind: KindConflict, Code: code, Msg: msg} }
func errGone(msg string) error           { return &Error{Kind: KindGone, Code: CodeExpired, Msg: msg} }

// ── 创建（PC 侧）──────────────────────────────────────────────────────────

// CreateInput 建票输入。
//
// 三个 PC 字段必须由**服务端**从请求里解析后传入（见 utility.SummarizeUserAgent
// 的文件注释）：它们是手机上供用户核对的唯一依据，采信客户端自报等于让用户
// 对着谎言做核对。
type CreateInput struct {
	PcUA  string
	PcIP  string
	PcGeo string
}

// Created 建票结果。QRCtx 是**只在这一刻出现一次**的原文 —— 库里只存它的哈希。
type Created struct {
	Ticket    string
	QRCtx     string
	ExpiresAt time.Time
}

// Create 新建一张待扫码票据。
//
// 不做"撞了就重试"：票据是 256 bit CSPRNG 输出，碰撞概率低到可以当成
// 零事件处理（口径同 logic/invite 对唯一索引的态度 —— 索引是最后的边界，
// 不是拿来触发重试的开关）。真撞上了就如实报 500，那意味着随机源出了问题，
// 而随机源出问题是要停机查的，不该被一次静默重试盖过去。
func Create(ctx context.Context, in CreateInput) (*Created, error) {
	cols := dao.QRLoginSession.Columns()
	now := time.Now()
	expire := now.Add(consts.QRTicketTTL)

	ticket := consts.QRTicketPrefix + utility.RandomToken(consts.QRTicketBytes)
	qrCtx := utility.RandomToken(consts.QRCtxBytes)

	if _, err := dao.QRLoginSession.Ctx(ctx).Data(g.Map{
		cols.Ticket:    ticket,
		cols.CtxHash:   utility.Sha256Hex(qrCtx),
		cols.Status:    entity.QRStatusPending,
		cols.PcUA:      in.PcUA,
		cols.PcIP:      in.PcIP,
		cols.PcGeo:     in.PcGeo,
		cols.ExpiresAt: expire,
		cols.CreatedAt: now,
		cols.UpdatedAt: now,
	}).Insert(); err != nil {
		return nil, err
	}
	return &Created{Ticket: ticket, QRCtx: qrCtx, ExpiresAt: expire}, nil
}

// ── 轮询（PC 侧）───────────────────────────────────────────────────────────

// View 轮询要回给 PC 的内容。
//
// 刻意**不含** PC 设备信息与 user_id：PC 是这些信息的来源，回给它没有意义，
// 而少回一个字段就少一个能被旁观者利用的口子。
type View struct {
	Status    string
	ExpiresIn int // 剩余秒数；已过期为 0
}

// Peek 供 PC 轮询查询状态。
//
// 防探测：qr_ctx 不匹配（含没带）时，**一律返回 pending**，不暴露真实进度。
// ticket 有 256 bit 熵，猜中不可能，所以这层遮蔽不是防"猜"，而是防"看到"：
// 二维码会被拍照、截图、投屏，任何拿到图片的人都能读到 URL 里的 ticket。
// 如果他能看到"某人已经扫过了"，那就是一个真实的信息泄露 ——
// 而这个信息对合法流程毫无用处，不给才是对的。
func Peek(ctx context.Context, ticket, callerCtx string) (*View, error) {
	row, err := findByTicket(ctx, ticket)
	if err != nil {
		return nil, err
	}
	if callerCtx == "" || utility.Sha256Hex(callerCtx) != row.CtxHash {
		return &View{Status: entity.QRStatusPending}, nil
	}
	now := time.Now()
	left := int(row.ExpiresAt.Sub(now).Seconds())
	if left < 0 {
		left = 0
	}
	return &View{Status: row.EffectiveStatus(now), ExpiresIn: left}, nil
}

// ── 预览（手机侧）───────────────────────────────────────────────────────────

// Preview 给手机确认页取"要被登录的那台机器"的信息。
//
// 与 Peek 相反，这里必须返回全部细节：这正是用户用来判断"是不是我本人"的
// 材料。调用方（控制器）已经确认了手机侧身份，所以不需要 qr_ctx ——
// 而且它**拿不到** qr_ctx（那在 PC 浏览器里）。
func Preview(ctx context.Context, ticket string) (*entity.QRLoginSession, error) {
	return findByTicket(ctx, ticket)
}

// ── 迁移 ──────────────────────────────────────────────────────────────────

// Scan 把票据推进到 scanned（pending → scanned）。
//
// 只有第一个扫到它的人能改变状态。第二个人（比如同一张二维码被两台手机扫）
// 会得到 qr_state_conflict —— 不静默成功：PC 端的"已扫码"提示必须对应
// 真实发生过的一次扫码，否则它会显示一个从未发生的中间态。
func Scan(ctx context.Context, ticket, scanUA string) error {
	cols := dao.QRLoginSession.Columns()
	now := time.Now()

	res, err := dao.QRLoginSession.Ctx(ctx).
		Where(cols.Ticket, ticket).
		WhereIn(cols.Status, g.Slice{entity.QRStatusPending}).
		WhereGT(cols.ExpiresAt, now).
		Data(g.Map{
			cols.Status:    entity.QRStatusScanned,
			cols.ScannedAt: now,
			cols.ScanUA:    scanUA,
			cols.UpdatedAt: now,
		}).Update()
	if err != nil {
		return err
	}
	if won, err := affected(res); err != nil {
		return err
	} else if won {
		return nil
	}
	return diagnose(ctx, ticket)
}

// Confirm 手机批准这次登录，把 user_id 与票据绑上。
//
// 这是整个功能里唯一的**授权动作**：pending 与 scanned 都不产生任何权限，
// 只有这一次条件 UPDATE 成功，PC 才有资格拿到某个账号的会话。
//
// 允许 pending → confirmed 是直接跳转的：手机 App 完全可以在打开深链后
// 直接展示确认页而不单独调 scan（设计文档 §9.1 第 4 步）。状态机接受这条捷径，
// 只是 PC 会因此看不到"已扫码"的中间态 —— 那是体验差异，不是安全问题。
func Confirm(ctx context.Context, ticket string, userID int64, ua string) error {
	cols := dao.QRLoginSession.Columns()
	if userID <= 0 {
		return errInvalid(CodeInvalid, "缺少有效的登录身份")
	}
	now := time.Now()

	res, err := dao.QRLoginSession.Ctx(ctx).
		Where(cols.Ticket, ticket).
		WhereIn(cols.Status, g.Slice{entity.QRStatusPending, entity.QRStatusScanned}).
		WhereGT(cols.ExpiresAt, now).
		Data(g.Map{
			cols.Status:      entity.QRStatusConfirmed,
			cols.UserID:      userID,
			cols.ConfirmedAt: now,
			cols.ConfirmUA:   ua,
			cols.UpdatedAt:   now,
		}).Update()
	if err != nil {
		return err
	}
	if won, err := affected(res); err != nil {
		return err
	} else if won {
		g.Log().Infof(ctx, "[auth-hub] 扫码登录已批准: ticket=%s user=%d", ticket, userID)
		return nil
	}
	return diagnose(ctx, ticket)
}

// Claim PC 领取登录态，返回批准者的 user_id。
//
// 这是全平台**唯一**把票据兑换成会话的地方，也是最需要较真的一个判断：
// 必须同时满足"状态是 confirmed"、"qr_ctx 与当初创建时一致"、"还没过期"，
// 三者写在同一条 UPDATE 的 WHERE 里，一次定胜负。
//
// 失败时给不给精确原因，取决于问的人是不是自己人：
//   - ctx 不匹配 / 没带 ctx → 统一 qr_not_ready。对旁观者，
//     "还没人扫"与"扫了但不是你"必须无法区分，否则它就是个状态探针。
//   - ctx 匹配但状态不对 → 给准确的 expired / used / conflict，
//     因为这会儿问的一定是当初创建这张票的浏览器，它有权知道自己东西的下场。
func Claim(ctx context.Context, ticket, callerCtx string) (int64, error) {
	cols := dao.QRLoginSession.Columns()
	now := time.Now()

	ctxMatched := callerCtx != ""
	ctxHash := ""
	if ctxMatched {
		ctxHash = utility.Sha256Hex(callerCtx)
	}

	q := dao.QRLoginSession.Ctx(ctx).
		Where(cols.Ticket, ticket).
		WhereIn(cols.Status, g.Slice{entity.QRStatusConfirmed}).
		WhereGT(cols.ExpiresAt, now)
	if ctxMatched {
		q = q.Where(cols.CtxHash, ctxHash)
	} else {
		// 没带 qr_ctx 时绝不能省略这个条件（那等于任何人可领），
		// 也不能直接返回失败就走 —— 统一进下面的失败分支，
		// 让"没带"与"带了但不匹配"得到完全相同的响应。
		q = q.Where(cols.CtxHash, "")
	}

	res, err := q.Data(g.Map{
		cols.Status:     entity.QRStatusConsumed,
		cols.ConsumedAt: now,
		cols.UpdatedAt:  now,
	}).Update()
	if err != nil {
		return 0, err
	}
	won, err := affected(res)
	if err != nil {
		return 0, err
	}
	if won {
		// 赢了才去读 user_id。这一次读**不是**判定：放行结论已经由
		// affected==1 唯一确定，读只是把刚被我锁定的那一行的批准者取回来。
		// 反过来说，如果这行此刻竟然不见了（清理任务并发删掉了它），
		// 宁可报错也不建会话 —— 一个无法归因的登录态比一次失败危险得多。
		var row entity.QRLoginSession
		found, err := db.ScanOne(ctx, dao.QRLoginSession.Ctx(ctx).
			Where(cols.Ticket, ticket).
			Where(cols.Status, entity.QRStatusConsumed), &row)
		if err != nil {
			return 0, err
		}
		if !found || row.UserID <= 0 {
			return 0, errInvalid(CodeNotReady, "二维码已失效，请刷新后重试")
		}
		return row.UserID, nil
	}

	if !ctxMatched {
		return 0, errInvalid(CodeNotReady, "还不能领取登录态")
	}
	return 0, diagnose(ctx, ticket)
}

// CancelByPC 作废**自己**创建的票据（换一张新二维码之前调用）。
//
// 与 Refuse 分成两个函数而不是共用一个"requireCtx bool"参数：
// 布尔参数在调用点读起来是 `Cancel(ctx, t, true)` —— 三个月后没人知道
// 那个 true 是"要校验"还是"不校验"。授权条件长什么样，就该在函数名上说得清。
func CancelByPC(ctx context.Context, ticket, callerCtx string) error {
	if callerCtx == "" {
		return errInvalid(CodeNotReady, "缺少票据上下文")
	}
	cols := dao.QRLoginSession.Columns()
	now := time.Now()

	res, err := dao.QRLoginSession.Ctx(ctx).
		Where(cols.Ticket, ticket).
		Where(cols.CtxHash, utility.Sha256Hex(callerCtx)).
		WhereIn(cols.Status, g.Slice{entity.QRStatusPending, entity.QRStatusScanned}).
		Data(g.Map{cols.Status: entity.QRStatusCancelled, cols.UpdatedAt: now}).
		Update()
	if err != nil {
		return err
	}
	if won, err := affected(res); err != nil {
		return err
	} else if won {
		return nil
	}
	// 这里不区分"不是你的票"与"票已confirmed所以不能撤"：
	// 前者是攻击探测，后者是罕见竞态，两者都只需让 PC 重新生成一张。
	return errInvalid(CodeNotReady, "二维码已不可撤销，请刷新")
}

// Refuse 手机侧拒绝这次扫码（"不是我操作的要登录"）。
//
// 授权来自手机侧身份（控制器已校验），因此不需要 qr_ctx —— 它也确实拿不到。
// 终态票据（consumed/cancelled）不可拒绝：会话都已经发出去了，
// 此时把它标成 cancelled 只会让审计记录自相矛盾。
func Refuse(ctx context.Context, ticket string) error {
	cols := dao.QRLoginSession.Columns()
	now := time.Now()

	res, err := dao.QRLoginSession.Ctx(ctx).
		Where(cols.Ticket, ticket).
		WhereIn(cols.Status, g.Slice{entity.QRStatusPending, entity.QRStatusScanned}).
		WhereGT(cols.ExpiresAt, now).
		Data(g.Map{cols.Status: entity.QRStatusCancelled, cols.UpdatedAt: now}).
		Update()
	if err != nil {
		return err
	}
	if won, err := affected(res); err != nil {
		return err
	} else if won {
		g.Log().Warningf(ctx, "[auth-hub] 扫码登录被手机侧拒绝: ticket=%s", ticket)
		return nil
	}
	return diagnose(ctx, ticket)
}

// ── 清理 ──────────────────────────────────────────────────────────────────

// Purge 删掉过期足够久的票据，返回删除行数。
//
// 为什么这张表必须有清理而其他表可以没有：它是**匿名可写**的
// （创建票据不需要任何身份），一次登录尝试就落一行，而且绝大多数行是失败的
// （用户没扫、扫了没批、换了张码）。给它配清理是必须的，不是可选的优化。
//
// 保留 QRRetainAfterExpiry 而不是随过随删：票据表是扫码登录唯一的审计轨迹
// ——「谁在什么时候批准了哪台机器的登录」只有这里记着。
func Purge(ctx context.Context) (int64, error) {
	cols := dao.QRLoginSession.Columns()
	cutoff := time.Now().Add(-consts.QRRetainAfterExpiry)

	res, err := dao.QRLoginSession.Ctx(ctx).
		WhereLT(cols.ExpiresAt, cutoff).
		Delete()
	if err != nil {
		return 0, err
	}
	return res.RowsAffected()
}

// ── 内部helper ────────────────────────────────────────────────────────────

func findByTicket(ctx context.Context, ticket string) (*entity.QRLoginSession, error) {
	if ticket == "" {
		return nil, errInvalid(CodeInvalid, "缺少票据")
	}
	var row entity.QRLoginSession
	found, err := db.ScanOne(ctx, dao.QRLoginSession.Ctx(ctx).
		Where(dao.QRLoginSession.Columns().Ticket, ticket), &row)
	if err != nil {
		return nil, err
	}
	if !found {
		return nil, errNotFound()
	}
	return &row, nil
}

// affected 把"这条条件 UPDATE 抢到了吗"收敛成一个判断。
//
// 单独包一层不是为了省事，是为了让"抢态"这个动作在六个迁移函数里长得一模一样：
// 任何一处自己写 RowsAffected 的比较，就多一个可以写成 ==0 而静默反向的机会。
func affected(res sql.Result) (bool, error) {
	n, err := res.RowsAffected()
	if err != nil {
		return false, err
	}
	return n > 0, nil
}

// diagnose 在迁移失败后读一次行，把"为什么没成"翻译成人能行动的错码。
//
// 强调一次：这个函数**不参与放行判定**。判定已经由条件 UPDATE 的 affected
// 行数唯一决定了，这里只是给失败找一个准确的说法。把它误用成判定依据，
// 就退回到了"先读再写"的并发漏洞上。
func diagnose(ctx context.Context, ticket string) error {
	row, err := findByTicket(ctx, ticket)
	if err != nil {
		return err // 含 errNotFound：票没了就是 qr_not_found
	}
	switch row.EffectiveStatus(time.Now()) {
	case entity.QRStatusExpired:
		return errGone("二维码已过期，请在电脑上刷新")
	case entity.QRStatusConfirmed:
		return errConflict(CodeUsed, "这张二维码已经被批准过了")
	case entity.QRStatusConsumed:
		return errConflict(CodeUsed, "这张二维码已经登录完成，请刷新")
	case entity.QRStatusCancelled:
		return errConflict(CodeStateConflict, "这张二维码已被取消")
	default:
		// pending / scanned 却迁移失败：只可能是并发请求在同一刻抢先推进了它
		return errConflict(CodeStateConflict, "这张二维码正在被处理，请稍后重试")
	}
}
