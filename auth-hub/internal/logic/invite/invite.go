// Package invite 负责注册邀请码：生成、管理、核销。
//
// 邀请码是自助注册的**唯一门槛**（见 /api/register）：没有一张"此刻仍能核销"
// 的码，就无法建档。所以这里有三个必须"不满足即拒绝"的判断点 —— 存在且启用、
// 未过期、次数没用完。任何一处静默放过，都等于把注册入口敞开；而"次数没用完"
// 还必须扛得住并发，实现方式见 Redeem。
//
// 与 middleware 的分工：本包只回答"这张码现在能不能用、把它用掉"；
// "谁能管理邀请码"是权限问题，由路由分组上的 RequireAdmin 回答 ——
// 权限判断散落到业务包里，漏掉一处就是一条匿名可用的管理接口。
package invite

import (
	"context"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/gogf/gf/v2/database/gdb"
	"github.com/gogf/gf/v2/frame/g"

	"github.com/ZHLX2005/go-ah/auth-hub/internal/consts"
	"github.com/ZHLX2005/go-ah/auth-hub/internal/dao"
	"github.com/ZHLX2005/go-ah/auth-hub/internal/db"
	"github.com/ZHLX2005/go-ah/auth-hub/internal/logic/user"
	"github.com/ZHLX2005/go-ah/auth-hub/internal/model/entity"
	"github.com/ZHLX2005/go-ah/auth-hub/internal/utility"
)

// maxNoteLen 备注长度上限，与 invitation_codes.note 的 VARCHAR(255) 对齐。
// 在代码里也拦一道：让超长备注在**接口返回 400**时被用户看到，
// 而不是让数据库抛出 "value too long for type character varying(255)"。
const maxNoteLen = 255

// mintAttempts 生成邀请码时最多重试几次（撞车概率约 2^-96，几次足够）
const mintAttempts = 5

// ── 失败原因 ────────────────────────────────────────────────────────────────

// ErrKind 失败种类 —— 只区分**状态码类别**，不区分具体原因。
//
// 具体原因走 Error.Code（invite_expired / invite_exhausted …）：Kind 决定
// HTTP 状态码，Code 决定界面上给用户看什么。两者混在一起的话，每加一种新的
// 失败原因都要重新掂量一遍"它该算 400 还是 409"，而这个问题的答案通常
// 只是 400 —— 把两个正交的维度塞进一个枚举，是这个枚举膨胀的唯一原因。
type ErrKind int

// 失败种类（与 HTTP 状态码一一对应的那几个）
const (
	// KindInvalid 请求本身不成立（含"码不可用"）→ 400
	KindInvalid ErrKind = iota
	// KindNotFound 目标不存在 → 404
	KindNotFound
	// KindConflict 与既有数据冲突（账号已被占用）→ 409
	KindConflict
)

// 面向客户端的稳定原因码。前端按它分支给文案，所以这些字符串是**契约**，
// 改名等于改接口。
const (
	// CodeInvalid 参数不合法
	CodeInvalid = "invalid_request"
	// CodeNotFound 邀请码不存在
	CodeNotFound = "invite_not_found"
	// CodeDisabled 邀请码已被停用
	CodeDisabled = "invite_disabled"
	// CodeExpired 邀请码已过期
	CodeExpired = "invite_expired"
	// CodeExhausted 邀请码可用次数已用完
	CodeExhausted = "invite_exhausted"
	// CodeUsernameTaken 账号已被占用
	CodeUsernameTaken = "username_taken"
)

// Error 带种类与原因码的业务错误。
//
// Code 与 Msg 都要：只给文本，前端只能靠字符串匹配做分支，改一句话就换了
// 语义；只给码，用户看到的是 invite_exhausted 这种看不懂的东西。
type Error struct {
	Kind ErrKind
	Code string
	Msg  string
}

// Error 实现 error 接口
func (e *Error) Error() string { return e.Msg }

func errInvalid(code, msg string) error { return &Error{Kind: KindInvalid, Code: code, Msg: msg} }

func errNotFound(msg string) error { return &Error{Kind: KindNotFound, Code: CodeNotFound, Msg: msg} }

func errConflict(code, msg string) error { return &Error{Kind: KindConflict, Code: code, Msg: msg} }

// ── 生成 ────────────────────────────────────────────────────────────────────

// GenerateInput 生成入参
type GenerateInput struct {
	// MaxUses 可核销次数；<= 0 时取默认值（1 次，即"一人一码"）
	MaxUses int
	// ExpiresAt 过期时间；nil 表示长期有效
	ExpiresAt *time.Time
	// Note 备注（发给谁、用来做什么）—— 邀请码列表里唯一能区分两张码的信息
	Note string
	// CreatedBy 创建者（管理员用户 ID），只用于追责，不参与任何判断
	CreatedBy int64
}

// Generate 生成一张邀请码并落库。
//
// 码本身用 CSPRNG（utility.RandomToken），不用自增、时间戳或账号派生：
// **可猜的邀请码等于没有邀请码** —— 猜中一张就白得一个账号，而且在审计里
// 只会看到一个陌生用户名，查不出他是从哪个入口进来的。
func Generate(ctx context.Context, in GenerateInput) (*entity.InvitationCode, error) {
	now := time.Now()

	// 生成时允许省略次数（展开成默认值）：新建表单留空是常态，
	// 而默认值 1 就是最常见的"一人一码"。更新时不这么做，见 Update。
	maxUses := in.MaxUses
	if maxUses <= 0 {
		maxUses = consts.DefaultInvitationMaxUses
	}
	if err := validateMaxUses(maxUses); err != nil {
		return nil, err
	}
	note, err := normalizeNote(in.Note)
	if err != nil {
		return nil, err
	}
	if in.ExpiresAt != nil {
		if err := validateExpiry(*in.ExpiresAt, now); err != nil {
			return nil, err
		}
	}

	cols := dao.InvitationCode.Columns()
	for attempt := 0; attempt < mintAttempts; attempt++ {
		code := consts.InvitationCodePrefix + utility.RandomToken(consts.InvitationCodeBytes)

		// 先查重再插入：96 bit 随机码撞车的概率可以忽略，但"可以忽略"不等于
		// "不会发生"，而撞车的后果是唯一索引报错 —— 管理员看到的是一个没头
		// 没尾的 500，且不知道重试就能成功。多花一次走索引的查询换掉这个
		// 失败模式，很划算。
		exists, err := FindByCode(ctx, code)
		if err != nil {
			return nil, err
		}
		if exists != nil {
			continue
		}

		data := g.Map{
			cols.Code:      code,
			cols.MaxUses:   maxUses,
			cols.UsedCount: 0,
			cols.Enabled:   true,
			cols.CreatedBy: in.CreatedBy,
			cols.Note:      note,
			cols.CreatedAt: now,
			cols.UpdatedAt: now,
		}
		if in.ExpiresAt != nil {
			data[cols.ExpiresAt] = *in.ExpiresAt
		}
		id, err := dao.InvitationCode.Ctx(ctx).Data(data).InsertAndGetId()
		if err != nil {
			return nil, err
		}
		return &entity.InvitationCode{
			Id:        id,
			Code:      code,
			MaxUses:   maxUses,
			UsedCount: 0,
			ExpiresAt: in.ExpiresAt,
			Enabled:   true,
			CreatedBy: in.CreatedBy,
			Note:      note,
			CreatedAt: now,
			UpdatedAt: now,
		}, nil
	}
	return nil, errInvalid(CodeInvalid, "生成邀请码失败，请重试")
}

// ── 取值校验 ────────────────────────────────────────────────────────────────
//
// 生成与修改共用同一组校验函数，而不是各写一份：**改配置是唯一能把一张
// 合法邀请码变成危险邀请码的操作**（把次数调到上限、把有效期推到十年后）。
// 如果只有"生成"那条路径校验，"新建时拒绝、编辑时放过"就成了一个只在对
// 邀请码做维护时才出现的漏洞。

// validateMaxUses 校验可用次数
func validateMaxUses(n int) error {
	if n <= 0 {
		return errInvalid(CodeInvalid, "可用次数必须大于 0")
	}
	if n > consts.MaxInvitationUses {
		return errInvalid(CodeInvalid,
			"可用次数不能超过 "+strconv.Itoa(consts.MaxInvitationUses)+" 次")
	}
	return nil
}

// validateExpiry 校验过期时间
func validateExpiry(expiresAt, now time.Time) error {
	// "过期时间已经过去"必须是明确拒绝：新建出来的码立刻处于过期状态，
	// 会让管理员以为整个功能坏了，而实际原因只是时间填错了。
	if !expiresAt.After(now) {
		return errInvalid(CodeInvalid, "过期时间必须晚于当前时间")
	}
	if expiresAt.After(now.AddDate(0, 0, consts.MaxInvitationValidDays)) {
		return errInvalid(CodeInvalid,
			"有效期最长 "+strconv.Itoa(consts.MaxInvitationValidDays)+" 天")
	}
	return nil
}

// normalizeNote 去掉首尾空白并校验长度。
//
// 长度在代码里也拦一道：让超长备注变成一次**接口 400**，而不是数据库抛出的
// "value too long for type character varying(255)" —— 后者会以 500 的形式
// 到达前端，用户看到的是"服务器错误"，而问题其实只是备注写长了。
func normalizeNote(note string) (string, error) {
	note = strings.TrimSpace(note)
	if utf8.RuneCountInString(note) > maxNoteLen {
		return "", errInvalid(CodeInvalid, "备注不能超过 "+strconv.Itoa(maxNoteLen)+" 个字符")
	}
	return note, nil
}

// ── 查询 ────────────────────────────────────────────────────────────────────

// List 邀请码列表（新建的排在前面：刚生成的那张就是要发给人的那张）
func List(ctx context.Context) ([]entity.InvitationCode, error) {
	var out []entity.InvitationCode
	if err := dao.InvitationCode.Ctx(ctx).Order("id desc").Scan(&out); err != nil {
		return nil, err
	}
	return out, nil
}

// ListByStatus 按状态过滤的列表；status 为空或 "all" 时返回全部。
//
// 过滤在 Go 侧做，不写成 SQL：状态是 enabled / expires_at / used_count 三者
// 算出来的派生值，用 SQL 表达就得把 entity.Status 的判断用 WHERE 再写一遍。
// 两份规则迟早不一致，而症状是"按可用过滤出来的那一行，点开却说不可用"。
func ListByStatus(ctx context.Context, status string) ([]entity.InvitationCode, error) {
	all, err := List(ctx)
	if err != nil {
		return nil, err
	}
	status = strings.TrimSpace(status)
	if status == "" || status == "all" {
		return all, nil
	}
	switch status {
	case entity.InvitationStatusActive, entity.InvitationStatusDisabled,
		entity.InvitationStatusExpired, entity.InvitationStatusExhausted:
	default:
		return nil, errInvalid(CodeInvalid, "未知的状态过滤值: "+status)
	}
	now := time.Now()
	out := make([]entity.InvitationCode, 0, len(all))
	for _, row := range all {
		if row.Status(now) == status {
			out = append(out, row)
		}
	}
	return out, nil
}

// FindByID 按主键查邀请码；不存在返回 (nil, nil)
func FindByID(ctx context.Context, id int64) (*entity.InvitationCode, error) {
	var c entity.InvitationCode
	found, err := db.ScanOne(ctx, dao.InvitationCode.Ctx(ctx).Where(dao.InvitationCode.Columns().Id, id), &c)
	if err != nil {
		return nil, err
	}
	if !found {
		return nil, nil
	}
	return &c, nil
}

// FindByCode 按码查邀请码；不存在返回 (nil, nil)
func FindByCode(ctx context.Context, code string) (*entity.InvitationCode, error) {
	var c entity.InvitationCode
	found, err := db.ScanOne(ctx, dao.InvitationCode.Ctx(ctx).Where(dao.InvitationCode.Columns().Code, code), &c)
	if err != nil {
		return nil, err
	}
	if !found {
		return nil, nil
	}
	return &c, nil
}

// Usages 某张邀请码的使用明细（最近的在前）
func Usages(ctx context.Context, codeID int64) ([]entity.InvitationCodeUsage, error) {
	var out []entity.InvitationCodeUsage
	if err := dao.InvitationCodeUsage.Ctx(ctx).
		Where(dao.InvitationCodeUsage.Columns().CodeID, codeID).
		Order("id desc").
		Scan(&out); err != nil {
		return nil, err
	}
	return out, nil
}

// ── 修改与删除 ──────────────────────────────────────────────────────────────

// UpdateInput 修改入参：**nil 表示"该项不改"**。
//
// 为什么用"不改"语义而不是全量替换：可写字段里有 max_uses，全量语义下
// 客户端漏传它就会被写成 0，而 0 又要被解释成"默认为 1"—— 于是一次只想
// 改备注的请求会把配额悄悄重置回 1 次。部分更新下"没传"与"传了 0"是
// 两件事，前者不动、后者被 validateMaxUses 明确拒绝。
type UpdateInput struct {
	// MaxUses 可用次数；nil 表示不改
	MaxUses *int
	// ExpiresAt 新的过期时间；nil 表示不改（若要"改成长期有效"用 ClearExpires）
	ExpiresAt *time.Time
	// ClearExpires 为 true 时把过期时间清空（长期有效）。
	//
	// 为什么需要它：在部分更新语义下，"改成空"和"不改"是两件不同的事，
	// 而 *time.Time 的 nil 只能表达其中一件。用"指针的指针"能少一个字段，
	// 代价是没人愿意读那个类型 —— 多一个布尔更贵吗？不。
	ClearExpires bool
	// Enabled 是否启用；nil 表示不改
	Enabled *bool
	// Note 备注；nil 表示不改（传空串 = 清空备注）
	Note *string
}

// Update 修改邀请码配置。
//
// 用"发现不存在就报 404"而不是直接 UPDATE：受影响行数为 0 无法区分
// "记录不存在"与"字段值没变化"（PG 会认为后者也是 1 行，但 MySQL 不会），
// 靠驱动行为推语义是脆的。先查一次，语义确定。
func Update(ctx context.Context, id int64, in UpdateInput) (*entity.InvitationCode, error) {
	cur, err := FindByID(ctx, id)
	if err != nil {
		return nil, err
	}
	if cur == nil {
		return nil, errNotFound("邀请码不存在")
	}

	now := time.Now()
	cols := dao.InvitationCode.Columns()
	// updated_at 每次都写：它表示"这条配置最后一次被改是什么时候"，
	// 而任何一次成功的 Update 都满足这个描述。
	data := g.Map{cols.UpdatedAt: now}

	if in.MaxUses != nil {
		if err := validateMaxUses(*in.MaxUses); err != nil {
			return nil, err
		}
		// 次数不能改到"已用数量"以下：那会让这张码立刻变成"已用完"，
		// 而管理员的本意几乎不可能是那个（要作废有停用）。直接拒绝、
		// 并把已用次数报出来，比让他事后在列表里发现"怎么突然用完了"要好。
		if *in.MaxUses < cur.UsedCount {
			return nil, errInvalid(CodeInvalid,
				"可用次数不能小于已用次数（已用 "+strconv.Itoa(cur.UsedCount)+" 次）；如需作废请停用该邀请码")
		}
		data[cols.MaxUses] = *in.MaxUses
	}

	switch {
	case in.ClearExpires:
		// 置 NULL = 长期有效。nil 值会原样传到写入阶段并落成 NULL
		// （见 internal/db 的 TestDataConversionSemantics）。
		data[cols.ExpiresAt] = nil
	case in.ExpiresAt != nil:
		if err := validateExpiry(*in.ExpiresAt, now); err != nil {
			return nil, err
		}
		data[cols.ExpiresAt] = *in.ExpiresAt
	}

	if in.Enabled != nil {
		data[cols.Enabled] = *in.Enabled
	}
	if in.Note != nil {
		note, err := normalizeNote(*in.Note)
		if err != nil {
			return nil, err
		}
		data[cols.Note] = note
	}

	if _, err := dao.InvitationCode.Ctx(ctx).Where(cols.Id, id).Data(data).Update(); err != nil {
		return nil, err
	}
	return FindByID(ctx, id)
}

// Delete 删除邀请码。
//
// 只删码本身，**保留使用明细**：明细里冗余存了 code 字符串，所以删码之后
// 仍然查得出"这个账号当初是用哪张码注册的"。若连明细一起删，就等于把
// "他是被谁邀请进来的"这条唯一线索抹掉了 —— 而这正是事后追责要查的东西。
func Delete(ctx context.Context, id int64) error {
	cur, err := FindByID(ctx, id)
	if err != nil {
		return err
	}
	if cur == nil {
		return errNotFound("邀请码不存在")
	}
	_, err = dao.InvitationCode.Ctx(ctx).Where(dao.InvitationCode.Columns().Id, id).Delete()
	return err
}

// ── 核销 ────────────────────────────────────────────────────────────────────

// RedeemInput 核销入参（口令已由调用方哈希，本包不接触明文）
type RedeemInput struct {
	Code         string
	Username     string
	PasswordHash string
	Email        string
}

// Redeem 核销邀请码并建立账号，返回新账号。
//
// 三件事必须在**一个事务**里完成。少任何一件，都会留下追不回来的脏数据：
//   - 先建账号再扣次数：扣失败 → 账号建出来了，码还能再用（白送名额）；
//   - 先扣次数再建账号：建档失败 → 次数被扣掉了，却没人注册成功（码被白白消耗）；
//   - 漏写使用明细：次数对得上，但"谁用掉的"永久丢失。
//
// 并发安全性来自第 ① 步的**条件更新**，而不是"先查后写"。两个请求同时用
// 同一张 1 次性的码时，第二个的条件更新会匹配到 0 行（此时 used_count 已经
// 等于 max_uses），于是它抢不到名额、整体回滚。换成"先 SELECT 看次数、
// 再 UPDATE"则两者都会读到未满而双双放行 —— 这是典型的检查-使用竞态，
// 只会在真的有人同时点注册时复现，平时完全看不出来。
func Redeem(ctx context.Context, in RedeemInput) (*entity.User, error) {
	code := strings.TrimSpace(in.Code)
	if code == "" {
		return nil, errInvalid(CodeNotFound, "邀请码不能为空")
	}
	now := time.Now()

	// 事务外先做一次只读预检，把"码本身的问题"分成可操作的原因
	// （不存在 / 停用 / 过期 / 用完）。这些判断放进事务里也行，但那样每个
	// 失败分支都要穿过回滚路径，错误语义会被"回滚是否成功"稀释。
	// 真正的并发保护仍在事务内（见下方 ①）。
	cur, err := FindByCode(ctx, code)
	if err != nil {
		return nil, err
	}
	switch {
	case cur == nil:
		return nil, errInvalid(CodeNotFound, "邀请码不存在")
	case !cur.Enabled:
		return nil, errInvalid(CodeDisabled, "邀请码已被停用")
	case cur.IsExpired(now):
		return nil, errInvalid(CodeExpired, "邀请码已过期")
	case cur.IsExhausted():
		return nil, errInvalid(CodeExhausted, "邀请码可用次数已用完")
	}

	cols := dao.InvitationCode.Columns()
	usageCols := dao.InvitationCodeUsage.Columns()

	var created *entity.User
	err = db.Instance().Transaction(ctx, func(ctx context.Context, tx gdb.TX) error {
		// ① 原子占位：把"还有没有名额"交给数据库在一次语句里判断。
		//    used_count 用 Counter 表达自增，由 gdb 生成 `"used_count"="used_count"+?`，
		//    而不是"先读出来 +1 再写回" —— 后者在并发下会丢更新。
		res, err := dao.InvitationCode.Tx(tx).Ctx(ctx).
			Where(cols.Id, cur.Id).
			Where(cols.UsedCount + " < " + cols.MaxUses).
			Data(g.Map{
				cols.UsedCount: gdb.Counter{Field: cols.UsedCount, Value: 1},
				cols.UpdatedAt: now,
			}).
			Update()
		if err != nil {
			return err
		}
		affected, err := res.RowsAffected()
		if err != nil {
			return err
		}
		if affected == 0 {
			// 预检时还有名额，这里却抢不到：只能是并发请求先占走了。
			// 返回业务错误会让整个事务回滚，这是刻意的 —— 抢不到名额的
			// 那次注册不该留下任何痕迹（包括已经建好的账号）。
			return errInvalid(CodeExhausted, "邀请码可用次数已用完")
		}

		// ② 建档。走 user 包而不是在这里自己拼 INSERT：账号长什么样只有一个
		//    答案，多一处拼装就多一个绕开校验、缺字段的账号。
		created, err = user.InsertWithTx(ctx, tx, user.CreateInput{
			Username:     in.Username,
			PasswordHash: in.PasswordHash,
			Email:        in.Email,
			// 注册成功即登录（接下来就下发全局会话），所以"最后登录时间"
			// 此刻就已确定，而不是留空等登录接口去补。
			LastLoginAt: &now,
		})
		if err != nil {
			return err
		}

		// ③ 使用明细：次数只能说明"用掉了几个名额"，明细才说明"谁用掉的"。
		_, err = dao.InvitationCodeUsage.Tx(tx).Ctx(ctx).Data(g.Map{
			usageCols.CodeID:   cur.Id,
			usageCols.Code:     cur.Code,
			usageCols.UserID:   created.Id,
			usageCols.Username: created.Username,
			usageCols.Email:    created.Email,
			usageCols.UsedAt:   now,
		}).Insert()
		return err
	})
	if err != nil {
		return nil, err
	}
	return created, nil
}

// CheckUsernameFree 检查账号是否已被占用，被占用时返回冲突错误。
//
// 放在事务**之前**调用，只是为了给出"账号已被占用"这句明确的话。它不是
// 安全边界：真正的保证是 users.username 上的唯一索引 —— 两个请求同时注册
// 同一个账号时，索引会让其中一个失败并回滚（连同它占用的邀请码名额），
// 而预检只是让绝大多数情况下用户看到的是人话，不是数据库报错。
func CheckUsernameFree(ctx context.Context, username string) error {
	u, err := user.FindByUsername(ctx, username)
	if err != nil {
		return err
	}
	if u != nil {
		return errConflict(CodeUsernameTaken, "该账号已被占用")
	}
	return nil
}
