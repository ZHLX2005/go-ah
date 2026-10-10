// Package user 处理本地账号的建档、查询与口令校验。
//
// 平台引入统一登录后，本地口令登录只保留给 IdP 自身的注册/管理后台使用，
// 但校验逻辑仍必须严谨：口令错误与账号不存在返回**不同**的原因码，
// 是为了让界面能给出可操作的提示；面向公网时若要防账号枚举，
// 应在上层把两者合并成同一提示，而不是在这里糊掉信息。
//
// 本包是**唯一**写 users 表的地方：建档（含邀请码注册那条路径）都走
// InsertWithTx，因此"新账号长什么样"只有一个答案。别的包直接往
// users 表里插行，早晚会造出一个缺字段、绕开校验的账号。
package user

import (
	"context"
	"regexp"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/gogf/gf/v2/database/gdb"
	"github.com/gogf/gf/v2/frame/g"

	"github.com/ZHLX2005/go-ah/auth-hub/internal/consts"
	"github.com/ZHLX2005/go-ah/auth-hub/internal/dao"
	"github.com/ZHLX2005/go-ah/auth-hub/internal/db"
	"github.com/ZHLX2005/go-ah/auth-hub/internal/model/entity"
	"github.com/ZHLX2005/go-ah/auth-hub/internal/utility"
)

// AuthError 口令登录失败的原因（ErrorCode 直接对应接口响应里的 error 字段）
type AuthError struct {
	ErrorCode string
	Message   string
}

// Error 实现 error 接口
func (e *AuthError) Error() string { return e.Message }

// usernameRe 账号字符集。
//
// 限定成字母/数字/下划线/点/横线，是为了让账号在**日志、URL、命令行**里
// 都是无歧义的：放开到任意字符后，一个含全角空格的账号会让"用户报障说
// 登不上"变成一件无法在工单里描述清楚的事（复制粘贴时看不出区别）。
var usernameRe = regexp.MustCompile(`^[A-Za-z0-9_.-]+$`)

// emailRe 邮箱的**宽松**校验：本地部分@域名.顶级域，且不含空白。
//
// 刻意不用 RFC 5322 的完整正则：那个表达式会把 `a+b@sub.domain.co` 这类
// 完全合法的地址判成非法，于是真实用户被拦在注册页面外面 —— 这是"严格"
// 换来的实际损失。真正的送达验证只有发信才能做到。
var emailRe = regexp.MustCompile(`^[^@\s]+@[^@\s]+\.[^@\s]+$`)

// FindByUsername 按账号查用户；不存在返回 (nil, nil)
func FindByUsername(ctx context.Context, username string) (*entity.User, error) {
	var u entity.User
	found, err := db.ScanOne(ctx, dao.User.Ctx(ctx).Where("username", username), &u)
	if err != nil {
		return nil, err
	}
	if !found {
		return nil, nil
	}
	return &u, nil
}

// FindByID 按主键查用户；不存在返回 (nil, nil)
func FindByID(ctx context.Context, id int64) (*entity.User, error) {
	var u entity.User
	found, err := db.ScanOne(ctx, dao.User.Ctx(ctx).Where("id", id), &u)
	if err != nil {
		return nil, err
	}
	if !found {
		return nil, nil
	}
	return &u, nil
}

// FindByEmail 按邮箱查用户；不存在返回 (nil, nil)。
//
// 取 id 最小的那条而不是"随便一条"：users.email 上没有唯一索引，
// 同一邮箱在库里可能存在多行（历史数据、手工插入）。不定序的查询会
// 让"同一个邮箱今天登进 A 账号、明天登进 B 账号"变成偶发故障，
// 而偶发故障的排查成本远高于这里多写一个 OrderAsc。
func FindByEmail(ctx context.Context, email string) (*entity.User, error) {
	var u entity.User
	found, err := db.ScanOne(ctx, dao.User.Ctx(ctx).Where("email", email).OrderAsc("id"), &u)
	if err != nil {
		return nil, err
	}
	if !found {
		return nil, nil
	}
	return &u, nil
}

// Authenticate 校验登录名与口令，成功返回用户。
//
// 登录名既可以是**账号**也可以是**邮箱**：管理员是按邮箱配置的
// （IDP_ADMIN_EMAIL），要求使用者记住"这个邮箱对应的账号名是 admin"
// 是一件只有写代码的人才知道的事。
//
// 两种登录名不会互相遮蔽：账号字符集 usernameRe 不允许 '@'，
// 所以一个含 '@' 的输入不可能命中 username 分支；反过来，某个账号名
// 恰好等于别人邮箱地址这种情况在结构上就不存在。顺序因此只影响
// "不含 @ 的输入要不要多查一次邮箱"，不影响正确性。
func Authenticate(ctx context.Context, identifier, password string) (*entity.User, error) {
	identifier = strings.TrimSpace(identifier)
	u, err := FindByUsername(ctx, identifier)
	if err != nil {
		return nil, err
	}
	if u == nil && strings.Contains(identifier, "@") {
		if u, err = FindByEmail(ctx, identifier); err != nil {
			return nil, err
		}
	}
	if u == nil {
		return nil, &AuthError{ErrorCode: "user_not_found", Message: "账号或邮箱不存在"}
	}
	if !utility.VerifyPassword(password, u.PasswordHash) {
		return nil, &AuthError{ErrorCode: "wrong_password", Message: "密码错误"}
	}
	return u, nil
}

// ── 建档 ────────────────────────────────────────────────────────────────────

// ValidateNewAccount 校验新账号的三项输入，不合法时返回带原因码的错误。
//
// 放在这里而不是散在控制器里：注册接口与将来可能的管理端"手工建号"
// 必须用同一套规则。规则一旦有两份，"这个账号明明能注册、为什么后台建不了"
// 就会变成需要读代码才能回答的问题。
func ValidateNewAccount(username, password, email string) error {
	if n := utf8.RuneCountInString(username); n < consts.MinUsernameLength || n > consts.MaxUsernameLength {
		return &AuthError{
			ErrorCode: "invalid_username",
			Message: "账号长度需在 " + strconv.Itoa(consts.MinUsernameLength) + "-" +
				strconv.Itoa(consts.MaxUsernameLength) + " 个字符之间",
		}
	}
	if !usernameRe.MatchString(username) {
		return &AuthError{
			ErrorCode: "invalid_username",
			Message:   "账号只能包含字母、数字、下划线、点和横线",
		}
	}
	if n := utf8.RuneCountInString(password); n < consts.MinPasswordLength {
		return &AuthError{
			ErrorCode: "invalid_password",
			Message:   "密码至少需要 " + strconv.Itoa(consts.MinPasswordLength) + " 个字符",
		}
	}
	if utf8.RuneCountInString(password) > consts.MaxPasswordLength {
		return &AuthError{ErrorCode: "invalid_password", Message: "密码过长"}
	}
	if email == "" {
		return &AuthError{ErrorCode: "invalid_email", Message: "邮箱不能为空"}
	}
	if len(email) > consts.MaxEmailLength || !emailRe.MatchString(email) {
		return &AuthError{ErrorCode: "invalid_email", Message: "邮箱格式不正确"}
	}
	return nil
}

// CreateInput 建档入参（口令由调用方先哈希，本包不接触明文）
type CreateInput struct {
	Username     string
	PasswordHash string
	Email        string
	Nickname     string
	// LastLoginAt 建档同时即一次登录时（邀请码注册就是这样）一并写入；
	// 留 nil 表示"从未登录过"，管理端据此显示 ——— 与"登录过但时间早"
	// 是两件不同的事，不能都塞成零值时间。
	LastLoginAt *time.Time
}

// InsertWithTx 在指定事务里建档，返回建好的账号。
//
// 为什么是 WithTx 而不是普通函数：邀请码核销要求"扣次数 + 建账号"原子，
// 建档失败必须把次数的扣减一起回滚。用连接池写行会**脱离事务**独立提交，
// 于是次数被扣掉、账号却回滚了 —— 名额白白消耗，而且没有任何报错。
//
// 返回的实体在内存里拼出来，不再回查一次：事务内的行对外部连接还不可见，
// 用 Ctx（连接池）去查会查不到，用事务去查又多一次往返。
func InsertWithTx(ctx context.Context, tx gdb.TX, in CreateInput) (*entity.User, error) {
	cols := dao.User.Columns()
	now := time.Now()
	nickname := in.Nickname
	if nickname == "" {
		// 昵称留空时用账号兜底：管理端列表里一片空白会让人分不清
		// "这个人没填昵称"和"这一行数据没读出来"
		nickname = in.Username
	}
	data := g.Map{
		cols.Username:     in.Username,
		cols.PasswordHash: in.PasswordHash,
		cols.Email:        in.Email,
		cols.Nickname:     nickname,
		cols.IsAdmin:      false,
		cols.CreatedAt:    now,
		cols.UpdatedAt:    now,
	}
	if in.LastLoginAt != nil {
		data[cols.LastLoginAt] = *in.LastLoginAt
	}
	id, err := dao.User.Tx(tx).Ctx(ctx).Data(data).InsertAndGetId()
	if err != nil {
		return nil, err
	}
	out := &entity.User{
		Id:           id,
		Username:     in.Username,
		PasswordHash: in.PasswordHash,
		Email:        in.Email,
		Nickname:     nickname,
		IsAdmin:      false,
		LastLoginAt:  in.LastLoginAt,
		CreatedAt:    now,
		UpdatedAt:    now,
	}
	return out, nil
}

// TouchLastLogin 记录最后登录时间。
//
// 刻意**不动 updated_at**：那个字段的含义是"账号资料被修改过"，登录不是
// 资料变更。混在一起之后，管理端看到 updated_at 变了会以为权限或资料被
// 动过，而实际上只是有人登录了一次 —— 一个字段承载两种语义，排查时必然误判。
//
// 写失败要往上抛，不静默吞掉：这条时间戳是管理端判断"账号还在不在用"
// 的唯一依据，悄悄不写，它就会变成一条看起来正常、实际是旧的记录。
func TouchLastLogin(ctx context.Context, userID int64) error {
	cols := dao.User.Columns()
	_, err := dao.User.Ctx(ctx).
		Where(cols.Id, userID).
		Data(g.Map{cols.LastLoginAt: time.Now()}).
		Update()
	return err
}
