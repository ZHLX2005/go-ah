// Package invite_test 是 logic/invite 的**外部测试包**，跑真实 PostgreSQL。
//
// 为什么不是纯单元测试：本包最要紧的两条性质都无法在内存里验证 ——
//   - 条件更新在并发下的排他性（`used_count < max_uses` 是否真的只放行一个人）；
//   - 失败路径是否真的把事务回滚干净（次数有没有被白扣）。
//
// 两者都要真库的锁与事务语义。测试在一个一次性 schema 上跑（internal/testpg），
// 结束时 DROP；未配置 AUTH_HUB_TEST_DSN 时整包跳过（本地没库不该看到一片红）。
package invite_test

import (
	"context"
	"errors"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gogf/gf/v2/os/gctx"

	"github.com/ZHLX2005/go-ah/auth-hub/internal/consts"
	"github.com/ZHLX2005/go-ah/auth-hub/internal/dao"
	"github.com/ZHLX2005/go-ah/auth-hub/internal/db"
	"github.com/ZHLX2005/go-ah/auth-hub/internal/logic/invite"
	"github.com/ZHLX2005/go-ah/auth-hub/internal/logic/user"
	"github.com/ZHLX2005/go-ah/auth-hub/internal/model/entity"
	"github.com/ZHLX2005/go-ah/auth-hub/internal/testpg"
	"github.com/ZHLX2005/go-ah/auth-hub/internal/utility"
)

// newDB 在一次性 schema 上初始化整套存储，返回 ctx。
func newDB(t *testing.T) context.Context {
	t.Helper()

	dsn, _ := testpg.NewSchema(t)
	ctx := gctx.New()

	if err := db.Init(ctx, db.InitOptions{
		DSN:                dsn,
		GSACRedirectURIs:   "http://127.0.0.1:8081/oauth/callback",
		GSACPostLogoutURIs: "http://127.0.0.1:8081/login",
	}); err != nil {
		t.Fatalf("db.Init 失败: %v", err)
	}
	// 注册晚于 testpg 的清理（t.Cleanup 后进先出）：先关连接池再 DROP schema，
	// 否则残留的连接会让 DROP 卡住。
	t.Cleanup(func() { _ = db.Instance().Close(ctx) })
	return ctx
}

// ============================================================
// 生成
// ============================================================

func TestGenerate_CodeShapeAndUniqueness(t *testing.T) {
	ctx := newDB(t)

	seen := make(map[string]bool)
	const n = 20
	for i := 0; i < n; i++ {
		c, err := invite.Generate(ctx, invite.GenerateInput{MaxUses: 1, Note: "并发前的最小验证"})
		if err != nil {
			t.Fatalf("第 %d 次 Generate 失败: %v", i+1, err)
		}
		if !strings.HasPrefix(c.Code, consts.InvitationCodePrefix) {
			t.Fatalf("邀请码缺少前缀: %q", c.Code)
		}
		// 前缀(4) + 12 字节 base64url 无填充(16)
		if len(c.Code) != 20 {
			t.Errorf("邀请码长度 = %d (%q), 期望 20", len(c.Code), c.Code)
		}
		if seen[c.Code] {
			t.Fatalf("生成出重复的邀请码: %q", c.Code)
		}
		seen[c.Code] = true
		if c.UsedCount != 0 || !c.Enabled {
			t.Errorf("新建的码应为 used_count=0 enabled=true, got %+v", c)
		}
		if c.Id == 0 {
			t.Error("应返回落库后的 id")
		}
	}

	all, err := invite.List(ctx)
	if err != nil {
		t.Fatalf("List 失败: %v", err)
	}
	if len(all) != n {
		t.Errorf("列表长度 = %d, 期望 %d", len(all), n)
	}
}

func TestGenerate_DefaultsAndRejects(t *testing.T) {
	ctx := newDB(t)

	t.Run("省略次数取默认值", func(t *testing.T) {
		c, err := invite.Generate(ctx, invite.GenerateInput{}) // MaxUses 为 0
		if err != nil {
			t.Fatalf("Generate 失败: %v", err)
		}
		if c.MaxUses != consts.DefaultInvitationMaxUses {
			t.Errorf("MaxUses = %d, 期望默认 %d", c.MaxUses, consts.DefaultInvitationMaxUses)
		}
	})

	t.Run("超过上限被拒绝", func(t *testing.T) {
		_, err := invite.Generate(ctx, invite.GenerateInput{MaxUses: consts.MaxInvitationUses + 1})
		if err == nil {
			t.Fatal("超过上限应当报错")
		}
	})

	t.Run("过去的过期时间被拒绝", func(t *testing.T) {
		past := time.Now().Add(-time.Minute)
		_, err := invite.Generate(ctx, invite.GenerateInput{MaxUses: 1, ExpiresAt: &past})
		if err == nil {
			t.Fatal("过去的过期时间应当报错")
		}
	})

	t.Run("长期有效时 expires_at 为空", func(t *testing.T) {
		c, err := invite.Generate(ctx, invite.GenerateInput{MaxUses: 1})
		if err != nil {
			t.Fatalf("Generate 失败: %v", err)
		}
		if c.ExpiresAt != nil {
			t.Errorf("未指定有效期时应为 nil, got %v", c.ExpiresAt)
		}
		// 从库里读回来验证：内存里的 nil 不代表列是 NULL
		back, err := invite.FindByID(ctx, c.Id)
		if err != nil {
			t.Fatalf("FindByID 失败: %v", err)
		}
		if back.ExpiresAt != nil {
			t.Errorf("库中 expires_at 应为 NULL, got %v", back.ExpiresAt)
		}
	})
}

// ============================================================
// 修改：部分更新语义 + 清空过期时间
// ============================================================

func TestUpdate_PartialSemantics(t *testing.T) {
	ctx := newDB(t)

	future := time.Now().Add(24 * time.Hour)
	c, err := invite.Generate(ctx, invite.GenerateInput{MaxUses: 2, Note: "原始备注", ExpiresAt: &future})
	if err != nil {
		t.Fatalf("Generate 失败: %v", err)
	}

	t.Run("只改备注时次数与有效期不动", func(t *testing.T) {
		note := "改过的备注"
		got, err := invite.Update(ctx, c.Id, invite.UpdateInput{Note: &note})
		if err != nil {
			t.Fatalf("Update 失败: %v", err)
		}
		if got.Note != note {
			t.Errorf("Note = %q, 期望 %q", got.Note, note)
		}
		// 全量替换语义下这两项会被写成零值/默认值，那正是要避免的
		if got.MaxUses != 2 {
			t.Errorf("MaxUses 被改动了: %d", got.MaxUses)
		}
		if got.ExpiresAt == nil {
			t.Error("ExpiresAt 被清空了（只改了备注，过期时间不该动）")
		}
	})

	t.Run("ClearExpires 把过期时间置为 NULL", func(t *testing.T) {
		got, err := invite.Update(ctx, c.Id, invite.UpdateInput{ClearExpires: true})
		if err != nil {
			t.Fatalf("Update 失败: %v", err)
		}
		if got.ExpiresAt != nil {
			t.Fatalf("内存结果 ExpiresAt = %v, 期望 nil", got.ExpiresAt)
		}
		back, err := invite.FindByID(ctx, c.Id)
		if err != nil {
			t.Fatalf("FindByID 失败: %v", err)
		}
		if back.ExpiresAt != nil {
			t.Errorf("库中 expires_at 应为 NULL, got %v —— 清空过期时间没生效", back.ExpiresAt)
		}
	})

	t.Run("停用", func(t *testing.T) {
		off := false
		got, err := invite.Update(ctx, c.Id, invite.UpdateInput{Enabled: &off})
		if err != nil {
			t.Fatalf("Update 失败: %v", err)
		}
		if got.Enabled {
			t.Error("Enabled 应为 false")
		}
		if got.Status(time.Now()) != entity.InvitationStatusDisabled {
			t.Errorf("Status = %q, 期望 disabled", got.Status(time.Now()))
		}
	})

	t.Run("次数不能改到小于已用次数", func(t *testing.T) {
		// 用一张独立的码：上面的子测试已经把它停用了，停用的码核销不了。
		c2 := mustGenerate(t, ctx, 2, nil)
		redeemOnce(t, ctx, c2.Code, "upd_user_1")
		redeemOnce(t, ctx, c2.Code, "upd_user_2")

		one := 1
		if _, err := invite.Update(ctx, c2.Id, invite.UpdateInput{MaxUses: &one}); err == nil {
			t.Fatal("已用 2 次时把次数改成 1 应当被拒绝：那会让 used_count > max_uses 这种自相矛盾的数据进库")
		}

		// 边界：改成与已用次数**相等**是允许的 —— 结果是一张"已用完"的码，
		// 状态清晰、数据不矛盾，不是要拦的那件事。
		two := 2
		got, err := invite.Update(ctx, c2.Id, invite.UpdateInput{MaxUses: &two})
		if err != nil {
			t.Fatalf("改成与已用次数相等不该报错: %v", err)
		}
		if got.Status(time.Now()) != entity.InvitationStatusExhausted {
			t.Errorf("Status = %q, 期望 exhausted", got.Status(time.Now()))
		}
	})

	t.Run("不存在的 id 返回 not_found", func(t *testing.T) {
		note := "x"
		_, err := invite.Update(ctx, 999999999, invite.UpdateInput{Note: &note})
		assertInviteError(t, err, invite.KindNotFound, invite.CodeNotFound)
	})
}

// ============================================================
// 核销：成功路径
// ============================================================

func TestRedeem_Success(t *testing.T) {
	ctx := newDB(t)

	c, err := invite.Generate(ctx, invite.GenerateInput{MaxUses: 2, Note: "给两个人"})
	if err != nil {
		t.Fatalf("Generate 失败: %v", err)
	}

	u, err := invite.Redeem(ctx, invite.RedeemInput{
		Code:         c.Code,
		Username:     "alice",
		PasswordHash: utility.HashPassword("alice-password"),
		Email:        "alice@example.com",
	})
	if err != nil {
		t.Fatalf("Redeem 失败: %v", err)
	}

	t.Run("账号建出来了且不是管理员", func(t *testing.T) {
		if u.Id == 0 || u.Username != "alice" || u.Email != "alice@example.com" {
			t.Fatalf("返回的账号不对: %+v", u)
		}
		if u.IsAdmin {
			t.Error("自助注册出来的账号绝不能是管理员")
		}
		back, err := user.FindByUsername(ctx, "alice")
		if err != nil {
			t.Fatalf("FindByUsername 失败: %v", err)
		}
		if back == nil {
			t.Fatal("账号没有落库")
		}
		if !utility.VerifyPassword("alice-password", back.PasswordHash) {
			t.Error("口令哈希与注册时的不一致")
		}
		if back.Nickname != "alice" {
			t.Errorf("未传昵称时应回落成账号, got %q", back.Nickname)
		}
	})

	t.Run("注册即登录：last_login_at 已写入", func(t *testing.T) {
		back, err := user.FindByUsername(ctx, "alice")
		if err != nil {
			t.Fatalf("FindByUsername 失败: %v", err)
		}
		if back.LastLoginAt == nil {
			t.Fatal("last_login_at 为空：注册成功即登录，这一列应当已写入")
		}
	})

	t.Run("次数 +1 且写入使用明细", func(t *testing.T) {
		back, err := invite.FindByID(ctx, c.Id)
		if err != nil {
			t.Fatalf("FindByID 失败: %v", err)
		}
		if back.UsedCount != 1 {
			t.Errorf("used_count = %d, 期望 1", back.UsedCount)
		}
		if back.Remaining() != 1 {
			t.Errorf("remaining = %d, 期望 1", back.Remaining())
		}

		usages, err := invite.Usages(ctx, c.Id)
		if err != nil {
			t.Fatalf("Usages 失败: %v", err)
		}
		if len(usages) != 1 {
			t.Fatalf("使用明细条数 = %d, 期望 1", len(usages))
		}
		got := usages[0]
		if got.UserID != u.Id || got.Username != "alice" || got.Email != "alice@example.com" {
			t.Errorf("使用明细内容不对: %+v", got)
		}
		if got.Code != c.Code {
			t.Errorf("使用明细里的码 = %q, 期望 %q（冗余留存，删码后仍可追溯）", got.Code, c.Code)
		}
	})

	t.Run("第二次核销（还有余额）也成功", func(t *testing.T) {
		u2, err := invite.Redeem(ctx, invite.RedeemInput{
			Code:         c.Code,
			Username:     "bob",
			PasswordHash: utility.HashPassword("bob-password"),
			Email:        "bob@example.com",
		})
		if err != nil {
			t.Fatalf("第二次 Redeem 失败: %v", err)
		}
		if u2.Username != "bob" {
			t.Errorf("返回的账号不对: %+v", u2)
		}
		back, _ := invite.FindByID(ctx, c.Id)
		if back.UsedCount != 2 || back.Remaining() != 0 {
			t.Errorf("used_count=%d remaining=%d, 期望 2/0", back.UsedCount, back.Remaining())
		}
		if back.Status(time.Now()) != entity.InvitationStatusExhausted {
			t.Errorf("Status = %q, 期望 exhausted", back.Status(time.Now()))
		}
	})
}

// ============================================================
// 核销：各失败分支
// ============================================================

func TestRedeem_FailureBranches(t *testing.T) {
	ctx := newDB(t)

	t.Run("码不存在", func(t *testing.T) {
		_, err := invite.Redeem(ctx, invite.RedeemInput{
			Code: "inv_does_not_exist", Username: "u1", PasswordHash: "h", Email: "u1@example.com",
		})
		assertInviteError(t, err, invite.KindInvalid, invite.CodeNotFound)
	})

	t.Run("码为空", func(t *testing.T) {
		_, err := invite.Redeem(ctx, invite.RedeemInput{Code: "   ", Username: "u1", PasswordHash: "h"})
		assertInviteError(t, err, invite.KindInvalid, invite.CodeNotFound)
	})

	t.Run("已停用", func(t *testing.T) {
		c := mustGenerate(t, ctx, 1, nil)
		off := false
		if _, err := invite.Update(ctx, c.Id, invite.UpdateInput{Enabled: &off}); err != nil {
			t.Fatalf("停用失败: %v", err)
		}
		_, err := invite.Redeem(ctx, invite.RedeemInput{
			Code: c.Code, Username: "u2", PasswordHash: "h", Email: "u2@example.com",
		})
		assertInviteError(t, err, invite.KindInvalid, invite.CodeDisabled)
	})

	t.Run("已过期", func(t *testing.T) {
		c := mustGenerate(t, ctx, 1, nil)
		// 直接把过期时间改到过去：接口层不允许填过去的时间，
		// 但时间会流逝，所以"生成时合法、核销时已过期"是真实场景。
		past := time.Now().Add(-time.Hour)
		if _, err := dao.InvitationCode.Ctx(ctx).
			Where(dao.InvitationCode.Columns().Id, c.Id).
			Data(map[string]any{dao.InvitationCode.Columns().ExpiresAt: past}).
			Update(); err != nil {
			t.Fatalf("改过期时间失败: %v", err)
		}
		_, err := invite.Redeem(ctx, invite.RedeemInput{
			Code: c.Code, Username: "u3", PasswordHash: "h", Email: "u3@example.com",
		})
		assertInviteError(t, err, invite.KindInvalid, invite.CodeExpired)
	})

	t.Run("次数已用完", func(t *testing.T) {
		c := mustGenerate(t, ctx, 1, nil)
		redeemOnce(t, ctx, c.Code, "u4")
		_, err := invite.Redeem(ctx, invite.RedeemInput{
			Code: c.Code, Username: "u5", PasswordHash: "h", Email: "u5@example.com",
		})
		assertInviteError(t, err, invite.KindInvalid, invite.CodeExhausted)
	})
}

// TestRedeem_RollbackKeepsQuota 归档失败必须把"占位"一起回滚。
//
// 这是整个功能里最容易写错、也最难发现的一条：先扣次数再建档，
// 建档失败时说一句"注册失败"就完事，次数却被白扣掉了 ——
// 表现为"邀请码用着用着就不能用了，而且没人注册成功"。
func TestRedeem_RollbackKeepsQuota(t *testing.T) {
	ctx := newDB(t)

	c := mustGenerate(t, ctx, 3, nil)

	// 先把用户名占住，让建档必然失败（username 上有唯一索引）
	if _, err := invite.Redeem(ctx, invite.RedeemInput{
		Code: c.Code, Username: "dup", PasswordHash: utility.HashPassword("pw-123456"), Email: "dup@example.com",
	}); err != nil {
		t.Fatalf("首次 Redeem 失败: %v", err)
	}

	before, err := invite.FindByID(ctx, c.Id)
	if err != nil {
		t.Fatalf("FindByID 失败: %v", err)
	}

	// 同一个用户名再来一次：建档会撞唯一索引，事务必须整体回滚
	if _, err := invite.Redeem(ctx, invite.RedeemInput{
		Code: c.Code, Username: "dup", PasswordHash: utility.HashPassword("pw-123456"), Email: "other@example.com",
	}); err == nil {
		t.Fatal("重复用户名应当失败")
	}

	after, err := invite.FindByID(ctx, c.Id)
	if err != nil {
		t.Fatalf("FindByID 失败: %v", err)
	}
	if after.UsedCount != before.UsedCount {
		t.Errorf("used_count 从 %d 变成了 %d —— 建档失败却扣了次数，名额被白扣",
			before.UsedCount, after.UsedCount)
	}

	// 使用明细也不该多出一条：那次注册并没有成功
	usages, err := invite.Usages(ctx, c.Id)
	if err != nil {
		t.Fatalf("Usages 失败: %v", err)
	}
	if len(usages) != 1 {
		t.Errorf("使用明细条数 = %d, 期望 1（失败的那次不该留下明细）", len(usages))
	}
}

// ============================================================
// 并发：一张 1 次性的码，同时来 8 个人，只能成功 1 个
// ============================================================

func TestRedeem_ConcurrentSingleUse(t *testing.T) {
	ctx := newDB(t)

	c := mustGenerate(t, ctx, 1, nil)
	results := concurrentRedeem(t, ctx, c.Code, 8)

	success, exhausted, other := classifyResults(t, results)
	if success != 1 {
		t.Errorf("成功次数 = %d, 期望 1 —— 一张 1 次性的码被放行了多次", success)
	}
	if exhausted != 7 {
		t.Errorf("因次数用尽而失败的次数 = %d, 期望 7（other=%d, 详情=%v）",
			exhausted, other, errorSummaries(results))
	}
	assertUsedCount(t, ctx, c.Id, 1)
	assertUsageCount(t, ctx, c.Id, 1)
}

func TestRedeem_ConcurrentMultiUse(t *testing.T) {
	ctx := newDB(t)

	const maxUses, callers = 3, 8
	c := mustGenerate(t, ctx, maxUses, nil)
	results := concurrentRedeem(t, ctx, c.Code, callers)

	success, exhausted, other := classifyResults(t, results)
	if success != maxUses {
		t.Errorf("成功次数 = %d, 期望 %d", success, maxUses)
	}
	if exhausted != callers-maxUses {
		t.Errorf("次数用尽失败数 = %d, 期望 %d（other=%d, 详情=%v）",
			exhausted, callers-maxUses, other, errorSummaries(results))
	}
	assertUsedCount(t, ctx, c.Id, maxUses)
	assertUsageCount(t, ctx, c.Id, maxUses)
}

// ============================================================
// 删除：明细保留
// ============================================================

func TestDelete_KeepsUsages(t *testing.T) {
	ctx := newDB(t)

	c := mustGenerate(t, ctx, 1, nil)
	redeemOnce(t, ctx, c.Code, "del_user")

	if err := invite.Delete(ctx, c.Id); err != nil {
		t.Fatalf("Delete 失败: %v", err)
	}
	back, err := invite.FindByID(ctx, c.Id)
	if err != nil {
		t.Fatalf("FindByID 失败: %v", err)
	}
	if back != nil {
		t.Fatal("邀请码应当已被删除")
	}

	// 明细必须还在：那是"这个账号当初被谁邀请进来"的唯一线索
	n, err := dao.InvitationCodeUsage.Ctx(ctx).
		Where(dao.InvitationCodeUsage.Columns().CodeID, c.Id).Count()
	if err != nil {
		t.Fatalf("统计使用明细失败: %v", err)
	}
	if n != 1 {
		t.Errorf("删码后使用明细条数 = %d, 期望 1（明细必须保留）", n)
	}

	// 再删一次应报 not_found
	err = invite.Delete(ctx, c.Id)
	assertInviteError(t, err, invite.KindNotFound, invite.CodeNotFound)
}

// ============================================================
// 状态过滤
// ============================================================

func TestListByStatus(t *testing.T) {
	ctx := newDB(t)

	active := mustGenerate(t, ctx, 1, nil)

	disabled := mustGenerate(t, ctx, 1, nil)
	off := false
	if _, err := invite.Update(ctx, disabled.Id, invite.UpdateInput{Enabled: &off}); err != nil {
		t.Fatalf("停用失败: %v", err)
	}

	used := mustGenerate(t, ctx, 1, nil)
	redeemOnce(t, ctx, used.Code, "filter_user")

	for _, c := range []struct {
		status string
		want   int
	}{
		{"", 3},
		{"all", 3},
		{entity.InvitationStatusActive, 1},
		{entity.InvitationStatusDisabled, 1},
		{entity.InvitationStatusExhausted, 1},
		{entity.InvitationStatusExpired, 0},
	} {
		rows, err := invite.ListByStatus(ctx, c.status)
		if err != nil {
			t.Fatalf("ListByStatus(%q) 失败: %v", c.status, err)
		}
		if len(rows) != c.want {
			t.Errorf("ListByStatus(%q) 返回 %d 条, 期望 %d", c.status, len(rows), c.want)
		}
	}

	if _, err := invite.ListByStatus(ctx, "不存在的状态"); err == nil {
		t.Error("未知的状态过滤值应当报错，而不是静默返回全部")
	}

	// 过滤出来的 active 必须真的可用：列表说可用、注册却被拒是最坏的体验
	rows, err := invite.ListByStatus(ctx, entity.InvitationStatusActive)
	if err != nil {
		t.Fatalf("ListByStatus 失败: %v", err)
	}
	if len(rows) == 0 || rows[0].Code != active.Code {
		t.Fatalf("active 过滤结果不对: %+v", rows)
	}
	redeemOnce(t, ctx, rows[0].Code, "from_list_user")
}

// ============================================================
// 账号占用预检
// ============================================================

func TestCheckUsernameFree(t *testing.T) {
	ctx := newDB(t)

	if err := invite.CheckUsernameFree(ctx, "nobody"); err != nil {
		t.Fatalf("未被占用的账号不该报错: %v", err)
	}

	c := mustGenerate(t, ctx, 1, nil)
	redeemOnce(t, ctx, c.Code, "taken")

	err := invite.CheckUsernameFree(ctx, "taken")
	assertInviteError(t, err, invite.KindConflict, invite.CodeUsernameTaken)

	// 种子账号也算被占用
	err = invite.CheckUsernameFree(ctx, consts.SeedUsername)
	assertInviteError(t, err, invite.KindConflict, invite.CodeUsernameTaken)
}

// ============================================================
// 测试脚手架
// ============================================================

// mustGenerate 生成一张码，失败即终止
func mustGenerate(t *testing.T, ctx context.Context, maxUses int, expiresAt *time.Time) *entity.InvitationCode {
	t.Helper()
	c, err := invite.Generate(ctx, invite.GenerateInput{MaxUses: maxUses, ExpiresAt: expiresAt})
	if err != nil {
		t.Fatalf("Generate 失败: %v", err)
	}
	return c
}

// redeemOnce 用指定账号核销一次，失败即终止
func redeemOnce(t *testing.T, ctx context.Context, code, username string) {
	t.Helper()
	if _, err := invite.Redeem(ctx, invite.RedeemInput{
		Code:         code,
		Username:     username,
		PasswordHash: utility.HashPassword(username + "-password"),
		Email:        username + "@example.com",
	}); err != nil {
		t.Fatalf("Redeem(%s) 失败: %v", username, err)
	}
}

// concurrentRedeem 并发核销同一张码，返回每次调用的错误（nil 表示成功）
func concurrentRedeem(t *testing.T, ctx context.Context, code string, n int) []error {
	t.Helper()

	// 口令哈希在并发之前算好：argon2id 每次要吃 64MB 内存，
	// 放进并发区会让测试变成在测量内存分配而不是事务排他性。
	hash := utility.HashPassword("concurrent-password")
	results := make([]error, n)

	var wg sync.WaitGroup
	start := make(chan struct{})
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			<-start // 一起出发，尽量制造真正的重叠
			_, err := invite.Redeem(ctx, invite.RedeemInput{
				Code:         code,
				Username:     "concurrent_" + itoa(idx),
				PasswordHash: hash,
				Email:        "concurrent_" + itoa(idx) + "@example.com",
			})
			results[idx] = err
		}(i)
	}
	close(start)
	wg.Wait()
	return results
}

// classifyResults 统计成功 / 次数用尽 / 其它错误
func classifyResults(t *testing.T, results []error) (success, exhausted, other int) {
	t.Helper()
	for _, err := range results {
		switch {
		case err == nil:
			success++
		default:
			var ie *invite.Error
			if errors.As(err, &ie) && ie.Code == invite.CodeExhausted {
				exhausted++
			} else {
				other++
			}
		}
	}
	return success, exhausted, other
}

// errorSummaries 把失败详情压成可读文本，出错时打印
func errorSummaries(results []error) []string {
	out := make([]string, 0, len(results))
	for i, err := range results {
		if err != nil {
			out = append(out, itoa(i)+": "+err.Error())
		}
	}
	return out
}

func assertUsedCount(t *testing.T, ctx context.Context, id int64, want int) {
	t.Helper()
	row, err := invite.FindByID(ctx, id)
	if err != nil {
		t.Fatalf("FindByID 失败: %v", err)
	}
	if row == nil {
		t.Fatal("邀请码不见了")
	}
	if row.UsedCount != want {
		t.Errorf("used_count = %d, 期望 %d", row.UsedCount, want)
	}
	// 并发下最容易出的错是"次数涨了但明细没写"或反之
	if got := lenOfUsages(t, ctx, id); got != want {
		t.Errorf("使用明细条数 = %d, 期望 %d（与 used_count 必须一致）", got, want)
	}
}

func assertUsageCount(t *testing.T, ctx context.Context, id int64, want int) {
	t.Helper()
	if got := lenOfUsages(t, ctx, id); got != want {
		t.Errorf("使用明细条数 = %d, 期望 %d", got, want)
	}
}

func lenOfUsages(t *testing.T, ctx context.Context, id int64) int {
	t.Helper()
	rows, err := invite.Usages(ctx, id)
	if err != nil {
		t.Fatalf("Usages 失败: %v", err)
	}
	return len(rows)
}

func assertInviteError(t *testing.T, err error, kind invite.ErrKind, code string) {
	t.Helper()
	if err == nil {
		t.Fatalf("应当返回 %s 错误，实际 nil", code)
	}
	var ie *invite.Error
	if !errors.As(err, &ie) {
		t.Fatalf("错误类型应为 *invite.Error, 实际 %T (%v)", err, err)
	}
	if ie.Kind != kind {
		t.Errorf("Kind = %v, 期望 %v", ie.Kind, kind)
	}
	if ie.Code != code {
		t.Errorf("Code = %q, 期望 %q", ie.Code, code)
	}
}

func itoa(n int) string { return strconv.Itoa(n) }
