// Package qr_test 是 logic/qr 的**外部测试包**，跑真实 PostgreSQL。
//
// 为什么必须真库而不是内存里测：这个包的全部价值就一句话
// ——「并发下只放行一次」。而"只放行一次"是数据库的 UPDATE 行锁给的，
// 用 fake 或 sqlite 内存库跑出来的通过，只证明了代码调用了一个 mock，
// 没有证明条件更新真的排他。要验的东西恰恰是 gdb 生成出来的那条 SQL
// 在真 PG 上的行为（见 logic/invite 的同类测试，口径一致）。
//
// 未设置 AUTH_HUB_TEST_DSN 时整包跳过，不失败 —— 与 testpg 的约定一致。
package qr_test

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/gogf/gf/v2/frame/g"
	"github.com/gogf/gf/v2/os/gctx"

	"github.com/ZHLX2005/go-ah/auth-hub/internal/consts"
	"github.com/ZHLX2005/go-ah/auth-hub/internal/dao"
	"github.com/ZHLX2005/go-ah/auth-hub/internal/db"
	"github.com/ZHLX2005/go-ah/auth-hub/internal/logic/qr"
	"github.com/ZHLX2005/go-ah/auth-hub/internal/logic/user"
	"github.com/ZHLX2005/go-ah/auth-hub/internal/model/entity"
	"github.com/ZHLX2005/go-ah/auth-hub/internal/testpg"
)

// newDB 在一次性 schema 上初始化整套存储（含种子账号 test）
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
	return ctx
}

// seedUserID 取种子管理员账号的 id，作为"手机上已登录的那个用户"
func seedUserID(t *testing.T, ctx context.Context) int64 {
	t.Helper()
	u, err := user.FindByUsername(ctx, consts.SeedUsername)
	if err != nil || u == nil {
		t.Fatalf("取种子账号 %s 失败: u=%v err=%v", consts.SeedUsername, u, err)
	}
	return u.Id
}

// mustCreate 建一张票，返回 ticket 与 qr_ctx 原文
func mustCreate(t *testing.T, ctx context.Context) (string, string) {
	t.Helper()
	c, err := qr.Create(ctx, qr.CreateInput{PcUA: "Chrome · Windows", PcIP: "203.0.113.7", PcGeo: "公网"})
	if err != nil {
		t.Fatalf("Create 失败: %v", err)
	}
	if c.Ticket == "" || c.QRCtx == "" {
		t.Fatalf("Create 返回空字段: %+v", c)
	}
	return c.Ticket, c.QRCtx
}

// statusOf 直接读库拿状态，绕过 Peek 的防探测遮蔽（只有测试需要看真值）
func statusOf(t *testing.T, ctx context.Context, ticket string) string {
	t.Helper()
	var row entity.QRLoginSession
	found, err := db.ScanOne(ctx, dao.QRLoginSession.Ctx(ctx).
		Where(dao.QRLoginSession.Columns().Ticket, ticket), &row)
	if err != nil {
		t.Fatalf("读票据失败: %v", err)
	}
	if !found {
		t.Fatalf("票据不存在: %s", ticket)
	}
	return row.Status
}

// ── 正常链路 ────────────────────────────────────────────────────────────────

func TestHappyPath(t *testing.T) {
	ctx := newDB(t)
	uid := seedUserID(t, ctx)
	ticket, qrCtx := mustCreate(t, ctx)

	if got := statusOf(t, ctx, ticket); got != entity.QRStatusPending {
		t.Fatalf("新建票据状态应为 pending，实际 %s", got)
	}
	// 库里绝不能留 qr_ctx 原文：只存哈希是"表被拖走也换不出领取凭据"的前提
	var row entity.QRLoginSession
	if _, err := db.ScanOne(ctx, dao.QRLoginSession.Ctx(ctx).
		Where(dao.QRLoginSession.Columns().Ticket, ticket), &row); err != nil {
		t.Fatal(err)
	}
	if row.CtxHash == qrCtx || len(row.CtxHash) != 64 {
		t.Fatalf("ctx_hash 应是 64 字符摘要而不是原文，实际 len=%d", len(row.CtxHash))
	}

	if err := qr.Scan(ctx, ticket, "Chrome · Android"); err != nil {
		t.Fatalf("Scan 失败: %v", err)
	}
	if got := statusOf(t, ctx, ticket); got != entity.QRStatusScanned {
		t.Fatalf("Scan 后应为 scanned，实际 %s", got)
	}
	if err := qr.Confirm(ctx, ticket, uid, "Chrome · Android"); err != nil {
		t.Fatalf("Confirm 失败: %v", err)
	}
	if got := statusOf(t, ctx, ticket); got != entity.QRStatusConfirmed {
		t.Fatalf("Confirm 后应为 confirmed，实际 %s", got)
	}

	gotUID, err := qr.Claim(ctx, ticket, qrCtx)
	if err != nil {
		t.Fatalf("Claim 失败: %v", err)
	}
	if gotUID != uid {
		t.Fatalf("Claim 返回的 user_id = %d，期望 %d", gotUID, uid)
	}
	if got := statusOf(t, ctx, ticket); got != entity.QRStatusConsumed {
		t.Fatalf("Claim 后应为 consumed，实际 %s", got)
	}
}

// 手机 App 可以不单独调 scan 直接确认（设计文档 §9.1 承认这条捷径）
func TestConfirmWithoutScan(t *testing.T) {
	ctx := newDB(t)
	uid := seedUserID(t, ctx)
	ticket, _ := mustCreate(t, ctx)

	if err := qr.Confirm(ctx, ticket, uid, "DingTalk · iOS"); err != nil {
		t.Fatalf("pending → confirmed 应当被允许: %v", err)
	}
	if got := statusOf(t, ctx, ticket); got != entity.QRStatusConfirmed {
		t.Fatalf("状态应为 confirmed，实际 %s", got)
	}
}

// ── 领取凭据 ────────────────────────────────────────────────────────────────

// qr_ctx 不匹配 = 转发攻击。这是本功能最关键的一条防线，必须测到。
func TestClaimRejectsWrongCtx(t *testing.T) {
	ctx := newDB(t)
	uid := seedUserID(t, ctx)
	ticket, _ := mustCreate(t, ctx)
	if err := qr.Confirm(ctx, ticket, uid, "x"); err != nil {
		t.Fatal(err)
	}

	// 攻击者从截图里读到 ticket，但他没有受害者浏览器里的 qr_ctx
	for _, ctxTry := range []string{"", "wrong-ctx-value", "a"} {
		if _, err := qr.Claim(ctx, ticket, ctxTry); err == nil {
			t.Fatalf("用 qr_ctx=%q 竟然领取成功 —— 防转发机制失效", ctxTry)
		}
	}
	// 失败的尝试绝不能把票据消耗掉：真正的 PC 还得能领
	if got := statusOf(t, ctx, ticket); got != entity.QRStatusConfirmed {
		t.Fatalf("错误 ctx 的领取不该改变状态，实际 %s", got)
	}
}

// 旁观者（无 qr_ctx）不该看到真实进度
func TestPeekMasksStatusForOutsiders(t *testing.T) {
	ctx := newDB(t)
	uid := seedUserID(t, ctx)
	ticket, qrCtx := mustCreate(t, ctx)

	if v, err := qr.Peek(ctx, ticket, ""); err != nil || v.Status != entity.QRStatusPending {
		t.Fatalf("无 ctx 应看到 pending，实际 %v / %v", v, err)
	}
	if err := qr.Confirm(ctx, ticket, uid, "x"); err != nil {
		t.Fatal(err)
	}
	if v, _ := qr.Peek(ctx, ticket, ""); v.Status != entity.QRStatusPending {
		t.Fatalf("已 confirmed 但对无 ctx 者必须仍显示 pending，实际 %s", v.Status)
	}
	v, err := qr.Peek(ctx, ticket, qrCtx)
	if err != nil {
		t.Fatal(err)
	}
	if v.Status != entity.QRStatusConfirmed {
		t.Fatalf("持有正确 ctx 的 PC 应看到 confirmed，实际 %s", v.Status)
	}
	if v.ExpiresIn <= 0 || v.ExpiresIn > int(consts.QRTicketTTL.Seconds()) {
		t.Fatalf("expires_in 超出合理范围: %d", v.ExpiresIn)
	}
}

// ── 并发排他性 ──────────────────────────────────────────────────────────────

// 十个并发 claim 只有一个能建立登录态。
//
// 这一条如果破了，症状是"同一次扫码发出多个会话"，
// 而多出来的那些会话在票据行上没有任何记录 —— 属于查不到出处的那类问题。
func TestConcurrentClaimSingleWinner(t *testing.T) {
	ctx := newDB(t)
	uid := seedUserID(t, ctx)
	ticket, qrCtx := mustCreate(t, ctx)
	if err := qr.Confirm(ctx, ticket, uid, "x"); err != nil {
		t.Fatal(err)
	}

	const n = 10
	var (
		wg   sync.WaitGroup
		mu   sync.Mutex
		won  []int64
		fail int
	)
	start := make(chan struct{})
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start // 尽量让所有 goroutine 同时冲进 UPDATE
			got, err := qr.Claim(ctx, ticket, qrCtx)
			mu.Lock()
			defer mu.Unlock()
			if err == nil {
				won = append(won, got)
			} else {
				fail++
			}
		}()
	}
	close(start)
	wg.Wait()

	if len(won) != 1 {
		t.Fatalf("并发 claim 必须恰好 1 个成功，实际成功 %d 个: %v", len(won), won)
	}
	if won[0] != uid {
		t.Fatalf("成功者返回的 user_id = %d，期望 %d", won[0], uid)
	}
	if fail != n-1 {
		t.Fatalf("失败数应为 %d，实际 %d", n-1, fail)
	}
}

// 十个并发 confirm 只能有一次批准生效
func TestConcurrentConfirmSingleWinner(t *testing.T) {
	ctx := newDB(t)
	uid := seedUserID(t, ctx)
	ticket, _ := mustCreate(t, ctx)

	const n = 10
	var (
		wg  sync.WaitGroup
		mu  sync.Mutex
		okN int
	)
	start := make(chan struct{})
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			err := qr.Confirm(ctx, ticket, uid, "x")
			mu.Lock()
			if err == nil {
				okN++
			}
			mu.Unlock()
		}()
	}
	close(start)
	wg.Wait()

	if okN != 1 {
		t.Fatalf("并发 confirm 必须恰好 1 个成功，实际 %d 个", okN)
	}
}

// 并发 scan 同理：只有一台设备"第一次扫上"
func TestConcurrentScanSingleWinner(t *testing.T) {
	ctx := newDB(t)
	ticket, _ := mustCreate(t, ctx)

	const n = 8
	var (
		wg   sync.WaitGroup
		mu   sync.Mutex
		wins int
	)
	start := make(chan struct{})
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			if err := qr.Scan(ctx, ticket, "x"); err == nil {
				mu.Lock()
				wins++
				mu.Unlock()
			}
		}()
	}
	close(start)
	wg.Wait()

	if wins != 1 {
		t.Fatalf("并发 scan 必须恰好 1 个成功，实际 %d 个", wins)
	}
}

// ── 非法迁移 ────────────────────────────────────────────────────────────────

func TestIllegalTransitions(t *testing.T) {
	ctx := newDB(t)
	uid := seedUserID(t, ctx)

	t.Run("已确认后不能再扫码", func(t *testing.T) {
		ticket, _ := mustCreate(t, ctx)
		if err := qr.Confirm(ctx, ticket, uid, "x"); err != nil {
			t.Fatal(err)
		}
		if err := qr.Scan(ctx, ticket, "x"); err == nil {
			t.Fatal("confirmed → scanned 不该被允许")
		}
	})

	t.Run("已消费的票据不能再被拒绝或重复确认", func(t *testing.T) {
		ticket, qrCtx := mustCreate(t, ctx)
		if err := qr.Confirm(ctx, ticket, uid, "x"); err != nil {
			t.Fatal(err)
		}
		if _, err := qr.Claim(ctx, ticket, qrCtx); err != nil {
			t.Fatal(err)
		}
		if err := qr.Refuse(ctx, ticket); err == nil {
			t.Fatal("consumed 之后 Refuse 不该成功")
		}
		if err := qr.Confirm(ctx, ticket, uid, "x"); err == nil {
			t.Fatal("consumed 之后再次 Confirm 不该成功")
		}
		if got := statusOf(t, ctx, ticket); got != entity.QRStatusConsumed {
			t.Fatalf("终态被改动了: %s", got)
		}
	})

	t.Run("取消后的票据不能领取", func(t *testing.T) {
		ticket, qrCtx := mustCreate(t, ctx)
		if err := qr.CancelByPC(ctx, ticket, qrCtx); err != nil {
			t.Fatal(err)
		}
		if _, err := qr.Claim(ctx, ticket, qrCtx); err == nil {
			t.Fatal("cancelled 的票据不该能被领取")
		}
	})

	t.Run("别人的票据不能被我取消", func(t *testing.T) {
		ticket, _ := mustCreate(t, ctx)
		if err := qr.CancelByPC(ctx, ticket, "not-my-ctx"); err == nil {
			t.Fatal("qr_ctx 不匹配却取消成功")
		}
	})

	t.Run("未知票据报 not_found", func(t *testing.T) {
		_, err := qr.Preview(ctx, "qrt_does_not_exist")
		var qe *qr.Error
		if !errors.As(err, &qe) || qe.Code != qr.CodeNotFound {
			t.Fatalf("应返回 qr_not_found，实际 %v", err)
		}
	})

	t.Run("未经确认不能领取", func(t *testing.T) {
		ticket, qrCtx := mustCreate(t, ctx)
		if _, err := qr.Claim(ctx, ticket, qrCtx); err == nil {
			t.Fatal("pending 状态下直接 Claim 竟然成功 —— 跳过了手机批准")
		}
	})
}

// ── 过期 ────────────────────────────────────────────────────────────────────

// expireNow 把票据的过期时间挪到过去。
//
// 用改库而不是改常量：QRTicketTTL 是编译期常量，为一个测试去开"可注入时钟"
// 的口子会波及整个 logic 层。把 expires_at 写成过去时刻，走的正是生产代码
// 同一条 WHERE expires_at > now() 分支 —— 测的是真判据。
func expireNow(t *testing.T, ctx context.Context, ticket string) {
	t.Helper()
	_, err := dao.QRLoginSession.Ctx(ctx).
		Where(dao.QRLoginSession.Columns().Ticket, ticket).
		Data(g.Map{dao.QRLoginSession.Columns().ExpiresAt: time.Now().Add(-time.Minute)}).
		Update()
	if err != nil {
		t.Fatalf("置过期失败: %v", err)
	}
}

func TestExpiry(t *testing.T) {
	ctx := newDB(t)
	uid := seedUserID(t, ctx)
	ticket, qrCtx := mustCreate(t, ctx)

	// 过期前先把手机端走完，模拟"批得太晚，PC 来晚了"
	if err := qr.Confirm(ctx, ticket, uid, "x"); err != nil {
		t.Fatal(err)
	}
	expireNow(t, ctx, ticket)

	if v, err := qr.Peek(ctx, ticket, qrCtx); err != nil {
		t.Fatal(err)
	} else if v.Status != entity.QRStatusExpired {
		t.Fatalf("过期票据应显示 expired，实际 %s", v.Status)
	}
	if _, err := qr.Claim(ctx, ticket, qrCtx); err == nil {
		t.Fatal("过期之后仍可领取会话 —— 这是必须堵死的口子")
	} else {
		var qe *qr.Error
		if !errors.As(err, &qe) || qe.Code != qr.CodeExpired {
			t.Fatalf("过期票据应报 qr_expired，实际 %v", err)
		}
	}
}

// 过期不能覆盖终态：一张已登录完成的票据显示成"已过期"会让审计记录自相矛盾
func TestExpiredDoesNotMaskTerminal(t *testing.T) {
	ctx := newDB(t)
	uid := seedUserID(t, ctx)
	ticket, qrCtx := mustCreate(t, ctx)
	if err := qr.Confirm(ctx, ticket, uid, "x"); err != nil {
		t.Fatal(err)
	}
	if _, err := qr.Claim(ctx, ticket, qrCtx); err != nil {
		t.Fatal(err)
	}
	expireNow(t, ctx, ticket)

	if got := statusOf(t, ctx, ticket); got != entity.QRStatusConsumed {
		t.Fatalf("终态不该被改写，实际 %s", got)
	}
	var row entity.QRLoginSession
	if _, err := db.ScanOne(ctx, dao.QRLoginSession.Ctx(ctx).
		Where(dao.QRLoginSession.Columns().Ticket, ticket), &row); err != nil {
		t.Fatal(err)
	}
	if s := row.EffectiveStatus(time.Now()); s != entity.QRStatusConsumed {
		t.Fatalf("已 consumed 的票据对外应仍是 consumed，实际 %s", s)
	}
}

// ── 清理 ────────────────────────────────────────────────────────────────────

func TestPurgeOnlyRemovesOldEnough(t *testing.T) {
	ctx := newDB(t)
	fresh, _ := mustCreate(t, ctx)
	stale, _ := mustCreate(t, ctx)

	// 刚过期的留着（仍在保留期内），过期超保留期的才删
	expireNow(t, ctx, stale)
	if _, err := dao.QRLoginSession.Ctx(ctx).
		Where(dao.QRLoginSession.Columns().Ticket, stale).
		Data(g.Map{dao.QRLoginSession.Columns().ExpiresAt: time.Now().Add(-consts.QRRetainAfterExpiry - time.Hour)}).
		Update(); err != nil {
		t.Fatal(err)
	}

	n, err := qr.Purge(ctx)
	if err != nil {
		t.Fatalf("Purge 失败: %v", err)
	}
	if n < 1 {
		t.Fatalf("Purge 应至少删掉 1 行，实际 %d", n)
	}
	if got := statusOf(t, ctx, fresh); got == "" {
		t.Fatal("新票据被误删了")
	}
	if _, err := qr.Preview(ctx, stale); err == nil {
		t.Fatal("过期很久的票据应该已被删除")
	}
	if _, err := qr.Preview(ctx, fresh); err != nil {
		t.Fatalf("仍在保留期内的票据不该被删: %v", err)
	}
}
