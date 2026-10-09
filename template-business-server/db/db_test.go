package db

import (
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/gogf/gf/v2/os/gctx"
)

// ============================================================
// 测试基础设施
//
// 每个用例一个自己的 SQLite 文件（t.TempDir 随用例回收）。
// 不用 :memory: 是因为 database/sql 是连接池驱动的，内存库在不同连接上
// 是**不同的库**，偶发的"表不存在"会以很难复现的方式出现。
// ============================================================

func testDB(t *testing.T) {
	t.Helper()
	if err := Init(gctx.New(), filepath.Join(t.TempDir(), "test.db")); err != nil {
		t.Fatalf("初始化测试库失败: %v", err)
	}
	closeTestDB(t)
}

// closeTestDB 在用例结束时关掉连接池。
//
// 不关会留下锁住的 SQLite 文件句柄，Windows 上 t.TempDir() 的回收随即失败
// （"The process cannot access the file because it is being used by another
// process"），报在 cleanUp 阶段，看上去像用例本身挂了。t.Cleanup 是后进先出，
// 这里比 TempDir 注册得晚，所以一定先关池再删目录。
func closeTestDB(t *testing.T) {
	t.Helper()
	t.Cleanup(func() {
		// instance 可能因为 Init 早期报错而仍是 nil（或指向上一个用例已关的池）
		if instance != nil {
			_ = instance.Close(gctx.New())
		}
	})
}

// TestInit_Idempotent 每次启动都会跑一遍建表，重复执行不能报错或清库
func TestInit_Idempotent(t *testing.T) {
	path := filepath.Join(t.TempDir(), "test.db")
	ctx := gctx.New()
	closeTestDB(t)

	for i := 0; i < 3; i++ {
		if err := Init(ctx, path); err != nil {
			t.Fatalf("第 %d 次 Init 失败: %v", i+1, err)
		}
	}

	// 写一行再重复 Init，验证"重复建表不会清库"
	if err := CreateUser(ctx, &BusinessUser{Sub: "1", Username: "test"}); err != nil {
		t.Fatalf("建用户失败: %v", err)
	}
	if err := Init(ctx, path); err != nil {
		t.Fatalf("再次 Init 失败: %v", err)
	}
	u, err := UserBySub(ctx, "1")
	if err != nil {
		t.Fatalf("查用户失败: %v", err)
	}
	if u == nil {
		t.Fatal("重复 Init 后原有数据丢失")
	}
}

func TestInit_RejectsEmptyPath(t *testing.T) {
	if err := Init(gctx.New(), "  "); err == nil {
		t.Error("空路径应当报错，否则会静默连到某个默认文件上")
	}
}

// ============================================================
// 业务用户
// ============================================================

func TestUserBySub_NotFound(t *testing.T) {
	testDB(t)
	u, err := UserBySub(gctx.New(), "不存在")
	if err != nil {
		t.Fatalf("查询不应报错: %v", err)
	}
	if u != nil {
		t.Errorf("不存在时应返回 nil, got=%+v", u)
	}
}

func TestCreateUser_BackfillsID(t *testing.T) {
	testDB(t)
	ctx := gctx.New()

	u := &BusinessUser{Sub: "42", Username: "test", Nickname: "测试用户", Email: "t@example.com", LastLoginAt: time.Now()}
	if err := CreateUser(ctx, u); err != nil {
		t.Fatalf("建用户失败: %v", err)
	}
	if u.Id == 0 {
		t.Error("CreateUser 应回填自增主键（后续 Upsert 靠它判断插入/更新）")
	}
	if u.CreatedAt.IsZero() || u.UpdatedAt.IsZero() {
		t.Error("CreateUser 应写入 created_at / updated_at")
	}

	got, err := UserBySub(ctx, "42")
	if err != nil {
		t.Fatalf("查用户失败: %v", err)
	}
	if got == nil {
		t.Fatal("刚建的用户查不到")
	}
	if got.Username != "test" || got.Nickname != "测试用户" || got.Email != "t@example.com" {
		t.Errorf("字段未正确落库: %+v", got)
	}
	if got.LastLoginAt.IsZero() {
		t.Error("last_login_at 应被写入（时间列往返）")
	}
}

// TestSyncUserProfile_UpdatesInPlace 同步 IDP 资料不应产生第二行
func TestSyncUserProfile_UpdatesInPlace(t *testing.T) {
	testDB(t)
	ctx := gctx.New()

	u := &BusinessUser{Sub: "42", Username: "old", LastLoginAt: time.Now()}
	if err := CreateUser(ctx, u); err != nil {
		t.Fatalf("建用户失败: %v", err)
	}

	u.Username, u.Nickname, u.Email = "new", "新昵称", "n@example.com"
	u.LastLoginAt = time.Now()
	if err := SyncUserProfile(ctx, u); err != nil {
		t.Fatalf("同步资料失败: %v", err)
	}

	n, err := Instance().Model(TableBusinessUser).Ctx(ctx).Count()
	if err != nil {
		t.Fatalf("统计失败: %v", err)
	}
	if n != 1 {
		t.Errorf("用户数 = %d, 期望 1（同步必须更新而不是插入）", n)
	}

	got, _ := UserBySub(ctx, "42")
	if got.Username != "new" || got.Nickname != "新昵称" {
		t.Errorf("资料未更新: %+v", got)
	}
}

// ============================================================
// 业务会话
// ============================================================

func newSession(sid string, ttl time.Duration) *BusinessSession {
	now := time.Now()
	return &BusinessSession{
		SessionID:             sid,
		UserSub:               "42",
		IDToken:               "cipher-id",
		AccessToken:           "cipher-access",
		RefreshToken:          "cipher-refresh",
		Encrypted:             true,
		AccessTokenExpiresAt:  now.Add(10 * time.Minute),
		RefreshTokenExpiresAt: now.Add(7 * 24 * time.Hour),
		ExpiresAt:             now.Add(ttl),
	}
}

// TestUpsertSession_InsertThenUpdate 同一个对象写两次只应有一行
func TestUpsertSession_InsertThenUpdate(t *testing.T) {
	testDB(t)
	ctx := gctx.New()

	s := newSession("sess-1", 8*time.Hour)
	if err := UpsertSession(ctx, s); err != nil {
		t.Fatalf("首次写入失败: %v", err)
	}
	if s.Id == 0 {
		t.Error("首次写入应回填主键")
	}

	firstID := s.Id
	s.AccessToken = "cipher-access-2"
	if err := UpsertSession(ctx, s); err != nil {
		t.Fatalf("二次写入失败: %v", err)
	}
	if s.Id != firstID {
		t.Errorf("二次写入不应换主键: %d → %d", firstID, s.Id)
	}

	n, err := Instance().Model(TableBusinessSession).Ctx(ctx).Count()
	if err != nil {
		t.Fatalf("统计失败: %v", err)
	}
	if n != 1 {
		t.Errorf("会话行数 = %d, 期望 1", n)
	}

	got, err := SessionByID(ctx, "sess-1")
	if err != nil {
		t.Fatalf("查询失败: %v", err)
	}
	if got == nil {
		t.Fatal("会话查不到")
	}
	if got.AccessToken != "cipher-access-2" {
		t.Errorf("access_token 未更新: %q", got.AccessToken)
	}
	if !got.Encrypted {
		t.Error("encrypted 标记未正确往返（bool ↔ INTEGER）")
	}
	if got.AccessTokenExpiresAt.IsZero() || got.RefreshTokenExpiresAt.IsZero() {
		t.Error("过期时间列未正确往返")
	}
}

func TestSessionByID_NotFound(t *testing.T) {
	testDB(t)
	s, err := SessionByID(gctx.New(), "没有这个会话")
	if err != nil {
		t.Fatalf("查询不应报错: %v", err)
	}
	if s != nil {
		t.Errorf("不存在时应返回 nil, got=%+v", s)
	}
}

// TestSessionByID_ExpiredIsInvisible 过期会话必须查不出来。
//
// 这条断言同时钉住了"时间列在 SQLite 里能正确比较"这件事 ——
// 时间是通过驱动格式化成文本存的，比较依赖两侧格式一致。
func TestSessionByID_ExpiredIsInvisible(t *testing.T) {
	testDB(t)
	ctx := gctx.New()

	if err := UpsertSession(ctx, newSession("gone", -time.Minute)); err != nil {
		t.Fatalf("写入失败: %v", err)
	}
	s, err := SessionByID(ctx, "gone")
	if err != nil {
		t.Fatalf("查询报错: %v", err)
	}
	if s != nil {
		t.Error("已过期的会话不应被查出来（过期判定在 SQL 里，调用方不可能忘）")
	}

	// 未过期的必须查得出来，否则上面的断言可能是"表为空"导致的假通过
	if err := UpsertSession(ctx, newSession("alive", time.Hour)); err != nil {
		t.Fatalf("写入失败: %v", err)
	}
	s, err = SessionByID(ctx, "alive")
	if err != nil {
		t.Fatalf("查询报错: %v", err)
	}
	if s == nil {
		t.Error("未过期的会话必须查得出来")
	}
}

func TestDeleteSession(t *testing.T) {
	testDB(t)
	ctx := gctx.New()

	if err := UpsertSession(ctx, newSession("sess-del", time.Hour)); err != nil {
		t.Fatalf("写入失败: %v", err)
	}
	if err := DeleteSession(ctx, "sess-del"); err != nil {
		t.Fatalf("删除失败: %v", err)
	}
	if s, _ := SessionByID(ctx, "sess-del"); s != nil {
		t.Error("会话未被删除")
	}
	// 删不存在的会话不算错误（登出时重复触发是正常的）
	if err := DeleteSession(ctx, "sess-del"); err != nil {
		t.Errorf("删除不存在的会话不应报错: %v", err)
	}
}

func TestDeleteExpiredSessions_And_ActiveSessions(t *testing.T) {
	testDB(t)
	ctx := gctx.New()
	now := time.Now()

	if err := UpsertSession(ctx, newSession("expired", -time.Hour)); err != nil {
		t.Fatalf("写入失败: %v", err)
	}
	if err := UpsertSession(ctx, newSession("alive", time.Hour)); err != nil {
		t.Fatalf("写入失败: %v", err)
	}

	// 清理前：两行都在
	n, err := Instance().Model(TableBusinessSession).Ctx(ctx).Count()
	if err != nil {
		t.Fatalf("统计失败: %v", err)
	}
	if n != 2 {
		t.Fatalf("会话行数 = %d, 期望 2", n)
	}

	active, err := ActiveSessions(ctx, now)
	if err != nil {
		t.Fatalf("取活跃会话失败: %v", err)
	}
	if len(active) != 1 || active[0].SessionID != "alive" {
		t.Errorf("活跃会话 = %+v, 期望只有 alive", active)
	}

	deleted, err := DeleteExpiredSessions(ctx, now)
	if err != nil {
		t.Fatalf("清理失败: %v", err)
	}
	if deleted != 1 {
		t.Errorf("清理行数 = %d, 期望 1", deleted)
	}

	n, _ = Instance().Model(TableBusinessSession).Ctx(ctx).Count()
	if n != 1 {
		t.Errorf("清理后行数 = %d, 期望 1（有效会话不能被误删）", n)
	}
}

// ============================================================
// DDL 切分与工具函数
// ============================================================

func TestSplitStatements_CoversBothTables(t *testing.T) {
	stmts := splitStatements(schemaDDL)

	var creates, idx int
	for _, s := range stmts {
		switch {
		case strings.HasPrefix(s, "CREATE TABLE IF NOT EXISTS business_users"):
			creates++
		case strings.HasPrefix(s, "CREATE TABLE IF NOT EXISTS business_sessions"):
			creates++
		case strings.HasPrefix(s, "CREATE INDEX IF NOT EXISTS"),
			strings.HasPrefix(s, "CREATE UNIQUE INDEX IF NOT EXISTS"):
			idx++
		case strings.HasPrefix(s, "CREATE"):
			t.Errorf("意外的建表语句: %s", firstLine(s))
		}
	}
	if creates != 2 {
		t.Errorf("建表语句数 = %d, 期望 2（business_users + business_sessions）", creates)
	}
	if idx == 0 {
		t.Error("索引语句一条都没切出来")
	}

	for _, s := range stmts {
		if strings.Contains(s, "--") {
			t.Errorf("注释行未被剔除: %s", firstLine(s))
		}
		if strings.HasSuffix(s, ";") {
			t.Errorf("语句不该以分号结尾（交给驱动时会拼出两个分号）: %s", firstLine(s))
		}
	}
}

func TestFirstLine(t *testing.T) {
	if got := firstLine("a\nb\nc"); got != "a …" {
		t.Errorf("= %q", got)
	}
	if got := firstLine("single"); got != "single" {
		t.Errorf("= %q", got)
	}
}

func TestEnv(t *testing.T) {
	t.Setenv("BIZ_TEST_KEY", "v")
	if got := Env("BIZ_TEST_KEY", "def"); got != "v" {
		t.Errorf("= %q, 期望 v", got)
	}
	if got := Env("BIZ_TEST_KEY_MISSING", "def"); got != "def" {
		t.Errorf("= %q, 期望 def", got)
	}
}
