// Package user_test 是 logic/user 的**外部测试包**，跑真实 PostgreSQL。
//
// 为什么登录这条路要落到真库上测：它唯一的输入是一串用户敲进来的字，
// 唯一的行为是"按它去库里找一行"，而这恰恰是内存 fake 最容易测出假绿的地方 ——
// 用 map 当存储时，"按邮箱也能找到"和"按账号找到"没有任何区别，
// 于是把 OrderAsc、把 '@' 分支写错都测不出来。
//
// 未配置 AUTH_HUB_TEST_DSN 时整包跳过（本地没库不该看到一片红）。
package user_test

import (
	"context"
	"testing"

	"github.com/gogf/gf/v2/os/gctx"

	"github.com/ZHLX2005/go-ah/auth-hub/internal/dao"
	"github.com/ZHLX2005/go-ah/auth-hub/internal/db"
	"github.com/ZHLX2005/go-ah/auth-hub/internal/logic/user"
	"github.com/ZHLX2005/go-ah/auth-hub/internal/testpg"
	"github.com/ZHLX2005/go-ah/auth-hub/internal/utility"
)

// newDB 在一次性 schema 上初始化整套存储（含种子里的唯一管理员），返回 ctx。
func newDB(t *testing.T) context.Context {
	t.Helper()

	dsn, _ := testpg.NewSchema(t)
	ctx := gctx.New()

	if err := db.Init(ctx, db.InitOptions{
		DSN:                dsn,
		GSACRedirectURIs:   "http://127.0.0.1:8081/oauth/callback",
		GSACPostLogoutURIs: "http://127.0.0.1:8081/login",
		// 用一组与默认值不同的管理员，顺带证明"登录名跟着配置走"：
		// 只有真实部署里那套配置能登进来，默认的 test 反而不该存在。
		AdminUsername: "owner",
		AdminEmail:    "owner@example.com",
		AdminPassword: "owner-password",
	}); err != nil {
		t.Fatalf("db.Init 失败: %v", err)
	}
	t.Cleanup(func() { _ = db.Instance().Close(ctx) })
	return ctx
}

// addUser 用与注册/建档完全相同的入口造一个普通账号，
// 不直接 INSERT —— 绕过建档案等于测一条生产上不存在的路径。
func addUser(t *testing.T, ctx context.Context, username, email, password string) int64 {
	t.Helper()
	ins := user.CreateInput{
		Username:     username,
		Email:        email,
		PasswordHash: utility.HashPassword(password),
	}
	tx, err := db.Instance().Begin(ctx)
	if err != nil {
		t.Fatalf("开启事务失败: %v", err)
	}
	u, err := user.InsertWithTx(ctx, tx, ins)
	if err != nil {
		_ = tx.Rollback()
		t.Fatalf("建档 %s 失败: %v", username, err)
	}
	if err := tx.Commit(); err != nil {
		t.Fatalf("提交失败: %v", err)
	}
	return u.Id
}

// ============================================================
// 登录名：账号或邮箱
// ============================================================

func TestAuthenticate_ByUsernameAndByEmail(t *testing.T) {
	ctx := newDB(t)
	id := addUser(t, ctx, "zhao", "2096343460@qq.com", "REDACTED")

	for _, tc := range []struct {
		name       string
		identifier string
	}{
		{"按账号", "zhao"},
		// 管理员是按邮箱配的，所以"邮箱也能当登录名"是这个功能的半边天：
		// 少了它，配 IDP_ADMIN_EMAIL 的人会拿到一个自己登不进去的账号
		{"按邮箱", "2096343460@qq.com"},
		{"账号带首尾空格", "  zhao  "},
	} {
		t.Run(tc.name, func(t *testing.T) {
			u, err := user.Authenticate(ctx, tc.identifier, "REDACTED")
			if err != nil {
				t.Fatalf("Authenticate(%q) 失败: %v", tc.identifier, err)
			}
			if u.Id != id {
				t.Errorf("登进的账号 id = %d, 期望 %d", u.Id, id)
			}
		})
	}
}

// TestAuthenticate_AdminByEmail 管理员用邮箱登录 —— 这正是生产上要用的那条路径
func TestAuthenticate_AdminByEmail(t *testing.T) {
	ctx := newDB(t)

	u, err := user.Authenticate(ctx, "owner@example.com", "owner-password")
	if err != nil {
		t.Fatalf("管理员按邮箱登录失败: %v", err)
	}
	if !u.IsAdmin {
		t.Error("登进来的管理员 is_admin=false")
	}
	if u.Username != "owner" {
		t.Errorf("username = %q, 期望 owner", u.Username)
	}
}

// TestAuthenticate_FailureCodes 失败原因必须可区分：
// 界面靠它给出「账号或邮箱不存在」还是「密码错误」这两种可操作提示。
// 这里断言的是**原因码**，不是文案 —— 文案会改，联调方依赖的是码。
func TestAuthenticate_FailureCodes(t *testing.T) {
	ctx := newDB(t)
	addUser(t, ctx, "zhao", "2096343460@qq.com", "REDACTED")

	for _, tc := range []struct {
		name       string
		identifier string
		password   string
		wantCode   string
	}{
		{"账号不存在", "nobody", "whatever", "user_not_found"},
		// 带 @ 的输入会走邮箱分支，同样要落到"不存在"而不是"密码错误"
		{"邮箱不存在", "nobody@example.com", "whatever", "user_not_found"},
		{"账号对应密码错误", "zhao", "wrong", "wrong_password"},
		{"邮箱对应密码错误", "2096343460@qq.com", "wrong", "wrong_password"},
		{"空登录名", "", "REDACTED", "user_not_found"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := user.Authenticate(ctx, tc.identifier, tc.password)
			if err == nil {
				t.Fatalf("Authenticate(%q, %q) 竟然成功了", tc.identifier, tc.password)
			}
			ae, ok := err.(*user.AuthError)
			if !ok {
				t.Fatalf("错误类型 = %T, 期望 *user.AuthError", err)
			}
			if ae.ErrorCode != tc.wantCode {
				t.Errorf("原因码 = %q, 期望 %q", ae.ErrorCode, tc.wantCode)
			}
		})
	}
}

// TestAuthenticate_UsernameWinsOverEmail 账号名与别人邮箱相同时，
// 账号优先。
//
// 这条性质现在靠 usernameRe 不允许 '@' 来保证（含 '@' 的输入不可能命中
// 账号分支），但那是一条**隐含**约束：哪天为了支持带 @ 的账号名放开字符集，
// 这个用例会立刻变成红色，而不是等到线上出现"某个账号登进去是别人"。
func TestAuthenticate_UsernameWinsOverEmail(t *testing.T) {
	ctx := newDB(t)

	// 制造冲突：B 的邮箱 = A 的账号名。注册接口现在拦得住（账号不能含 @），
	// 但历史数据里可能有，所以直接用 dao 造出来。
	aID := addUser(t, ctx, "shared", "a@example.com", "password-a")
	if _, err := dao.User.Ctx(ctx).Data(map[string]any{
		"username":      "b",
		"email":         "shared",
		"password_hash": utility.HashPassword("password-b"),
	}).InsertAndGetId(); err != nil {
		t.Fatalf("造冲突数据失败: %v", err)
	}

	u, err := user.Authenticate(ctx, "shared", "password-a")
	if err != nil {
		t.Fatalf("按账号登录失败: %v", err)
	}
	if u.Id != aID {
		t.Errorf("登进的账号 id = %d, 期望账号分支命中的 %d", u.Id, aID)
	}
}

// TestFindByEmail_DeterministicWithDuplicates email 上没有唯一索引，
// 同邮箱多行时必须稳定命中 id 最小的那条 —— 否则会出现
// "同一邮箱今天进 A、明天进 B"的偶发故障。
func TestFindByEmail_DeterministicWithDuplicates(t *testing.T) {
	ctx := newDB(t)

	first := addUser(t, ctx, "dup-1", "dup@example.com", "p1")
	addUser(t, ctx, "dup-2", "dup@example.com", "p2")

	for i := 0; i < 3; i++ {
		u, err := user.FindByEmail(ctx, "dup@example.com")
		if err != nil {
			t.Fatalf("第 %d 次查询失败: %v", i+1, err)
		}
		if u == nil {
			t.Fatal("没查到")
		}
		if u.Id != first {
			t.Fatalf("第 %d 次命中 id = %d, 期望稳定命中 %d", i+1, u.Id, first)
		}
	}
}
