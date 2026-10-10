// Package db_test 是 internal/db 的**外部测试包**。
//
// 写成外部包（package db_test）而不是内部包，是因为它要用 internal/testpg
// 建一次性 schema，而 testpg 又需要 import internal/db 来复用 DSN 解析 ——
// 内部测试包会让两者成环。不碰数据库的那部分测试仍留在 db 包内
// （db_test.go 里那些纯函数用例），两边各取所需。
package db_test

import (
	"context"
	"testing"
	"time"

	"github.com/gogf/gf/v2/os/gctx"

	"github.com/ZHLX2005/go-ah/auth-hub/internal/consts"
	"github.com/ZHLX2005/go-ah/auth-hub/internal/db"
	"github.com/ZHLX2005/go-ah/auth-hub/internal/testpg"
	"github.com/ZHLX2005/go-ah/auth-hub/internal/utility"
)

const (
	gsacRedirects  = "http://127.0.0.1:8081/oauth/callback"
	gsacPostLogout = "http://127.0.0.1:8081/login"
)

// newDB 在一次性 schema 上初始化整套存储，返回 ctx。
func newDB(t *testing.T) context.Context {
	t.Helper()

	dsn, _ := testpg.NewSchema(t)
	ctx := gctx.New()

	if err := db.Init(ctx, db.InitOptions{
		DSN:                dsn,
		GSACRedirectURIs:   gsacRedirects,
		GSACPostLogoutURIs: gsacPostLogout,
	}); err != nil {
		t.Fatalf("db.Init 失败: %v", err)
	}
	return ctx
}

// ============================================================
// 建表与种子数据
// ============================================================

func TestInit_CreatesSchemaAndTables(t *testing.T) {
	ctx := newDB(t)

	// 全部业务表都必须可用（漏建一张不会在启动时报错，只会等到被用到才炸）
	tables := []string{
		consts.TableUser,
		consts.TableOAuthClient,
		consts.TableOAuthAuthorizationCode,
		consts.TableOAuthRefreshToken,
		consts.TableOAuthAccessToken,
		consts.TableUserSession,
		consts.TableSigningKey,
		// 邀请码两张表：注册链路唯一新增的存储。它们漏建的症状特别隐蔽 ——
		// 服务照常启动，直到有人真的拿邀请码注册才报"表不存在"。
		consts.TableInvitationCode,
		consts.TableInvitationCodeUsage,
	}
	for _, tbl := range tables {
		// 用 Count 而不是 Scan(&map[string]any)：gf 的 Scan 只接受
		// struct / *struct / []struct / []*struct，传 map 会直接报
		// "element of parameter pointer for function Scan should type of
		// struct/*struct/[]struct/[]*struct"（GORM 是允许 map 的）。
		// 这里只想确认"表建出来了且能查"，不关心内容，Count 语义更准。
		if _, err := db.Instance().Model(tbl).Ctx(ctx).Count(); err != nil {
			t.Errorf("表 %s 不可查询: %v", tbl, err)
		}
	}

	// 新增列单独查一次：schema.sql 用 CREATE TABLE IF NOT EXISTS 建 users，
	// 对**已存在**的表它什么都不做，所以 last_login_at 必须靠 ALTER TABLE
	// ADD COLUMN IF NOT EXISTS 补上。这里的选择列就是那个 ALTER 的哨兵 ——
	// 少了它，升级部署后"最后登录"列会永远报错。
	var u struct {
		LastLoginAt *time.Time
	}
	if err := db.Instance().Model(consts.TableUser).Ctx(ctx).
		Where("username", consts.SeedAdminUsername).Scan(&u); err != nil {
		t.Fatalf("users.last_login_at 不可查询（ALTER TABLE 漏了？）: %v", err)
	}
	if u.LastLoginAt != nil {
		t.Errorf("预置账号从未登录过时 last_login_at 应为 NULL, got %v", u.LastLoginAt)
	}
}

// TestInit_SeedsSoleAdmin 种子必须建出**唯一**核心管理员：
// 它是平台的权限根（管理员 → 发邀请码 → 账号进入平台的唯一入口），
// 少建了进不去后台，多建了等于多一个能转走平台所有权的人。
func TestInit_SeedsSoleAdmin(t *testing.T) {
	ctx := newDB(t)

	var u struct {
		Id           int64
		Username     string
		Email        string
		PasswordHash string
		IsAdmin      bool
	}
	if err := db.Instance().Model(consts.TableUser).Ctx(ctx).
		Where("email", consts.SeedAdminEmail).Scan(&u); err != nil {
		t.Fatalf("查询管理员失败: %v", err)
	}
	if u.Id == 0 {
		t.Fatalf("未创建管理员 %s", consts.SeedAdminEmail)
	}
	if !u.IsAdmin {
		t.Error("配置的管理员账号必须 is_admin=true，否则管理后台进不去")
	}
	if u.Username != consts.SeedAdminUsername {
		t.Errorf("username = %q, 期望 %q", u.Username, consts.SeedAdminUsername)
	}
	if !utility.VerifyPassword(consts.SeedAdminPassword, u.PasswordHash) {
		t.Error("管理员的口令哈希与 SeedAdminPassword 不匹配")
	}

	// 「唯一」是这一项的关键：全表 is_admin=true 的行必须恰好一条
	assertSoleAdmin(t, ctx, u.Id)
}

// TestInit_DemotesOtherAdmins 旧库里已存在的其他管理员必须在启动时被降级。
// 这是"唯一核心管理员"真正的落地动作 —— 只保证新账号是管理员，
// 而放着旧管理员不管，等于权限根有两个，等于没有收敛。
func TestInit_DemotesOtherAdmins(t *testing.T) {
	dsn, _ := testpg.NewSchema(t)
	ctx := gctx.New()

	opt := db.InitOptions{
		DSN:                dsn,
		GSACRedirectURIs:   gsacRedirects,
		GSACPostLogoutURIs: gsacPostLogout,
	}
	if err := db.Init(ctx, opt); err != nil {
		t.Fatalf("首次 Init 失败: %v", err)
	}

	// 造一个"历史遗留管理员"：模拟之前手工提过权的账号
	id, err := db.Instance().Model(consts.TableUser).Ctx(ctx).Data(map[string]any{
		"username":      "legacy-admin",
		"email":         "legacy@example.com",
		"password_hash": utility.HashPassword("whatever"),
		"is_admin":      true,
	}).InsertAndGetId()
	if err != nil {
		t.Fatalf("造历史管理员失败: %v", err)
	}

	// 降级发生在 seed 里，而 seed 只在 Init 时跑 —— 再 Init 一次等同重启
	if err := db.Init(ctx, opt); err != nil {
		t.Fatalf("二次 Init 失败: %v", err)
	}

	var legacy struct {
		IsAdmin bool
	}
	if err := db.Instance().Model(consts.TableUser).Ctx(ctx).
		Where("id", id).Scan(&legacy); err != nil {
		t.Fatalf("查询历史管理员失败: %v", err)
	}
	if legacy.IsAdmin {
		t.Error("历史管理员未被降级：平台上仍有第二个管理员")
	}

	var admin struct{ Id int64 }
	if err := db.Instance().Model(consts.TableUser).Ctx(ctx).
		Where("email", consts.SeedAdminEmail).Scan(&admin); err != nil {
		t.Fatalf("查询管理员失败: %v", err)
	}
	assertSoleAdmin(t, ctx, admin.Id)
}

// TestInit_AdminFollowsOptions 管理员必须跟着配置走。
// 生产环境用 IDP_ADMIN_EMAIL/PASSWORD 指定真实管理员，这条路径不能只在
// 默认值上验证过 —— 默认值能过、配置项没接上，是这类改动最常见的失败形态。
func TestInit_AdminFollowsOptions(t *testing.T) {
	dsn, _ := testpg.NewSchema(t)
	ctx := gctx.New()

	const (
		wantUser  = "owner"
		wantEmail = "owner@example.com"
		wantPwd   = "a-strong-password"
	)
	if err := db.Init(ctx, db.InitOptions{
		DSN:                dsn,
		GSACRedirectURIs:   gsacRedirects,
		GSACPostLogoutURIs: gsacPostLogout,
		AdminUsername:      wantUser,
		AdminEmail:         wantEmail,
		AdminPassword:      wantPwd,
	}); err != nil {
		t.Fatalf("db.Init 失败: %v", err)
	}

	var u struct {
		Id           int64
		Username     string
		PasswordHash string
		IsAdmin      bool
	}
	if err := db.Instance().Model(consts.TableUser).Ctx(ctx).
		Where("email", wantEmail).Scan(&u); err != nil {
		t.Fatalf("查询失败: %v", err)
	}
	if u.Id == 0 {
		t.Fatalf("未按配置创建管理员 %s", wantEmail)
	}
	if u.Username != wantUser {
		t.Errorf("username = %q, 期望 %q", u.Username, wantUser)
	}
	if !u.IsAdmin {
		t.Error("按配置创建的管理员不是管理员")
	}
	if !utility.VerifyPassword(wantPwd, u.PasswordHash) {
		t.Error("按配置创建的管理员口令不对")
	}
	assertSoleAdmin(t, ctx, u.Id)

	// 指定了管理员就不该再建默认账号：留着它等于在公网 IdP 上
	// 挂一个口令写在常量里的可登录账号
	n, err := db.Instance().Model(consts.TableUser).Ctx(ctx).
		Where("username", consts.SeedAdminUsername).Count()
	if err != nil {
		t.Fatalf("统计默认账号失败: %v", err)
	}
	if n != 0 {
		t.Errorf("配置了管理员之后仍建出了默认账号 %s", consts.SeedAdminUsername)
	}
}

// assertSoleAdmin 断言全表只有 adminID 一个管理员
func assertSoleAdmin(t *testing.T, ctx context.Context, adminID int64) {
	t.Helper()
	admins, err := db.Instance().Model(consts.TableUser).Ctx(ctx).
		Where("is_admin", true).Count()
	if err != nil {
		t.Fatalf("统计管理员失败: %v", err)
	}
	if admins != 1 {
		t.Errorf("管理员数量 = %d, 期望恰好 1", admins)
	}
	var only struct{ Id int64 }
	if err := db.Instance().Model(consts.TableUser).Ctx(ctx).
		Where("is_admin", true).Scan(&only); err != nil {
		t.Fatalf("查询管理员失败: %v", err)
	}
	if only.Id != adminID {
		t.Errorf("唯一管理员 id = %d, 期望 %d", only.Id, adminID)
	}
}

func TestInit_SeedsClients(t *testing.T) {
	ctx := newDB(t)

	var c struct {
		Id           int64
		ClientID     string
		RedirectURIs string
		IsPublic     *bool
		PKCERequired *bool
		Enabled      *bool
	}
	if err := db.Instance().Model(consts.TableOAuthClient).Ctx(ctx).
		Where("client_id", consts.ClientGSAC).Scan(&c); err != nil {
		t.Fatalf("查询 gs-ac 客户端失败: %v", err)
	}
	if c.Id == 0 {
		t.Fatal("未注册 gs-ac 客户端 —— 业务侧会直接登录失败")
	}
	if c.RedirectURIs != gsacRedirects {
		t.Errorf("redirect_uris = %q, 期望 %q", c.RedirectURIs, gsacRedirects)
	}
	// 公共客户端 + 强制 PKCE：无密钥的客户端只能靠 PKCE 防授权码拦截
	if c.IsPublic == nil || !*c.IsPublic {
		t.Error("gs-ac 应为公共客户端")
	}
	if c.PKCERequired == nil || !*c.PKCERequired {
		t.Error("gs-ac 必须强制 PKCE")
	}

	// 模板客户端与 CLI 客户端也必须就位
	for _, id := range []string{consts.ClientTemplateWeb, consts.ClientCLI} {
		n, err := db.Instance().Model(consts.TableOAuthClient).Ctx(ctx).Where("client_id", id).Count()
		if err != nil {
			t.Fatalf("查询客户端 %s 失败: %v", id, err)
		}
		if n == 0 {
			t.Errorf("未注册内置客户端 %s", id)
		}
	}
}

// TestInit_Idempotent Init 每次启动都会跑一遍，重复执行不能产生重复数据
func TestInit_Idempotent(t *testing.T) {
	dsn, _ := testpg.NewSchema(t)
	ctx := gctx.New()

	opt := db.InitOptions{
		DSN:                dsn,
		GSACRedirectURIs:   gsacRedirects,
		GSACPostLogoutURIs: gsacPostLogout,
	}
	for i := 0; i < 3; i++ {
		if err := db.Init(ctx, opt); err != nil {
			t.Fatalf("第 %d 次 db.Init 失败: %v", i+1, err)
		}
	}

	// gdb 的 Count() 返回 (int, error)，与 GORM 的 Count(&n) 写指针不同
	users, err := db.Instance().Model(consts.TableUser).Ctx(ctx).Count()
	if err != nil {
		t.Fatalf("统计用户失败: %v", err)
	}
	clients, err := db.Instance().Model(consts.TableOAuthClient).Ctx(ctx).Count()
	if err != nil {
		t.Fatalf("统计客户端失败: %v", err)
	}
	// 一次种子：1 个账号 + 3 个客户端
	if users != 1 {
		t.Errorf("用户数 = %d, 期望 1（种子必须幂等）", users)
	}
	if clients != 3 {
		t.Errorf("客户端数 = %d, 期望 3（种子必须幂等）", clients)
	}
}

// TestInit_SyncsGSACRedirectURIs 换域名/端口后重启必须同步白名单，
// 否则登录会以 redirect_uri 不匹配失败
func TestInit_SyncsGSACRedirectURIs(t *testing.T) {
	dsn, _ := testpg.NewSchema(t)
	ctx := gctx.New()

	first := db.InitOptions{
		DSN:                dsn,
		GSACRedirectURIs:   "http://old.example/oauth/callback",
		GSACPostLogoutURIs: "http://old.example/login",
	}
	if err := db.Init(ctx, first); err != nil {
		t.Fatalf("首次 Init 失败: %v", err)
	}

	second := db.InitOptions{
		DSN:                dsn,
		GSACRedirectURIs:   gsacRedirects,
		GSACPostLogoutURIs: gsacPostLogout,
	}
	if err := db.Init(ctx, second); err != nil {
		t.Fatalf("二次 Init 失败: %v", err)
	}

	var c struct {
		RedirectURIs   string
		PostLogoutURIs string
	}
	if err := db.Instance().Model(consts.TableOAuthClient).Ctx(ctx).
		Where("client_id", consts.ClientGSAC).Scan(&c); err != nil {
		t.Fatalf("查询失败: %v", err)
	}
	if c.RedirectURIs != gsacRedirects {
		t.Errorf("redirect_uris = %q, 期望同步为 %q", c.RedirectURIs, gsacRedirects)
	}
	if c.PostLogoutURIs != gsacPostLogout {
		t.Errorf("post_logout_uris = %q, 期望同步为 %q", c.PostLogoutURIs, gsacPostLogout)
	}
}

// TestInit_KeepsExistingAdminPassword 账号已存在时不覆盖口令：
// 否则每次部署都会把用户改过的密码打回默认值
func TestInit_KeepsExistingAdminPassword(t *testing.T) {
	dsn, _ := testpg.NewSchema(t)
	ctx := gctx.New()

	opt := db.InitOptions{
		DSN:                dsn,
		GSACRedirectURIs:   gsacRedirects,
		GSACPostLogoutURIs: gsacPostLogout,
	}
	if err := db.Init(ctx, opt); err != nil {
		t.Fatalf("首次 Init 失败: %v", err)
	}

	// 用户改了密码
	changed := utility.HashPassword("a-different-password")
	if _, err := db.Instance().Model(consts.TableUser).Ctx(ctx).
		Where("username", consts.SeedAdminUsername).
		Data(map[string]any{"password_hash": changed}).Update(); err != nil {
		t.Fatalf("改密失败: %v", err)
	}

	if err := db.Init(ctx, opt); err != nil {
		t.Fatalf("二次 Init 失败: %v", err)
	}

	var u struct {
		PasswordHash string
	}
	if err := db.Instance().Model(consts.TableUser).Ctx(ctx).
		Where("username", consts.SeedAdminUsername).Scan(&u); err != nil {
		t.Fatalf("查询失败: %v", err)
	}
	if !utility.VerifyPassword("a-different-password", u.PasswordHash) {
		t.Error("重启后用户口令被重置了（种子不该覆盖已存在的账号）")
	}
}

// TestInit_RejectsInvalidDSN 非法 DSN 必须启动即失败，不能静默降级
func TestInit_RejectsInvalidDSN(t *testing.T) {
	ctx := gctx.New()
	for _, dsn := range []string{"", "mysql://u:p@h/db", "postgres://h/db"} {
		if err := db.Init(ctx, db.InitOptions{DSN: dsn}); err == nil {
			t.Errorf("非法 DSN 应当报错: %q", dsn)
		}
	}
}
