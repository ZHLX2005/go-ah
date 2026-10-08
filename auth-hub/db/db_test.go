package db

import (
	"net/url"
	"sync"
	"testing"

	"github.com/ZHLX2005/go-ah/auth-hub/internal/testpg"
)

// ============================================================
// 测试基础设施
//
// 存储已从 SQLite 换成共享 PostgreSQL，因此每个测试在真库上开一个
// 一次性 schema（见 internal/testpg），跑完即 DROP。
// 未配置 AUTH_HUB_TEST_DSN 时全部跳过。
// ============================================================

// setupSeedDB 在一次性 schema 上执行迁移 + 种子，返回该 schema 的 DSN
func setupSeedDB(t *testing.T) string {
	t.Helper()
	dsn, _ := testpg.NewSchema(t)
	Init(dsn)
	return dsn
}

// resetKeys 清掉密钥的进程内状态，用于模拟「进程重启」
func resetKeys() {
	once = sync.Once{}
	SigningKey = nil
	KeyID = "idp-key-1"
}

// ============================================================
// 种子数据：预置账号与客户端
// ============================================================

func TestSeed_CreatesAdminUser(t *testing.T) {
	setupSeedDB(t)

	var u User
	if err := DB.Where("username = ?", "test").First(&u).Error; err != nil {
		t.Fatalf("未找到预置账号 test: %v", err)
	}
	if !u.IsAdmin {
		t.Error("预置账号 test 应为管理员")
	}
	if !VerifyPassword("test123456", u.PasswordHash) {
		t.Error("预置账号密码应为 test123456")
	}
	if VerifyPassword("wrong", u.PasswordHash) {
		t.Error("错误密码不应通过")
	}
	if u.Email == "" || u.Nickname == "" {
		t.Error("预置账号应带 email 与 nickname")
	}
}

func TestSeed_Idempotent(t *testing.T) {
	dsn, _ := testpg.NewSchema(t)

	Init(dsn)
	var firstCount int64
	DB.Model(&User{}).Count(&firstCount)

	// 再次 Init 同一库，不应产生重复数据
	Init(dsn)
	var secondCount int64
	DB.Model(&User{}).Count(&secondCount)

	if firstCount != secondCount {
		t.Errorf("重复 Init 不应重复播种: %d -> %d", firstCount, secondCount)
	}

	var clientCount int64
	DB.Model(&OAuthClient{}).Count(&clientCount)
	if clientCount != 3 {
		t.Errorf("应注册 3 个客户端(template-web-client / gs-ac / oidc-cli), 实际 %d", clientCount)
	}
}

func TestSeed_PromotesLegacyTestUser(t *testing.T) {
	setupSeedDB(t)

	// 模拟旧库：把 test 降级为普通用户
	if err := DB.Model(&User{}).Where("username = ?", "test").Update("is_admin", false).Error; err != nil {
		t.Fatalf("降级失败: %v", err)
	}
	var u User
	DB.Where("username = ?", "test").First(&u)
	if u.IsAdmin {
		t.Fatal("前置条件失败：应已降级")
	}

	// 重新播种应自动提升回管理员
	seed()

	DB.Where("username = ?", "test").First(&u)
	if !u.IsAdmin {
		t.Error("种子逻辑应把既有的 test 账号提升为管理员")
	}
}

// ============================================================
// 预置客户端配置
// ============================================================

func TestSeed_TemplateWebClient(t *testing.T) {
	setupSeedDB(t)

	var c OAuthClient
	if err := DB.Where("client_id = ?", "template-web-client").First(&c).Error; err != nil {
		t.Fatalf("未找到 template-web-client: %v", err)
	}
	if !c.IsPublicClient() {
		t.Error("模板业务客户端应为公共客户端(PKCE)")
	}
	if !c.PKCENeeded() {
		t.Error("模板业务客户端应强制 PKCE")
	}
	if !c.IsEnabled() {
		t.Error("模板业务客户端应默认启用")
	}
	if c.ClientSecret != "" {
		t.Error("公共客户端不应有 client_secret")
	}
	if c.RedirectURIs != "http://127.0.0.1:8081/oauth/callback" {
		t.Errorf("回调地址不匹配: %s", c.RedirectURIs)
	}
}

// TestSeed_GsacClient gs-ac 接入方客户端的注册形态
func TestSeed_GsacClient(t *testing.T) {
	setupSeedDB(t)

	var c OAuthClient
	if err := DB.Where("client_id = ?", "gs-ac").First(&c).Error; err != nil {
		t.Fatalf("未找到 gs-ac 客户端: %v", err)
	}
	if !c.IsPublicClient() || !c.PKCENeeded() || !c.IsEnabled() {
		t.Error("gs-ac 应为启用的 PKCE 公共客户端")
	}
	if c.ClientSecret != "" {
		t.Error("公共客户端不应有 client_secret")
	}
	// 两个前端都要能回调
	if !contains(c.RedirectURIs, "http://127.0.0.1:5173/oauth/callback") {
		t.Errorf("缺少 Vue 管理台回调地址, got=%q", c.RedirectURIs)
	}
	if !contains(c.RedirectURIs, "http://127.0.0.1:5173/access/oidc/callback") {
		t.Errorf("缺少 access 插件回调地址, got=%q", c.RedirectURIs)
	}
	if !contains(c.PostLogoutURIs, "http://127.0.0.1:5173/login") {
		t.Errorf("缺少统一登出回跳地址, got=%q", c.PostLogoutURIs)
	}
}

// TestSeed_GsacClient_EnvOverride 回调白名单可由环境变量覆盖（部署换域名用）
func TestSeed_GsacClient_EnvOverride(t *testing.T) {
	setupSeedDB(t)

	const custom = "https://gsac.example.com/oauth/callback"
	const customOut = "https://gsac.example.com/login"
	t.Setenv("GSAC_REDIRECT_URI", custom)
	t.Setenv("GSAC_POST_LOGOUT_URI", customOut)

	// 再次播种应按新环境变量同步白名单
	seed()

	var c OAuthClient
	if err := DB.Where("client_id = ?", "gs-ac").First(&c).Error; err != nil {
		t.Fatalf("未找到 gs-ac 客户端: %v", err)
	}
	if c.RedirectURIs != custom {
		t.Errorf("回调地址未跟随环境变量: got=%q want=%q", c.RedirectURIs, custom)
	}
	if c.PostLogoutURIs != customOut {
		t.Errorf("登出回跳未跟随环境变量: got=%q want=%q", c.PostLogoutURIs, customOut)
	}
}

func TestSeed_CLIClientLoopbackWildcard(t *testing.T) {
	setupSeedDB(t)

	var c OAuthClient
	if err := DB.Where("client_id = ?", "oidc-cli").First(&c).Error; err != nil {
		t.Fatalf("未找到 oidc-cli: %v", err)
	}
	if !c.IsPublicClient() || !c.PKCENeeded() {
		t.Error("CLI 客户端应为启用 PKCE 的公共客户端")
	}
	// 必须注册回环通配地址（CLI 端口动态分配）
	if !contains(c.RedirectURIs, "127.0.0.1:*/callback") {
		t.Errorf("CLI 客户端应注册回环通配回调, got=%q", c.RedirectURIs)
	}
	if !contains(c.RedirectURIs, "localhost:*/callback") {
		t.Errorf("CLI 客户端应同时注册 localhost 变体, got=%q", c.RedirectURIs)
	}
}

// ============================================================
// 表结构 / schema 隔离
// ============================================================

func TestAutoMigrate_AllTables(t *testing.T) {
	setupSeedDB(t)

	models := []struct {
		name  string
		model interface{}
	}{
		{"users", &User{}},
		{"oauth_clients", &OAuthClient{}},
		{"oauth_authorization_codes", &OAuthAuthorizationCode{}},
		{"oauth_refresh_tokens", &OAuthRefreshToken{}},
		{"oauth_access_tokens", &OAuthAccessToken{}},
		{"user_sessions", &UserSession{}},
		{"signing_key_records", &SigningKeyRecord{}},
	}
	for _, m := range models {
		if !DB.Migrator().HasTable(m.model) {
			t.Errorf("缺少表: %s", m.name)
		}
	}
}

// TestSchemaIsolation 表必须落在独立 schema 里。
// 共享 PG 的 public 下已有别人的同名 users 表，串了会出大问题。
func TestSchemaIsolation(t *testing.T) {
	dsn, _ := testpg.NewSchema(t)
	Init(dsn)

	want := SchemaFromDSN(dsn)
	if want == DefaultSchema {
		t.Fatalf("测试 schema 不应等于默认生产 schema %s", DefaultSchema)
	}
	var got string
	if err := DB.Raw("SELECT current_schema()").Scan(&got).Error; err != nil {
		t.Fatalf("查询 current_schema 失败: %v", err)
	}
	if got != want {
		t.Errorf("search_path 未生效: current_schema=%s want=%s", got, want)
	}
}

func TestOAuthClient_ExplicitFalseRoundTrip(t *testing.T) {
	setupSeedDB(t)

	c := OAuthClient{
		ClientID:     "confidential",
		ClientName:   "机密客户端",
		RedirectURIs: "https://app.example.com/cb",
		IsPublic:     BoolPtr(false),
		PKCERequired: BoolPtr(false),
		Enabled:      BoolPtr(true),
	}
	if err := DB.Create(&c).Error; err != nil {
		t.Fatalf("创建失败: %v", err)
	}

	var got OAuthClient
	DB.Where("client_id = ?", "confidential").First(&got)
	if got.IsPublicClient() {
		t.Error("is_public=false 未能持久化（GORM default 标签陷阱回归）")
	}
	if got.PKCENeeded() {
		t.Error("pkce_required=false 未能持久化")
	}
	if !got.IsEnabled() {
		t.Error("enabled=true 未持久化")
	}
}

// ============================================================
// 签名密钥持久化
// ============================================================

// TestInitKeys_PersistsAcrossRestart 密钥必须跨重启稳定。
// 这条以前是坏的：密钥只在进程内存里生成，重启即换，而 kid 固定不变 ——
// 客户端缓存的 JWKS 会与之一致性失配，表现为所有已签发 token 验签失败。
func TestInitKeys_PersistsAcrossRestart(t *testing.T) {
	setupSeedDB(t)

	resetKeys()
	InitKeys()
	if SigningKey == nil {
		t.Fatal("首次启动应生成密钥")
	}
	first := SigningKey

	// 模拟重启：清掉进程内状态，重新走一遍加载流程
	resetKeys()
	InitKeys()

	if SigningKey == nil {
		t.Fatal("重启后未能加载签名密钥")
	}
	if SigningKey.N.Cmp(first.N) != 0 || SigningKey.D.Cmp(first.D) != 0 {
		t.Error("重启后签名密钥发生变化 —— 已签发的 id_token 会全部验签失败")
	}

	var n int64
	DB.Model(&SigningKeyRecord{}).Count(&n)
	if n != 1 {
		t.Errorf("应只持久化一把密钥, 实际 %d", n)
	}
}

// TestSigningKey_PEMRoundTrip PKCS#8 编解码往返
func TestSigningKey_PEMRoundTrip(t *testing.T) {
	setupSeedDB(t)
	resetKeys()
	InitKeys()

	pemStr, err := marshalPrivateKeyPEM(SigningKey)
	if err != nil {
		t.Fatalf("序列化失败: %v", err)
	}
	back, err := parsePrivateKeyPEM(pemStr)
	if err != nil {
		t.Fatalf("反序列化失败: %v", err)
	}
	if back.N.Cmp(SigningKey.N) != 0 {
		t.Error("PEM 往返后模数不一致")
	}
	if _, err := parsePrivateKeyPEM("not a pem"); err == nil {
		t.Error("非法 PEM 应报错")
	}
}

// TestEnvOverride_SigningKey 环境变量注入的固定密钥应被优先采用
// （多副本部署时靠它保证各实例用同一把）
func TestEnvOverride_SigningKey(t *testing.T) {
	setupSeedDB(t)

	resetKeys()
	InitKeys()
	expected := SigningKey
	pemStr, err := marshalPrivateKeyPEM(expected)
	if err != nil {
		t.Fatalf("序列化失败: %v", err)
	}

	// 清空密钥表，模拟另一台全新实例只拿到 env
	if err := DB.Exec("TRUNCATE TABLE signing_key_records").Error; err != nil {
		t.Fatalf("清空密钥表失败: %v", err)
	}
	resetKeys()
	t.Setenv(signingKeyEnv, pemStr)
	InitKeys()

	if SigningKey == nil || SigningKey.N.Cmp(expected.N) != 0 {
		t.Error("未采用环境变量注入的签名密钥")
	}

	// env 注入不应往库里写记录（避免多副本各写一份）
	var n int64
	DB.Model(&SigningKeyRecord{}).Count(&n)
	if n != 0 {
		t.Errorf("env 注入的密钥不应落库, 实际写入 %d 条", n)
	}
}

// ============================================================
// 纯函数
// ============================================================

func TestSchemaFromDSN(t *testing.T) {
	cases := []struct {
		dsn  string
		want string
	}{
		{"postgres://u:p@h:5432/db?sslmode=disable&search_path=auth_hub", "auth_hub"},
		{"postgres://u:p@h:5432/db?search_path=a,b", "a"},
		{"postgres://u:p@h:5432/db", DefaultSchema},
		{"postgres://u:p@h:5432/db?search_path=", DefaultSchema},
		{"::not a dsn::", DefaultSchema},
	}
	for _, c := range cases {
		if got := SchemaFromDSN(c.dsn); got != c.want {
			t.Errorf("SchemaFromDSN(%q) = %q, want %q", c.dsn, got, c.want)
		}
	}
}

func TestMaskDSN_HidesPassword(t *testing.T) {
	got := MaskDSN("postgres://postgres:secret123@47.110.80.47:5432/postgres?sslmode=disable")
	if contains(got, "secret123") {
		t.Errorf("日志串仍含明文密码: %s", got)
	}
	if !contains(got, "47.110.80.47") {
		t.Errorf("应保留主机信息便于排查: %s", got)
	}
}

func TestEnsureSchema_RejectsInjection(t *testing.T) {
	setupSeedDB(t)

	bad := "postgres://u:p@h:5432/db?search_path=" +
		url.QueryEscape(`auth_hub"; DROP SCHEMA public CASCADE; --`)
	if err := ensureSchema(bad); err == nil {
		t.Error("非法 schema 名应被拒绝（否则 IDP_DSN 就是 SQL 注入入口）")
	}
}

// contains 简单子串判断
func contains(s, sub string) bool {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}
