package db

import (
	"testing"
)

// ============================================================
// 种子数据：预置账号与客户端
// ============================================================

// setupSeedDB 在内存库上执行迁移 + 种子
func setupSeedDB(t *testing.T) string {
	t.Helper()
	// 使用临时文件库（seed 需要真实落盘表结构）
	path := t.TempDir() + "/seed.db"
	Init(path)
	return path
}

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
	path := t.TempDir() + "/idem.db"

	Init(path)
	var firstCount int64
	DB.Model(&User{}).Count(&firstCount)

	// 再次 Init 同一库，不应产生重复数据
	Init(path)
	var secondCount int64
	DB.Model(&User{}).Count(&secondCount)

	if firstCount != secondCount {
		t.Errorf("重复 Init 不应重复播种: %d -> %d", firstCount, secondCount)
	}

	var clientCount int64
	DB.Model(&OAuthClient{}).Count(&clientCount)
	if clientCount != 2 {
		t.Errorf("应注册 2 个客户端, 实际 %d", clientCount)
	}
}

func TestSeed_PromotesLegacyTestUser(t *testing.T) {
	path := t.TempDir() + "/legacy.db"

	// 先建库
	Init(path)

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
// 表结构完整性
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
	}
	for _, m := range models {
		if !DB.Migrator().HasTable(m.model) {
			t.Errorf("缺少表: %s", m.name)
		}
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

// contains 简单子串判断
func contains(s, sub string) bool {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}
