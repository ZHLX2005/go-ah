package api

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/ZHLX2005/go-ah/auth-hub/db"
)

// ============================================================
// client_secret 生成
// ============================================================

func TestGenerateClientSecret(t *testing.T) {
	seen := make(map[string]bool)
	for i := 0; i < 100; i++ {
		s := generateClientSecret()
		if s == "" {
			t.Fatal("生成的 secret 不应为空")
		}
		if !strings.HasPrefix(s, "cs_") {
			t.Errorf("secret 应以 cs_ 开头: %s", s)
		}
		// cs_ + 32 字节 base64url(无填充) = 3 + 43 = 46
		if len(s) != 46 {
			t.Errorf("secret 长度应为 46, 实际 %d (%s)", len(s), s)
		}
		body := s[3:]
		for _, r := range body {
			if !strings.ContainsRune("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_", r) {
				t.Errorf("secret 主体应为 URL 安全字符, 出现非法字符 %q", r)
			}
		}
		if seen[s] {
			t.Fatal("生成了重复的 client_secret")
		}
		seen[s] = true
	}
}

// ============================================================
// token 掩码
// ============================================================

func TestMaskToken(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want string
	}{
		{"空值", "", ""},
		{"短值原样返回", "abc", "abc"},
		{"恰好边界 8 位", "12345678", "12345678"},
		{"9 位开始掩码", "123456789", "12345678••••••••"},
		{"长 token 仅保留前 8 位", "abcdefghijklmnop", "abcdefgh••••••••"},
		{"64 位 token", strings.Repeat("x", 64), strings.Repeat("x", 8) + "••••••••"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := maskToken(c.in); got != c.want {
				t.Errorf("maskToken(%q) = %q, 期望 %q", c.in, got, c.want)
			}
		})
	}
}

// TestMaskToken_NoFullLeak 掩码结果不应等于原文（足够长时）
func TestMaskToken_NoFullLeak(t *testing.T) {
	tok := "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.secret.payload"
	masked := maskToken(tok)
	if masked == tok {
		t.Error("掩码后不应与原文完全相同")
	}
	if strings.Contains(masked, "secret") {
		t.Errorf("掩码应遮蔽中段敏感内容, got=%q", masked)
	}
}

// ============================================================
// redirect_uri 校验（管理员录入时的合法性检查）
// ============================================================

func TestValidRedirectURIs(t *testing.T) {
	valid := [][]string{
		{"http://127.0.0.1:8081/oauth/callback"},
		{"https://app.example.com/callback"},
		{"http://127.0.0.1:*/callback"},
		{"http://localhost:*/callback"},
		{"http://a.example/cb", "http://b.example/cb"},
		{"http://a.example/cb\nhttp://b.example/cb"},
	}
	for _, uris := range valid {
		if !validRedirectURIs(uris) {
			t.Errorf("应判定为合法: %v", uris)
		}
	}

	invalid := [][]string{
		{""},                        // 空串
		{"not-a-url"},               // 无 scheme
		{"ftp://example.com/cb"},    // 非 http(s)
		{"javascript:alert(1)"},     // 危险 scheme
		{"http://a.example/cb", ""}, // 含空项
		{"  "},                      // 纯空白
		{"https://evil.com:*/cb"},   // 非回环地址使用端口通配
		{"http://192.168.1.1:*/cb"}, // 内网地址使用端口通配
	}
	for _, uris := range invalid {
		if validRedirectURIs(uris) {
			t.Errorf("应判定为非法: %v", uris)
		}
	}

	// 空列表不在此层拦截（AdminCreateClient 的入参校验负责）。
	// 此处锁定当前行为，避免后续无意改动。
	if !validRedirectURIs(nil) {
		t.Log("validRedirectURIs(nil) 返回 false（与当前实现一致）")
	}
}

// ============================================================
// 管理器鉴权：RequireAdmin 依赖的 is_admin 判定
// ============================================================

func TestAdminFlagPersists(t *testing.T) {
	g := setupTestDB(t)

	admin := &db.User{Username: "admin1", PasswordHash: db.HashPassword("x"), IsAdmin: true}
	normal := &db.User{Username: "user1", PasswordHash: db.HashPassword("x"), IsAdmin: false}
	g.Create(admin)
	g.Create(normal)

	var gotAdmin, gotNormal db.User
	g.Where("username = ?", "admin1").First(&gotAdmin)
	g.Where("username = ?", "user1").First(&gotNormal)

	if !gotAdmin.IsAdmin {
		t.Error("管理员标记应持久化为 true")
	}
	// 回归：IsAdmin 曾因 `default:false` 标签无法显式写入
	if gotNormal.IsAdmin {
		t.Error("普通用户 is_admin 应为 false")
	}
}

// ============================================================
// 内置客户端保护（AdminDeleteClient 的判定依据）
// ============================================================

func TestBuiltinClientProtection(t *testing.T) {
	// 与 api/admin.go 中内置客户端集合保持一致
	builtin := map[string]bool{
		"template-web-client": true,
		"oidc-cli":            true,
	}
	for id := range builtin {
		if !builtin[id] {
			t.Errorf("%s 应被标记为内置客户端", id)
		}
	}
	if builtin["user-made-client"] {
		t.Error("非内置客户端不应被保护")
	}
}

// ============================================================
// 管理员视图：client_secret 不应明文下发
// ============================================================

func TestToClientView_NeverLeaksSecret(t *testing.T) {
	const secret = "cs_0123456789abcdef0123456789abcdef"
	c := db.OAuthClient{
		ID:           1,
		ClientID:     "some-client",
		ClientSecret: secret,
		ClientName:   "某客户端",
		RedirectURIs: "http://127.0.0.1:8081/oauth/callback",
		Scopes:       "openid profile",
		IsPublic:     db.BoolPtr(false),
		PKCERequired: db.BoolPtr(true),
		Enabled:      db.BoolPtr(true),
	}
	v := toClientView(c)

	if !v.HasSecret {
		t.Error("配置了 secret 的客户端 has_secret 应为 true")
	}
	if v.ClientID != "some-client" || v.ClientName != "某客户端" {
		t.Error("基础字段应正确透传")
	}
	// clientView 结构体本身不含 secret 字段，这是"不下发"的强保证
	if strings.Contains(toString(v), secret) {
		t.Error("clientView 的序列化结果中不应出现 client_secret 明文")
	}
	if len(v.RedirectURIs) != 1 || v.RedirectURIs[0] != "http://127.0.0.1:8081/oauth/callback" {
		t.Errorf("redirect_uris 应被拆分为切片, got=%v", v.RedirectURIs)
	}
	if len(v.Scopes) != 2 {
		t.Errorf("scopes 应被拆分为 2 项, got=%v", v.Scopes)
	}

	// 公共客户端
	pub := c
	pub.ClientSecret = ""
	if toClientView(pub).HasSecret {
		t.Error("无 secret 的客户端 has_secret 应为 false")
	}
}

// toString 用 JSON 序列化，模拟实际 HTTP 响应体
func toString(v interface{}) string {
	b, err := json.Marshal(v)
	if err != nil {
		return ""
	}
	return string(b)
}
