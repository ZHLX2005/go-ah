package api

import (
	"crypto/sha256"
	"encoding/base64"
	"strings"
	"testing"

	"github.com/ZHLX2005/go-ah/auth-hub/db"
)

// ============================================================
// PKCE 校验（S256 / plain / 错误 verifier）
// ============================================================

// s256 生成 RFC 7636 规定的 code_challenge
func s256(verifier string) string {
	h := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(h[:])
}

func TestVerifyPKCE_S256(t *testing.T) {
	// RFC 7636 Appendix B 官方测试向量
	const verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
	const expectedChallenge = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"

	if got := s256(verifier); got != expectedChallenge {
		t.Fatalf("S256 计算结果与 RFC 7636 向量不符: got=%s want=%s", got, expectedChallenge)
	}

	cases := []struct {
		name      string
		verifier  string
		challenge string
		method    string
		want      bool
	}{
		{"S256 正确", verifier, expectedChallenge, "S256", true},
		{"S256 错误 verifier", "wrong-verifier-value", expectedChallenge, "S256", false},
		{"S256 错误 challenge", verifier, "not-the-right-challenge", "S256", false},
		{"S256 空 challenge", verifier, "", "S256", false},
		{"plain 正确", "plain-verifier-123", "plain-verifier-123", "plain", true},
		{"plain 错误", "plain-verifier-123", "other", "plain", false},
		// 未知 method 一律按 S256 处理（比静默降级为 plain 更安全）
		{"未知 method 走 S256", verifier, expectedChallenge, "s256", true},
		{"未知 method 不降级为 plain", "abc", "abc", "unknown", false},
		{"空 method 走 S256", verifier, expectedChallenge, "", true},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := verifyPKCE(tc.verifier, tc.challenge, tc.method); got != tc.want {
				t.Errorf("verifyPKCE(%q, %q, %q) = %v, 期望 %v",
					tc.verifier, tc.challenge, tc.method, got, tc.want)
			}
		})
	}
}

// TestVerifyPKCE_NoVerifier 空 verifier 永不应通过（除非 challenge 也为空）
func TestVerifyPKCE_NoVerifier(t *testing.T) {
	if verifyPKCE("", "somechallenge", "S256") {
		t.Error("空 verifier 不应通过 S256 校验")
	}
}

// ============================================================
// redirect_uri 白名单
// ============================================================

func TestClientAllowsRedirect_ExactMatch(t *testing.T) {
	c := &db.OAuthClient{RedirectURIs: "http://127.0.0.1:8081/oauth/callback"}

	if !clientAllowsRedirect(c, "http://127.0.0.1:8081/oauth/callback") {
		t.Error("精确匹配应通过")
	}
	// 端口不同 -> 拒绝
	if clientAllowsRedirect(c, "http://127.0.0.1:9999/oauth/callback") {
		t.Error("端口不同应被拒绝（精确注册项不含通配）")
	}
	// 路径不同 -> 拒绝
	if clientAllowsRedirect(c, "http://127.0.0.1:8081/evil") {
		t.Error("路径不同应被拒绝")
	}
	// 主机不同 -> 拒绝
	if clientAllowsRedirect(c, "http://evil.com/oauth/callback") {
		t.Error("非注册主机应被拒绝")
	}
	// 空 -> 拒绝
	if clientAllowsRedirect(c, "") {
		t.Error("空 redirect_uri 应被拒绝")
	}
}

func TestClientAllowsRedirect_LoopbackWildcard(t *testing.T) {
	// CLI 客户端：端口通配
	c := &db.OAuthClient{
		RedirectURIs: "http://127.0.0.1:*/callback http://localhost:*/callback",
	}

	allow := []string{
		"http://127.0.0.1:9999/callback",
		"http://127.0.0.1:1/callback",
		"http://127.0.0.1:65535/callback",
		"http://localhost:8080/callback",
	}
	for _, u := range allow {
		if !clientAllowsRedirect(c, u) {
			t.Errorf("回环通配应放行: %s", u)
		}
	}

	deny := []struct {
		uri string
		why string
	}{
		{"http://127.0.0.1:9999/other", "路径不匹配"},
		{"http://evil.com:9999/callback", "非回环主机"},
		{"http://127.0.0.1/callback", "缺少端口"},
		{"http://127.0.0.1:abc/callback", "端口非数字"},
		{"https://127.0.0.1:9999/callback", "scheme 不匹配"},
		{"http://127.0.0.1:9999/callback/extra", "路径多了一层"},
		{"http://192.168.1.1:9999/callback", "内网非回环地址"},
		{"http://127.0.0.1.attacker.com:9999/callback", "域名前缀伪装"},
	}
	for _, d := range deny {
		if clientAllowsRedirect(c, d.uri) {
			t.Errorf("应拒绝 (%s): %s", d.why, d.uri)
		}
	}
}

// TestMatchRedirectPattern_EdgeCases 边界与解析陷阱
func TestMatchRedirectPattern_EdgeCases(t *testing.T) {
	// 曾经的 bug：用 strings.Index(pattern, "/") 取路径，
	// 会命中 "http://" 里的 "//"，导致路径解析错误
	pattern := "http://127.0.0.1:*/callback"
	cases := []struct {
		uri  string
		want bool
	}{
		{"http://127.0.0.1:12345/callback", true},
		{"http://127.0.0.1:12345/callbac", false},
		{"http://127.0.0.1:12345/callbackx", false},
		{"http://127.0.0.1:12345/", false},
	}
	for _, tc := range cases {
		if got := matchRedirectPattern(pattern, tc.uri); got != tc.want {
			t.Errorf("matchRedirectPattern(%q, %q) = %v, 期望 %v",
				pattern, tc.uri, got, tc.want)
		}
	}
}

func TestClientAllowsRedirect_MultipleURIs(t *testing.T) {
	c := &db.OAuthClient{
		RedirectURIs: "http://a.example/cb\nhttp://b.example/cb  http://c.example/cb",
	}
	for _, u := range []string{
		"http://a.example/cb",
		"http://b.example/cb",
		"http://c.example/cb",
	} {
		if !clientAllowsRedirect(c, u) {
			t.Errorf("多 URI 注册应放行: %s", u)
		}
	}
	if clientAllowsRedirect(c, "http://d.example/cb") {
		t.Error("未注册的 URI 应拒绝")
	}
}

func TestClientAllowsPostLogout(t *testing.T) {
	c := &db.OAuthClient{PostLogoutURIs: "http://127.0.0.1:8081/"}
	if !clientAllowsPostLogout(c, "http://127.0.0.1:8081/") {
		t.Error("已注册的登出地址应放行")
	}
	if clientAllowsPostLogout(c, "http://evil.com/") {
		t.Error("未注册的登出地址应拒绝")
	}
	// 空值表示允许（回落到 signout 页面）
	if !clientAllowsPostLogout(c, "") {
		t.Error("空 post_logout_uri 应放行")
	}
}

// ============================================================
// 密码哈希（argon2id）
// ============================================================

func TestPasswordHashRoundTrip(t *testing.T) {
	const pw = "test123456"
	h := db.HashPassword(pw)

	if !strings.HasPrefix(h, "argon2id$") {
		t.Fatalf("哈希应以 argon2id$ 开头: %s", h)
	}
	if parts := strings.Split(h, "$"); len(parts) != 3 {
		t.Fatalf("哈希格式应为 argon2id$salt$hash，实际 %d 段", len(parts))
	}
	if !db.VerifyPassword(pw, h) {
		t.Error("正确密码应校验通过")
	}
	if db.VerifyPassword("wrong-password", h) {
		t.Error("错误密码不应通过")
	}
	if db.VerifyPassword("", h) {
		t.Error("空密码不应通过")
	}
}

func TestPasswordHash_UniqueSalt(t *testing.T) {
	// 同一密码两次哈希应不同（随机盐）
	h1 := db.HashPassword("same-password")
	h2 := db.HashPassword("same-password")
	if h1 == h2 {
		t.Error("相同密码两次哈希不应相同（应使用随机盐）")
	}
	// 但都应能通过校验
	if !db.VerifyPassword("same-password", h1) || !db.VerifyPassword("same-password", h2) {
		t.Error("两个哈希都应能校验通过")
	}
}

func TestVerifyPassword_Malformed(t *testing.T) {
	bad := []string{
		"",
		"plaintext",
		"argon2id$onlyonepart",
		"bcrypt$salt$hash",
		"argon2id$!!!notbase64!!!$alsobad",
	}
	for _, b := range bad {
		if db.VerifyPassword("test123456", b) {
			t.Errorf("畸形哈希不应通过校验: %q", b)
		}
	}
}

// ============================================================
// 工具函数
// ============================================================

func TestItoa(t *testing.T) {
	cases := map[uint]string{0: "0", 1: "1", 9: "9", 10: "10", 123: "123", 4294967295: "4294967295"}
	for in, want := range cases {
		if got := itoa(in); got != want {
			t.Errorf("itoa(%d) = %q, 期望 %q", in, got, want)
		}
	}
}

func TestIsAllDigits(t *testing.T) {
	yes := []string{"0", "1", "80", "8080", "65535"}
	no := []string{"", "a", "80a", "a80", "80.1", "-1", " 80", "80 "}
	for _, s := range yes {
		if !isAllDigits(s) {
			t.Errorf("isAllDigits(%q) 应为 true", s)
		}
	}
	for _, s := range no {
		if isAllDigits(s) {
			t.Errorf("isAllDigits(%q) 应为 false", s)
		}
	}
}

func TestRandomToken(t *testing.T) {
	seen := make(map[string]bool)
	for i := 0; i < 200; i++ {
		tok := db.RandomToken(32)
		if tok == "" {
			t.Fatal("生成的 token 不应为空")
		}
		if seen[tok] {
			t.Fatalf("生成了重复的 token: %s", tok)
		}
		seen[tok] = true
		// URL 安全字符集
		for _, r := range tok {
			if !strings.ContainsRune("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_", r) {
				t.Fatalf("token 含非 URL 安全字符: %q", r)
			}
		}
	}
}

func TestTokenHashPrefix(t *testing.T) {
	if got := db.TokenHashPrefix("short"); got != "short" {
		t.Errorf("短 token 应原样返回, got=%q", got)
	}
	long := "abcdefghijklmnopqrstuvwxyz"
	if got := db.TokenHashPrefix(long); got != "abcdefghijkl..." {
		t.Errorf("长 token 应截断为前 12 位加省略号, got=%q", got)
	}
}
