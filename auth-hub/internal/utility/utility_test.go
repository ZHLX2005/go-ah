package utility

import (
	"strings"
	"testing"
)

// ============================================================
// 口令哈希（argon2id）
// ============================================================

func TestPasswordHashRoundTrip(t *testing.T) {
	const pw = "test123456"
	h := HashPassword(pw)

	if !strings.HasPrefix(h, "argon2id$") {
		t.Fatalf("哈希应以 argon2id$ 开头: %s", h)
	}
	if parts := strings.Split(h, "$"); len(parts) != 3 {
		t.Fatalf("哈希格式应为 argon2id$salt$hash，实际 %d 段", len(parts))
	}
	if !VerifyPassword(pw, h) {
		t.Error("正确密码应校验通过")
	}
	if VerifyPassword("wrong-password", h) {
		t.Error("错误密码不应通过")
	}
	if VerifyPassword("", h) {
		t.Error("空密码不应通过")
	}
}

func TestPasswordHash_UniqueSalt(t *testing.T) {
	// 同一密码两次哈希应不同（随机盐）
	h1 := HashPassword("same-password")
	h2 := HashPassword("same-password")
	if h1 == h2 {
		t.Error("相同密码两次哈希不应相同（应使用随机盐）")
	}
	// 但都应能通过校验
	if !VerifyPassword("same-password", h1) || !VerifyPassword("same-password", h2) {
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
		// 第三段不是合法 base64：解码失败必须判为不通过，而不是当成空哈希
		"argon2id$AAAAAAAAAAAAAAAAAAAAAA$***",
	}
	for _, b := range bad {
		if VerifyPassword("test123456", b) {
			t.Errorf("畸形哈希不应通过校验: %q", b)
		}
	}
}

// ============================================================
// 随机串
// ============================================================

func TestRandomToken(t *testing.T) {
	seen := make(map[string]bool)
	for i := 0; i < 200; i++ {
		tok := RandomToken(32)
		if tok == "" {
			t.Fatal("生成的 token 不应为空")
		}
		if seen[tok] {
			t.Fatalf("生成了重复的 token: %s", tok)
		}
		seen[tok] = true
		// URL 安全字符集（base64url 无填充）
		for _, r := range tok {
			if !strings.ContainsRune("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_", r) {
				t.Fatalf("token 含非 URL 安全字符: %q", r)
			}
		}
	}
}

// TestRandomToken_Length 长度按字节计，编码后为 4/3 倍（无填充向上取整）
func TestRandomToken_Length(t *testing.T) {
	cases := map[int]int{
		16: 22, // 16 字节 -> ceil(16/3)*4 = 24，去填充 22
		32: 43,
		48: 64,
	}
	for n, want := range cases {
		if got := len(RandomToken(n)); got != want {
			t.Errorf("RandomToken(%d) 长度 = %d, 期望 %d", n, got, want)
		}
	}
}

// ============================================================
// 内部分段
// ============================================================

func TestSplitN(t *testing.T) {
	cases := []struct {
		in   string
		sep  byte
		n    int
		want []string
	}{
		{"a$b$c", '$', 3, []string{"a", "b", "c"}},
		// 最后一段保留剩余内容：哈希里可能出现更多分隔符
		{"a$b$c$d", '$', 3, []string{"a", "b", "c$d"}},
		{"abc", '$', 3, []string{"abc"}},
		{"", '$', 3, []string{""}},
		{"a$b", '$', 2, []string{"a", "b"}},
	}
	for _, tc := range cases {
		got := splitN(tc.in, tc.sep, tc.n)
		if len(got) != len(tc.want) {
			t.Errorf("splitN(%q,%q,%d) = %v, 期望 %v", tc.in, tc.sep, tc.n, got, tc.want)
			continue
		}
		for i := range got {
			if got[i] != tc.want[i] {
				t.Errorf("splitN(%q,%q,%d)[%d] = %q, 期望 %q", tc.in, tc.sep, tc.n, i, got[i], tc.want[i])
			}
		}
	}
}
