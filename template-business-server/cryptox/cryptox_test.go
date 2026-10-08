package cryptox

import (
	"encoding/base64"
	"strings"
	"testing"
)

// ============================================================
// 加密引擎构建：密钥校验
// ============================================================

func TestNewEngineFromSecret_Empty(t *testing.T) {
	if _, err := NewEngineFromSecret(""); err == nil {
		t.Error("空密钥应报错")
	}
	if _, err := NewEngineFromSecret("   "); err == nil {
		t.Error("纯空白密钥应报错")
	}
}

func TestNewEngineFromSecret_TooShort(t *testing.T) {
	short := []string{"a", "123456789012345", "short"}
	for _, s := range short {
		if len(s) >= MinSecretLen {
			t.Fatalf("测试数据 %q 不应满足最小长度", s)
		}
		if _, err := NewEngineFromSecret(s); err == nil {
			t.Errorf("长度 %d 的密钥应被拒绝", len(s))
		}
	}
}

func TestNewEngineFromSecret_Valid(t *testing.T) {
	s := strings.Repeat("x", MinSecretLen)
	e, err := NewEngineFromSecret(s)
	if err != nil {
		t.Fatalf("合法密钥应通过: %v", err)
	}
	if e == nil {
		t.Fatal("应返回非空引擎")
	}
	// 恰好 MinSecretLen 应通过
	if _, err := NewEngineFromSecret(strings.Repeat("y", MinSecretLen)); err != nil {
		t.Errorf("%d 位密钥应通过: %v", MinSecretLen, err)
	}
}

// ============================================================
// 加密 / 解密往返
// ============================================================

func TestEncryptDecrypt_RoundTrip(t *testing.T) {
	e, _ := NewEngineFromSecret("test-secret-0123456789")

	plaintexts := []string{
		"short",
		"eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxIn0.signature",
		strings.Repeat("A", 4096),                    // 长 token
		"包含中文字符的令牌内容",                                // 多字节
		"special-chars !@#$%^&*()_+-=[]{}|;:',.<>/?", // 特殊字符
	}
	for _, p := range plaintexts {
		ct, err := e.Encrypt(p)
		if err != nil {
			t.Fatalf("加密失败: %v", err)
		}
		got, err := e.Decrypt(ct)
		if err != nil {
			t.Fatalf("解密失败: %v", err)
		}
		if got != p {
			t.Errorf("往返不一致: 期望 %q, 实际 %q", p, got)
		}
	}
}

func TestEncrypt_EmptyStaysEmpty(t *testing.T) {
	e, _ := NewEngineFromSecret("test-secret-0123456789")

	ct, err := e.Encrypt("")
	if err != nil {
		t.Fatalf("加密空串不应报错: %v", err)
	}
	if ct != "" {
		t.Errorf("空串加密结果应为空串, got=%q", ct)
	}
	pt, err := e.Decrypt("")
	if err != nil {
		t.Fatalf("解密空串不应报错: %v", err)
	}
	if pt != "" {
		t.Errorf("空串解密结果应为空串, got=%q", pt)
	}
}

// ============================================================
// 盐值与 nonce 随机性
// ============================================================

func TestEncrypt_RandomSaltAndNonce(t *testing.T) {
	e, _ := NewEngineFromSecret("test-secret-0123456789")
	const plain = "same-plaintext-value"

	seen := make(map[string]bool)
	for i := 0; i < 50; i++ {
		ct, _ := e.Encrypt(plain)
		if seen[ct] {
			t.Fatal("同一明文多次加密产生了相同密文（salt/nonce 未随机）")
		}
		seen[ct] = true
	}

	// 两次加密的盐值部分应不同
	c1, _ := e.Encrypt(plain)
	c2, _ := e.Encrypt(plain)
	s1 := saltOf(t, c1)
	s2 := saltOf(t, c2)
	if string(s1) == string(s2) {
		t.Error("两次加密的盐值不应相同")
	}
}

func TestEncrypt_SaltIsUniquePerRecord(t *testing.T) {
	e, _ := NewEngineFromSecret("test-secret-0123456789")
	c, _ := e.Encrypt("value")
	raw, err := base64.StdEncoding.DecodeString(c)
	if err != nil {
		t.Fatalf("密文应为标准 base64: %v", err)
	}
	if len(raw) < SaltLen+12 {
		t.Fatalf("密文长度不足: %d", len(raw))
	}
	// 结构：salt(16) || nonce(12) || ciphertext+tag
	salt := raw[:SaltLen]
	nonce := raw[SaltLen : SaltLen+12]
	if len(salt) != 16 || len(nonce) != 12 {
		t.Error("salt/nonce 长度不符")
	}
	// 盐不应全为 0
	allZero := true
	for _, b := range salt {
		if b != 0 {
			allZero = false
			break
		}
	}
	if allZero {
		t.Error("盐值不应全为 0")
	}
}

// ============================================================
// 密钥不匹配 / 篡改检测
// ============================================================

func TestDecrypt_WrongKeyFails(t *testing.T) {
	e1, _ := NewEngineFromSecret("secret-number-one-0123456")
	e2, _ := NewEngineFromSecret("secret-number-two-7654321")

	ct, _ := e1.Encrypt("sensitive-refresh-token")
	if ct == "" {
		t.Fatal("加密失败")
	}
	if _, err := e2.Decrypt(ct); err == nil {
		t.Error("使用不同密钥解密应失败")
	}
}

func TestDecrypt_TamperedCiphertextFails(t *testing.T) {
	e, _ := NewEngineFromSecret("test-secret-0123456789")
	ct, _ := e.Encrypt("sensitive-value")

	// 翻转密文最后一位（GCM tag 区）
	raw, _ := base64.StdEncoding.DecodeString(ct)
	raw[len(raw)-1] ^= 0x01
	tampered := base64.StdEncoding.EncodeToString(raw)

	if _, err := e.Decrypt(tampered); err == nil {
		t.Error("篡改密文应被 GCM 认证标签检测出来")
	}
}

func TestDecrypt_TamperedSaltFails(t *testing.T) {
	e, _ := NewEngineFromSecret("test-secret-0123456789")
	ct, _ := e.Encrypt("sensitive-value")

	raw, _ := base64.StdEncoding.DecodeString(ct)
	raw[0] ^= 0xFF // 改盐值
	tampered := base64.StdEncoding.EncodeToString(raw)

	if _, err := e.Decrypt(tampered); err == nil {
		t.Error("篡改盐值应导致解密失败")
	}
}

func TestDecrypt_MalformedInput(t *testing.T) {
	e, _ := NewEngineFromSecret("test-secret-0123456789")

	bad := []string{
		"not-base64!!!",
		"YWJj", // 太短
		base64.StdEncoding.EncodeToString([]byte("tooshort")),
	}
	for _, b := range bad {
		if _, err := e.Decrypt(b); err == nil {
			t.Errorf("畸形密文应报错: %q", b)
		}
	}
}

// ============================================================
// 明文不可见
// ============================================================

func TestEncrypt_NoPlaintextLeak(t *testing.T) {
	e, _ := NewEngineFromSecret("test-secret-0123456789")
	const token = "eyJhbGciOiJSUzI1NiJ9.UNIQUE_MARKER_PAYLOAD.SIGNATURE"

	// 多次加密都不应出现明文片段
	for i := 0; i < 20; i++ {
		ct, _ := e.Encrypt(token)
		if strings.Contains(ct, "UNIQUE_MARKER") {
			t.Fatalf("密文中泄漏了明文标记: %s", ct)
		}
		if strings.HasPrefix(ct, "eyJ") {
			t.Fatalf("密文以 JWT 特征前缀开头: %s", ct)
		}
		raw, _ := base64.StdEncoding.DecodeString(ct)
		if strings.Contains(string(raw), "UNIQUE_MARKER") {
			t.Fatal("base64 解码后泄漏了明文标记")
		}
	}
}

// ============================================================
// IsCiphertext 粗判（存量明文迁移用）
// ============================================================

func TestIsCiphertext(t *testing.T) {
	e, _ := NewEngineFromSecret("test-secret-0123456789")
	ct, _ := e.Encrypt("some-token-value")

	cases := []struct {
		name string
		in   string
		want bool
	}{
		{"空串", "", false},
		{"明文 JWT", "eyJhbGciOiJSUzI1NiJ9.payload.sig", false},
		{"普通明文", "plaintext-token", false},
		{"非法 base64", "!!!not-base64!!!", false},
		{"真实密文", ct, true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := IsCiphertext(c.in); got != c.want {
				t.Errorf("IsCiphertext(%q) = %v, 期望 %v", c.in, got, c.want)
			}
		})
	}
}

// ============================================================
// 确定性：同密钥同盐可复现（内部 deriveKey 稳定性）
// ============================================================

func TestDeriveKey_Deterministic(t *testing.T) {
	e1, _ := NewEngineFromSecret("stable-secret-0123456789")
	e2, _ := NewEngineFromSecret("stable-secret-0123456789")

	// 用固定盐派生，两个引擎应得到相同密钥
	salt := []byte("0123456789abcdef")
	k1 := e1.deriveKey(salt)
	k2 := e2.deriveKey(salt)

	if len(k1) != KeyLen {
		t.Fatalf("密钥长度应为 %d, 实际 %d", KeyLen, len(k1))
	}
	if string(k1) != string(k2) {
		t.Error("相同密钥材料 + 相同盐应派生出相同密钥")
	}

	// 不同盐 -> 不同密钥
	k3 := e1.deriveKey([]byte("fedcba9876543210"))
	if string(k1) == string(k3) {
		t.Error("不同盐应派生出不同密钥")
	}
}

// ============================================================
// 辅助
// ============================================================

func saltOf(t *testing.T, ct string) []byte {
	t.Helper()
	raw, err := base64.StdEncoding.DecodeString(ct)
	if err != nil {
		t.Fatalf("base64 解码失败: %v", err)
	}
	return raw[:SaltLen]
}
