package admin

import (
	"strings"
	"testing"

	"github.com/ZHLX2005/go-ah/auth-hub/internal/consts"
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
			if got := MaskToken(c.in); got != c.want {
				t.Errorf("MaskToken(%q) = %q, 期望 %q", c.in, got, c.want)
			}
		})
	}
}

// TestMaskToken_NoFullLeak 掩码结果不应等于原文（足够长时）
func TestMaskToken_NoFullLeak(t *testing.T) {
	tok := "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.secret.payload"
	masked := MaskToken(tok)
	if masked == tok {
		t.Error("掩码后不应与原文完全相同")
	}
	if strings.Contains(masked, "secret") {
		t.Errorf("掩码应遮蔽中段敏感内容, got=%q", masked)
	}
}

// ============================================================
// 内置客户端
// ============================================================

// TestBuiltinClients 内置客户端名单是删除保护与种子数据的共同依据，
// 这里钉住取值：改名会让保护失效（删掉内置客户端会让平台不可用）
func TestBuiltinClients(t *testing.T) {
	if consts.ClientTemplateWeb != "template-web-client" {
		t.Errorf("ClientTemplateWeb = %q", consts.ClientTemplateWeb)
	}
	if consts.ClientCLI != "oidc-cli" {
		t.Errorf("ClientCLI = %q", consts.ClientCLI)
	}
	if consts.ClientGSAC != "gs-ac" {
		t.Errorf("ClientGSAC = %q", consts.ClientGSAC)
	}
}

// ============================================================
// 失败种类 → 状态码的语义（种类由业务层定，状态码由表示层定）
// ============================================================

// TestErrorKinds 业务层只回答"哪一类失败"，不再靠 message 文本反推状态码
func TestErrorKinds(t *testing.T) {
	cases := []struct {
		name string
		err  error
		kind ErrKind
		msg  string
	}{
		{"参数非法", errInvalid("client_id 不能为空"), KindInvalid, "client_id 不能为空"},
		{"目标不存在", errNotFound("客户端不存在"), KindNotFound, "客户端不存在"},
		{"冲突", errConflict("该 client_id 已存在"), KindConflict, "该 client_id 已存在"},
		{"受保护", errProtected("内置客户端不可删除"), KindProtected, "内置客户端不可删除"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			ae, ok := c.err.(*Error)
			if !ok {
				t.Fatalf("错误类型应为 *admin.Error, 实际 %T", c.err)
			}
			if ae.Kind != c.kind {
				t.Errorf("Kind = %v, 期望 %v", ae.Kind, c.kind)
			}
			if ae.Msg != c.msg {
				t.Errorf("Msg = %q, 期望 %q", ae.Msg, c.msg)
			}
			if ae.Error() != c.msg {
				t.Errorf("Error() = %q, 期望 %q", ae.Error(), c.msg)
			}
		})
	}
}
