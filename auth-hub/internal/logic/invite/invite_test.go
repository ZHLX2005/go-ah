package invite

import (
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/ZHLX2005/go-ah/auth-hub/internal/consts"
)

// ============================================================
// 取值校验：生成与修改共用，规则不一致就等于给"改配置"开了后门
// ============================================================

func TestValidateMaxUses(t *testing.T) {
	cases := []struct {
		name    string
		in      int
		wantErr bool
	}{
		{"1 次（一人一码）", 1, false},
		{"多人共用", 50, false},
		{"恰好等于上限", consts.MaxInvitationUses, false},
		{"零次", 0, true},
		{"负数", -1, true},
		{"超过上限", consts.MaxInvitationUses + 1, true},
		{"手滑多打几个零", 999999999, true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			err := validateMaxUses(c.in)
			if c.wantErr && err == nil {
				t.Fatalf("validateMaxUses(%d) 应当报错", c.in)
			}
			if !c.wantErr && err != nil {
				t.Fatalf("validateMaxUses(%d) 不应报错: %v", c.in, err)
			}
			if err != nil {
				assertKind(t, err, KindInvalid, CodeInvalid)
			}
		})
	}
}

func TestValidateExpiry(t *testing.T) {
	now := time.Date(2026, 10, 9, 12, 0, 0, 0, time.UTC)
	cases := []struct {
		name    string
		in      time.Time
		wantErr bool
	}{
		{"一分钟后", now.Add(time.Minute), false},
		{"一年后", now.AddDate(1, 0, 0), false},
		{"恰好等于最长有效期", now.AddDate(0, 0, consts.MaxInvitationValidDays), false},
		// 过期时间不能是"已经过去"：新建出来的码立刻处于过期状态，
		// 管理员会以为功能坏了，而原因只是时间填错。
		{"恰好是现在", now, true},
		{"一分钟前", now.Add(-time.Minute), true},
		{"超出最长有效期", now.AddDate(0, 0, consts.MaxInvitationValidDays+1), true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			err := validateExpiry(c.in, now)
			if c.wantErr && err == nil {
				t.Fatalf("validateExpiry(%s) 应当报错", c.in)
			}
			if !c.wantErr && err != nil {
				t.Fatalf("validateExpiry(%s) 不应报错: %v", c.in, err)
			}
		})
	}
}

func TestNormalizeNote(t *testing.T) {
	t.Run("去首尾空白", func(t *testing.T) {
		got, err := normalizeNote("  给张三  ")
		if err != nil {
			t.Fatalf("不应报错: %v", err)
		}
		if got != "给张三" {
			t.Errorf("got %q, 期望 %q", got, "给张三")
		}
	})

	t.Run("空备注允许", func(t *testing.T) {
		got, err := normalizeNote("   ")
		if err != nil {
			t.Fatalf("不应报错: %v", err)
		}
		if got != "" {
			t.Errorf("got %q, 期望空串", got)
		}
	})

	t.Run("恰好 255 个字符允许", func(t *testing.T) {
		// 按**字符**而不是字节数：备注是中文时，255 字节只有 85 个汉字，
		// 而数据库列的 VARCHAR(255) 是按字符计的。
		if _, err := normalizeNote(strings.Repeat("备", maxNoteLen)); err != nil {
			t.Fatalf("255 个字符不应报错: %v", err)
		}
	})

	t.Run("超长被拦下", func(t *testing.T) {
		_, err := normalizeNote(strings.Repeat("备", maxNoteLen+1))
		if err == nil {
			t.Fatal("超长备注应当报错（否则会变成数据库层的 500）")
		}
		assertKind(t, err, KindInvalid, CodeInvalid)
	})
}

// ============================================================
// 失败原因：Kind 决定状态码，Code 决定前端文案
// ============================================================

func TestErrorKinds(t *testing.T) {
	cases := []struct {
		name string
		err  error
		kind ErrKind
		code string
		msg  string
	}{
		{"参数非法", errInvalid(CodeInvalid, "可用次数必须大于 0"), KindInvalid, CodeInvalid, "可用次数必须大于 0"},
		{"不存在", errNotFound("邀请码不存在"), KindNotFound, CodeNotFound, "邀请码不存在"},
		{"账号冲突", errConflict(CodeUsernameTaken, "该账号已被占用"), KindConflict, CodeUsernameTaken, "该账号已被占用"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			ie, ok := c.err.(*Error)
			if !ok {
				t.Fatalf("错误类型应为 *invite.Error, 实际 %T", c.err)
			}
			if ie.Kind != c.kind {
				t.Errorf("Kind = %v, 期望 %v", ie.Kind, c.kind)
			}
			if ie.Code != c.code {
				t.Errorf("Code = %q, 期望 %q", ie.Code, c.code)
			}
			if ie.Msg != c.msg || ie.Error() != c.msg {
				t.Errorf("Msg/Error() = %q/%q, 期望 %q", ie.Msg, ie.Error(), c.msg)
			}
			// errors.As 要能穿透出来：控制器就是这么取 Kind 的
			var target *Error
			if !errors.As(c.err, &target) {
				t.Error("errors.As 应当能取出 *invite.Error")
			}
		})
	}
}

// TestRedeemCodesAreStable 原因码是接口契约的一部分（前端按它给文案），
// 改名等于改接口 —— 这里钉住取值。
func TestRedeemCodesAreStable(t *testing.T) {
	pairs := []struct{ got, want string }{
		{CodeInvalid, "invalid_request"},
		{CodeNotFound, "invite_not_found"},
		{CodeDisabled, "invite_disabled"},
		{CodeExpired, "invite_expired"},
		{CodeExhausted, "invite_exhausted"},
		{CodeUsernameTaken, "username_taken"},
	}
	for _, p := range pairs {
		if p.got != p.want {
			t.Errorf("原因码 %q 应为 %q（前端按它给文案，改名等于改接口）", p.got, p.want)
		}
	}
}

// TestInvitationCodePrefix 前缀是运维在日志/工单里辨认邀请码的依据
func TestInvitationCodePrefix(t *testing.T) {
	if consts.InvitationCodePrefix != "inv_" {
		t.Errorf("InvitationCodePrefix = %q, 期望 inv_", consts.InvitationCodePrefix)
	}
	// 码长 = 前缀 + 12 字节的 base64url（无填充，16 字符）
	if got := len(consts.InvitationCodePrefix) + 16; got != 20 {
		t.Errorf("邀请码长度 = %d, 期望 20", got)
	}
}

func assertKind(t *testing.T, err error, kind ErrKind, code string) {
	t.Helper()
	var ie *Error
	if !errors.As(err, &ie) {
		t.Fatalf("错误类型应为 *invite.Error, 实际 %T (%v)", err, err)
	}
	if ie.Kind != kind {
		t.Errorf("Kind = %v, 期望 %v", ie.Kind, kind)
	}
	if ie.Code != code {
		t.Errorf("Code = %q, 期望 %q", ie.Code, code)
	}
}
