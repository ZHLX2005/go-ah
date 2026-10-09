package entity

import (
	"testing"
	"time"
)

// 三个布尔开关用 *bool，语义是「nil 表示未显式设置，按 true 处理」。
//
// 为什么不能用 bool：那样无法区分"没设置"与"显式关掉"，管理后台
// 就永远关不掉一个开关 —— 关掉的写入会被当成零值而被忽略。
func TestOAuthClientBoolSemantics(t *testing.T) {
	t.Run("nil 按 true 处理", func(t *testing.T) {
		c := &OAuthClient{}
		if !c.IsPublicClient() {
			t.Error("IsPublic 为 nil 时应按 true 处理")
		}
		if !c.PKCENeeded() {
			t.Error("PKCERequired 为 nil 时应按 true 处理")
		}
		if !c.IsEnabled() {
			t.Error("Enabled 为 nil 时应按 true 处理")
		}
	})

	t.Run("显式 false 必须被尊重", func(t *testing.T) {
		c := &OAuthClient{
			IsPublic:     boolPtr(false),
			PKCERequired: boolPtr(false),
			Enabled:      boolPtr(false),
		}
		if c.IsPublicClient() {
			t.Error("显式 false 不应被当成 nil")
		}
		if c.PKCENeeded() {
			t.Error("显式 false 不应被当成 nil")
		}
		if c.IsEnabled() {
			t.Error("显式 false 不应被当成 nil")
		}
	})
}

func boolPtr(b bool) *bool { return &b }

// 邀请码的「还能不能用」由 enabled / expires_at / used_count-max_uses 三者共同决定。
//
// 这套判断必须只有一份：管理端列表要显示状态、注册端要决定放不放行。
// 两处各写一遍的结果是「列表显示可用、注册却被拒」—— 用户看到的是系统坏了。
func TestInvitationCodeStatus(t *testing.T) {
	now := time.Date(2026, 10, 9, 12, 0, 0, 0, time.UTC)
	past := now.Add(-time.Hour)
	future := now.Add(time.Hour)

	cases := []struct {
		name       string
		code       InvitationCode
		wantStatus string
		wantRedeem bool
		wantRemain int
	}{
		{
			name:       "长期有效且未用完",
			code:       InvitationCode{MaxUses: 3, UsedCount: 1, Enabled: true},
			wantStatus: InvitationStatusActive,
			wantRedeem: true,
			wantRemain: 2,
		},
		{
			name:       "有有效期但还没到",
			code:       InvitationCode{MaxUses: 1, Enabled: true, ExpiresAt: &future},
			wantStatus: InvitationStatusActive,
			wantRedeem: true,
			wantRemain: 1,
		},
		{
			name:       "已过期",
			code:       InvitationCode{MaxUses: 1, Enabled: true, ExpiresAt: &past},
			wantStatus: InvitationStatusExpired,
			wantRedeem: false,
			wantRemain: 1,
		},
		{
			name:       "次数用尽",
			code:       InvitationCode{MaxUses: 2, UsedCount: 2, Enabled: true},
			wantStatus: InvitationStatusExhausted,
			wantRedeem: false,
			wantRemain: 0,
		},
		{
			name:       "已停用",
			code:       InvitationCode{MaxUses: 1, Enabled: false},
			wantStatus: InvitationStatusDisabled,
			wantRedeem: false,
			wantRemain: 1,
		},
		{
			// 判断顺序：停用是管理员自己做的决定，比"正好也过期了"更该被先看到
			name:       "既停用又过期时优先报停用",
			code:       InvitationCode{MaxUses: 1, Enabled: false, ExpiresAt: &past},
			wantStatus: InvitationStatusDisabled,
			wantRedeem: false,
			wantRemain: 1,
		},
		{
			// 用完 + 过期是常态（先被领光，然后时间到了），报"过期"即可
			name:       "既用完又过期时优先报过期",
			code:       InvitationCode{MaxUses: 1, UsedCount: 1, Enabled: true, ExpiresAt: &past},
			wantStatus: InvitationStatusExpired,
			wantRedeem: false,
			wantRemain: 0,
		},
		{
			// 数据异常（used > max）也不该让剩余次数变成负数
			name:       "used_count 超过 max_uses 时剩余为 0",
			code:       InvitationCode{MaxUses: 1, UsedCount: 5, Enabled: true},
			wantStatus: InvitationStatusExhausted,
			wantRedeem: false,
			wantRemain: 0,
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := c.code.Status(now); got != c.wantStatus {
				t.Errorf("Status = %q, 期望 %q", got, c.wantStatus)
			}
			if got := c.code.IsRedeemable(now); got != c.wantRedeem {
				t.Errorf("IsRedeemable = %v, 期望 %v", got, c.wantRedeem)
			}
			if got := c.code.Remaining(); got != c.wantRemain {
				t.Errorf("Remaining = %d, 期望 %d", got, c.wantRemain)
			}
		})
	}
}

// TestInvitationCodeStatusMatchesRedeemable 状态与"能否核销"必须一致：
// active 就是可核销，其余三个都不可核销。这两者一旦分叉，
// 界面会出现"显示可用但注册被拒"或者反过来"显示已停用但还能注册"。
func TestInvitationCodeStatusMatchesRedeemable(t *testing.T) {
	now := time.Now()
	past := now.Add(-time.Hour)
	all := []InvitationCode{
		{MaxUses: 1, Enabled: true},
		{MaxUses: 1, Enabled: true, ExpiresAt: &past},
		{MaxUses: 1, UsedCount: 1, Enabled: true},
		{MaxUses: 1, Enabled: false},
	}
	for _, c := range all {
		want := c.Status(now) == InvitationStatusActive
		if got := c.IsRedeemable(now); got != want {
			t.Errorf("Status=%q 但 IsRedeemable=%v，两者不一致", c.Status(now), got)
		}
	}
}

// TestUserLastLoginAtNilMeansNever 从未登录必须是 nil 指针，而不是零值时间。
//
// 零值时间（0001-01-01）在界面上会被格式化成"—"，与"从未登录"看起来一样，
// 但两者在数据层含义不同：一个是"没这一列数据"，一个是"这一列是零值"。
// 用指针区分开，管理端才能明确判断"这账号一次都没被用过"。
func TestUserLastLoginAtNilMeansNever(t *testing.T) {
	u := User{}
	if u.LastLoginAt != nil {
		t.Error("新建的 User 结构体 LastLoginAt 应为 nil")
	}
	now := time.Now()
	u.LastLoginAt = &now
	if u.LastLoginAt.IsZero() {
		t.Error("赋值后不应为零值")
	}
}
