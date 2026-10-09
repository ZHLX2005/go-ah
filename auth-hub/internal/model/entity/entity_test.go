package entity

import "testing"

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
