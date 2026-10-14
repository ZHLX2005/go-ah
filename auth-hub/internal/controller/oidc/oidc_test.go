package oidc

import "testing"

// 这两个助手是 prompt=login 的全部机制所在，值得钉死：
//   - 认错参数会导致「带 prompt 也照样静默 SSO」，换人登录失效；
//   - 摘错参数会导致「登录成功又被 prompt=login 打回登录页」，死循环。
// 走完整 Authorize 流程需要真库（客户端表 + 会话表），那里的覆盖由
// internal/logic/oidc/flow_test.go（AUTH_HUB_TEST_DSN 门控）承担；
// 这里只钉纯函数行为。

func TestPromptRequestsLogin(t *testing.T) {
	cases := []struct {
		name   string
		prompt string
		want   bool
	}{
		{"空参数不要求重登", "", false},
		{"裸 login 要求重登", "login", true},
		{"login 在组合里也成立", "consent login", true},
		{"login 在组合里（顺序无关）", "login consent", true},
		{"其余取值按未携带处理", "consent", false},
		{"none 不触发重登", "none", false},
		{"大小写宽容（客户端拼参常见）", "Login", true},
		{"前后空白可容忍", "  login  ", true},
		{"子串不算（select_login 不是 login）", "select_login", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := promptRequestsLogin(tc.prompt); got != tc.want {
				t.Fatalf("promptRequestsLogin(%q) = %v, want %v", tc.prompt, got, tc.want)
			}
		})
	}
}

func TestStripQueryParam(t *testing.T) {
	cases := []struct {
		name string
		in   string
		key  string
		want string
	}{
		{"中间的 prompt 被摘掉", "client_id=mn-rt&prompt=login&state=s1", "prompt", "client_id=mn-rt&state=s1"},
		{"开头的 prompt 被摘掉", "prompt=login&client_id=mn-rt", "prompt", "client_id=mn-rt"},
		{"结尾的 prompt 被摘掉", "client_id=mn-rt&prompt=login", "prompt", "client_id=mn-rt"},
		{"只剩 prompt 时摘成空串", "prompt=login", "prompt", ""},
		{"其余参数的顺序与编码原样保留", "scope=openid+profile&prompt=login&redirect_uri=http%3A%2F%2F127.0.0.1%3A1%2Fcb", "prompt", "scope=openid+profile&redirect_uri=http%3A%2F%2F127.0.0.1%3A1%2Fcb"},
		{"同名字段只摘完整键名（xprompt 不动）", "xprompt=1&prompt=login&a=2", "prompt", "xprompt=1&a=2"},
		{"没有该参数时原样返回", "client_id=mn-rt&state=s1", "prompt", "client_id=mn-rt&state=s1"},
		{"空 query 原样返回", "", "prompt", ""},
		{"裸键（无 = 号）不算命中", "prompt&client_id=x", "prompt", "prompt&client_id=x"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := stripQueryParam(tc.in, tc.key); got != tc.want {
				t.Fatalf("stripQueryParam(%q, %q) = %q, want %q", tc.in, tc.key, got, tc.want)
			}
		})
	}
}
