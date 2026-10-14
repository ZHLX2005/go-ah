package auth

import "testing"

// return_to 由前端查询串带入、登录成功后原样交给浏览器跳转 —— 不设防就是
// 认证中心域名下的开放重定向（钓鱼跳板）。这里把边界逐个钉死。
func TestSanitizeReturnTo(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want string
	}{
		{"空值落回默认授权端点", "", defaultReturnTo},
		{"裸根路径合法", "/", "/"},
		{"站内相对路径原样保留（含查询串）", "/oauth2/auth?client_id=mn-rt&state=s1", "/oauth2/auth?client_id=mn-rt&state=s1"},
		{"协议相对地址被拒（等于换站）", "//evil.com/x", defaultReturnTo},
		{"绝对地址被拒", "https://evil.com/x", defaultReturnTo},
		{"http 绝对地址被拒", "http://evil.com", defaultReturnTo},
		{"非 HTTP 协议被拒", "javascript:alert(1)", defaultReturnTo},
		{"反斜杠归一化绕行被拒", `/\\evil.com`, defaultReturnTo},
		{"反斜杠开头的相对段被拒", "/\\evil.com", defaultReturnTo},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := sanitizeReturnTo(tc.in); got != tc.want {
				t.Fatalf("sanitizeReturnTo(%q) = %q, want %q", tc.in, got, tc.want)
			}
		})
	}
}
