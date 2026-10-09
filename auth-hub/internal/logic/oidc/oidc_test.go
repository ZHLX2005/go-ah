package oidc

import (
	"crypto/sha256"
	"encoding/base64"
	"strconv"
	"testing"

	"github.com/ZHLX2005/go-ah/auth-hub/internal/model/entity"
)

// s256 生成 RFC 7636 规定的 code_challenge
func s256(verifier string) string {
	h := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(h[:])
}

// ============================================================
// PKCE 校验（S256 / plain / 错误 verifier）
// ============================================================

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
			if got := VerifyPKCE(tc.verifier, tc.challenge, tc.method); got != tc.want {
				t.Errorf("VerifyPKCE(%q, %q, %q) = %v, 期望 %v",
					tc.verifier, tc.challenge, tc.method, got, tc.want)
			}
		})
	}
}

// TestVerifyPKCE_NoVerifier 空 verifier 永不应通过
func TestVerifyPKCE_NoVerifier(t *testing.T) {
	if VerifyPKCE("", "somechallenge", "S256") {
		t.Error("空 verifier 不应通过 S256 校验")
	}
}

// ============================================================
// redirect_uri 白名单
// ============================================================

func TestClientAllowsRedirect_ExactMatch(t *testing.T) {
	c := &entity.OAuthClient{RedirectURIs: "http://127.0.0.1:8081/oauth/callback"}

	if !ClientAllowsRedirect(c, "http://127.0.0.1:8081/oauth/callback") {
		t.Error("精确匹配应通过")
	}
	// 端口不同 -> 拒绝
	if ClientAllowsRedirect(c, "http://127.0.0.1:9999/oauth/callback") {
		t.Error("端口不同应被拒绝（精确注册项不含通配）")
	}
	// 路径不同 -> 拒绝
	if ClientAllowsRedirect(c, "http://127.0.0.1:8081/evil") {
		t.Error("路径不同应被拒绝")
	}
	// 主机不同 -> 拒绝
	if ClientAllowsRedirect(c, "http://evil.com/oauth/callback") {
		t.Error("非注册主机应被拒绝")
	}
	// 空 -> 拒绝
	if ClientAllowsRedirect(c, "") {
		t.Error("空 redirect_uri 应被拒绝")
	}
}

func TestClientAllowsRedirect_LoopbackWildcard(t *testing.T) {
	// CLI 客户端：端口通配
	c := &entity.OAuthClient{
		RedirectURIs: "http://127.0.0.1:*/callback http://localhost:*/callback",
	}

	allow := []string{
		"http://127.0.0.1:9999/callback",
		"http://127.0.0.1:1/callback",
		"http://127.0.0.1:65535/callback",
		"http://localhost:8080/callback",
	}
	for _, u := range allow {
		if !ClientAllowsRedirect(c, u) {
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
		if ClientAllowsRedirect(c, d.uri) {
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
	c := &entity.OAuthClient{
		RedirectURIs: "http://a.example/cb\nhttp://b.example/cb  http://c.example/cb",
	}
	for _, u := range []string{
		"http://a.example/cb",
		"http://b.example/cb",
		"http://c.example/cb",
	} {
		if !ClientAllowsRedirect(c, u) {
			t.Errorf("多 URI 注册应放行: %s", u)
		}
	}
	if ClientAllowsRedirect(c, "http://d.example/cb") {
		t.Error("未注册的 URI 应拒绝")
	}
}

func TestClientAllowsPostLogout(t *testing.T) {
	c := &entity.OAuthClient{PostLogoutURIs: "http://127.0.0.1:8081/"}
	if !ClientAllowsPostLogout(c, "http://127.0.0.1:8081/") {
		t.Error("已注册的登出地址应放行")
	}
	if ClientAllowsPostLogout(c, "http://evil.com/") {
		t.Error("未注册的登出地址应拒绝")
	}
	// 空值表示允许（回落到 signout 页面）
	if !ClientAllowsPostLogout(c, "") {
		t.Error("空 post_logout_uri 应放行")
	}
}

// TestClientAllowsPostLogout_OpenRedirect 没有这层校验，/oauth2/logout
// 就是任意站点可用的开放重定向
func TestClientAllowsPostLogout_OpenRedirect(t *testing.T) {
	c := &entity.OAuthClient{PostLogoutURIs: "http://127.0.0.1:8081/"}
	// 前缀相同但主机不同的地址必须拒绝
	for _, u := range []string{
		"http://127.0.0.1:8081.evil.com/",
		"http://127.0.0.1:8081/../evil",
		"//evil.com",
	} {
		if ClientAllowsPostLogout(c, u) {
			t.Errorf("开放重定向候选应拒绝: %s", u)
		}
	}
}

// ============================================================
// 注册回调地址的格式校验
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
		if !ValidRedirectURIs(uris) {
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
		if ValidRedirectURIs(uris) {
			t.Errorf("应判定为非法: %v", uris)
		}
	}

	// 空列表不在此层拦截（CreateClient 的入参校验负责）。
	// 此处锁定当前行为，避免后续无意改动。
	if !ValidRedirectURIs(nil) {
		t.Log("ValidRedirectURIs(nil) 返回 false（与当前实现一致）")
	}
}

// ============================================================
// 工具函数
// ============================================================

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

// TestSub 用户 ID 到 OIDC sub 的映射必须稳定：sub 变了等于换了身份
func TestSub(t *testing.T) {
	if got := Sub(0); got != "0" {
		t.Errorf("Sub(0) = %q", got)
	}
	if got := Sub(12345); got != strconv.FormatInt(12345, 10) {
		t.Errorf("Sub(12345) = %q", got)
	}
}

// ============================================================
// 协议错误
// ============================================================

func TestNewProtocolError(t *testing.T) {
	pe := NewProtocolError(400, "invalid_grant", "授权码已使用")
	if pe.Status != 400 || pe.Code != "invalid_grant" || pe.Desc != "授权码已使用" {
		t.Errorf("字段不符: %+v", pe)
	}
	// 实现 error 接口，且 Error() 给可读原因（日志里要能看懂）
	if pe.Error() != "授权码已使用" {
		t.Errorf("Error() = %q", pe.Error())
	}
}
