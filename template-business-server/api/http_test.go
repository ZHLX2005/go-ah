package api

import (
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/gogf/gf/v2/frame/g"
	"github.com/gogf/gf/v2/os/gctx"

	"github.com/ZHLX2005/go-ah/template-business-server/db"
)

// ============================================================
// 装配层的黑盒验证：路由是否都挂上、各端点的响应形状是否与契约一致。
//
// 刻意只走**不依赖 IDP 的路径**（未登录 / 参数非法 / 本机自检），
// 这样装配错误（少挂一条路由、信封写错、cookie 属性漏了）在 CI 里
// 不需要一个跑着的 IDP 就能被测出来。
// ============================================================

// testClient 测试用 HTTP 客户端。
//
// 显式把 Proxy 置空：宿主机器上常配了 HTTP 代理，默认客户端会去读
// HTTP_PROXY —— 代理拿不到回环地址，表现为 502 或直接挂住，排查起来
// 像是"服务没起来"。测试目标是本机，必须直连。
var testClient = &http.Client{
	Timeout:   10 * time.Second,
	Transport: &http.Transport{Proxy: nil},
}

// routeInventory 全部对外端点。新增端点必须同时加到这份清单里 ——
// 清单与路由表不一致时测试会失败，避免"加了路由忘了配套验证"。
var routeInventory = []struct{ method, path string }{
	{"GET", "/api/config"},
	{"POST", "/api/auth/callback"},
	{"GET", "/api/session"},
	{"GET", "/api/profile"},
	{"POST", "/api/refresh"},
	{"POST", "/api/logout"},
	{"GET", "/api/health"},
	{"GET", "/api/security-status"},
}

func TestHTTPContract(t *testing.T) {
	base := startBizServer(t)

	// ── 运维接口：裸对象，没有 code 信封 ───────────────────────────────────
	t.Run("健康检查是裸对象", func(t *testing.T) {
		res, body := do(t, "GET", base+"/api/health", "")
		if res.StatusCode != http.StatusOK {
			t.Fatalf("状态码 = %d, 期望 200", res.StatusCode)
		}
		if s(body["status"]) != "ok" {
			t.Errorf("status = %q", s(body["status"]))
		}
		if s(body["service"]) != "template-business-server" {
			t.Errorf("service = %q", s(body["service"]))
		}
		if _, has := body["code"]; has {
			t.Error("运维接口不应有 code 信封")
		}
	})

	t.Run("安全状态下发的 TTL 字样与契约一致", func(t *testing.T) {
		_, body := do(t, "GET", base+"/api/security-status", "")
		enc := m(body["token_encryption"])
		ref := m(body["auto_refresh"])

		if s(enc["algorithm"]) != "AES-256-GCM" {
			t.Errorf("algorithm = %q", s(enc["algorithm"]))
		}
		if enc["iterations"] != float64(120000) {
			t.Errorf("iterations = %v, 期望 120000", enc["iterations"])
		}
		if enc["ready"] != true {
			t.Error("测试里已注入密钥，ready 应为 true")
		}
		if s(enc["key_source"]) != "env:BIZ_TOKEN_SECRET" {
			t.Errorf("key_source = %q", s(enc["key_source"]))
		}
		// 这三个值是响应契约的一部分，不能变成 "10m0s"/"168h0m0s"
		for k, want := range map[string]string{
			"access_token_ttl": "10m",
			"refresh_ttl":      "168h",
			"threshold":        "2m",
		} {
			if s(ref[k]) != want {
				t.Errorf("%s = %q, 期望 %q", k, s(ref[k]), want)
			}
		}
	})

	// ── /api/config：裸对象，IDP 不可用时要给出兜底地址与原因 ─────────────
	t.Run("配置接口在 IDP 不可用时仍给出兜底地址", func(t *testing.T) {
		res, body := do(t, "GET", base+"/api/config", "")
		if res.StatusCode != http.StatusOK {
			t.Fatalf("状态码 = %d, 期望 200", res.StatusCode)
		}
		if _, has := body["code"]; has {
			t.Error("/api/config 是裸对象，不应有 code 信封")
		}
		if s(body["client_id"]) == "" {
			t.Error("client_id 缺失：前端靠它生成 PKCE 授权请求")
		}
		if s(body["scope"]) != "openid profile email" {
			t.Errorf("scope = %q", s(body["scope"]))
		}
		if body["idp_available"] != false {
			t.Error("测试环境没有 IDP，idp_available 应为 false")
		}
		if !strings.HasSuffix(s(body["authorization_endpoint"]), "/oauth2/auth") {
			t.Errorf("兜底授权地址不对: %q", s(body["authorization_endpoint"]))
		}
		if s(body["idp_error"]) == "" {
			t.Error("IDP 不可用时应给出 idp_error，否则排障只能靠猜")
		}
	})

	// ── 登录态：未登录不是错误 ────────────────────────────────────────────
	t.Run("未登录时 session 返回 code=0 且 data 为 null", func(t *testing.T) {
		res, body := do(t, "GET", base+"/api/session", "")
		if res.StatusCode != http.StatusOK {
			t.Fatalf("状态码 = %d, 期望 200（未登录不是错误，首页要据此显示登录入口）", res.StatusCode)
		}
		if body["code"] != float64(0) {
			t.Errorf("code = %v, 期望 0", body["code"])
		}
		if v, has := body["data"]; !has || v != nil {
			t.Errorf("data = %v, 期望 null", v)
		}
	})

	t.Run("未登录时 profile 返回 401", func(t *testing.T) {
		res, body := do(t, "GET", base+"/api/profile", "")
		if res.StatusCode != http.StatusUnauthorized {
			t.Fatalf("状态码 = %d, 期望 401", res.StatusCode)
		}
		if s(body["error"]) != "unauthorized" {
			t.Errorf("error = %q", s(body["error"]))
		}
		if _, has := body["code"]; has {
			t.Error("失败响应不应有 code 字段（与迁移前一致）")
		}
	})

	t.Run("伪造的会话 cookie 不被认账", func(t *testing.T) {
		// 值必须是 ASCII：net/http 解析 Cookie 头时按字节校验，
		// 非 ASCII 会被**整条丢弃**，请求退化成"没带 cookie"，
		// 这条用例就测不到"库里查不到这个 session_id"这条路径了。
		req, _ := http.NewRequest("GET", base+"/api/profile", nil)
		req.AddCookie(&http.Cookie{Name: SessionCookie, Value: "forged-session-id-not-in-db"})
		res, err := testClient.Do(req)
		if err != nil {
			t.Fatalf("请求失败: %v", err)
		}
		defer res.Body.Close()
		if res.StatusCode != http.StatusUnauthorized {
			t.Errorf("状态码 = %d, 期望 401（查不到会话应当是未登录，不是 500）", res.StatusCode)
		}
	})

	t.Run("未登录时 refresh 返回 401", func(t *testing.T) {
		res, body := do(t, "POST", base+"/api/refresh", "")
		if res.StatusCode != http.StatusUnauthorized {
			t.Fatalf("状态码 = %d, 期望 401", res.StatusCode)
		}
		if s(body["error"]) != "unauthorized" {
			t.Errorf("error = %q", s(body["error"]))
		}
	})

	// ── 登出：混合形状 + 清 cookie ────────────────────────────────────────
	t.Run("登出返回业务信封与 IDP 登出地址", func(t *testing.T) {
		res, body := do(t, "POST", base+"/api/logout", "")
		if res.StatusCode != http.StatusOK {
			t.Fatalf("状态码 = %d, 期望 200", res.StatusCode)
		}
		if body["code"] != float64(0) {
			t.Errorf("code = %v, 期望 0", body["code"])
		}
		if s(body["message"]) != "业务会话已销毁" {
			t.Errorf("message = %q", s(body["message"]))
		}
		if body["idp_logout"] != true {
			t.Error("idp_logout 应为 true：只删业务会话不足以完成单点登出")
		}
		u := s(body["logout_url"])
		for _, want := range []string{"/oauth2/logout?", "post_logout_redirect_uri=", "client_id="} {
			if !strings.Contains(u, want) {
				t.Errorf("logout_url 缺少 %q: %s", want, u)
			}
		}

		// 必须下发清除 cookie 的指令，否则浏览器会一直带着旧会话 ID。
		//
		// 断言 Max-Age=0 而不是 -1：gin 的 c.SetCookie(..., -1, ...) 内部也是
		// 走 http.SetCookie，而 net/http 序列化时 MaxAge<0 一律写成 Max-Age=0。
		// 也就是说这里要钉的是"和迁移前逐字节一致"，-1 从来就没出现过。
		setCookie := res.Header.Get("Set-Cookie")
		if !strings.Contains(setCookie, SessionCookie+"=;") || !strings.Contains(setCookie, "Max-Age=0") {
			t.Errorf("清除 cookie 的响应头不对: %q", setCookie)
		}
		if !strings.Contains(setCookie, "HttpOnly") {
			t.Errorf("会话 cookie 必须是 HttpOnly: %q", setCookie)
		}
	})

	// ── 回调入参：由适配层拦下，与 IDP 无关 ───────────────────────────────
	t.Run("回调请求体不是合法 JSON 时被适配器拦下", func(t *testing.T) {
		res, body := do(t, "POST", base+"/api/auth/callback", "{不是 JSON")
		if res.StatusCode != http.StatusBadRequest {
			t.Fatalf("状态码 = %d, 期望 400", res.StatusCode)
		}
		if s(body["error"]) != "invalid_request" {
			t.Errorf("error = %q", s(body["error"]))
		}
	})

	t.Run("回调时 IDP 不可达返回 503", func(t *testing.T) {
		res, body := do(t, "POST", base+"/api/auth/callback",
			`{"code":"c","code_verifier":"v"}`)
		if res.StatusCode != http.StatusServiceUnavailable {
			t.Fatalf("状态码 = %d, 期望 503", res.StatusCode)
		}
		if s(body["error"]) != "idp_unavailable" {
			t.Errorf("error = %q", s(body["error"]))
		}
	})

	// ── 路由清单 ↔ 路由表 一致性 ──────────────────────────────────────────
	t.Run("路由清单里的端点都可达（非 404）", func(t *testing.T) {
		for _, e := range routeInventory {
			res, _ := do(t, e.method, base+e.path, "")
			if res.StatusCode == http.StatusNotFound {
				t.Errorf("%s %s 返回 404：路由没挂上", e.method, e.path)
			}
		}
	})
}

// ============================================================
// 测试夹具
// ============================================================

func startBizServer(t *testing.T) string {
	t.Helper()

	if err := db.Init(gctx.New(), filepath.Join(t.TempDir(), "biz-http.db")); err != nil {
		t.Fatalf("初始化测试库失败: %v", err)
	}
	// 先注册关池、后注册关服务：t.Cleanup 后进先出，于是顺序是
	// 「关服务 → 关连接池 → 删临时目录」，不会出现服务还在跑时把库抽走。
	t.Cleanup(func() { _ = db.Instance().Close(gctx.New()) })
	// 注入一个可用的加密引擎（/api/security-status 会读它的状态）
	setupTestCrypto(t, testSecret)

	// 指向一个必然连不上的地址：本文件要验证的正是"IDP 不在时的行为"，
	// 且端口 1 会立刻被拒绝，不会让用例等超时。
	// （包级变量在测试里直接改是安全的：同一包的测试串行执行。）
	IDPIssuer = "http://127.0.0.1:1"
	ClientID = "template-web-client"
	RedirectURI = "http://127.0.0.1:8081/oauth/callback"
	PostLogoutURI = "http://127.0.0.1:8081/"
	t.Cleanup(func() { provider, verifier, oauth2Cfg = nil, nil, nil })

	addr := fmt.Sprintf("127.0.0.1:%d", freePort(t))
	s := g.Server("biz-http-test")
	s.SetAddr(addr)
	s.SetSwaggerPath("")
	s.SetOpenApiPath("")
	s.SetAccessLogEnabled(false)
	s.SetErrorLogEnabled(false)
	s.SetDumpRouterMap(false)

	// webDist 传空：容器部署下前端由 nginx 托管，Go 侧只提供 API
	Register(gctx.New(), s, "")

	if err := s.Start(); err != nil {
		t.Fatalf("启动测试服务失败: %v", err)
	}
	t.Cleanup(func() { _ = s.Shutdown() })

	base := "http://" + addr
	waitReady(t, base)
	return base
}

func freePort(t *testing.T) int {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("取空闲端口失败: %v", err)
	}
	defer func() { _ = l.Close() }()
	return l.Addr().(*net.TCPAddr).Port
}

func waitReady(t *testing.T, base string) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		res, err := testClient.Get(base + "/api/health")
		if err == nil {
			_ = res.Body.Close()
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatal("测试服务启动超时")
}

// do 发一个请求并解出 JSON body；body 为空串时不带请求体
func do(t *testing.T, method, url, payload string) (*http.Response, map[string]interface{}) {
	t.Helper()

	var rdr io.Reader
	if payload != "" {
		rdr = strings.NewReader(payload)
	}
	req, err := http.NewRequest(method, url, rdr)
	if err != nil {
		t.Fatalf("构造请求失败: %v", err)
	}
	if payload != "" {
		req.Header.Set("Content-Type", "application/json")
	}
	res, err := testClient.Do(req)
	if err != nil {
		t.Fatalf("%s %s 请求失败: %v", method, url, err)
	}
	defer res.Body.Close()

	raw, _ := io.ReadAll(res.Body)
	var body map[string]interface{}
	if len(raw) > 0 {
		if err := json.Unmarshal(raw, &body); err != nil {
			t.Fatalf("%s %s 响应不是 JSON（%s）: %s", method, url, res.Header.Get("Content-Type"), string(raw))
		}
	}
	return res, body
}

func s(v interface{}) string {
	if v == nil {
		return ""
	}
	str, _ := v.(string)
	return str
}

func m(v interface{}) map[string]interface{} {
	out, _ := v.(map[string]interface{})
	return out
}
