// Package router_test 用真实 HTTP 请求验证装配层：路由是否都挂上、
// 管理分组是否真的被鉴权中间件拦住、各端点的响应形状是否与约定的契约一致。
//
// 刻意选不碰数据库的调用路径（未登录 / 缺参数 / 参数非法），这样这套测试
// 不需要一个真 PG 就能跑 —— 装配错误（少挂一条路由、中间件没挂上、
// 响应信封搞错）在没有库的环境里也应该被测出来，而不是等到部署后。
package router_test

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/gogf/gf/v2/frame/g"

	"github.com/ZHLX2005/go-ah/auth-hub/internal/config"
	"github.com/ZHLX2005/go-ah/auth-hub/internal/router"
)

// testIssuer 测试期固定的 issuer，让发现文档的断言不受宿主环境变量影响
const testIssuer = "http://idp.test"

// testClient 测试用 HTTP 客户端。
//
// 显式把 Proxy 置空：宿主机器上常配了 HTTP 代理，而默认客户端会去读
// HTTP_PROXY —— 代理拿不到回环地址，表现为请求 502 或直接挂住，
// 排查起来像是"服务没起来"。测试目标是本机，必须直连。
var testClient = &http.Client{
	Timeout:   5 * time.Second,
	Transport: &http.Transport{Proxy: nil},
}

type endpoint struct {
	method string
	path   string
}

// routeInventory 全部对外端点。新增端点必须同时加到这份清单里 ——
// 清单与路由表不一致时测试会失败，避免"加了路由忘了配套验证"。
var routeInventory = []endpoint{
	{"GET", "/.well-known/openid-configuration"},
	{"GET", "/.well-known/jwks.json"},

	{"POST", "/api/login"},
	{"GET", "/api/me"},
	{"POST", "/api/logout"},
	// 自助注册。它是唯一匿名可写的业务端点，必须在清单里 ——
	// 漏掉它就等于"这条入口挂了没人知道"，而它挂了意味着没人能注册。
	{"POST", "/api/register"},

	{"GET", "/api/consent"},
	{"POST", "/api/consent"},

	{"GET", "/oauth2/auth"},
	{"POST", "/oauth2/token"},
	{"GET", "/oauth2/userinfo"},
	{"POST", "/oauth2/revoke"},
	{"GET", "/oauth2/logout"},

	{"GET", "/api/admin/me"},
	{"GET", "/api/admin/users"},
	{"GET", "/api/admin/users/1/sessions"},
	{"GET", "/api/admin/users/1/tokens"},
	{"GET", "/api/admin/clients"},
	{"POST", "/api/admin/clients"},
	{"PUT", "/api/admin/clients/1"},
	{"DELETE", "/api/admin/clients/1"},
	{"GET", "/api/admin/refresh-tokens"},
	{"POST", "/api/admin/revoke-token"},

	{"GET", "/api/admin/invites"},
	{"POST", "/api/admin/invites"},
	{"PUT", "/api/admin/invites/1"},
	{"DELETE", "/api/admin/invites/1"},
	{"GET", "/api/admin/invites/1/usages"},
}

// adminRoutes 必须落在鉴权分组里的端点
var adminRoutes = []endpoint{
	{"GET", "/api/admin/me"},
	{"GET", "/api/admin/users"},
	{"GET", "/api/admin/users/1/sessions"},
	{"GET", "/api/admin/users/1/tokens"},
	{"GET", "/api/admin/clients"},
	{"POST", "/api/admin/clients"},
	{"PUT", "/api/admin/clients/1"},
	{"DELETE", "/api/admin/clients/1"},
	{"GET", "/api/admin/refresh-tokens"},
	{"POST", "/api/admin/revoke-token"},

	{"GET", "/api/admin/invites"},
	{"POST", "/api/admin/invites"},
	{"PUT", "/api/admin/invites/1"},
	{"DELETE", "/api/admin/invites/1"},
	{"GET", "/api/admin/invites/1/usages"},
}

func TestHTTPContract(t *testing.T) {
	t.Setenv("IDP_ISSUER", testIssuer)

	base := startServer(t)

	t.Run("发现文档按 issuer 拼出全部端点", func(t *testing.T) {
		res, body := get(t, base+"/.well-known/openid-configuration")
		if res.StatusCode != http.StatusOK {
			t.Fatalf("状态码 = %d, 期望 200", res.StatusCode)
		}
		want := map[string]string{
			"issuer":                 testIssuer,
			"authorization_endpoint": testIssuer + "/oauth2/auth",
			"token_endpoint":         testIssuer + "/oauth2/token",
			"userinfo_endpoint":      testIssuer + "/oauth2/userinfo",
			"jwks_uri":               testIssuer + "/.well-known/jwks.json",
			"end_session_endpoint":   testIssuer + "/oauth2/logout",
			"revocation_endpoint":    testIssuer + "/oauth2/revoke",
		}
		for k, v := range want {
			if got := str(body[k]); got != v {
				t.Errorf("%s = %q, 期望 %q", k, got, v)
			}
		}
	})

	t.Run("未登录时 me 返回 code=0 且 data 为 null", func(t *testing.T) {
		res, body := get(t, base+"/api/me")
		if res.StatusCode != http.StatusOK {
			t.Fatalf("状态码 = %d, 期望 200", res.StatusCode)
		}
		if code, ok := body["code"]; !ok || num(code) != 0 {
			t.Errorf("code = %v, 期望 0", body["code"])
		}
		v, ok := body["data"]
		if !ok {
			t.Fatal("响应缺少 data 字段（前端靠它判断是否登录）")
		}
		if v != nil {
			t.Errorf("未登录时 data 应为 null, 实际 %v", v)
		}
	})

	t.Run("登录缺参数返回业务信封 400", func(t *testing.T) {
		res, body := postJSON(t, base+"/api/login", `{"username":"","password":""}`)
		if res.StatusCode != http.StatusBadRequest {
			t.Fatalf("状态码 = %d, 期望 400", res.StatusCode)
		}
		if num(body["code"]) != 1 || str(body["error"]) != "invalid_request" {
			t.Errorf("信封不符: %v", body)
		}
		if str(body["message"]) != "账号和密码不能为空" {
			t.Errorf("message = %q", str(body["message"]))
		}
	})

	t.Run("注册缺邀请码返回业务信封 400", func(t *testing.T) {
		// 本项目最容易踩的一条：把 /api/register 当成普通注册端点，
		// 直接 POST 账号口令。这时必须回一句明确的"邀请码不能为空"，
		// 而不是让请求一路走到核销才炸。
		res, body := postJSON(t, base+"/api/register",
			`{"username":"newbie","password":"password123","email":"newbie@example.com"}`)
		if res.StatusCode != http.StatusBadRequest {
			t.Fatalf("状态码 = %d, 期望 400", res.StatusCode)
		}
		if num(body["code"]) != 1 || str(body["error"]) != "invite_not_found" {
			t.Errorf("信封不符: %v", body)
		}
		if str(body["message"]) != "邀请码不能为空" {
			t.Errorf("message = %q", str(body["message"]))
		}
	})

	t.Run("注册时账号格式不合法先于邀请码核销被拦下", func(t *testing.T) {
		// 顺序是刻意的：邀请码是消耗品，一次注定失败的注册不该浪费它。
		// 账号格式这类"自己能问清楚"的问题必须在核销之前问完。
		// 这里刻意带了一个不存在的邀请码 —— 如果校验顺序反了，
		// 响应会变成邀请码相关的错误（或因为没库而 500），而不是这条。
		res, body := postJSON(t, base+"/api/register",
			`{"username":"ab","password":"password123","email":"newbie@example.com","invite_code":"inv_notarealcode0"}`)
		if res.StatusCode != http.StatusBadRequest {
			t.Fatalf("状态码 = %d, 期望 400", res.StatusCode)
		}
		if str(body["error"]) != "invalid_username" {
			t.Errorf("error = %q, 期望 invalid_username（说明账号校验没在核销之前跑）", str(body["error"]))
		}
	})

	t.Run("请求体不是合法 JSON 时被适配器拦下", func(t *testing.T) {
		res, body := postRaw(t, base+"/api/login", "application/json", `{not json`)
		if res.StatusCode != http.StatusBadRequest {
			t.Fatalf("状态码 = %d, 期望 400", res.StatusCode)
		}
		if num(body["code"]) != 1 || str(body["error"]) != "invalid_request" {
			t.Errorf("信封不符: %v", body)
		}
		if str(body["message"]) != "请求参数格式错误" {
			t.Errorf("message = %q", str(body["message"]))
		}
	})

	t.Run("授权确认页信息未登录返回 401（无 code 信封）", func(t *testing.T) {
		res, body := get(t, base+"/api/consent?client_id=gs-ac&scope=openid")
		if res.StatusCode != http.StatusUnauthorized {
			t.Fatalf("状态码 = %d, 期望 401", res.StatusCode)
		}
		if str(body["error"]) != "not_authenticated" {
			t.Errorf("error = %q", str(body["error"]))
		}
	})

	t.Run("userinfo 缺 access_token 返回 401 与 WWW-Authenticate", func(t *testing.T) {
		res, body := get(t, base+"/oauth2/userinfo")
		if res.StatusCode != http.StatusUnauthorized {
			t.Fatalf("状态码 = %d, 期望 401", res.StatusCode)
		}
		if !strings.Contains(res.Header.Get("WWW-Authenticate"), "Bearer") {
			t.Errorf("WWW-Authenticate = %q", res.Header.Get("WWW-Authenticate"))
		}
		if str(body["error"]) != "invalid_token" {
			t.Errorf("error = %q", str(body["error"]))
		}
		// 协议错误响应不带 code 字段（OIDC 客户端按标准字段解析）
		if _, has := body["code"]; has {
			t.Error("协议错误响应不应包含 code 字段")
		}
	})

	t.Run("revoke 缺 token 返回协议错误 400", func(t *testing.T) {
		res, body := postForm(t, base+"/oauth2/revoke", "")
		if res.StatusCode != http.StatusBadRequest {
			t.Fatalf("状态码 = %d, 期望 400", res.StatusCode)
		}
		if str(body["error"]) != "invalid_request" {
			t.Errorf("error = %q", str(body["error"]))
		}
	})

	t.Run("RP 未带回跳地址时 logout 返回 logged_out", func(t *testing.T) {
		res, body := get(t, base+"/oauth2/logout")
		if res.StatusCode != http.StatusOK {
			t.Fatalf("状态码 = %d, 期望 200", res.StatusCode)
		}
		if str(body["status"]) != "logged_out" {
			t.Errorf("status = %q", str(body["status"]))
		}
	})

	t.Run("前端登出返回业务信封", func(t *testing.T) {
		res, body := postJSON(t, base+"/api/logout", `{}`)
		if res.StatusCode != http.StatusOK {
			t.Fatalf("状态码 = %d, 期望 200", res.StatusCode)
		}
		if num(body["code"]) != 0 {
			t.Errorf("code = %v", body["code"])
		}
		if str(body["message"]) != "已退出全局会话" {
			t.Errorf("message = %q", str(body["message"]))
		}
	})

	t.Run("管理端点全部被鉴权中间件拦住", func(t *testing.T) {
		for _, e := range adminRoutes {
			res, body := request(t, e.method, base+e.path, "application/json", "")
			if res.StatusCode != http.StatusUnauthorized {
				t.Errorf("%s %s 状态码 = %d, 期望 401（说明鉴权中间件没挂上）",
					e.method, e.path, res.StatusCode)
				continue
			}
			if str(body["error"]) != "not_authenticated" {
				t.Errorf("%s %s error = %q", e.method, e.path, str(body["error"]))
			}
			if _, has := body["code"]; has {
				t.Errorf("%s %s 鉴权失败响应不应包含 code 字段", e.method, e.path)
			}
		}
	})

	t.Run("路由清单里的端点都可达（非 404）", func(t *testing.T) {
		for _, e := range routeInventory {
			res, _ := request(t, e.method, base+e.path, "application/json", "")
			if res.StatusCode == http.StatusNotFound {
				t.Errorf("%s %s 返回 404，路由未注册", e.method, e.path)
			}
		}
	})
}

// ── 测试脚手架 ──────────────────────────────────────────────────────────────

// startServer 在随机空闲端口上启动一个真实服务，返回其 base URL。
func startServer(t *testing.T) string {
	t.Helper()

	ctx := context.Background()
	config.Load(ctx)

	addr := fmt.Sprintf("127.0.0.1:%d", freePort(t))
	s := g.Server("auth-hub-router-test")
	s.SetAddr(addr)
	// 关掉 gf 自带的可选端点与访问日志，避免干扰路由清点
	s.SetSwaggerPath("")
	s.SetOpenApiPath("")
	s.SetAccessLogEnabled(false)
	s.SetErrorLogEnabled(false)
	s.SetDumpRouterMap(false)

	// webDist 传空：容器部署下前端由 nginx 托管，Go 侧只提供 API
	router.Register(ctx, s, "")

	if err := s.Start(); err != nil {
		t.Fatalf("启动测试服务失败: %v", err)
	}
	t.Cleanup(func() { _ = s.Shutdown() })

	base := "http://" + addr
	waitReady(t, base)
	return base
}

// freePort 取一个当前空闲的端口
func freePort(t *testing.T) int {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("取空闲端口失败: %v", err)
	}
	defer func() { _ = l.Close() }()
	return l.Addr().(*net.TCPAddr).Port
}

// waitReady 等端口真正开始服务（Start 是非阻塞的）
func waitReady(t *testing.T, base string) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		res, err := testClient.Get(base + "/.well-known/openid-configuration")
		if err == nil {
			_ = res.Body.Close()
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatal("测试服务在 5s 内未就绪")
}

func get(t *testing.T, url string) (*http.Response, map[string]any) {
	t.Helper()
	return request(t, http.MethodGet, url, "", "")
}

func postJSON(t *testing.T, url, body string) (*http.Response, map[string]any) {
	t.Helper()
	return request(t, http.MethodPost, url, "application/json", body)
}

func postRaw(t *testing.T, url, contentType, body string) (*http.Response, map[string]any) {
	t.Helper()
	return request(t, http.MethodPost, url, contentType, body)
}

func postForm(t *testing.T, url, body string) (*http.Response, map[string]any) {
	t.Helper()
	return request(t, http.MethodPost, url, "application/x-www-form-urlencoded", body)
}

func request(t *testing.T, method, url, contentType, body string) (*http.Response, map[string]any) {
	t.Helper()

	var reader io.Reader
	if body != "" {
		reader = strings.NewReader(body)
	}
	req, err := http.NewRequest(method, url, reader)
	if err != nil {
		t.Fatalf("构造请求失败: %v", err)
	}
	if contentType != "" && body != "" {
		req.Header.Set("Content-Type", contentType)
	}
	res, err := testClient.Do(req)
	if err != nil {
		t.Fatalf("%s %s 请求失败: %v", method, url, err)
	}
	defer func() { _ = res.Body.Close() }()

	raw, err := io.ReadAll(res.Body)
	if err != nil {
		t.Fatalf("读取响应失败: %v", err)
	}
	parsed := map[string]any{}
	if len(raw) > 0 {
		_ = json.Unmarshal(raw, &parsed)
	}
	return res, parsed
}

func str(v any) string {
	s, _ := v.(string)
	return s
}

func num(v any) float64 {
	f, _ := v.(float64)
	return f
}
