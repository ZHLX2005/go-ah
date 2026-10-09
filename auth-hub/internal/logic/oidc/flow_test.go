// Package oidc_test 用真实 PostgreSQL 验证授权码 / 令牌 / 会话三条流程。
//
// 为什么必须是外部测试包且必须连真库：这些流程的正确性都挂在数据库约束上
// —— 授权码只能用一次（唯一索引 + used_at）、令牌吊销是标记而非删除、
// 会话过期按 expires_at 判定。SQLite 与 PG 在时间精度、bool 默认值、
// 唯一冲突行为上的差异，正是这类测试要拦住的东西。
//
// 未设置 AUTH_HUB_TEST_DSN 时整包跳过（见 internal/testpg）。
package oidc_test

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"os"
	"testing"
	"time"

	"github.com/gogf/gf/v2/os/gctx"

	"github.com/ZHLX2005/go-ah/auth-hub/internal/config"
	"github.com/ZHLX2005/go-ah/auth-hub/internal/consts"
	"github.com/ZHLX2005/go-ah/auth-hub/internal/dao"
	"github.com/ZHLX2005/go-ah/auth-hub/internal/db"
	"github.com/ZHLX2005/go-ah/auth-hub/internal/logic/oidc"
	"github.com/ZHLX2005/go-ah/auth-hub/internal/logic/session"
	"github.com/ZHLX2005/go-ah/auth-hub/internal/logic/signing"
	"github.com/ZHLX2005/go-ah/auth-hub/internal/model/entity"
	"github.com/ZHLX2005/go-ah/auth-hub/internal/testpg"
)

const (
	testIssuer   = "http://idp.test"
	testRedirect = "http://127.0.0.1:8081/oauth/callback"
	testVerifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
)

// TestMain 注入配置与签名密钥（密钥走"显式注入"以免依赖数据库，
// 但本包的用例本身都要真库，跳过逻辑由 testpg 统一处理）。
func TestMain(m *testing.M) {
	ctx := gctx.GetInitCtx()
	_ = os.Setenv("IDP_ISSUER", testIssuer)

	// 配置必须先加载：签 id_token 时要读 issuer，未加载会 panic（装配顺序错误）
	config.Load(ctx)

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		panic(err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		panic(err)
	}
	pemStr := string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}))

	// config 与 signing 必须在这里初始化：签名密钥晚于 db，但注入式不需要库
	if err := signing.Load(ctx, pemStr); err != nil {
		panic(err)
	}
	os.Exit(m.Run())
}

// setup 在一次性 schema 上初始化存储，返回 ctx 与预置用户
func setup(t *testing.T) (context.Context, *entity.User) {
	t.Helper()

	dsn, _ := testpg.NewSchema(t)
	ctx := gctx.New()
	if err := db.Init(ctx, db.InitOptions{
		DSN:                dsn,
		GSACRedirectURIs:   testRedirect,
		GSACPostLogoutURIs: "http://127.0.0.1:8081/login",
	}); err != nil {
		t.Fatalf("db.Init 失败: %v", err)
	}

	var u entity.User
	if err := dao.User.Ctx(ctx).Where("username", consts.SeedUsername).Scan(&u); err != nil {
		t.Fatalf("查询预置用户失败: %v", err)
	}
	if u.Id == 0 {
		t.Fatal("预置用户不存在")
	}
	return ctx, &u
}

func challengeOf(verifier string) string {
	h := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(h[:])
}

func newCode(t *testing.T, ctx context.Context, u *entity.User) string {
	t.Helper()
	code, err := oidc.CreateAuthorizationCode(ctx, oidc.AuthCodeInput{
		ClientID:            consts.ClientGSAC,
		UserID:              u.Id,
		RedirectURI:         testRedirect,
		Scope:               "openid profile email",
		Nonce:               "n-1",
		CodeChallenge:       challengeOf(testVerifier),
		CodeChallengeMethod: "S256",
	})
	if err != nil {
		t.Fatalf("生成授权码失败: %v", err)
	}
	return code
}

// ============================================================
// 授权码：只能消费一次
// ============================================================

func TestAuthorizationCode_SingleUse(t *testing.T) {
	ctx, u := setup(t)
	code := newCode(t, ctx, u)

	ac, err := oidc.ConsumeAuthorizationCode(ctx, code, consts.ClientGSAC, testRedirect, testVerifier)
	if err != nil {
		t.Fatalf("首次消费应成功: %v", err)
	}
	if ac.UserID != u.Id {
		t.Errorf("UserID = %d, 期望 %d", ac.UserID, u.Id)
	}
	if ac.Scope != "openid profile email" {
		t.Errorf("Scope = %q", ac.Scope)
	}
	if ac.Nonce != "n-1" {
		t.Errorf("Nonce = %q", ac.Nonce)
	}

	// 第二次必须失败：授权码复用是最典型的攻击面
	_, err = oidc.ConsumeAuthorizationCode(ctx, code, consts.ClientGSAC, testRedirect, testVerifier)
	if err == nil {
		t.Fatal("授权码被重复使用（必须拒绝）")
	}
	pe, ok := err.(*oidc.ProtocolError)
	if !ok {
		t.Fatalf("错误类型 = %T, 期望 *ProtocolError", err)
	}
	if pe.Code != "invalid_grant" {
		t.Errorf("错误码 = %q, 期望 invalid_grant", pe.Code)
	}
}

func TestAuthorizationCode_PKCE(t *testing.T) {
	ctx, u := setup(t)

	t.Run("verifier 错误", func(t *testing.T) {
		code := newCode(t, ctx, u)
		if _, err := oidc.ConsumeAuthorizationCode(ctx, code, consts.ClientGSAC, testRedirect, "wrong-verifier"); err == nil {
			t.Error("verifier 不匹配时应拒绝")
		}
	})

	t.Run("redirect_uri 不匹配", func(t *testing.T) {
		code := newCode(t, ctx, u)
		if _, err := oidc.ConsumeAuthorizationCode(ctx, code, consts.ClientGSAC, "http://evil.example/cb", testVerifier); err == nil {
			t.Error("redirect_uri 不匹配时应拒绝")
		}
	})

	t.Run("client_id 不匹配", func(t *testing.T) {
		code := newCode(t, ctx, u)
		if _, err := oidc.ConsumeAuthorizationCode(ctx, code, "another-client", testRedirect, testVerifier); err == nil {
			t.Error("client_id 不匹配时应拒绝")
		}
	})

	t.Run("未知授权码", func(t *testing.T) {
		if _, err := oidc.ConsumeAuthorizationCode(ctx, "not-a-code", consts.ClientGSAC, testRedirect, testVerifier); err == nil {
			t.Error("未知授权码应拒绝")
		}
	})
}

func TestAuthorizationCode_Expiry(t *testing.T) {
	ctx, u := setup(t)
	code := newCode(t, ctx, u)

	// 把过期时间改到过去
	if _, err := dao.OAuthAuthorizationCode.Ctx(ctx).
		Where("code", code).
		Data(map[string]any{"expires_at": time.Now().Add(-time.Minute)}).
		Update(); err != nil {
		t.Fatalf("改过期时间失败: %v", err)
	}

	if _, err := oidc.ConsumeAuthorizationCode(ctx, code, consts.ClientGSAC, testRedirect, testVerifier); err == nil {
		t.Error("过期授权码必须拒绝")
	}
}

// TestAuthorizationCode_UsedMarkedBeforeIssue 消费时先标记已用再发令牌：
// 反过来的话，并发两次请求可能都通过校验
func TestAuthorizationCode_UsedMarkedBeforeIssue(t *testing.T) {
	ctx, u := setup(t)
	code := newCode(t, ctx, u)

	if _, err := oidc.ConsumeAuthorizationCode(ctx, code, consts.ClientGSAC, testRedirect, testVerifier); err != nil {
		t.Fatalf("消费失败: %v", err)
	}

	var rec entity.OAuthAuthorizationCode
	if err := dao.OAuthAuthorizationCode.Ctx(ctx).Where("code", code).Scan(&rec); err != nil {
		t.Fatalf("查询失败: %v", err)
	}
	if rec.UsedAt == nil {
		t.Error("消费后 used_at 必须落库（否则可被重复消费）")
	}
}

// ============================================================
// 令牌签发、刷新、吊销
// ============================================================

func TestIssueTokenSet_AndUserInfo(t *testing.T) {
	ctx, u := setup(t)

	set, err := oidc.IssueTokenSet(ctx, consts.ClientGSAC, u, "openid profile email", "nonce-42")
	if err != nil {
		t.Fatalf("签发令牌失败: %v", err)
	}
	if set.AccessToken == "" || set.RefreshToken == "" || set.IDToken == "" {
		t.Fatalf("三个令牌都应签发: %+v", set)
	}
	if set.ExpiresIn != int(consts.AccessTokenTTL.Seconds()) {
		t.Errorf("ExpiresIn = %d, 期望 %d", set.ExpiresIn, int(consts.AccessTokenTTL.Seconds()))
	}
	if set.Scope != "openid profile email" {
		t.Errorf("Scope = %q", set.Scope)
	}

	// access_token 可换 userinfo，且按 scope 带出字段
	res, err := oidc.UserInfo(ctx, set.AccessToken)
	if err != nil {
		t.Fatalf("userinfo 失败: %v", err)
	}
	if res.User.Id != u.Id {
		t.Errorf("userinfo 用户 = %d, 期望 %d", res.User.Id, u.Id)
	}
	if res.Scope != "openid profile email" {
		t.Errorf("userinfo scope = %q", res.Scope)
	}

	// 不存在的令牌必须拒绝
	if _, err := oidc.UserInfo(ctx, "not-a-token"); err == nil {
		t.Error("非法 access_token 应被拒绝")
	}
}

// TestRefreshToken_NoRotation 刷新不轮换 refresh_token —— 这是迁移前的既有
// 行为，本次迁移原样保留（轮换会改变客户端必须重新保存令牌的契约）。
//
// 这里把现状钉住，避免之后无意改动；同时也说明它是个已知的取舍：
// refresh_token 在有效期内一直可用，一旦泄露，只能靠登出/管理端吊销止血。
func TestRefreshToken_NoRotation(t *testing.T) {
	ctx, u := setup(t)

	set, err := oidc.IssueTokenSet(ctx, consts.ClientGSAC, u, "openid", "")
	if err != nil {
		t.Fatalf("签发失败: %v", err)
	}

	next, err := oidc.RefreshTokenSet(ctx, consts.ClientGSAC, set.RefreshToken)
	if err != nil {
		t.Fatalf("刷新失败: %v", err)
	}
	if next.AccessToken == "" {
		t.Error("刷新后应返回新的 access_token")
	}
	if next.AccessToken == set.AccessToken {
		t.Error("刷新应换发新的 access_token（旧 access_token 仍在有效期内）")
	}
	if next.RefreshToken != set.RefreshToken {
		t.Errorf("refresh_token 被轮换了（%q -> %q）：与既有契约不符",
			set.RefreshToken, next.RefreshToken)
	}
	// 同一个 refresh_token 仍然可用
	if _, err := oidc.RefreshTokenSet(ctx, consts.ClientGSAC, set.RefreshToken); err != nil {
		t.Errorf("未轮换的 refresh_token 应可重复使用: %v", err)
	}
}

// TestRefreshToken_ClientMismatch 令牌不能被别的客户端拿去刷新
func TestRefreshToken_ClientMismatch(t *testing.T) {
	ctx, u := setup(t)

	set, err := oidc.IssueTokenSet(ctx, consts.ClientGSAC, u, "openid", "")
	if err != nil {
		t.Fatalf("签发失败: %v", err)
	}
	if _, err := oidc.RefreshTokenSet(ctx, consts.ClientTemplateWeb, set.RefreshToken); err == nil {
		t.Error("client 不匹配时应拒绝")
	}
}

func TestRefreshToken_Revocation(t *testing.T) {
	ctx, u := setup(t)

	set, err := oidc.IssueTokenSet(ctx, consts.ClientGSAC, u, "openid", "")
	if err != nil {
		t.Fatalf("签发失败: %v", err)
	}

	// 吊销前可用
	if _, err := oidc.RefreshTokenSet(ctx, consts.ClientGSAC, set.RefreshToken); err != nil {
		t.Fatalf("吊销前刷新应成功: %v", err)
	}

	// 管理端按 refresh_token 值吊销
	affected, err := oidc.Revoke(ctx, set.RefreshToken, consts.ClientGSAC)
	if err != nil {
		t.Fatalf("吊销失败: %v", err)
	}
	if affected == 0 {
		t.Fatal("吊销未命中任何行")
	}

	// 吊销后必须失败，且为 invalid_grant（RFC 6749 §5.2 对应 400）
	_, err = oidc.RefreshTokenSet(ctx, consts.ClientGSAC, set.RefreshToken)
	if err == nil {
		t.Fatal("已吊销的 refresh_token 不应还能刷新")
	}
	pe, ok := err.(*oidc.ProtocolError)
	if !ok {
		t.Fatalf("错误类型 = %T, 期望 *ProtocolError", err)
	}
	if pe.Code != "invalid_grant" {
		t.Errorf("错误码 = %q, 期望 invalid_grant", pe.Code)
	}
	if pe.Status != 400 {
		t.Errorf("状态码 = %d, 期望 400", pe.Status)
	}
}

func TestRefreshToken_Expired(t *testing.T) {
	ctx, u := setup(t)

	set, err := oidc.IssueTokenSet(ctx, consts.ClientGSAC, u, "openid", "")
	if err != nil {
		t.Fatalf("签发失败: %v", err)
	}
	if _, err := dao.OAuthRefreshToken.Ctx(ctx).
		Where("token", set.RefreshToken).
		Data(map[string]any{"expires_at": time.Now().Add(-time.Minute)}).
		Update(); err != nil {
		t.Fatalf("改过期时间失败: %v", err)
	}

	if _, err := oidc.RefreshTokenSet(ctx, consts.ClientGSAC, set.RefreshToken); err == nil {
		t.Error("过期 refresh_token 必须拒绝")
	}
}

// TestRevoke_UnknownTokenStillOK 吊销未知令牌不能报错：
// 否则这个端点就成了"令牌是否存在"的探测接口（RFC 7009）
func TestRevoke_UnknownTokenStillOK(t *testing.T) {
	ctx, _ := setup(t)

	if _, err := oidc.Revoke(ctx, "never-issued-token", consts.ClientGSAC); err != nil {
		t.Errorf("吊销未知令牌不应报错: %v", err)
	}
}

// ============================================================
// 会话
// ============================================================

func TestSession_IssueAndResolve(t *testing.T) {
	ctx, u := setup(t)

	sid, ttl, err := session.Issue(ctx, u.Id)
	if err != nil {
		t.Fatalf("创建会话失败: %v", err)
	}
	if sid == "" {
		t.Fatal("会话 ID 不应为空")
	}
	if ttl != consts.SessionTTL {
		t.Errorf("ttl = %v, 期望 %v", ttl, consts.SessionTTL)
	}

	got, err := session.CurrentUser(ctx, sid)
	if err != nil {
		t.Fatalf("解析会话失败: %v", err)
	}
	if got == nil || got.Id != u.Id {
		t.Fatalf("会话未解析出正确用户: %+v", got)
	}

	// 空 sid 是"未登录"，不是错误
	got, err = session.CurrentUser(ctx, "")
	if err != nil {
		t.Errorf("空 sid 不应报错: %v", err)
	}
	if got != nil {
		t.Error("空 sid 应返回 nil 用户")
	}

	// 不存在的 sid 同理
	got, err = session.CurrentUser(ctx, "no-such-session")
	if err != nil {
		t.Errorf("未知 sid 不应报错: %v", err)
	}
	if got != nil {
		t.Error("未知 sid 应返回 nil 用户")
	}
}

func TestSession_Expiry(t *testing.T) {
	ctx, u := setup(t)

	sid, _, err := session.Issue(ctx, u.Id)
	if err != nil {
		t.Fatalf("创建会话失败: %v", err)
	}
	if _, err := dao.UserSession.Ctx(ctx).
		Where("session_id", sid).
		Data(map[string]any{"expires_at": time.Now().Add(-time.Minute)}).
		Update(); err != nil {
		t.Fatalf("改过期时间失败: %v", err)
	}

	got, err := session.CurrentUser(ctx, sid)
	if err != nil {
		t.Fatalf("解析会话失败: %v", err)
	}
	if got != nil {
		t.Error("过期会话必须按未登录处理")
	}
}

// TestSession_Destroy_RevokesEverything 登出必须连带吊销令牌：
// 只删会话的话，业务方手里的 refresh_token 仍能换新 id_token，
// 用户会看到"登出后又被静默登录回来"
func TestSession_Destroy_RevokesEverything(t *testing.T) {
	ctx, u := setup(t)

	sid, _, err := session.Issue(ctx, u.Id)
	if err != nil {
		t.Fatalf("创建会话失败: %v", err)
	}
	set, err := oidc.IssueTokenSet(ctx, consts.ClientGSAC, u, "openid", "")
	if err != nil {
		t.Fatalf("签发令牌失败: %v", err)
	}

	if err := session.Destroy(ctx, sid); err != nil {
		t.Fatalf("销毁会话失败: %v", err)
	}

	// 会话没了
	if got, _ := session.CurrentUser(ctx, sid); got != nil {
		t.Error("会话应已被销毁")
	}
	// refresh_token 被吊销
	if _, err := oidc.RefreshTokenSet(ctx, consts.ClientGSAC, set.RefreshToken); err == nil {
		t.Error("登出后 refresh_token 仍可用（会被静默登录回来）")
	}
	// access_token 被清空
	if _, err := oidc.UserInfo(ctx, set.AccessToken); err == nil {
		t.Error("登出后 access_token 仍可用")
	}
}
