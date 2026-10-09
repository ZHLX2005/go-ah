package api

import (
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/gogf/gf/v2/os/gctx"

	"github.com/ZHLX2005/go-ah/template-business-server/cryptox"
	"github.com/ZHLX2005/go-ah/template-business-server/db"
)

// ============================================================
// 测试基础设施
// ============================================================

const testSecret = "unit-test-secret-0123456789abcdef"

// setupTestDB 每个用例一个独立的 SQLite 文件，并在结束时关掉连接池。
//
// 关池这步不能省：SQLite 文件句柄未释放时，Windows 上 t.TempDir() 的回收
// 会失败（"being used by another process"），错误报在清理阶段而不是用例里，
// 很容易被误读成被测代码有问题。
func setupTestDB(t *testing.T) {
	t.Helper()
	if err := db.Init(gctx.New(), filepath.Join(t.TempDir(), "biz.db")); err != nil {
		t.Fatalf("初始化测试库失败: %v", err)
	}
	t.Cleanup(func() { _ = db.Instance().Close(gctx.New()) })
}

func setupTestCrypto(t *testing.T, secret string) {
	t.Helper()
	e, err := cryptox.NewEngineFromSecret(secret)
	if err != nil {
		t.Fatalf("构建加密引擎失败: %v", err)
	}
	cryptoEngine = e
	t.Cleanup(func() { cryptoEngine = nil })
}

// newTestSession 构造一个明文 token 的会话对象（尚未落库）
func newTestSession(sid string) *db.BusinessSession {
	return &db.BusinessSession{
		SessionID:             sid,
		UserSub:               "42",
		IDToken:               "eyJhbGciOiJSUzI1NiJ9.ID_TOKEN_PAYLOAD.SIG",
		AccessToken:           "eyJhbGciOiJSUzI1NiJ9.ACCESS_TOKEN_PAYLOAD.SIG",
		RefreshToken:          "eyJhbGciOiJSUzI1NiJ9.REFRESH_TOKEN_PAYLOAD.SIG",
		AccessTokenExpiresAt:  time.Now().Add(AccessTokenTTL),
		RefreshTokenExpiresAt: time.Now().Add(RefreshTokenTTL),
		ExpiresAt:             time.Now().Add(SessionLifetime),
	}
}

// reload 从库里读回原始行（含密文），用于验证"落库为密文"
func reload(t *testing.T, sid string) db.BusinessSession {
	t.Helper()
	var raw db.BusinessSession
	if err := db.Instance().Model(db.TableBusinessSession).Ctx(gctx.New()).
		Where("session_id", sid).Scan(&raw); err != nil {
		t.Fatalf("回读会话失败: %v", err)
	}
	if raw.SessionID == "" {
		t.Fatalf("会话 %s 不在库里", sid)
	}
	return raw
}

// ============================================================
// 加密存储：落库为密文，读取可还原
// ============================================================

func TestSaveSession_StoresCiphertext(t *testing.T) {
	setupTestDB(t)
	setupTestCrypto(t, testSecret)

	sess := newTestSession("sess-cipher")
	plainRefresh := sess.RefreshToken
	if err := saveSession(gctx.New(), sess); err != nil {
		t.Fatalf("保存会话失败: %v", err)
	}

	raw := reload(t, "sess-cipher")
	for name, v := range map[string]string{
		"id_token":      raw.IDToken,
		"access_token":  raw.AccessToken,
		"refresh_token": raw.RefreshToken,
	} {
		if v == "" {
			t.Errorf("%s 不应为空", name)
			continue
		}
		if strings.HasPrefix(v, "eyJ") {
			t.Errorf("%s 落库为明文 JWT（应以密文存储）", name)
		}
		if !cryptox.IsCiphertext(v) {
			t.Errorf("%s 不是合法密文格式", name)
		}
	}

	if !raw.Encrypted {
		t.Error("encrypted 标记应为 true")
	}
	if strings.Contains(raw.RefreshToken, plainRefresh) {
		t.Error("库中出现了明文 refresh_token")
	}
}

// TestSaveSession_PreservesPlaintextInMemory saveSession 不得污染调用方内存
func TestSaveSession_PreservesPlaintextInMemory(t *testing.T) {
	setupTestDB(t)
	setupTestCrypto(t, testSecret)

	sess := newTestSession("sess-plain")
	origID, origAccess, origRefresh := sess.IDToken, sess.AccessToken, sess.RefreshToken

	if err := saveSession(gctx.New(), sess); err != nil {
		t.Fatalf("保存失败: %v", err)
	}
	if sess.IDToken != origID || sess.AccessToken != origAccess || sess.RefreshToken != origRefresh {
		t.Error("saveSession 返回后调用方持有的明文 token 不应被改写")
	}
	if sess.Id == 0 {
		t.Error("首次保存应回填主键")
	}
}

func TestReadTokens_RoundTrip(t *testing.T) {
	setupTestDB(t)
	setupTestCrypto(t, testSecret)
	ctx := gctx.New()

	sess := newTestSession("sess-roundtrip")
	orig := &SessionTokens{sess.IDToken, sess.AccessToken, sess.RefreshToken}
	if err := saveSession(ctx, sess); err != nil {
		t.Fatalf("保存失败: %v", err)
	}

	raw := reload(t, "sess-roundtrip")
	got, err := ReadTokens(&raw)
	if err != nil {
		t.Fatalf("读取 token 失败: %v", err)
	}
	if got.IDToken != orig.IDToken {
		t.Error("id_token 解密后不一致")
	}
	if got.AccessToken != orig.AccessToken {
		t.Error("access_token 解密后不一致")
	}
	if got.RefreshToken != orig.RefreshToken {
		t.Error("refresh_token 解密后不一致")
	}
}

// TestReadTokens_LegacyPlaintext 存量明文行应原样返回（平滑迁移）
func TestReadTokens_LegacyPlaintext(t *testing.T) {
	setupTestDB(t)
	setupTestCrypto(t, testSecret)
	ctx := gctx.New()

	// 直接写一条 encrypted=false 的历史行
	legacy := &db.BusinessSession{
		SessionID:             "legacy-sess",
		UserSub:               "42",
		IDToken:               "legacy.id.token",
		AccessToken:           "legacy.access.token",
		RefreshToken:          "legacy.refresh.token",
		Encrypted:             false,
		AccessTokenExpiresAt:  time.Now().Add(AccessTokenTTL),
		RefreshTokenExpiresAt: time.Now().Add(RefreshTokenTTL),
		ExpiresAt:             time.Now().Add(SessionLifetime),
	}
	if err := db.UpsertSession(ctx, legacy); err != nil {
		t.Fatalf("插入历史行失败: %v", err)
	}

	raw := reload(t, "legacy-sess")
	got, err := ReadTokens(&raw)
	if err != nil {
		t.Fatalf("读取历史行不应报错: %v", err)
	}
	if got.RefreshToken != "legacy.refresh.token" {
		t.Errorf("历史明文行应原样返回, got=%q", got.RefreshToken)
	}
}

func TestReadTokens_WrongKeyFails(t *testing.T) {
	setupTestDB(t)
	setupTestCrypto(t, testSecret)
	ctx := gctx.New()

	sess := newTestSession("sess-wrongkey")
	if err := saveSession(ctx, sess); err != nil {
		t.Fatalf("保存失败: %v", err)
	}
	raw := reload(t, "sess-wrongkey")

	// 换一台"服务器"（不同密钥）
	setupTestCrypto(t, "a-completely-different-secret-key")

	if _, err := ReadTokens(&raw); err == nil {
		t.Error("使用不同密钥读取应失败")
	}
}

func TestReadTokens_NilSession(t *testing.T) {
	if _, err := ReadTokens(nil); err == nil {
		t.Error("nil 会话应报错而不是 panic")
	}
}

func TestEncrypt_NoEngineReturnsError(t *testing.T) {
	setupTestDB(t)
	cryptoEngine = nil // 模拟未初始化

	sess := newTestSession("sess-noengine")
	if err := saveSession(gctx.New(), sess); err == nil {
		t.Error("未初始化加密引擎时保存应报错")
	}
	if _, err := decryptToken("anything"); err == nil {
		t.Error("未初始化加密引擎时解密应报错")
	}
	if CryptoReady() {
		t.Error("CryptoReady 应为 false")
	}
}

// ============================================================
// 续期判定 shouldRefresh
// ============================================================

func TestShouldRefresh(t *testing.T) {
	now := time.Now()

	cases := []struct {
		name string
		sess *db.BusinessSession
		want bool
	}{
		{"nil 会话", nil, false},
		{
			"无 refresh_token",
			&db.BusinessSession{RefreshToken: "", AccessTokenExpiresAt: now.Add(time.Second)},
			false,
		},
		{
			"access_token 还有 30 分钟（远未到阈值）",
			&db.BusinessSession{
				RefreshToken:          "rt",
				AccessTokenExpiresAt:  now.Add(30 * time.Minute),
				RefreshTokenExpiresAt: now.Add(RefreshTokenTTL),
			},
			false,
		},
		{
			"access_token 还有 5 分钟（大于 2 分钟阈值）",
			&db.BusinessSession{
				RefreshToken:          "rt",
				AccessTokenExpiresAt:  now.Add(5 * time.Minute),
				RefreshTokenExpiresAt: now.Add(RefreshTokenTTL),
			},
			false,
		},
		{
			"access_token 还有 90 秒（小于 2 分钟阈值）",
			&db.BusinessSession{
				RefreshToken:          "rt",
				AccessTokenExpiresAt:  now.Add(90 * time.Second),
				RefreshTokenExpiresAt: now.Add(RefreshTokenTTL),
			},
			true,
		},
		{
			"access_token 恰好 2 分钟（边界，应触发）",
			&db.BusinessSession{
				RefreshToken:          "rt",
				AccessTokenExpiresAt:  now.Add(RefreshThreshold),
				RefreshTokenExpiresAt: now.Add(RefreshTokenTTL),
			},
			true,
		},
		{
			"access_token 已过期",
			&db.BusinessSession{
				RefreshToken:          "rt",
				AccessTokenExpiresAt:  now.Add(-time.Minute),
				RefreshTokenExpiresAt: now.Add(RefreshTokenTTL),
			},
			true,
		},
		{
			"refresh_token 已过期（续期无意义）",
			&db.BusinessSession{
				RefreshToken:          "rt",
				AccessTokenExpiresAt:  now.Add(30 * time.Second),
				RefreshTokenExpiresAt: now.Add(-time.Hour),
			},
			false,
		},
		{
			"老数据无过期时间（视为需续期）",
			&db.BusinessSession{
				RefreshToken:          "rt",
				AccessTokenExpiresAt:  time.Time{},
				RefreshTokenExpiresAt: now.Add(RefreshTokenTTL),
			},
			true,
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := shouldRefresh(c.sess); got != c.want {
				t.Errorf("shouldRefresh() = %v, 期望 %v", got, c.want)
			}
		})
	}
}

// ============================================================
// TTL 常量与对外字样
// ============================================================

func TestTTLConstants(t *testing.T) {
	if AccessTokenTTL != 10*time.Minute {
		t.Errorf("AccessTokenTTL = %v, 期望 10m", AccessTokenTTL)
	}
	if RefreshTokenTTL != 7*24*time.Hour {
		t.Errorf("RefreshTokenTTL = %v, 期望 168h", RefreshTokenTTL)
	}
	if RefreshThreshold != 2*time.Minute {
		t.Errorf("RefreshThreshold = %v, 期望 2m", RefreshThreshold)
	}
	if SessionLifetime != 8*time.Hour {
		t.Errorf("SessionLifetime = %v, 期望 8h", SessionLifetime)
	}
}

// TestHumanDurationMatchesContract /api/security-status 下发的字样是响应契约
// 的一部分（前端与 e2e 都在读），不能因为换成 Duration.String() 而变成 "10m0s"。
func TestHumanDurationMatchesContract(t *testing.T) {
	cases := map[time.Duration]string{
		AccessTokenTTL:   "10m",
		RefreshTokenTTL:  "168h",
		RefreshThreshold: "2m",
		90 * time.Second: "1m30s", // 非整分整时不硬凑
	}
	for d, want := range cases {
		if got := humanDuration(d); got != want {
			t.Errorf("humanDuration(%v) = %q, 期望 %q", d, got, want)
		}
	}
}

// ============================================================
// 续期器：扫描 / 清理 / 销毁
// ============================================================

func TestRefresher_SweepCleansExpiredSessions(t *testing.T) {
	setupTestDB(t)
	setupTestCrypto(t, testSecret)
	ctx := gctx.New()

	// 一个已整体过期的会话
	expired := newTestSession("expired-sess")
	expired.ExpiresAt = time.Now().Add(-time.Hour)
	if err := db.UpsertSession(ctx, expired); err != nil {
		t.Fatalf("写入失败: %v", err)
	}
	// 一个有效但无需续期的会话
	valid := newTestSession("valid-sess")
	if err := saveSession(ctx, valid); err != nil {
		t.Fatalf("写入失败: %v", err)
	}

	r := NewRefresher(time.Second)
	if count := r.sweep(ctx); count != 0 {
		t.Errorf("本轮不应有续期发生, got=%d", count)
	}

	n, err := db.Instance().Model(db.TableBusinessSession).Ctx(ctx).
		Where("session_id", "expired-sess").Count()
	if err != nil {
		t.Fatalf("统计失败: %v", err)
	}
	if n != 0 {
		t.Error("已整体过期的会话应被清理")
	}

	n, err = db.Instance().Model(db.TableBusinessSession).Ctx(ctx).
		Where("session_id", "valid-sess").Count()
	if err != nil {
		t.Fatalf("统计失败: %v", err)
	}
	if n != 1 {
		t.Error("有效会话不应被误删")
	}
}

func TestRefresher_StartStopIdempotent(t *testing.T) {
	setupTestDB(t)
	setupTestCrypto(t, testSecret)
	ctx := gctx.New()

	r := NewRefresher(50 * time.Millisecond)
	r.Start(ctx)
	r.Start(ctx) // 重复启动不应 panic 或起两个协程

	time.Sleep(120 * time.Millisecond)

	r.mu.Lock()
	started, checks := r.started, r.checks
	r.mu.Unlock()

	if !started {
		t.Error("启动后 started 应为 true")
	}
	if checks == 0 {
		t.Error("巡检应至少执行过一次")
	}

	r.Stop()
	r.Stop() // 重复停止不应 panic

	r.mu.Lock()
	checksAfterStop := r.checks
	r.mu.Unlock()

	time.Sleep(120 * time.Millisecond)

	r.mu.Lock()
	checksLater := r.checks
	r.mu.Unlock()

	if checksLater != checksAfterStop {
		t.Error("停止后不应继续巡检")
	}
}

// TestRefresher_RevokeCallback 续期失败时应触发回调并删除会话
func TestRefresher_RevokeCallback(t *testing.T) {
	setupTestDB(t)
	setupTestCrypto(t, testSecret)
	ctx := gctx.New()

	sess := newTestSession("sess-revoke")
	if err := saveSession(ctx, sess); err != nil {
		t.Fatalf("保存失败: %v", err)
	}

	r := NewRefresher(time.Second)
	var gotSessionID, gotSub string
	var gotReason error
	r.OnSessionRevoked = func(sid, sub string, reason error) {
		gotSessionID, gotSub, gotReason = sid, sub, reason
	}

	r.revoke(ctx, sess, errTestRefreshFailed)

	if gotSessionID != sess.SessionID {
		t.Errorf("回调 sessionID = %q, 期望 %q", gotSessionID, sess.SessionID)
	}
	if gotSub != sess.UserSub {
		t.Errorf("回调 sub = %q, 期望 %q", gotSub, sess.UserSub)
	}
	if gotReason == nil {
		t.Error("回调应携带失败原因")
	}

	n, err := db.Instance().Model(db.TableBusinessSession).Ctx(ctx).
		Where("session_id", sess.SessionID).Count()
	if err != nil {
		t.Fatalf("统计失败: %v", err)
	}
	if n != 0 {
		t.Error("续期失败后会话应被删除")
	}

	r.mu.Lock()
	revoked := r.revoked
	r.mu.Unlock()
	if revoked != 1 {
		t.Errorf("revoked 计数应为 1, got=%d", revoked)
	}
}

// TestRefresher_DecryptFailureDestroysSession 密钥不匹配时会话应被销毁
func TestRefresher_DecryptFailureDestroysSession(t *testing.T) {
	setupTestDB(t)
	setupTestCrypto(t, testSecret)
	ctx := gctx.New()

	sess := newTestSession("sess-rotated")
	// 强制进入续期窗口
	sess.AccessTokenExpiresAt = time.Now().Add(30 * time.Second)
	if err := saveSession(ctx, sess); err != nil {
		t.Fatalf("保存失败: %v", err)
	}

	// 换密钥，模拟密钥轮换/丢失
	setupTestCrypto(t, "rotated-secret-key-0123456789abcd")

	r := NewRefresher(time.Second)
	revoked := false
	r.OnSessionRevoked = func(string, string, error) { revoked = true }

	raw := reload(t, sess.SessionID)
	if r.refreshOne(ctx, &raw) {
		t.Error("解密失败时不应报告续期成功")
	}
	if !revoked {
		t.Error("解密失败应触发会话销毁回调")
	}

	n, err := db.Instance().Model(db.TableBusinessSession).Ctx(ctx).
		Where("session_id", sess.SessionID).Count()
	if err != nil {
		t.Fatalf("统计失败: %v", err)
	}
	if n != 0 {
		t.Error("解密失败的会话应被删除（无法恢复）")
	}
}

var errTestRefreshFailed = &testError{"refresh_token 已吊销"}

type testError struct{ msg string }

func (e *testError) Error() string { return e.msg }

// ============================================================
// randomToken
// ============================================================

func TestRandomToken(t *testing.T) {
	a, b := randomToken(32), randomToken(32)
	if a == b {
		t.Error("两次生成不应相同")
	}
	if len(a) == 0 {
		t.Error("不应为空")
	}
	// base64 RawURL 编码：只含 URL 安全字符，cookie 里不需要转义
	if strings.ContainsAny(a, "+/=") {
		t.Errorf("应使用 URL 安全编码: %q", a)
	}
}
