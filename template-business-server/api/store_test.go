package api

import (
	"strings"
	"testing"
	"time"

	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"

	"github.com/ZHLX2005/go-ah/template-business-server/cryptox"
	"github.com/ZHLX2005/go-ah/template-business-server/db"
)

// ============================================================
// 测试基础设施
// ============================================================

const testSecret = "unit-test-secret-0123456789abcdef"

func setupTestDB(t *testing.T) *gorm.DB {
	t.Helper()
	dsn := "file:" + t.Name() + "?mode=memory&cache=shared"
	g, err := gorm.Open(sqlite.Open(dsn), &gorm.Config{
		Logger: logger.Default.LogMode(logger.Silent),
	})
	if err != nil {
		t.Fatalf("打开内存数据库失败: %v", err)
	}
	if err := g.AutoMigrate(&db.BusinessUser{}, &db.BusinessSession{}); err != nil {
		t.Fatalf("迁移失败: %v", err)
	}
	db.DB = g
	return g
}

func setupTestCrypto(t *testing.T, secret string) {
	t.Helper()
	e, err := cryptox.NewEngineFromSecret(secret)
	if err != nil {
		t.Fatalf("构建加密引擎失败: %v", err)
	}
	cryptoEngine = e
}

// newSession 构造一个明文 token 的会话对象（尚未落库）
func newSession() *db.BusinessSession {
	return &db.BusinessSession{
		SessionID:             "sess-" + time.Now().Format("150405.000000000"),
		UserSub:               "1",
		IDToken:               "eyJhbGciOiJSUzI1NiJ9.ID_TOKEN_PAYLOAD.SIG",
		AccessToken:           "eyJhbGciOiJSUzI1NiJ9.ACCESS_TOKEN_PAYLOAD.SIG",
		RefreshToken:          "eyJhbGciOiJSUzI1NiJ9.REFRESH_TOKEN_PAYLOAD.SIG",
		AccessTokenExpiresAt:  time.Now().Add(AccessTokenTTL),
		RefreshTokenExpiresAt: time.Now().Add(RefreshTokenTTL),
		ExpiresAt:             time.Now().Add(SessionLifetime),
	}
}

// ============================================================
// 加密存储：落库为密文，读取可还原
// ============================================================

func TestSaveSession_StoresCiphertext(t *testing.T) {
	g := setupTestDB(t)
	setupTestCrypto(t, testSecret)

	sess := newSession()
	plainRefresh := sess.RefreshToken
	if err := saveSession(sess); err != nil {
		t.Fatalf("保存会话失败: %v", err)
	}

	// 直接从库里读原始行
	var raw db.BusinessSession
	g.Where("session_id = ?", sess.SessionID).First(&raw)

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

func TestSaveSession_PreservesPlaintextInMemory(t *testing.T) {
	setupTestDB(t)
	setupTestCrypto(t, testSecret)

	sess := newSession()
	origID, origAccess, origRefresh := sess.IDToken, sess.AccessToken, sess.RefreshToken

	if err := saveSession(sess); err != nil {
		t.Fatalf("保存失败: %v", err)
	}
	// saveSession 不应污染调用方内存中的明文
	if sess.IDToken != origID || sess.AccessToken != origAccess || sess.RefreshToken != origRefresh {
		t.Error("saveSession 后调用方持有的明文 token 不应被改写")
	}
}

func TestReadTokens_RoundTrip(t *testing.T) {
	g := setupTestDB(t)
	setupTestCrypto(t, testSecret)

	sess := newSession()
	orig := &SessionTokens{sess.IDToken, sess.AccessToken, sess.RefreshToken}
	if err := saveSession(sess); err != nil {
		t.Fatalf("保存失败: %v", err)
	}

	var stored db.BusinessSession
	g.Where("session_id = ?", sess.SessionID).First(&stored)

	got, err := ReadTokens(&stored)
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
	g := setupTestDB(t)
	setupTestCrypto(t, testSecret)

	// 直接插入一条 encrypted=false 的历史行
	legacy := &db.BusinessSession{
		SessionID:             "legacy-sess",
		UserSub:               "1",
		IDToken:               "legacy.id.token",
		AccessToken:           "legacy.access.token",
		RefreshToken:          "legacy.refresh.token",
		Encrypted:             false,
		AccessTokenExpiresAt:  time.Now().Add(AccessTokenTTL),
		RefreshTokenExpiresAt: time.Now().Add(RefreshTokenTTL),
		ExpiresAt:             time.Now().Add(SessionLifetime),
	}
	if err := g.Create(legacy).Error; err != nil {
		t.Fatalf("插入历史行失败: %v", err)
	}

	var stored db.BusinessSession
	g.Where("session_id = ?", "legacy-sess").First(&stored)

	got, err := ReadTokens(&stored)
	if err != nil {
		t.Fatalf("读取历史行不应报错: %v", err)
	}
	if got.RefreshToken != "legacy.refresh.token" {
		t.Errorf("历史明文行应原样返回, got=%q", got.RefreshToken)
	}
}

func TestReadTokens_WrongKeyFails(t *testing.T) {
	g := setupTestDB(t)
	setupTestCrypto(t, testSecret)

	sess := newSession()
	saveSession(sess)

	var stored db.BusinessSession
	g.Where("session_id = ?", sess.SessionID).First(&stored)

	// 换一台"服务器"（不同密钥）
	setupTestCrypto(t, "a-completely-different-secret-key")

	if _, err := ReadTokens(&stored); err == nil {
		t.Error("使用不同密钥读取应失败")
	}
}

func TestEncrypt_NoEngineReturnsError(t *testing.T) {
	setupTestDB(t)
	cryptoEngine = nil // 模拟未初始化

	sess := newSession()
	if err := saveSession(sess); err == nil {
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
		{
			"nil 会话",
			nil,
			false,
		},
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
// TTL 常量
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

// ============================================================
// 续期器：扫描 / 清理过期会话
// ============================================================

func TestRefresher_SweepCleansExpiredSessions(t *testing.T) {
	g := setupTestDB(t)
	setupTestCrypto(t, testSecret)

	// 一个已整体过期的会话
	g.Create(&db.BusinessSession{
		SessionID: "expired-sess",
		UserSub:   "1",
		ExpiresAt: time.Now().Add(-time.Hour),
	})
	// 一个有效但无需续期的会话
	valid := newSession()
	saveSession(valid)

	r := NewRefresher(time.Second)
	count := r.sweep()

	if count != 0 {
		t.Errorf("本轮不应有续期发生, got=%d", count)
	}

	var expiredCount int64
	g.Model(&db.BusinessSession{}).Where("session_id = ?", "expired-sess").Count(&expiredCount)
	if expiredCount != 0 {
		t.Error("已整体过期的会话应被清理")
	}

	var validCount int64
	g.Model(&db.BusinessSession{}).Where("session_id = ?", valid.SessionID).Count(&validCount)
	if validCount != 1 {
		t.Error("有效会话不应被误删")
	}
}

func TestRefresher_StartStopIdempotent(t *testing.T) {
	setupTestDB(t)
	setupTestCrypto(t, testSecret)

	r := NewRefresher(50 * time.Millisecond)
	r.Start()
	r.Start() // 重复启动不应 panic 或起两个协程

	time.Sleep(120 * time.Millisecond)

	r.mu.Lock()
	started := r.started
	checks := r.checks
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
	g := setupTestDB(t)
	setupTestCrypto(t, testSecret)

	sess := newSession()
	saveSession(sess)

	r := NewRefresher(time.Second)

	var gotSessionID, gotSub string
	var gotReason error
	r.OnSessionRevoked = func(sid, sub string, reason error) {
		gotSessionID, gotSub, gotReason = sid, sub, reason
	}

	r.revoke(sess, errTestRefreshFailed)

	if gotSessionID != sess.SessionID {
		t.Errorf("回调 sessionID = %q, 期望 %q", gotSessionID, sess.SessionID)
	}
	if gotSub != sess.UserSub {
		t.Errorf("回调 sub = %q, 期望 %q", gotSub, sess.UserSub)
	}
	if gotReason == nil {
		t.Error("回调应携带失败原因")
	}

	var count int64
	g.Model(&db.BusinessSession{}).Where("session_id = ?", sess.SessionID).Count(&count)
	if count != 0 {
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
	g := setupTestDB(t)
	setupTestCrypto(t, testSecret)

	sess := newSession()
	// 强制进入续期窗口
	sess.AccessTokenExpiresAt = time.Now().Add(30 * time.Second)
	saveSession(sess)

	// 换密钥，模拟密钥轮换/丢失
	setupTestCrypto(t, "rotated-secret-key-0123456789abcd")

	r := NewRefresher(time.Second)
	revoked := false
	r.OnSessionRevoked = func(string, string, error) { revoked = true }

	var stored db.BusinessSession
	g.Where("session_id = ?", sess.SessionID).First(&stored)

	if r.refreshOne(&stored) {
		t.Error("解密失败时不应报告续期成功")
	}
	if !revoked {
		t.Error("解密失败应触发会话销毁回调")
	}

	var count int64
	g.Model(&db.BusinessSession{}).Where("session_id = ?", sess.SessionID).Count(&count)
	if count != 0 {
		t.Error("解密失败的会话应被删除（无法恢复）")
	}
}

var errTestRefreshFailed = &testError{"refresh_token 已吊销"}

type testError struct{ msg string }

func (e *testError) Error() string { return e.msg }
