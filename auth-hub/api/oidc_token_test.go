package api

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"math/big"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"

	"github.com/ZHLX2005/go-ah/auth-hub/db"
)

// ============================================================
// 测试基础设施
// ============================================================

// setupTestDB 打开内存 SQLite 并迁移全部表，返回可用的 DB
func setupTestDB(t *testing.T) *gorm.DB {
	t.Helper()
	// 每个测试用独立的内存库（DSN 带唯一名，避免并发测试互相干扰）
	dsn := "file:" + t.Name() + "?mode=memory&cache=shared"
	g, err := gorm.Open(sqlite.Open(dsn), &gorm.Config{
		Logger: logger.Default.LogMode(logger.Silent),
	})
	if err != nil {
		t.Fatalf("打开内存数据库失败: %v", err)
	}
	if err := g.AutoMigrate(
		&db.User{},
		&db.OAuthClient{},
		&db.OAuthAuthorizationCode{},
		&db.OAuthRefreshToken{},
		&db.OAuthAccessToken{},
		&db.UserSession{},
	); err != nil {
		t.Fatalf("迁移失败: %v", err)
	}
	db.DB = g
	return g
}

// setupTestKeys 生成测试用 RSA 密钥
func setupTestKeys(t *testing.T) {
	t.Helper()
	k, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("生成 RSA 密钥失败: %v", err)
	}
	db.SigningKey = k
	db.KeyID = "test-key-1"
}

// testUser 创建一个测试用户
func testUser(t *testing.T, g *gorm.DB) *db.User {
	t.Helper()
	u := &db.User{
		Username:     "test",
		PasswordHash: db.HashPassword("test123456"),
		Email:        "test@example.com",
		Nickname:     "测试用户",
		IsAdmin:      true,
	}
	if err := g.Create(u).Error; err != nil {
		t.Fatalf("创建测试用户失败: %v", err)
	}
	return u
}

// ============================================================
// id_token 签发与验签（RS256）
// ============================================================

func TestSignIDToken_Claims(t *testing.T) {
	setupTestDB(t)
	setupTestKeys(t)
	u := testUser(t, db.DB)

	tok, err := signIDToken(u, "template-web-client", "nonce-abc", "openid profile email")
	if err != nil {
		t.Fatalf("签发 id_token 失败: %v", err)
	}
	if tok == "" {
		t.Fatal("id_token 不应为空")
	}

	// 解析（此处仅校验 claim 内容，签名校验见下一个用例）
	parsed, err := jwt.Parse(tok, func(tk *jwt.Token) (interface{}, error) {
		return &db.SigningKey.PublicKey, nil
	})
	if err != nil {
		t.Fatalf("解析 id_token 失败: %v", err)
	}
	if !parsed.Valid {
		t.Fatal("id_token 应校验通过")
	}

	claims, ok := parsed.Claims.(jwt.MapClaims)
	if !ok {
		t.Fatal("claims 类型断言失败")
	}

	want := map[string]string{
		"iss":                Issuer,
		"sub":                itoa(u.ID),
		"aud":                "template-web-client",
		"nonce":              "nonce-abc",
		"name":               u.Nickname,
		"preferred_username": u.Username,
		"email":              u.Email,
	}
	for k, v := range want {
		if got, _ := claims[k].(string); got != v {
			t.Errorf("claim %q = %q, 期望 %q", k, got, v)
		}
	}

	// exp 应晚于 iat
	iat, _ := claims["iat"].(float64)
	exp, _ := claims["exp"].(float64)
	if exp <= iat {
		t.Errorf("exp(%v) 应晚于 iat(%v)", exp, iat)
	}
	if exp-iat != 3600 {
		t.Errorf("有效期应为 3600 秒, 实际 %v", exp-iat)
	}

	// Header 应携带 kid 且 alg 为 RS256
	if kid, _ := parsed.Header["kid"].(string); kid != db.KeyID {
		t.Errorf("header kid = %q, 期望 %q", kid, db.KeyID)
	}
	if alg, _ := parsed.Header["alg"].(string); alg != "RS256" {
		t.Errorf("header alg = %q, 期望 RS256", alg)
	}
}

// TestSignIDToken_ScopeGating scope 不含 profile/email 时不应泄漏对应 claim
func TestSignIDToken_ScopeGating(t *testing.T) {
	setupTestDB(t)
	setupTestKeys(t)
	u := testUser(t, db.DB)

	tok, err := signIDToken(u, "c", "", "openid")
	if err != nil {
		t.Fatalf("签发失败: %v", err)
	}
	parsed, _ := jwt.Parse(tok, func(tk *jwt.Token) (interface{}, error) {
		return &db.SigningKey.PublicKey, nil
	})
	claims := parsed.Claims.(jwt.MapClaims)

	if _, has := claims["name"]; has {
		t.Error("scope 不含 profile 时不应包含 name")
	}
	if _, has := claims["email"]; has {
		t.Error("scope 不含 email 时不应包含 email")
	}
	if _, has := claims["nonce"]; has {
		t.Error("nonce 为空时不应包含 nonce claim")
	}
}

// TestSignIDToken_WrongKeyRejected 使用错误公钥验签必须失败
func TestSignIDToken_WrongKeyRejected(t *testing.T) {
	setupTestDB(t)
	setupTestKeys(t)
	u := testUser(t, db.DB)

	tok, err := signIDToken(u, "c", "", "openid")
	if err != nil {
		t.Fatalf("签发失败: %v", err)
	}

	otherKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	parsed, err := jwt.Parse(tok, func(tk *jwt.Token) (interface{}, error) {
		return &otherKey.PublicKey, nil
	})
	if err == nil && parsed.Valid {
		t.Error("使用错误公钥验签不应通过")
	}
}

// TestSignIDToken_TamperedRejected 篡改 payload 后验签失败
func TestSignIDToken_TamperedRejected(t *testing.T) {
	setupTestDB(t)
	setupTestKeys(t)
	u := testUser(t, db.DB)

	tok, _ := signIDToken(u, "c", "", "openid")
	// 篡改签名最后一位
	b := []byte(tok)
	if b[len(b)-1] == 'A' {
		b[len(b)-1] = 'B'
	} else {
		b[len(b)-1] = 'A'
	}
	parsed, err := jwt.Parse(string(b), func(tk *jwt.Token) (interface{}, error) {
		return &db.SigningKey.PublicKey, nil
	})
	if err == nil && parsed.Valid {
		t.Error("篡改签名后不应通过验签")
	}
}

// ============================================================
// JWKS 公钥导出
// ============================================================

func TestJWKS_MatchesSigningKey(t *testing.T) {
	setupTestKeys(t)

	// 复现 JWKS 里的 n/e 计算方式
	n := db.SigningKey.PublicKey.N
	e := db.SigningKey.PublicKey.E

	nB64 := base64.RawURLEncoding.EncodeToString(n.Bytes())
	eBytes := big.NewInt(int64(e)).Bytes()
	eB64 := base64.RawURLEncoding.EncodeToString(eBytes)

	// 反解验证
	gotN := new(big.Int)
	rawN, err := base64.RawURLEncoding.DecodeString(nB64)
	if err != nil {
		t.Fatalf("n 不是合法 base64url: %v", err)
	}
	gotN.SetBytes(rawN)
	if gotN.Cmp(n) != 0 {
		t.Error("JWKS 的 n 与私钥模数不一致")
	}

	gotE := new(big.Int)
	rawE, _ := base64.RawURLEncoding.DecodeString(eB64)
	gotE.SetBytes(rawE)
	if gotE.Int64() != int64(e) {
		t.Errorf("JWKS 的 e = %v, 期望 %d", gotE, e)
	}

	if e != 65537 {
		t.Errorf("RSA 公钥指数应为 65537, 实际 %d", e)
	}
}

// ============================================================
// 授权码一次性
// ============================================================

func TestAuthCode_SingleUse(t *testing.T) {
	g := setupTestDB(t)
	u := testUser(t, g)

	code := &db.OAuthAuthorizationCode{
		Code:                "code-single-use",
		ClientID:            "template-web-client",
		UserID:              u.ID,
		RedirectURI:         "http://127.0.0.1:8081/oauth/callback",
		Scope:               "openid profile email",
		CodeChallenge:       s256("verifier-abc"),
		CodeChallengeMethod: "S256",
		ExpiresAt:           time.Now().Add(AuthCodeTTL),
	}
	if err := g.Create(code).Error; err != nil {
		t.Fatalf("创建授权码失败: %v", err)
	}

	// 第一次：未使用
	var first db.OAuthAuthorizationCode
	if err := g.Where("code = ?", "code-single-use").First(&first).Error; err != nil {
		t.Fatalf("查询授权码失败: %v", err)
	}
	if first.UsedAt != nil {
		t.Fatal("新授权码 UsedAt 应为空")
	}

	// 标记已使用
	usedAt := time.Now()
	g.Model(&first).Update("used_at", usedAt)

	// 第二次：已使用
	var second db.OAuthAuthorizationCode
	g.Where("code = ?", "code-single-use").First(&second)
	if second.UsedAt == nil {
		t.Error("授权码使用后 UsedAt 不应为空（一次性语义）")
	}
}

func TestAuthCode_Expiry(t *testing.T) {
	g := setupTestDB(t)
	u := testUser(t, g)

	expired := &db.OAuthAuthorizationCode{
		Code:      "code-expired",
		ClientID:  "c",
		UserID:    u.ID,
		ExpiresAt: time.Now().Add(-1 * time.Minute), // 已过期
	}
	g.Create(expired)

	var got db.OAuthAuthorizationCode
	g.Where("code = ?", "code-expired").First(&got)
	if got.ExpiresAt.After(time.Now()) {
		t.Error("该授权码应为已过期")
	}

	// 模拟 handler 的查询条件：code 存在且未过期
	var counted int64
	g.Model(&db.OAuthAuthorizationCode{}).
		Where("code = ? AND expires_at > ?", "code-expired", time.Now()).
		Count(&counted)
	if counted != 0 {
		t.Error("过期授权码不应被有效查询命中")
	}
}

// ============================================================
// refresh_token 吊销
// ============================================================

func TestRefreshToken_Revocation(t *testing.T) {
	g := setupTestDB(t)
	u := testUser(t, g)

	rt := &db.OAuthRefreshToken{
		Token:     "rt-to-revoke",
		ClientID:  "template-web-client",
		UserID:    u.ID,
		Scope:     "openid profile email",
		ExpiresAt: time.Now().Add(RefreshTokenTTL),
	}
	g.Create(rt)

	// 初始可用
	var before db.OAuthRefreshToken
	g.Where("token = ?", "rt-to-revoke").First(&before)
	if before.RevokedAt != nil {
		t.Fatal("新建 refresh_token 不应已吊销")
	}

	// 吊销
	nowT := time.Now()
	g.Model(&before).Update("revoked_at", nowT)

	// 吊销后：handler 的有效性查询条件应命中 0 条
	var valid int64
	g.Model(&db.OAuthRefreshToken{}).
		Where("token = ? AND revoked_at IS NULL AND expires_at > ?", "rt-to-revoke", time.Now()).
		Count(&valid)
	if valid != 0 {
		t.Error("已吊销的 refresh_token 不应通过有效性检查")
	}
}

func TestRefreshToken_Expired(t *testing.T) {
	g := setupTestDB(t)
	u := testUser(t, g)

	g.Create(&db.OAuthRefreshToken{
		Token:     "rt-expired",
		ClientID:  "c",
		UserID:    u.ID,
		ExpiresAt: time.Now().Add(-time.Hour),
	})

	var valid int64
	g.Model(&db.OAuthRefreshToken{}).
		Where("token = ? AND revoked_at IS NULL AND expires_at > ?", "rt-expired", time.Now()).
		Count(&valid)
	if valid != 0 {
		t.Error("已过期的 refresh_token 不应通过有效性检查")
	}
}

// ============================================================
// TTL 常量一致性（Task4 规则）
// ============================================================

func TestTTLConstants(t *testing.T) {
	cases := []struct {
		name string
		got  time.Duration
		want time.Duration
	}{
		{"access_token TTL", AccessTokenTTL, 10 * time.Minute},
		{"refresh_token TTL", RefreshTokenTTL, 7 * 24 * time.Hour},
		{"授权码 TTL", AuthCodeTTL, 5 * time.Minute},
		{"会话 TTL", SessionTTL, 8 * time.Hour},
	}
	for _, c := range cases {
		if c.got != c.want {
			t.Errorf("%s = %v, 期望 %v", c.name, c.got, c.want)
		}
	}
}

// ============================================================
// 布尔指针语义（GORM 显式 false 陷阱回归）
// ============================================================

func TestBoolPtrSemantics(t *testing.T) {
	// nil 应视为默认开启
	c := &db.OAuthClient{}
	if !c.IsPublicClient() {
		t.Error("IsPublic 为 nil 时应视为公共客户端")
	}
	if !c.PKCENeeded() {
		t.Error("PKCERequired 为 nil 时应视为强制 PKCE")
	}
	if !c.IsEnabled() {
		t.Error("Enabled 为 nil 时应视为启用")
	}

	// 显式 false 应被保留
	c2 := &db.OAuthClient{
		IsPublic:     db.BoolPtr(false),
		PKCERequired: db.BoolPtr(false),
		Enabled:      db.BoolPtr(false),
	}
	if c2.IsPublicClient() {
		t.Error("显式 false 应被视为机密客户端")
	}
	if c2.PKCENeeded() {
		t.Error("显式 false 不应强制 PKCE")
	}
	if c2.IsEnabled() {
		t.Error("显式 false 应被视为禁用")
	}
}

// TestClientExplicitFalsePersists 回归测试：显式 false 必须能落库
// （历史 bug：`default:true` 标签让 GORM 把显式 false 当零值忽略）
func TestClientExplicitFalsePersists(t *testing.T) {
	g := setupTestDB(t)

	g.Create(&db.OAuthClient{
		ClientID:     "confidential-client",
		ClientName:   "机密客户端",
		RedirectURIs: "http://example.com/cb",
		IsPublic:     db.BoolPtr(false),
		PKCERequired: db.BoolPtr(false),
		Enabled:      db.BoolPtr(true),
	})

	var got db.OAuthClient
	if err := g.Where("client_id = ?", "confidential-client").First(&got).Error; err != nil {
		t.Fatalf("查询失败: %v", err)
	}
	if got.IsPublicClient() {
		t.Error("is_public=false 应被持久化，但读回后变成了 true")
	}
	if got.PKCENeeded() {
		t.Error("pkce_required=false 应被持久化")
	}
	if !got.IsEnabled() {
		t.Error("enabled=true 应被持久化")
	}
}

// ============================================================
// 用户会话
// ============================================================

func TestUserSession_Expiry(t *testing.T) {
	g := setupTestDB(t)
	u := testUser(t, g)

	// 有效会话
	sid := db.RandomToken(32)
	g.Create(&db.UserSession{
		SessionID: sid,
		UserID:    u.ID,
		ExpiresAt: time.Now().Add(SessionTTL),
	})

	var valid int64
	g.Model(&db.UserSession{}).
		Where("session_id = ? AND expires_at > ?", sid, time.Now()).
		Count(&valid)
	if valid != 1 {
		t.Error("未过期会话应被命中")
	}

	// 过期会话
	expiredSid := db.RandomToken(32)
	g.Create(&db.UserSession{
		SessionID: expiredSid,
		UserID:    u.ID,
		ExpiresAt: time.Now().Add(-time.Minute),
	})
	var expiredCount int64
	g.Model(&db.UserSession{}).
		Where("session_id = ? AND expires_at > ?", expiredSid, time.Now()).
		Count(&expiredCount)
	if expiredCount != 0 {
		t.Error("已过期会话不应被命中")
	}
}

// ============================================================
// argon2id 哈希长度稳定性
// ============================================================

func TestPasswordHash_Argon2Params(t *testing.T) {
	h := db.HashPassword("x")
	parts := splitOnDollar(h)
	if len(parts) != 3 {
		t.Fatalf("格式错误: %s", h)
	}
	hashRaw, err := base64.RawStdEncoding.DecodeString(parts[2])
	if err != nil {
		t.Fatalf("hash 段解码失败: %v", err)
	}
	if len(hashRaw) != 32 {
		t.Errorf("argon2id 输出应为 32 字节, 实际 %d", len(hashRaw))
	}
	saltRaw, err := base64.RawStdEncoding.DecodeString(parts[1])
	if err != nil {
		t.Fatalf("salt 段解码失败: %v", err)
	}
	if len(saltRaw) != 16 {
		t.Errorf("salt 应为 16 字节, 实际 %d", len(saltRaw))
	}
}

func splitOnDollar(s string) []string {
	var out []string
	start := 0
	for i := 0; i < len(s); i++ {
		if s[i] == '$' {
			out = append(out, s[start:i])
			start = i + 1
		}
	}
	return append(out, s[start:])
}

// 确保 sha256 引用被使用（s256 helper 在 oidc_util_test.go 中定义）
var _ = sha256.Sum256
