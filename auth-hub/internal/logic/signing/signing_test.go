package signing

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/gogf/gf/v2/os/gctx"
	"github.com/golang-jwt/jwt/v5"

	"github.com/ZHLX2005/go-ah/auth-hub/internal/config"
	"github.com/ZHLX2005/go-ah/auth-hub/internal/consts"
	"github.com/ZHLX2005/go-ah/auth-hub/internal/model/entity"
)

const testIssuer = "http://idp.test"

// TestMain 准备一份注入式签名密钥。
//
// 走"显式注入"这条路（而不是落库）是刻意的：这套测试因此完全不碰数据库，
// 在任何环境下都能跑起来验证 id_token 的签发与声明裁剪。
func TestMain(m *testing.M) {
	ctx := gctx.GetInitCtx()
	_ = os.Setenv("IDP_ISSUER", testIssuer)
	config.Load(ctx)

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		panic(err)
	}
	pemStr, err := marshalPrivateKeyPEM(key)
	if err != nil {
		panic(err)
	}
	if err := Load(ctx, pemStr); err != nil {
		panic(err)
	}
	os.Exit(m.Run())
}

func testUser() *entity.User {
	return &entity.User{
		Id:       42,
		Username: "test",
		Nickname: "测试用户",
		Email:    "test@example.com",
	}
}

// parseAndVerify 解析并验签 id_token，同时校验算法
func parseAndVerify(t *testing.T, token string) jwt.MapClaims {
	t.Helper()

	pub, err := PublicKey(gctx.GetInitCtx())
	if err != nil {
		t.Fatalf("取公钥失败: %v", err)
	}
	parsed, err := jwt.Parse(token, func(*jwt.Token) (interface{}, error) {
		return pub, nil
	}, jwt.WithValidMethods([]string{"RS256"}))
	if err != nil {
		t.Fatalf("验签失败: %v", err)
	}
	claims, ok := parsed.Claims.(jwt.MapClaims)
	if !ok {
		t.Fatal("claims 类型不符")
	}
	return claims
}

// ============================================================
// id_token 的声明
// ============================================================

func TestIDToken_Claims(t *testing.T) {
	const nonce = "n-0S6_WzA2Mj"
	const scope = "openid profile email"

	before := time.Now()
	tok, err := IDToken(gctx.GetInitCtx(), testUser(), "gs-ac", nonce, scope)
	if err != nil {
		t.Fatalf("签发失败: %v", err)
	}
	if tok == "" {
		t.Fatal("签发的 token 不应为空")
	}

	claims := parseAndVerify(t, tok)
	if got := claims["iss"]; got != testIssuer {
		t.Errorf("iss = %v, 期望 %s", got, testIssuer)
	}
	if got := claims["sub"]; got != "42" {
		t.Errorf("sub = %v, 期望 42", got)
	}
	if got := claims["aud"]; got != "gs-ac" {
		t.Errorf("aud = %v, 期望 gs-ac", got)
	}
	if got := claims["nonce"]; got != nonce {
		t.Errorf("nonce = %v, 期望 %s", got, nonce)
	}

	// required 的三个时间声明必须都在，且关系正确
	exp, ok := claims["exp"].(float64)
	if !ok {
		t.Fatalf("exp 缺失或类型不符: %v", claims["exp"])
	}
	iat, ok := claims["iat"].(float64)
	if !ok {
		t.Fatalf("iat 缺失或类型不符: %v", claims["iat"])
	}
	authTime, ok := claims["auth_time"].(float64)
	if !ok {
		t.Fatalf("auth_time 缺失或类型不符: %v", claims["auth_time"])
	}

	if iat < float64(before.Add(-time.Minute).Unix()) {
		t.Errorf("iat 早于签发时刻: %v", iat)
	}
	wantExp := iat + consts.IDTokenTTL.Seconds()
	if int64(exp) != int64(wantExp) {
		t.Errorf("exp - iat = %d 秒, 期望 %d 秒（IDTokenTTL）", int64(exp)-int64(iat), int64(consts.IDTokenTTL.Seconds()))
	}
	if int64(authTime) != int64(iat) {
		t.Errorf("auth_time = %v, 期望与 iat 相同（口令登录即时）", authTime)
	}
}

func TestIDToken_HeaderKid(t *testing.T) {
	tok, err := IDToken(gctx.GetInitCtx(), testUser(), "gs-ac", "", "openid")
	if err != nil {
		t.Fatalf("签发失败: %v", err)
	}
	parsed, _, err := jwt.NewParser().ParseUnverified(tok, jwt.MapClaims{})
	if err != nil {
		t.Fatalf("解析失败: %v", err)
	}
	if got := parsed.Header["kid"]; got != consts.DefaultKeyID {
		t.Errorf("kid = %v, 期望 %s（JWKS 里必须能找到同一个 kid）", got, consts.DefaultKeyID)
	}
	if got := parsed.Header["alg"]; got != "RS256" {
		t.Errorf("alg = %v, 期望 RS256", got)
	}
}

// TestIDToken_ScopeGating 声明按 scope 裁剪：没申请就看不到对应字段
func TestIDToken_ScopeGating(t *testing.T) {
	cases := []struct {
		name         string
		scope        string
		wantName     bool
		wantEmail    bool
		wantUsername bool
	}{
		{"仅 openid", "openid", false, false, false},
		{"openid profile", "openid profile", true, false, true},
		{"openid email", "openid email", false, true, false},
		{"全量", "openid profile email", true, true, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			tok, err := IDToken(gctx.GetInitCtx(), testUser(), "gs-ac", "", tc.scope)
			if err != nil {
				t.Fatalf("签发失败: %v", err)
			}
			claims := parseAndVerify(t, tok)

			if _, ok := claims["name"]; ok != tc.wantName {
				t.Errorf("name 存在 = %v, 期望 %v", ok, tc.wantName)
			}
			if _, ok := claims["preferred_username"]; ok != tc.wantUsername {
				t.Errorf("preferred_username 存在 = %v, 期望 %v", ok, tc.wantUsername)
			}
			if _, ok := claims["email"]; ok != tc.wantEmail {
				t.Errorf("email 存在 = %v, 期望 %v", ok, tc.wantEmail)
			}
			if _, ok := claims["email_verified"]; ok != tc.wantEmail {
				t.Errorf("email_verified 存在 = %v, 期望 %v", ok, tc.wantEmail)
			}
		})
	}
}

// TestIDToken_EmptyNonceOmitted nonce 为空时不应出现该声明
func TestIDToken_EmptyNonceOmitted(t *testing.T) {
	tok, err := IDToken(gctx.GetInitCtx(), testUser(), "gs-ac", "", "openid")
	if err != nil {
		t.Fatalf("签发失败: %v", err)
	}
	claims := parseAndVerify(t, tok)
	if _, ok := claims["nonce"]; ok {
		t.Error("nonce 为空时不应写入该声明")
	}
}

// ============================================================
// 防篡改
// ============================================================

func TestIDToken_TamperedRejected(t *testing.T) {
	tok, err := IDToken(gctx.GetInitCtx(), testUser(), "gs-ac", "", "openid")
	if err != nil {
		t.Fatalf("签发失败: %v", err)
	}

	// 改签名段**中间**的字符。
	//
	// 不能改最后一个字符：RS256 签名的 base64url 尾部带 2 个填充位，解码时
	// 被丢弃，换掉末位字符解出来还是同一段字节，签名照过 —— 断言会变成假绿灯。
	// 这里从中间下手，保证解出的签名真的变了。
	parts := strings.Split(tok, ".")
	if len(parts) != 3 {
		t.Fatalf("id_token 不是三段式: %q", tok)
	}
	sig := []byte(parts[2])
	mid := len(sig) / 2
	if sig[mid] == 'A' {
		sig[mid] = 'B'
	} else {
		sig[mid] = 'A'
	}
	tampered := parts[0] + "." + parts[1] + "." + string(sig)

	pub, _ := PublicKey(gctx.GetInitCtx())
	if _, err := jwt.Parse(tampered, func(*jwt.Token) (interface{}, error) {
		return pub, nil
	}, jwt.WithValidMethods([]string{"RS256"})); err == nil {
		t.Error("被篡改的 token 不应通过验签")
	}
}

func TestIDToken_WrongKeyRejected(t *testing.T) {
	// 用另一把私钥签发同样的声明：客户端拿我们的公钥验，必须失败
	other, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("生成密钥失败: %v", err)
	}
	now := time.Now()
	claims := jwt.MapClaims{
		"iss": testIssuer,
		"sub": "42",
		"aud": "gs-ac",
		"exp": now.Add(time.Hour).Unix(),
		"iat": now.Unix(),
	}
	forged, err := jwt.NewWithClaims(jwt.SigningMethodRS256, claims).SignedString(other)
	if err != nil {
		t.Fatalf("签发失败: %v", err)
	}

	pub, _ := PublicKey(gctx.GetInitCtx())
	if _, err := jwt.Parse(forged, func(*jwt.Token) (interface{}, error) {
		return pub, nil
	}, jwt.WithValidMethods([]string{"RS256"})); err == nil {
		t.Error("非本平台密钥签发的 token 不应通过验签")
	}
}

// ============================================================
// 密钥本身
// ============================================================

func TestPublicKey_MatchesPrivateKey(t *testing.T) {
	pub, err := PublicKey(gctx.GetInitCtx())
	if err != nil {
		t.Fatalf("取公钥失败: %v", err)
	}
	mu.RLock()
	priv := privateKey
	mu.RUnlock()

	if priv == nil {
		t.Fatal("私钥未加载")
	}
	if pub.N.Cmp(priv.N) != 0 || pub.E != priv.E {
		t.Error("JWKS 暴露的公钥与签名私钥不匹配 —— 客户端会全部验签失败")
	}
	if pub.E != 65537 {
		t.Errorf("RSA 公钥指数 = %d, 期望 65537", pub.E)
	}
}

func TestKeyID_Default(t *testing.T) {
	if got := KeyID(); got != consts.DefaultKeyID {
		t.Errorf("KeyID() = %q, 期望 %q", got, consts.DefaultKeyID)
	}
}

func TestSubOf(t *testing.T) {
	if got := SubOf(0); got != "0" {
		t.Errorf("SubOf(0) = %q", got)
	}
	if got := SubOf(9876543210); got != "9876543210" {
		t.Errorf("SubOf(9876543210) = %q", got)
	}
}

// ============================================================
// PEM 解析
// ============================================================

func TestParsePrivateKeyPEM_PKCS8AndPKCS1(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("生成密钥失败: %v", err)
	}

	// PKCS#8
	p8, err := marshalPrivateKeyPEM(key)
	if err != nil {
		t.Fatalf("序列化 PKCS#8 失败: %v", err)
	}
	got, err := parsePrivateKeyPEM(p8)
	if err != nil {
		t.Fatalf("解析 PKCS#8 失败: %v", err)
	}
	if got.N.Cmp(key.N) != 0 {
		t.Error("PKCS#8 解析结果与原文不符")
	}

	// PKCS#1（历史写法，必须仍然兼容，否则老库里的密钥读不出来）
	p1 := string(pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(key),
	}))
	got, err = parsePrivateKeyPEM(p1)
	if err != nil {
		t.Fatalf("解析 PKCS#1 失败: %v", err)
	}
	if got.N.Cmp(key.N) != 0 {
		t.Error("PKCS#1 解析结果与原文不符")
	}
}

func TestParsePrivateKeyPEM_Invalid(t *testing.T) {
	bad := []string{
		"",
		"not a pem at all",
		"-----BEGIN PRIVATE KEY-----\nzzzz\n-----END PRIVATE KEY-----",
	}
	for _, b := range bad {
		if _, err := parsePrivateKeyPEM(b); err == nil {
			t.Errorf("非法 PEM 应当报错: %q", b)
		}
	}
}
