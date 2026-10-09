// Package signing 负责 id_token 的 RSA 签名密钥与签发。
//
// 密钥的来源优先级（顺序不可调换）：
//
//	① 环境变量 IDP_SIGNING_KEY_PEM —— 多副本部署时各实例共用同一把
//	② 数据库里持久化的那一把     —— 单实例重启后保持稳定
//	③ 都没有                   —— 生成一把并落库
//
// ③ 的「落库」不能省：密钥若只活在进程内存里，每次容器重启都会换一把，
// 而 kid 仍是固定的 idp-key-1 —— 客户端缓存的 JWKS 立刻失配，
// 现象是「重启后所有已签发的 id_token 一律验签失败」，
// 报错只会说签名不匹配，很难联想到"密钥换了"。
package signing

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/gogf/gf/v2/frame/g"
	"github.com/golang-jwt/jwt/v5"

	"github.com/ZHLX2005/go-ah/auth-hub/internal/config"
	"github.com/ZHLX2005/go-ah/auth-hub/internal/consts"
	"github.com/ZHLX2005/go-ah/auth-hub/internal/dao"
	"github.com/ZHLX2005/go-ah/auth-hub/internal/db"
	"github.com/ZHLX2005/go-ah/auth-hub/internal/model/entity"
)

var (
	mu         sync.RWMutex
	privateKey *rsa.PrivateKey
	keyID      = consts.DefaultKeyID
)

// Load 加载或生成签名密钥。幂等：重复调用只生效第一次。
//
// 必须在 db.Init 之后调用（② 与 ③ 都要读写数据库）。
func Load(ctx context.Context, injectedPEM string) error {
	mu.Lock()
	defer mu.Unlock()
	if privateKey != nil {
		return nil
	}

	// ① 显式注入
	if s := strings.TrimSpace(injectedPEM); s != "" {
		k, err := parsePrivateKeyPEM(s)
		if err != nil {
			return fmt.Errorf("%s 解析失败: %w", consts.SigningKeyEnv, err)
		}
		privateKey = k
		g.Log().Info(ctx, "[auth-hub] 已从环境变量加载 RSA 签名密钥（id_token 使用 RS256）")
		return nil
	}

	// ② 数据库已有
	//
	// "库里还没有这一行"是**首次启动的正常状态**，不是故障：
	// 若这里用 Scan，零行会返回 sql.ErrNoRows，等于新库永远起不来。
	var rec entity.SigningKeyRecord
	found, err := db.ScanOne(ctx, dao.SigningKey.Ctx(ctx).Order("id DESC"), &rec)
	if err != nil {
		return fmt.Errorf("读取签名密钥失败: %w", err)
	}
	if found && rec.Pem != "" {
		k, err := parsePrivateKeyPEM(rec.Pem)
		if err != nil {
			// 库里的密钥解析不了，是必须人工介入的状态：继续跑会签出
			// 客户端验不过的 token，比启动失败更难查。
			return fmt.Errorf("数据库中的签名密钥无法解析 (kid=%s): %w", rec.KeyID, err)
		}
		privateKey = k
		keyID = rec.KeyID
		g.Log().Infof(ctx, "[auth-hub] 已从数据库加载 RSA 签名密钥 (kid=%s)", keyID)
		return nil
	}

	// ③ 首次启动：生成并落库
	k, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return fmt.Errorf("生成 RSA 密钥失败: %w", err)
	}
	pemStr, err := marshalPrivateKeyPEM(k)
	if err != nil {
		return fmt.Errorf("序列化 RSA 密钥失败: %w", err)
	}
	if _, err := dao.SigningKey.Ctx(ctx).Data(g.Map{
		"key_id":     keyID,
		"pem":        pemStr,
		"created_at": time.Now(),
	}).Insert(); err != nil {
		return fmt.Errorf("签名密钥落库失败（重启后密钥会变，不可接受）: %w", err)
	}
	privateKey = k
	g.Log().Infof(ctx, "[auth-hub] 已生成并持久化 RSA 签名密钥 (kid=%s)", keyID)
	return nil
}

// KeyID 当前签名密钥的 kid
func KeyID() string {
	mu.RLock()
	defer mu.RUnlock()
	return keyID
}

// PublicKey 当前签名公钥（JWKS 端点用）
func PublicKey(ctx context.Context) (*rsa.PublicKey, error) {
	mu.RLock()
	defer mu.RUnlock()
	if privateKey == nil {
		return nil, fmt.Errorf("签名密钥未加载：请确认 signing.Load 已在启动时调用")
	}
	return &privateKey.PublicKey, nil
}

// IDToken 按 OIDC 规范签发 id_token（RS256）。
//
// 声明按 scope 裁剪：没申请 profile 就不该看到昵称，
// 没申请 email 就不该看到邮箱 —— 这是 scope 的语义，不是可选项。
func IDToken(ctx context.Context, user *entity.User, clientID, nonce, scope string) (string, error) {
	mu.RLock()
	key := privateKey
	kid := keyID
	mu.RUnlock()
	if key == nil {
		return "", fmt.Errorf("签名密钥未加载：请确认 signing.Load 已在启动时调用")
	}

	now := time.Now()
	claims := jwt.MapClaims{
		"iss":       config.Get().Issuer,
		"sub":       subOf(user.Id),
		"aud":       clientID,
		"exp":       now.Add(consts.IDTokenTTL).Unix(),
		"iat":       now.Unix(),
		"auth_time": now.Unix(),
	}
	if nonce != "" {
		claims["nonce"] = nonce
	}
	if strings.Contains(scope, "profile") {
		claims["name"] = user.Nickname
		claims["preferred_username"] = user.Username
	}
	if strings.Contains(scope, "email") {
		claims["email"] = user.Email
		claims["email_verified"] = true
	}

	tok := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	tok.Header["kid"] = kid
	return tok.SignedString(key)
}

// SubOf 把用户 ID 转成 OIDC 的 sub（统一出口，避免各处自己拼数字串）
func SubOf(userID int64) string { return subOf(userID) }

func subOf(userID int64) string {
	return fmt.Sprintf("%d", userID)
}

// marshalPrivateKeyPEM 序列化为 PKCS#8 PEM
func marshalPrivateKeyPEM(k *rsa.PrivateKey) (string, error) {
	der, err := x509.MarshalPKCS8PrivateKey(k)
	if err != nil {
		return "", err
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})), nil
}

// parsePrivateKeyPEM 解析 PKCS#8 PEM；兼容历史的 PKCS#1 写法
func parsePrivateKeyPEM(s string) (*rsa.PrivateKey, error) {
	block, _ := pem.Decode([]byte(s))
	if block == nil {
		return nil, fmt.Errorf("不是合法的 PEM 文本")
	}
	if k, err := x509.ParsePKCS8PrivateKey(block.Bytes); err == nil {
		rk, ok := k.(*rsa.PrivateKey)
		if !ok {
			return nil, fmt.Errorf("私钥不是 RSA 类型（实际 %T）", k)
		}
		return rk, nil
	}
	if rk, err := x509.ParsePKCS1PrivateKey(block.Bytes); err == nil {
		return rk, nil
	}
	return nil, fmt.Errorf("无法解析私钥（PKCS#8 与 PKCS#1 都失败）")
}
