package db

// 运行时密钥与随机数工具

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"log"
	"os"
	"sync"
)

var (
	// SigningKey IDP 用于签发 id_token 的 RSA 私钥（RS256）。
	// 由 InitKeys 从环境变量或数据库加载，加载不到才新生成并落库。
	SigningKey *rsa.PrivateKey
	// KeyID 写入 JWT 头的 kid，客户端据此在 JWKS 里挑选公钥
	KeyID = "idp-key-1"
	once  sync.Once
)

// signingKeyEnv 用固定密钥启动的环境变量名（多副本部署时各实例共用同一把）
const signingKeyEnv = "IDP_SIGNING_KEY_PEM"

// InitKeys 加载或生成 id_token 签名密钥，优先级：
//
//	① env IDP_SIGNING_KEY_PEM  —— 多副本部署时保证各实例用同一把
//	② 数据库里已有的一条      —— 单实例重启后保持稳定
//	③ 都没有                  —— 生成一把并落库
//
// ③ 里的「落库」不能省：密钥若只活在进程内存里，每次重启都会换一把，
// 而 kid 仍是固定的 idp-key-1 —— 客户端缓存的 JWKS 与之一致性失配，
// 表现为「重启后所有已签发的 id_token 一律验签失败」，且报错信息
// 只会说签名不匹配，很难联想到「密钥换了」。
//
// 必须在 Init() 之后调用（需要 DB）。
func InitKeys() {
	once.Do(func() {
		if DB == nil {
			log.Fatalf("[IDP] InitKeys 必须在 db.Init 之后调用（当前 DB 为空）")
		}

		// ① 环境变量注入
		if pemStr := os.Getenv(signingKeyEnv); pemStr != "" {
			k, err := parsePrivateKeyPEM(pemStr)
			if err != nil {
				log.Fatalf("[IDP] %s 解析失败: %v", signingKeyEnv, err)
			}
			SigningKey = k
			log.Println("[IDP] 已从环境变量加载 RSA 签名密钥（id_token 使用 RS256）")
			return
		}

		// ② 数据库已有
		var rec SigningKeyRecord
		if err := DB.Order("id DESC").First(&rec).Error; err == nil && rec.PEM != "" {
			k, perr := parsePrivateKeyPEM(rec.PEM)
			if perr != nil {
				log.Fatalf("[IDP] 数据库中的签名密钥无法解析 (kid=%s): %v", rec.KeyID, perr)
			}
			SigningKey = k
			KeyID = rec.KeyID
			log.Printf("[IDP] 已从数据库加载 RSA 签名密钥 (kid=%s)", KeyID)
			return
		}

		// ③ 首次启动：生成并落库
		k, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			log.Fatalf("生成 RSA 密钥失败: %v", err)
		}
		pemStr, err := marshalPrivateKeyPEM(k)
		if err != nil {
			log.Fatalf("序列化 RSA 密钥失败: %v", err)
		}
		if err := DB.Create(&SigningKeyRecord{KeyID: KeyID, PEM: pemStr}).Error; err != nil {
			log.Fatalf("[IDP] 签名密钥落库失败（重启后密钥会变，不可接受）: %v", err)
		}
		SigningKey = k
		log.Printf("[IDP] 已生成并持久化 RSA 签名密钥 (kid=%s)", KeyID)
	})
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
	// 兼容 PKCS#1
	if rk, err := x509.ParsePKCS1PrivateKey(block.Bytes); err == nil {
		return rk, nil
	}
	return nil, fmt.Errorf("无法解析私钥（PKCS#8 与 PKCS#1 都失败）")
}

// RandomToken 生成 URL 安全随机字符串
func RandomToken(n int) string {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b)
}

// TokenHashPrefix 返回 token 的前 12 位，用于日志/展示
func TokenHashPrefix(t string) string {
	if len(t) <= 12 {
		return t
	}
	return fmt.Sprintf("%s...", t[:12])
}
