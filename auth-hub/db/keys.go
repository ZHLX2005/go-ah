package db

// 运行时密钥与随机数工具

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"fmt"
	"log"
	"sync"
)

var (
	// SigningKey IDP 用于签发 id_token 的 RSA 私钥（进程内生成，重启后变化）
	SigningKey *rsa.PrivateKey
	KeyID      = "idp-key-1"
	once       sync.Once
)

// InitKeys 生成/加载签名密钥
func InitKeys() {
	once.Do(func() {
		k, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			log.Fatalf("生成 RSA 密钥失败: %v", err)
		}
		SigningKey = k
		log.Println("[IDP] 已生成 RSA 签名密钥（id_token 使用 RS256）")
	})
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
