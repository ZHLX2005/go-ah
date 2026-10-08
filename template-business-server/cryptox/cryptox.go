// Package cryptox 提供 template-business-server 侧的 Token 加密持久化能力。
//
// 设计要点（与 oidc-cli 采用同一套算法方案，但密钥来源不同）：
//   - 算法：AES-256-GCM（认证加密，防篡改）
//   - 密钥派生：PBKDF2-HMAC-SHA256，120000 轮
//   - 存储格式：base64( salt(16) || nonce(12) || ciphertext+tag )
//   - 盐值随机生成，随密文一起保存，每条记录独立
//   - 密钥来源：环境变量 BIZ_TOKEN_SECRET（不落库、不硬编码）
//
// 与 CLI 的差异：
//
//	CLI 的口令来自本机指纹（hostname/user/home/OS），因为 CLI 运行在用户机器上；
//	业务服务运行在服务器上，没有稳定"机器指纹"语义，因此强制要求显式注入环境变量密钥，
//	启动时校验强度，避免把 refresh_token 用弱密钥或空密钥加密后落库。
package cryptox

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"

	"golang.org/x/crypto/pbkdf2"
)

const (
	// PBKDF2Iterations 密钥派生轮数
	PBKDF2Iterations = 120000
	// KeyLen AES-256
	KeyLen = 32
	// SaltLen 随机盐长度
	SaltLen = 16

	// EnvSecret 环境变量名：业务服务 Token 加密密钥
	EnvSecret = "BIZ_TOKEN_SECRET"
	// 最小密钥长度，防止使用 "123" 之类的弱密钥
	MinSecretLen = 16
)

// 错误定义
var (
	ErrNoSecret     = errors.New("未配置 " + EnvSecret + " 环境变量：业务服务必须显式注入 Token 加密密钥")
	ErrWeakSecret   = fmt.Errorf("%s 长度不足：至少需要 %d 个字符", EnvSecret, MinSecretLen)
	ErrCipherBroken = errors.New("密文格式非法或已被篡改")
)

// Engine 加密引擎，持有已派生的密钥材料
type Engine struct {
	secret string
}

// NewEngine 读取环境变量并校验强度，构建加密引擎
func NewEngine() (*Engine, error) {
	return NewEngineFromSecret(os.Getenv(EnvSecret))
}

// NewEngineFromSecret 使用显式密钥材料构建引擎（便于单元测试注入）
func NewEngineFromSecret(secret string) (*Engine, error) {
	if strings.TrimSpace(secret) == "" {
		return nil, ErrNoSecret
	}
	if len(secret) < MinSecretLen {
		return nil, ErrWeakSecret
	}
	return &Engine{secret: secret}, nil
}

// MustEngine 构建引擎，失败直接 panic（供 main 启动期调用）
func MustEngine() *Engine {
	e, err := NewEngine()
	if err != nil {
		panic(err)
	}
	return e
}

// deriveKey PBKDF2-HMAC-SHA256(secret, salt) -> 32B
func (e *Engine) deriveKey(salt []byte) []byte {
	return pbkdf2.Key([]byte(e.secret), salt, PBKDF2Iterations, KeyLen, sha256.New)
}

// Encrypt 加密明文，返回 base64(salt || nonce || ciphertext)
// 每次调用都使用全新随机 salt 与 nonce，同一明文两次加密结果不同
func (e *Engine) Encrypt(plaintext string) (string, error) {
	if plaintext == "" {
		// 空值不加密，避免把 "" 变成一段看起来存在的密文
		return "", nil
	}
	salt := make([]byte, SaltLen)
	if _, err := io.ReadFull(rand.Reader, salt); err != nil {
		return "", fmt.Errorf("生成盐值失败: %w", err)
	}
	key := e.deriveKey(salt)

	block, err := aes.NewCipher(key)
	if err != nil {
		return "", fmt.Errorf("创建 AES cipher 失败: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", fmt.Errorf("创建 GCM 失败: %w", err)
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", fmt.Errorf("生成 nonce 失败: %w", err)
	}
	// 把 salt 作为附加认证数据（AAD），密文被搬运到别的记录时解密会失败
	sealed := gcm.Seal(nonce, nonce, []byte(plaintext), salt)
	raw := append(salt, sealed...)
	return base64.StdEncoding.EncodeToString(raw), nil
}

// Decrypt 解密 Encrypt 的输出
func (e *Engine) Decrypt(encoded string) (string, error) {
	if encoded == "" {
		return "", nil
	}
	raw, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return "", fmt.Errorf("%w: base64 解码失败", ErrCipherBroken)
	}
	if len(raw) < SaltLen+12 {
		return "", ErrCipherBroken
	}
	salt, rest := raw[:SaltLen], raw[SaltLen:]
	key := e.deriveKey(salt)

	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}
	ns := gcm.NonceSize()
	if len(rest) < ns {
		return "", ErrCipherBroken
	}
	plain, err := gcm.Open(nil, rest[:ns], rest[ns:], salt)
	if err != nil {
		// 统一成"密钥不匹配或数据被篡改"，不泄漏底层细节
		return "", fmt.Errorf("%w: 密钥不匹配或数据被篡改", ErrCipherBroken)
	}
	return string(plain), nil
}

// IsCiphertext 粗判：非空且能被 base64 解码且长度合理
// 用于"存量明文数据平滑迁移"，避免把历史明文当成密文去解密
func IsCiphertext(s string) bool {
	if s == "" {
		return false
	}
	raw, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		return false
	}
	return len(raw) >= SaltLen+12
}
