// Package internal 提供 template-oidc-cli 的内部实现：PKCE、浏览器唤起、
// 临时回调服务、加密存储与后台续期。
package internal

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"os"
	"os/user"
	"runtime"
	"strings"

	"golang.org/x/crypto/pbkdf2"
)

// ============================================================
// AES-GCM 加密存储（Task4 统一加密方案）
//
// 密钥派生：PBKDF2-HMAC-SHA256
// 输入口令 = 本机硬件/用户信息（+ 可选用户口令）
// 盐值随机生成，随密文一起保存（salt || nonce || ciphertext）
// 不使用任何硬编码密钥。
// ============================================================

const (
	pbkdf2Iterations = 120000
	pbkdf2KeyLen     = 32 // AES-256
	// StorePasswordEnv 可选：通过环境变量提供额外口令，增强密钥强度
	StorePasswordEnv = "OIDC_CLI_PASSPHRASE"
)

// CryptoEngine 封装密钥派生与加解密
type CryptoEngine struct {
	// machineSecret 由本机信息派生，作为 PBKDF2 的基础口令
	machineSecret string
	// optionalPassphrase 用户可选口令（环境变量），为空则仅用本机信息
	optionalPassphrase string
}

// NewCryptoEngine 构建加密引擎：
// 口令 = hostname + 系统用户 + 家目录 + OS + 可选用户口令
func NewCryptoEngine() *CryptoEngine {
	return &CryptoEngine{
		machineSecret:      machineFingerprint(),
		optionalPassphrase: os.Getenv(StorePasswordEnv),
	}
}

// machineFingerprint 采集本机稳定特征，保证同一台机器同一用户可解密
func machineFingerprint() string {
	host, _ := os.Hostname()
	home, _ := os.UserHomeDir()
	name := ""
	if u, err := user.Current(); err == nil {
		name = u.Username
		name += "|" + u.Uid
	}
	return strings.Join([]string{host, name, home, runtime.GOOS, runtime.GOARCH}, "::")
}

// deriveKey 使用 PBKDF2 从口令 + 盐派生 32 字节密钥
func (e *CryptoEngine) deriveKey(salt []byte) []byte {
	pass := e.machineSecret
	if e.optionalPassphrase != "" {
		pass += "::" + e.optionalPassphrase
	}
	return pbkdf2.Key([]byte(pass), salt, pbkdf2Iterations, pbkdf2KeyLen, sha256.New)
}

// Encrypt 加密明文，输出格式：salt(16) || nonce(12) || ciphertext
func (e *CryptoEngine) Encrypt(plaintext []byte) ([]byte, error) {
	salt := make([]byte, 16)
	if _, err := io.ReadFull(rand.Reader, salt); err != nil {
		return nil, fmt.Errorf("生成盐值失败: %w", err)
	}
	key := e.deriveKey(salt)

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("创建 AES cipher 失败: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("创建 GCM 失败: %w", err)
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, fmt.Errorf("生成 nonce 失败: %w", err)
	}
	// Seal 结果拼接在 nonce 之后
	out := gcm.Seal(nonce, nonce, plaintext, salt)
	// out = nonce || ciphertext，前拼 salt
	return append(salt, out...), nil
}

// Decrypt 解密 Encrypt 产生的数据
func (e *CryptoEngine) Decrypt(data []byte) ([]byte, error) {
	if len(data) < 16+12 {
		return nil, errors.New("密文长度不足，数据可能已损坏")
	}
	salt := data[:16]
	rest := data[16:]
	key := e.deriveKey(salt)

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	ns := gcm.NonceSize()
	if len(rest) < ns {
		return nil, errors.New("密文长度不足")
	}
	plain, err := gcm.Open(nil, rest[:ns], rest[ns:], salt)
	if err != nil {
		return nil, errors.New("解密失败：密钥不匹配或数据被篡改（换机器/换用户后无法解密）")
	}
	return plain, nil
}

// ============================================================
// 通用加密工具，供 template-business-server 复用同一方案
// ============================================================

// DeriveKeyFromSecret 从给定密钥材料 + 盐派生 AES-256 密钥
// 业务服务使用环境变量作为 secret（不使用硬编码密钥）
func DeriveKeyFromSecret(secret string, salt []byte) []byte {
	return pbkdf2.Key([]byte(secret), salt, pbkdf2Iterations, pbkdf2KeyLen, sha256.New)
}

// EncryptWithKey 使用已派生密钥加密，输出 salt || nonce || ciphertext
func EncryptWithKey(key []byte, plaintext []byte) ([]byte, error) {
	salt := make([]byte, 16)
	if _, err := io.ReadFull(rand.Reader, salt); err != nil {
		return nil, err
	}
	return encryptWithSaltAndKey(key, salt, plaintext)
}

func encryptWithSaltAndKey(key, salt, plaintext []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}
	out := gcm.Seal(nonce, nonce, plaintext, salt)
	return append(salt, out...), nil
}

// ============================================================
// 常量时间比较（state 校验等）
// ============================================================

// ConstantTimeEqual 常量时间字符串比较，防时序攻击
func ConstantTimeEqual(a, b string) bool {
	return hmac.Equal([]byte(a), []byte(b))
}

// B64 无填充 URL 安全编码，便于展示
func B64(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }
