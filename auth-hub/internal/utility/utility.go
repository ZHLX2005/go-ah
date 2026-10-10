// Package utility 收敛无状态工具函数：随机串、口令哈希、摘要。
//
// 之所以单独成包而不是随手放进 db 或 logic：这些函数的调用方横跨
// 会话、令牌、用户建档、扫码票据几处，放进任何一处的业务包里都会让另一处
// 反向依赖它。工具函数与业务无关，就该待在业务之外。
package utility

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"

	"golang.org/x/crypto/argon2"
)

// RandomToken 生成 URL 安全的随机串，长度按**字节**计（编码后为 4/3 倍）。
// 用于授权码、access/refresh token、会话 ID —— 这些值一律由 CSPRNG 生成，
// 不用时间戳或自增，否则可被猜出。
func RandomToken(n int) string {
	b := make([]byte, n)
	// rand.Read 在密码学随机源不可用时才会返回错误，此时生成出来的令牌
	// 不具备不可预测性，宁可 panic 也不能返回一个"看起来像令牌"的值。
	if _, err := rand.Read(b); err != nil {
		panic("crypto/rand 不可用，无法生成安全随机串: " + err.Error())
	}
	return base64.RawURLEncoding.EncodeToString(b)
}

// HashPassword 使用 argon2id 生成口令哈希，格式: argon2id$salt$hash
func HashPassword(password string) string {
	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		panic("crypto/rand 不可用，无法生成口令盐值: " + err.Error())
	}
	hash := argon2.IDKey([]byte(password), salt, 1, 64*1024, 4, 32)
	b64 := base64.RawStdEncoding
	return "argon2id$" + b64.EncodeToString(salt) + "$" + b64.EncodeToString(hash)
}

// VerifyPassword 校验明文口令是否匹配 argon2id 哈希。
//
// 比较用常量时间异或，不用 bytes.Equal：后者在首个不同字节就返回，
// 通过响应耗时可以把哈希逐字节猜出来。
func VerifyPassword(password, encoded string) bool {
	b64 := base64.RawStdEncoding
	parts := splitN(encoded, '$', 3)
	if len(parts) != 3 || parts[0] != "argon2id" {
		return false
	}
	salt, err1 := b64.DecodeString(parts[1])
	hash, err2 := b64.DecodeString(parts[2])
	if err1 != nil || err2 != nil {
		return false
	}
	computed := argon2.IDKey([]byte(password), salt, 1, 64*1024, 4, 32)
	if len(computed) != len(hash) {
		return false
	}
	var diff byte
	for i := range computed {
		diff |= computed[i] ^ hash[i]
	}
	return diff == 0
}

// splitN 按分隔符切分为最多 n 段（最后一段保留剩余内容）
func splitN(s string, sep byte, n int) []string {
	var out []string
	start := 0
	for i := 0; i < len(s) && len(out) < n-1; i++ {
		if s[i] == sep {
			out = append(out, s[start:i])
			start = i + 1
		}
	}
	out = append(out, s[start:])
	return out
}

// Sha256Hex 对字符串取 SHA-256 并以 hex 编码返回（64 字符）。
//
// 用于"库里只存摘要、不存凭据原文"的场合（扫码票据的 qr_ctx）。
// 注意这里**不**是口令哈希：口令要经得起离线爆破所以必须用 argon2id 这种
// 又慢又吃内存的函数，而 qr_ctx 是 128 bit 随机值，暴力不可行，
// 用 SHA-256 纯为"表被拖走时拿不去直接用"，快反而是优点。
// 把两者混为一谈（拿 sha256 存口令，或拿 argon2id 存高频查询的随机凭据）
// 都是常见的事故来源，所以这个函数的用途在名字和注释里钉死。
func Sha256Hex(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])
}
