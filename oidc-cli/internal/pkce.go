package internal

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
)

// ============================================================
// PKCE (RFC 7636) 参数生成
// CLI 属于公共客户端，无 client_secret，必须使用 PKCE
// ============================================================

// PKCE 保存一次授权流程所需的全部参数
type PKCE struct {
	State         string
	Nonce         string
	CodeVerifier  string
	CodeChallenge string
	Method        string
}

// NewPKCE 生成 state / nonce / code_verifier / code_challenge(S256)
func NewPKCE() (*PKCE, error) {
	state, err := randomURLSafe(32)
	if err != nil {
		return nil, err
	}
	nonce, err := randomURLSafe(32)
	if err != nil {
		return nil, err
	}
	// RFC 7636: code_verifier 43~128 字符，使用 unreserved 字符集
	verifier, err := randomURLSafe(32)
	if err != nil {
		return nil, err
	}
	return &PKCE{
		State:         state,
		Nonce:         nonce,
		CodeVerifier:  verifier,
		CodeChallenge: CodeChallengeS256(verifier),
		Method:        "S256",
	}, nil
}

// CodeChallengeS256 计算 code_challenge = BASE64URL(SHA256(verifier))
func CodeChallengeS256(verifier string) string {
	h := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(h[:])
}

// randomURLSafe 生成 n 字节随机数的无填充 URL 安全 base64
func randomURLSafe(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("生成随机数失败: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}
