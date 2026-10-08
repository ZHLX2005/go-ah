package api

import (
	"crypto/rand"
	"encoding/base64"
)

// randomToken 生成 URL 安全随机字符串（用于会话 ID）
func randomToken(n int) string {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b)
}
