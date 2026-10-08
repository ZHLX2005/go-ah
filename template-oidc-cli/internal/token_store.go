package internal

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

// ============================================================
// 加密 Token 存储
// 位置：~/.oidc-cli/store.enc
// 格式：AES-GCM 密文（salt || nonce || ciphertext），内容为 JSON
// ============================================================

// TokenSet 一整套令牌（同时用于本地存储与续期）
type TokenSet struct {
	AccessToken  string `json:"access_token"`
	IDToken      string `json:"id_token"`
	RefreshToken string `json:"refresh_token"`
	TokenType    string `json:"token_type"`
	Scope        string `json:"scope"`
	// ExpiresAt access_token 绝对过期时间
	ExpiresAt time.Time `json:"expires_at"`
	// RefreshExpiresAt refresh_token 绝对过期时间
	RefreshExpiresAt time.Time `json:"refresh_expires_at"`
	// 关联信息，便于 whoami 展示与登出
	Issuer    string    `json:"issuer"`
	ClientID  string    `json:"client_id"`
	Subject   string    `json:"subject"`
	Username  string    `json:"username"`
	UpdatedAt time.Time `json:"updated_at"`
}

// ExpiresIn 返回 access_token 距过期剩余时间
func (t *TokenSet) ExpiresIn() time.Duration {
	return time.Until(t.ExpiresAt)
}

// ShouldRefresh 距离过期 < 2 分钟时触发续期
func (t *TokenSet) ShouldRefresh() bool {
	return t.RefreshToken != "" && time.Until(t.ExpiresAt) < RefreshThreshold
}

// RefreshThreshold 续期触发阈值（Task4：过期前 2 分钟）
const RefreshThreshold = 2 * time.Minute

// AccessTokenTTL / RefreshTokenTTL 与 IDP 侧保持一致
const (
	AccessTokenTTL  = 10 * time.Minute
	RefreshTokenTTL = 7 * 24 * time.Hour
)

// TokenStore 加密存储管理器
type TokenStore struct {
	path string
	cry  *CryptoEngine
}

// DefaultStorePath 返回 ~/.oidc-cli/store.enc
func DefaultStorePath() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("获取用户家目录失败: %w", err)
	}
	return filepath.Join(home, ".oidc-cli", "store.enc"), nil
}

// NewTokenStore 创建存储管理器，path 为空则使用默认路径
func NewTokenStore(path string) (*TokenStore, error) {
	if path == "" {
		p, err := DefaultStorePath()
		if err != nil {
			return nil, err
		}
		path = p
	}
	return &TokenStore{path: path, cry: NewCryptoEngine()}, nil
}

// Path 返回存储文件路径
func (s *TokenStore) Path() string { return s.path }

// Save 加密写入（目录权限 0700，文件权限 0600）
func (s *TokenStore) Save(ts *TokenSet) error {
	ts.UpdatedAt = time.Now()
	plain, err := json.MarshalIndent(ts, "", "  ")
	if err != nil {
		return fmt.Errorf("序列化 token 失败: %w", err)
	}
	enc, err := s.cry.Encrypt(plain)
	if err != nil {
		return fmt.Errorf("加密 token 失败: %w", err)
	}
	dir := filepath.Dir(s.path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("创建存储目录失败: %w", err)
	}
	// 原子写入：先写临时文件再重命名，避免续期过程读到半截文件
	tmp := s.path + ".tmp"
	if err := os.WriteFile(tmp, enc, 0o600); err != nil {
		return fmt.Errorf("写入存储文件失败: %w", err)
	}
	if err := os.Rename(tmp, s.path); err != nil {
		return fmt.Errorf("提交存储文件失败: %w", err)
	}
	return nil
}

// Load 读取并解密
func (s *TokenStore) Load() (*TokenSet, error) {
	enc, err := os.ReadFile(s.path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, fmt.Errorf("本地未找到登录凭据（%s），请先执行 oidc-cli login", s.path)
		}
		return nil, fmt.Errorf("读取存储文件失败: %w", err)
	}
	plain, err := s.cry.Decrypt(enc)
	if err != nil {
		return nil, err
	}
	var ts TokenSet
	if err := json.Unmarshal(plain, &ts); err != nil {
		return nil, fmt.Errorf("解析 token 失败: %w", err)
	}
	return &ts, nil
}

// Exists 存储文件是否存在
func (s *TokenStore) Exists() bool {
	_, err := os.Stat(s.path)
	return err == nil
}

// Delete 删除本地凭据（logout 使用）；文件不存在不报错
func (s *TokenStore) Delete() error {
	if err := os.Remove(s.path); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("删除本地凭据失败: %w", err)
	}
	return nil
}
