package api

import (
	"errors"
	"log"
	"time"

	"github.com/ZHLX2005/go-ah/template-business-server/cryptox"
	"github.com/ZHLX2005/go-ah/template-business-server/db"
)

// ============================================================
// 业务侧 Token 加密存储层（Task4）
//
// 所有对 BusinessSession 中 token 字段的读写都必须经过本文件，
// 避免某个接口忘记解密而把密文当作 token 直接发给 IDP。
//
// 写路径：Encrypt -> DB
// 读路径：DB -> Decrypt
// ============================================================

// ttl 常量，与 IDP 侧保持一致
const (
	// AccessTokenTTL access_token 有效期
	AccessTokenTTL = 10 * time.Minute
	// RefreshTokenTTL refresh_token 有效期
	RefreshTokenTTL = 7 * 24 * time.Hour
	// RefreshThreshold 距过期小于该阈值即触发自动续期
	RefreshThreshold = 2 * time.Minute
)

// cryptoEngine 全局加密引擎，在 main 启动期初始化
var cryptoEngine *cryptox.Engine

// InitCrypto 初始化加密引擎；密钥来自环境变量 BIZ_TOKEN_SECRET。
// 失败会返回错误，由 main 决定是否终止启动——默认必须终止，
// 否则会在没有加密能力的情况下继续提供登录服务。
func InitCrypto() error {
	e, err := cryptox.NewEngine()
	if err != nil {
		return err
	}
	cryptoEngine = e
	return nil
}

// engine 返回加密引擎，未初始化时报错而不是 panic
func engine() (*cryptox.Engine, error) {
	if cryptoEngine == nil {
		return nil, errors.New("加密引擎未初始化：请先调用 InitCrypto() 并配置 BIZ_TOKEN_SECRET")
	}
	return cryptoEngine, nil
}

// CryptoReady 报告加密引擎是否已就绪（供健康检查使用）
func CryptoReady() bool { return cryptoEngine != nil }

// ============================================================
// 加解密包装：对空串透明（空串不加密，保持 ""）
// ============================================================

func encryptToken(plain string) (string, error) {
	if plain == "" {
		return "", nil
	}
	e, err := engine()
	if err != nil {
		return "", err
	}
	return e.Encrypt(plain)
}

// decryptToken 解密；对存量明文（Encrypted=false）调用方应直接使用原值
func decryptToken(cipherText string) (string, error) {
	if cipherText == "" {
		return "", nil
	}
	e, err := engine()
	if err != nil {
		return "", err
	}
	return e.Decrypt(cipherText)
}

// ============================================================
// 会话读写
// ============================================================

// saveSession 持久化会话，token 字段自动加密
// 调用方传入的是明文 token 的 sess；本函数会就地加密后再写库，
// 因此调用方在 Save 之后不应再依赖 sess 中的 token 字段为明文。
// 需要明文的场景请使用 ReadTokens() 读取。
func saveSession(sess *db.BusinessSession) error {
	encID, err := encryptToken(sess.IDToken)
	if err != nil {
		return err
	}
	encAccess, err := encryptToken(sess.AccessToken)
	if err != nil {
		return err
	}
	encRefresh, err := encryptToken(sess.RefreshToken)
	if err != nil {
		return err
	}

	// 备份明文，写库后还原内存中的值，保证调用方拿到的仍是明文
	plainID, plainAccess, plainRefresh := sess.IDToken, sess.AccessToken, sess.RefreshToken

	sess.IDToken = encID
	sess.AccessToken = encAccess
	sess.RefreshToken = encRefresh
	sess.Encrypted = true

	err = db.DB.Save(sess).Error

	sess.IDToken = plainID
	sess.AccessToken = plainAccess
	sess.RefreshToken = plainRefresh

	if err != nil {
		return err
	}
	log.Printf("[BIZ][安全] 会话 %s 的 token 已加密落库 (access_exp=%s)",
		sess.SessionID, sess.AccessTokenExpiresAt.Format("15:04:05"))
	return nil
}

// SessionTokens 会话中解密后的三个 token
type SessionTokens struct {
	IDToken      string
	AccessToken  string
	RefreshToken string
}

// ReadTokens 读取并解密会话中的 token
// 对历史明文行（Encrypted=false）直接返回原值，实现平滑迁移
func ReadTokens(sess *db.BusinessSession) (*SessionTokens, error) {
	if sess == nil {
		return nil, errors.New("会话为空")
	}
	if !sess.Encrypted {
		// 存量明文数据：不尝试解密
		return &SessionTokens{
			IDToken:      sess.IDToken,
			AccessToken:  sess.AccessToken,
			RefreshToken: sess.RefreshToken,
		}, nil
	}
	id, err := decryptToken(sess.IDToken)
	if err != nil {
		return nil, err
	}
	access, err := decryptToken(sess.AccessToken)
	if err != nil {
		return nil, err
	}
	refresh, err := decryptToken(sess.RefreshToken)
	if err != nil {
		return nil, err
	}
	return &SessionTokens{IDToken: id, AccessToken: access, RefreshToken: refresh}, nil
}

// ============================================================
// 续期判定
// ============================================================

// shouldRefresh 判断会话是否到了该续期的时间点：
//   - 有 refresh_token
//   - access_token 已过期，或距过期不足 RefreshThreshold
//   - refresh_token 自身尚未过期
func shouldRefresh(sess *db.BusinessSession) bool {
	if sess == nil || sess.RefreshToken == "" {
		return false
	}
	if !sess.RefreshTokenExpiresAt.IsZero() && time.Now().After(sess.RefreshTokenExpiresAt) {
		// refresh_token 已过期，续期也没有意义
		return false
	}
	if sess.AccessTokenExpiresAt.IsZero() {
		// 老数据没有记录过期时间，视为需要续期
		return true
	}
	return time.Until(sess.AccessTokenExpiresAt) <= RefreshThreshold
}
