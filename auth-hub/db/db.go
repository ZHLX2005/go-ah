package db

import (
	"crypto/rand"
	"encoding/base64"
	"log"
	"os"

	"golang.org/x/crypto/argon2"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

var DB *gorm.DB

// Init 打开 SQLite 数据库并执行自动迁移 + 种子数据
func Init(path string) *gorm.DB {
	var err error
	DB, err = gorm.Open(sqlite.Open(path), &gorm.Config{
		Logger: logger.Default.LogMode(logger.Silent),
	})
	if err != nil {
		log.Fatalf("打开数据库失败: %v", err)
	}

	if err := DB.AutoMigrate(
		&User{},
		&OAuthClient{},
		&OAuthAuthorizationCode{},
		&OAuthRefreshToken{},
		&OAuthAccessToken{},
		&UserSession{},
	); err != nil {
		log.Fatalf("数据库迁移失败: %v", err)
	}

	seed()
	return DB
}

// seed 写入预置数据：测试账号 test/test123456（管理员）与各客户端
func seed() {
	var user User
	if err := DB.Where("username = ?", "test").First(&user).Error; err != nil {
		DB.Create(&User{
			Username:     "test",
			PasswordHash: HashPassword("test123456"),
			Email:        "test@example.com",
			Nickname:     "测试用户",
			IsAdmin:      true,
		})
		log.Println("[IDP] 已创建预置账号: test / test123456（管理员）")
	} else if !user.IsAdmin {
		// 兼容旧库：确保 test 是管理员
		DB.Model(&user).Update("is_admin", true)
		log.Println("[IDP] 已将 test 提升为管理员")
	}

	// 模板业务平台（SPA 公共客户端，PKCE）
	var client OAuthClient
	if err := DB.Where("client_id = ?", "template-web-client").First(&client).Error; err != nil {
		DB.Create(&OAuthClient{
			ClientID:       "template-web-client",
			ClientName:     "模板业务平台",
			RedirectURIs:   "http://127.0.0.1:8081/oauth/callback",
			Scopes:         "openid profile email",
			IsPublic:       BoolPtr(true),
			PKCERequired:   BoolPtr(true),
			Enabled:        BoolPtr(true),
			PostLogoutURIs: "http://127.0.0.1:8081/",
		})
		log.Println("[IDP] 已注册客户端: template-web-client (PKCE 公共客户端)")
	}

	// oidc-cli 命令行客户端
	// 回调端口由 CLI 运行时自动分配，因此注册回环通配地址
	// http://127.0.0.1:*/callback —— 仅放开端口，主机与路径严格受限
	var cliClient OAuthClient
	if err := DB.Where("client_id = ?", "oidc-cli").First(&cliClient).Error; err != nil {
		DB.Create(&OAuthClient{
			ClientID:       "oidc-cli",
			ClientName:     "oidc-cli 命令行客户端",
			RedirectURIs:   "http://127.0.0.1:*/callback http://localhost:*/callback",
			Scopes:         "openid profile email",
			IsPublic:       BoolPtr(true),
			PKCERequired:   BoolPtr(true),
			Enabled:        BoolPtr(true),
			PostLogoutURIs: "http://127.0.0.1:*/* http://localhost:*/*",
		})
		log.Println("[IDP] 已注册客户端: oidc-cli (PKCE 公共客户端, 回环通配回调)")
	}
}

// HashPassword 使用 argon2id 生成密码哈希，格式: argon2id$salt$hash
func HashPassword(password string) string {
	salt := make([]byte, 16)
	_, _ = rand.Read(salt)
	hash := argon2.IDKey([]byte(password), salt, 1, 64*1024, 4, 32)
	b64 := base64.RawStdEncoding
	return "argon2id$" + b64.EncodeToString(salt) + "$" + b64.EncodeToString(hash)
}

// VerifyPassword 校验明文密码是否匹配 argon2id 哈希
func VerifyPassword(password, encoded string) bool {
	b64 := base64.RawStdEncoding
	var salt, hash []byte
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
	// 常量时间比较
	var diff byte
	for i := range computed {
		diff |= computed[i] ^ hash[i]
	}
	return diff == 0
}

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

// Env 读取环境变量，带默认值
func Env(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}
