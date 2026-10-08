package db

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"log"
	"net/url"
	"os"
	"regexp"
	"strings"

	"golang.org/x/crypto/argon2"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

var DB *gorm.DB

const (
	// DefaultSchema auth-hub 的表统一落在独立 schema 里。
	//
	// 为什么不能直接用 public：这台 PG 是共享实例，public 下已经有别人的
	// 同名 users 表。不隔离的话 AutoMigrate 会去改那张表、或被它的结构卡住 ——
	// 两种结果都很难查。
	DefaultSchema = "auth_hub"

	// DefaultDSN 共享 PG（与 gs-ac 同一实例，不同 schema）。
	// 生产应通过 IDP_DSN 覆盖，不要把连接串固化进镜像。
	DefaultDSN = "postgres://postgres:REDACTED@47.110.80.47:5432/postgres?sslmode=disable&search_path=" + DefaultSchema
)

// schemaNameRe 合法 schema 名白名单。
// schema 名要拼进 DDL（标识符没法用占位符参数化），因此必须校验 ——
// 否则一个带分号的 IDP_DSN 就能注入任意 SQL。
var schemaNameRe = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)

// Init 连接 PostgreSQL、确保 schema 存在、自动迁移并写入种子数据。
// dsn 为空时用 DefaultDSN。
func Init(dsn string) *gorm.DB {
	if strings.TrimSpace(dsn) == "" {
		dsn = DefaultDSN
	}

	var err error
	// 重复 Init（测试里同一进程多次调用）时先关掉上一个连接池，
	// 否则每调一次就漏一个池。
	if DB != nil {
		if prev, perr := DB.DB(); perr == nil {
			_ = prev.Close()
		}
	}
	DB, err = gorm.Open(postgres.Open(dsn), &gorm.Config{
		Logger: logger.Default.LogMode(logger.Silent),
	})
	if err != nil {
		log.Fatalf("连接 PostgreSQL 失败: %v\n       目标: %s\n"+
			"       请检查 IDP_DSN", err, MaskDSN(dsn))
	}

	// 建 schema 必须走全限定 DDL：此刻 search_path 指向的 schema 还不存在，
	// 直接建表会失败（PostgreSQL 不会自动创建 search_path 里的 schema）。
	if err := ensureSchema(dsn); err != nil {
		log.Fatalf("%v", err)
	}

	if err := DB.AutoMigrate(
		&User{},
		&OAuthClient{},
		&OAuthAuthorizationCode{},
		&OAuthRefreshToken{},
		&OAuthAccessToken{},
		&UserSession{},
		&SigningKeyRecord{},
	); err != nil {
		log.Fatalf("数据库迁移失败: %v", err)
	}

	seed()
	return DB
}

// SchemaFromDSN 取出 DSN 里 search_path 的第一个 schema，无则回落到 DefaultSchema。
func SchemaFromDSN(dsn string) string {
	u, err := url.Parse(dsn)
	if err == nil {
		if sp := u.Query().Get("search_path"); sp != "" {
			if first := strings.TrimSpace(strings.Split(sp, ",")[0]); first != "" {
				return first
			}
		}
	}
	return DefaultSchema
}

// ensureSchema 确保 DSN 指定的 schema 已存在
func ensureSchema(dsn string) error {
	schema := SchemaFromDSN(dsn)
	if !schemaNameRe.MatchString(schema) {
		return fmt.Errorf("非法的 schema 名 %q（只允许字母/数字/下划线，且不以数字开头）", schema)
	}
	// 标识符无法参数化，安全性由上面的白名单校验保证
	if err := DB.Exec(`CREATE SCHEMA IF NOT EXISTS "` + schema + `"`).Error; err != nil {
		return fmt.Errorf("创建 schema %s 失败: %w", schema, err)
	}
	return nil
}

// MaskDSN 打日志前抹掉连接串里的密码
func MaskDSN(dsn string) string {
	u, err := url.Parse(dsn)
	if err != nil || u.User == nil {
		return "(dsn 解析失败)"
	}
	if _, hasPwd := u.User.Password(); hasPwd {
		u.User = url.UserPassword(u.User.Username(), "***")
	}
	return u.Redacted()
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

	// gs-ac 权限管理平台（SPA 公共客户端，PKCE）
	//
	// 与模板客户端的区别：gs-ac 是真实接入方，其回调地址随部署环境变化，
	// 因此注册值走环境变量（可空格分隔多个，回调校验是「任一命中即通过」）：
	//   GSAC_REDIRECT_URI    前端统一登录回调页地址
	//   GSAC_POST_LOGOUT_URI 统一登出后的回跳地址
	// 默认值覆盖 gs-ac 的两个前端（均为 Vite 开发端口 5173）：
	//   /oauth/callback        Vue 管理台 (web/embedding)
	//   /access/oidc/callback  access 插件 (web/acesss)
	gsacRedirect := Env("GSAC_REDIRECT_URI",
		"http://127.0.0.1:5173/oauth/callback http://127.0.0.1:5173/access/oidc/callback")
	gsacLogout := Env("GSAC_POST_LOGOUT_URI",
		"http://127.0.0.1:5173/login http://127.0.0.1:5173/access/login")
	var gsacClient OAuthClient
	if err := DB.Where("client_id = ?", "gs-ac").First(&gsacClient).Error; err != nil {
		DB.Create(&OAuthClient{
			ClientID:       "gs-ac",
			ClientName:     "GSAC 权限管理平台",
			RedirectURIs:   gsacRedirect,
			Scopes:         "openid profile email",
			IsPublic:       BoolPtr(true),
			PKCERequired:   BoolPtr(true),
			Enabled:        BoolPtr(true),
			PostLogoutURIs: gsacLogout,
		})
		log.Printf("[IDP] 已注册客户端: gs-ac (PKCE 公共客户端, redirect=%s)", gsacRedirect)
	} else {
		// 已存在则同步最新回调白名单：换域名/端口时无需手动改库
		DB.Model(&gsacClient).Updates(map[string]any{
			"redirect_uris":    gsacRedirect,
			"post_logout_uris": gsacLogout,
		})
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
