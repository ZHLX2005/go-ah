// Package testpg 为单元测试提供一次性的 PostgreSQL 隔离环境。
//
// 为什么需要它：auth-hub 的存储已从 SQLite 换成共享 PG，测试不能再
// 「开个内存库」了 —— 它们必须连真实 PG（SQL 方言、唯一索引、自增序列
// 这些差异只有在真库上才验证得出来），但又绝不能让测试数据碰到生产 schema。
//
// 做法：每个测试建一个随机命名的 schema，测试结束后 DROP。
// 本包刻意不 import db 包 —— 那样会让 db 包的 in-package 测试（db_test.go）
// 无法导入本包（Go 不允许测试包与其依赖形成环）。
package testpg

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"net/url"
	"os"
	"strings"
	"testing"

	"gorm.io/driver/postgres"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

// EnvKey 测试 PG 连接串的环境变量名。
// 不设该变量时所有依赖真实数据库的测试都会被跳过（而不是失败）——
// 本地没配库的人不该看到一片红。
const EnvKey = "AUTH_HUB_TEST_DSN"

// schemaPrefix 测试 schema 的固定前缀。
// 作用是让「哪些 schema 是测试残留」一眼可辨，便于人工清理。
const schemaPrefix = "auth_hub_t_"

// BaseDSN 返回测试用基础连接串；未配置则跳过当前测试。
//
// 期望形式（不带 search_path）：
//
//	AUTH_HUB_TEST_DSN=postgres://postgres:pw@host:5432/postgres?sslmode=disable
func BaseDSN(t testing.TB) string {
	t.Helper()
	dsn := os.Getenv(EnvKey)
	if strings.TrimSpace(dsn) == "" {
		t.Skipf("跳过：未设置 %s（需要一个可建 schema 的 PostgreSQL 连接串）", EnvKey)
	}
	if sp := searchPathOf(dsn); sp != "" {
		t.Fatalf("%s 不应带 search_path（当前 %q）：测试会创建并删除 schema，"+
			"基础连接串指向已有 schema 太危险", EnvKey, sp)
	}
	return dsn
}

// NewSchema 建一个一次性 schema，返回带 search_path 的 DSN 与清理函数。
//
// 调用方拿到 dsn 后交给 db.Init —— 此时 schema 已存在，
// Init 内部的 CREATE SCHEMA IF NOT EXISTS 是幂等的。
func NewSchema(t testing.TB) (dsn string, cleanup func()) {
	t.Helper()
	base := BaseDSN(t)

	name := schemaPrefix + randomSuffix()
	if err := execRaw(base, `CREATE SCHEMA "`+name+`"`); err != nil {
		t.Fatalf("创建测试 schema %s 失败: %v", name, err)
	}

	cleanup = func() {
		// CASCADE：schema 里有表也能删干净，避免残留一堆测试 schema
		if err := execRaw(base, `DROP SCHEMA IF EXISTS "`+name+`" CASCADE`); err != nil {
			t.Logf("警告：清理测试 schema %s 失败: %v", name, err)
		}
	}
	// 双保险：调用方漏了 defer 也能在测试结束时清掉
	t.Cleanup(cleanup)

	return withSearchPath(base, name), cleanup
}

// execRaw 用独立连接执行一条 DDL（不进入任何测试 schema）
func execRaw(dsn, stmt string) error {
	g, err := gorm.Open(postgres.Open(dsn), &gorm.Config{
		Logger: logger.Default.LogMode(logger.Silent),
	})
	if err != nil {
		return fmt.Errorf("连接失败: %w", err)
	}
	sqlDB, err := g.DB()
	if err != nil {
		return err
	}
	defer func() { _ = sqlDB.Close() }()
	return g.Exec(stmt).Error
}

func searchPathOf(dsn string) string {
	u, err := url.Parse(dsn)
	if err != nil {
		return ""
	}
	return strings.TrimSpace(u.Query().Get("search_path"))
}

// withSearchPath 在保留原有 query 的前提下追加 search_path
func withSearchPath(dsn, schema string) string {
	u, err := url.Parse(dsn)
	if err != nil {
		return dsn
	}
	q := u.Query()
	q.Set("search_path", schema)
	u.RawQuery = q.Encode()
	return u.String()
}

func randomSuffix() string {
	b := make([]byte, 4)
	if _, err := rand.Read(b); err != nil {
		return "fallback"
	}
	return hex.EncodeToString(b)
}
