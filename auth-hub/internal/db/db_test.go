package db

import (
	"strings"
	"testing"

	"github.com/ZHLX2005/go-ah/auth-hub/internal/consts"
)

// ============================================================
// DSN 解析
// ============================================================

func TestParseDSN_PostgresURL(t *testing.T) {
	node, schema, err := ParseDSN("postgres://postgres:pw@db.example.com:5433/postgres?sslmode=disable")
	if err != nil {
		t.Fatalf("解析失败: %v", err)
	}
	if node.Type != "pgsql" {
		t.Errorf("Type = %q, 期望 pgsql", node.Type)
	}
	if node.Host != "db.example.com" {
		t.Errorf("Host = %q", node.Host)
	}
	if node.Port != "5433" {
		t.Errorf("Port = %q", node.Port)
	}
	if node.User != "postgres" || node.Pass != "pw" {
		t.Errorf("User/Pass = %q/%q", node.User, node.Pass)
	}
	if node.Name != "postgres" {
		t.Errorf("Name = %q", node.Name)
	}
	// 未显式指定 search_path 时必须补默认 schema：隔离是默认行为，
	// 不能因为漏配就把表建进共享的 public
	if schema != consts.DefaultSchema {
		t.Errorf("schema = %q, 期望 %q", schema, consts.DefaultSchema)
	}
	if !strings.Contains(node.Extra, "search_path="+consts.DefaultSchema) {
		t.Errorf("Extra 未补 search_path: %q", node.Extra)
	}
	if !strings.Contains(node.Extra, "sslmode=disable") {
		t.Errorf("Extra 丢失了原有参数: %q", node.Extra)
	}
}

func TestParseDSN_ExplicitSchema(t *testing.T) {
	_, schema, err := ParseDSN("postgres://u:p@h:5432/db?search_path=custom_schema")
	if err != nil {
		t.Fatalf("解析失败: %v", err)
	}
	if schema != "custom_schema" {
		t.Errorf("schema = %q, 期望 custom_schema", schema)
	}
}

func TestParseDSN_MultiSchemaTakesFirst(t *testing.T) {
	_, schema, err := ParseDSN("postgres://u:p@h:5432/db?search_path=first,second")
	if err != nil {
		t.Fatalf("解析失败: %v", err)
	}
	if schema != "first" {
		t.Errorf("schema = %q, 期望 first", schema)
	}
}

func TestParseDSN_DefaultPort(t *testing.T) {
	node, _, err := ParseDSN("postgres://u:p@h/db")
	if err != nil {
		t.Fatalf("解析失败: %v", err)
	}
	if node.Port != "5432" {
		t.Errorf("Port = %q, 期望默认 5432", node.Port)
	}
}

func TestParseDSN_PostgresqlScheme(t *testing.T) {
	if _, _, err := ParseDSN("postgresql://u:p@h/db"); err != nil {
		t.Errorf("postgresql:// 也应被识别: %v", err)
	}
}

func TestParseDSN_PgsqlLink(t *testing.T) {
	node, schema, err := ParseDSN("pgsql:postgres:pw@tcp(47.110.80.47:5432)/postgres?sslmode=disable")
	if err != nil {
		t.Fatalf("解析失败: %v", err)
	}
	if node.Type != "pgsql" {
		t.Errorf("Type = %q", node.Type)
	}
	if schema != consts.DefaultSchema {
		t.Errorf("schema = %q, 期望 %q", schema, consts.DefaultSchema)
	}
	// link 形式原样交给 gf，但必须补上 search_path
	if !strings.Contains(node.Link, "search_path="+consts.DefaultSchema) {
		t.Errorf("Link 未补 search_path: %q", node.Link)
	}
	if !strings.Contains(node.Link, "sslmode=disable") {
		t.Errorf("Link 丢失了原有参数: %q", node.Link)
	}
}

func TestParseDSN_PgsqlLinkWithSearchPath(t *testing.T) {
	// 已有 query 时用 & 连接，不能再加一个 ?
	node, schema, err := ParseDSN("pgsql:u:p@tcp(h:5432)/db?sslmode=disable&search_path=other")
	if err != nil {
		t.Fatalf("解析失败: %v", err)
	}
	if schema != "other" {
		t.Errorf("schema = %q, 期望 other", schema)
	}
	if strings.Contains(node.Link, "??") || strings.Count(node.Link, "?") != 1 {
		t.Errorf("query 分隔符拼错: %q", node.Link)
	}
}

func TestParseDSN_Errors(t *testing.T) {
	cases := []struct {
		name string
		dsn  string
	}{
		{"空串", ""},
		{"纯空白", "   "},
		{"缺少用户名", "postgres://h:5432/db"},
		{"未知协议", "mysql://u:p@h/db"},
		{"裸主机", "db.example.com:5432"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if _, _, err := ParseDSN(c.dsn); err == nil {
				t.Errorf("应当报错: %q", c.dsn)
			}
		})
	}
}

// TestParseDSN_SchemaInjection schema 名要拼进 DDL（标识符无法参数化），
// 因此必须白名单校验，否则一个带分号的 DSN 就能注入任意 SQL
func TestParseDSN_SchemaInjection(t *testing.T) {
	bad := []string{
		"postgres://u:p@h/db?search_path=bad-name",          // 连字符
		"postgres://u:p@h/db?search_path=1abc",              // 数字开头
		"postgres://u:p@h/db?search_path=auth_hub;DROP",     // 分号注入
		"postgres://u:p@h/db?search_path=auth_hub%3BDROP",   // 同上（编码后）
		"postgres://u:p@h/db?search_path=public;DROP+TABLE", // 空格 + 分号
	}
	for _, dsn := range bad {
		if _, _, err := ParseDSN(dsn); err == nil {
			t.Errorf("非法 schema 名应被拒绝: %q", dsn)
		}
	}
}

// ============================================================
// schema 提取
// ============================================================

func TestSchemaFromDSN(t *testing.T) {
	// 有效：返回解析出的 schema（含兜底）
	if got := SchemaFromDSN("postgres://u:p@h/db?search_path=x"); got != "x" {
		t.Errorf("= %q", got)
	}
	if got := SchemaFromDSN("postgres://u:p@h/db"); got != consts.DefaultSchema {
		t.Errorf("未指定时应兜底默认 schema, got %q", got)
	}
	// 解析不了也要兜底，而不是返回空串
	if got := SchemaFromDSN("garbage"); got != consts.DefaultSchema {
		t.Errorf("无法解析时应兜底, got %q", got)
	}
}

func TestSchemaFromDSNExplicit(t *testing.T) {
	// 只回答"调用方显式写过没有"：没写返回空（测试环境靠这个判断能不能当一次性库）
	if got := SchemaFromDSNExplicit("postgres://u:p@h/db"); got != "" {
		t.Errorf("未显式指定时应返回空串, got %q", got)
	}
	if got := SchemaFromDSNExplicit("postgres://u:p@h/db?search_path=x"); got != "x" {
		t.Errorf("= %q", got)
	}
	if got := SchemaFromDSNExplicit("pgsql:u:p@tcp(h:5432)/db?search_path=y"); got != "y" {
		t.Errorf("= %q", got)
	}
	for _, dsn := range []string{"", "garbage", "mysql://u:p@h/db"} {
		if got := SchemaFromDSNExplicit(dsn); got != "" {
			t.Errorf("SchemaFromDSNExplicit(%q) = %q, 期望空串", dsn, got)
		}
	}
}

func TestWithSearchPath(t *testing.T) {
	got := WithSearchPath("postgres://u:p@h/db?sslmode=disable", "tmp_x1")
	if !strings.Contains(got, "search_path=tmp_x1") {
		t.Errorf("未替换 search_path: %q", got)
	}
	if !strings.Contains(got, "sslmode=disable") {
		t.Errorf("丢失原有参数: %q", got)
	}

	// 覆盖已有值
	got = WithSearchPath("postgres://u:p@h/db?search_path=old", "new_one")
	if !strings.Contains(got, "search_path=new_one") || strings.Contains(got, "old") {
		t.Errorf("未覆盖旧值: %q", got)
	}

	// 非法 schema 名原样返回（不在这里拼一个可能被注入的标识符）
	raw := "postgres://u:p@h/db"
	if got := WithSearchPath(raw, "bad-name"); got != raw {
		t.Errorf("非法 schema 名应原样返回, got %q", got)
	}
	if got := WithSearchPath(raw, "a;DROP"); got != raw {
		t.Errorf("非法 schema 名应原样返回, got %q", got)
	}
}

func TestFirstSchema(t *testing.T) {
	cases := map[string]string{
		"a":     "a",
		" a ":   "a",
		"a,b":   "a",
		" a ,b": "a",
		",b":    consts.DefaultSchema,
		"":      consts.DefaultSchema,
		"   ":   consts.DefaultSchema,
	}
	for in, want := range cases {
		if got := firstSchema(in); got != want {
			t.Errorf("firstSchema(%q) = %q, 期望 %q", in, got, want)
		}
	}
}

// ============================================================
// 日志脱敏
// ============================================================

func TestMaskDSN(t *testing.T) {
	out := MaskDSN("postgres://postgres:s3cr3t@db.example.com:5432/postgres")
	if strings.Contains(out, "s3cr3t") {
		t.Errorf("密码未脱敏: %q", out)
	}
	if !strings.Contains(out, "db.example.com") {
		t.Errorf("主机名应保留（否则日志看不出连的哪个库）: %q", out)
	}

	// 无密码时不该 panic，也不该凭空造一个
	out = MaskDSN("postgres://postgres@db.example.com:5432/postgres")
	if !strings.Contains(out, "db.example.com") {
		t.Errorf("无密码 DSN 脱敏后主机应保留: %q", out)
	}

	// 解析不了时给一句可读的话，而不是 panic
	if got := MaskDSN("not-a-dsn"); got == "" {
		t.Error("解析失败也应返回可读占位")
	}
}

// ============================================================
// 建表语句切分
// ============================================================

func TestSplitStatements(t *testing.T) {
	sql := `
-- 这是注释，应当被丢弃
CREATE SCHEMA IF NOT EXISTS "x";  -- 行尾注释

CREATE TABLE IF NOT EXISTS "x"."t" (
  id bigserial PRIMARY KEY,
  name text NOT NULL
);

CREATE INDEX IF NOT EXISTS "idx_t_name" ON "x"."t" ("name");
`
	stmts := splitStatements(sql)
	if len(stmts) != 3 {
		t.Fatalf("切分结果 = %d 条, 期望 3 条\n%#v", len(stmts), stmts)
	}
	if !strings.HasPrefix(stmts[0], "CREATE SCHEMA") {
		t.Errorf("第 1 条 = %q", stmts[0])
	}
	if !strings.Contains(stmts[1], "CREATE TABLE") {
		t.Errorf("第 2 条 = %q", stmts[1])
	}
	if !strings.Contains(stmts[2], "CREATE INDEX") {
		t.Errorf("第 3 条 = %q", stmts[2])
	}
	// 每条都不应以分号开头或全空白
	for i, s := range stmts {
		if strings.HasPrefix(s, ";") || strings.TrimSpace(s) == "" {
			t.Errorf("第 %d 条不正常: %q", i+1, s)
		}
	}
}

func TestSplitStatements_Empty(t *testing.T) {
	if got := splitStatements("-- 只有注释\n"); len(got) != 0 {
		t.Errorf("只有注释时不应产生语句, got %#v", got)
	}
}

func TestFirstLine(t *testing.T) {
	if got := firstLine("SELECT 1"); got != "SELECT 1" {
		t.Errorf("= %q", got)
	}
	if got := firstLine("CREATE TABLE x (\n  a int\n)"); got != "CREATE TABLE x ( …" {
		t.Errorf("= %q", got)
	}
}

// ============================================================
// 内嵌 DDL 的自检
// ============================================================

// TestSchemaDDL_CoversAllTables 内嵌 DDL 必须覆盖 consts 里声明的全部表名。
//
// 这条检查值钱在于：漏建一张表不会在启动时报错（gdb 按需查询，
// 只有真正访问到那张表时才炸），而是等到某个功能被用到才暴露。
func TestSchemaDDL_CoversAllTables(t *testing.T) {
	tables := []string{
		consts.TableUser,
		consts.TableOAuthClient,
		consts.TableOAuthAuthorizationCode,
		consts.TableOAuthRefreshToken,
		consts.TableOAuthAccessToken,
		consts.TableUserSession,
		consts.TableSigningKey,
	}
	for _, tbl := range tables {
		// 用带引号的形式匹配："users" 是 "user_sessions" 的子串，
		// 只做子串匹配会让这张检查形同虚设
		quoted := `CREATE TABLE IF NOT EXISTS "` + tbl + `"`
		if !strings.Contains(schemaDDL, quoted) {
			t.Errorf("内嵌 DDL 中缺少表 %q", tbl)
		}
	}
}

// TestSchemaDDL_Idempotent 建表语句必须可重复执行（每次启动都会跑一遍）
func TestSchemaDDL_Idempotent(t *testing.T) {
	for i, stmt := range splitStatements(schemaDDL) {
		upper := strings.ToUpper(stmt)
		switch {
		case strings.HasPrefix(upper, "CREATE TABLE"):
			if !strings.Contains(upper, "IF NOT EXISTS") {
				t.Errorf("第 %d 条建表语句缺少 IF NOT EXISTS: %s", i+1, firstLine(stmt))
			}
		case strings.HasPrefix(upper, "CREATE INDEX"), strings.HasPrefix(upper, "CREATE UNIQUE INDEX"):
			if !strings.Contains(upper, "IF NOT EXISTS") {
				t.Errorf("第 %d 条建索引语句缺少 IF NOT EXISTS: %s", i+1, firstLine(stmt))
			}
		}
	}
}
