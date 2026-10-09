// Package db 是数据库访问的**唯一入口**：连接、schema 隔离、建表与种子数据。
//
// 设计约束（来自 code-engine 的存储访问纪律）：
//   - 全平台只有本包持有 gdb 实例，业务代码一律经 internal/dao 访问表，
//     不允许任何地方出现 "g.DB()" 或自己拼 SQL；
//   - 实例可通过 SetInstance 注入，测试据此把整棵树指向一次性 schema；
//   - 非法 DSN / 非法 schema 名一律启动即失败，不静默降级到默认库。
package db

import (
	"context"
	_ "embed"
	"fmt"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/gogf/gf/v2/database/gdb"
	"github.com/gogf/gf/v2/frame/g"

	// PostgreSQL 驱动在本包注册，而不是放在 main.go：
	// 注册动作跟着"唯一创建连接的包"走，任何链接了 db 的测试二进制都能拿到
	// 驱动，不依赖入口是否恰好 import 了它。否则一旦某次重构把 main 里的
	// blank import 挪走，报出来的是"cannot find database driver"这种
	// 指向错误方向的错。
	_ "github.com/gogf/gf/contrib/drivers/pgsql/v2"

	"github.com/ZHLX2005/go-ah/auth-hub/internal/consts"
	"github.com/ZHLX2005/go-ah/auth-hub/internal/model/do"
	"github.com/ZHLX2005/go-ah/auth-hub/internal/utility"
)

// schemaDDL 建表语句，随二进制一起分发（不依赖运行时文件路径）
//
//go:embed ddl/schema.sql
var schemaDDL string

// schemaNameRe 合法 schema 名白名单。
//
// schema 名要拼进 DDL（标识符没法用占位符参数化），因此必须校验 ——
// 否则一个带分号的 IDP_DSN 就能注入任意 SQL。
var schemaNameRe = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)

// searchPathRe 从 link 形式的 DSN 里提取 search_path
var searchPathRe = regexp.MustCompile(`[?&]search_path=([A-Za-z_][A-Za-z0-9_]*)`)

// instance 当前生效的数据库实例（全平台唯一）
var instance gdb.DB

// Instance 返回数据访问实例。未 Init 就取属于装配顺序错误。
func Instance() gdb.DB {
	if instance == nil {
		panic("[auth-hub] db.Init 未调用，装配顺序错误")
	}
	return instance
}

// SetInstance 注入实例（测试用：把整棵树指向一次性 schema）
func SetInstance(db gdb.DB) { instance = db }

// ScanOne 把单行查询结果扫进 dest；**零行不是错误**，用 found 表示是否命中。
//
// 为什么要包一层：gdb 的 Model.Scan（经 Record.Struct）在零行时返回
// sql.ErrNoRows。但"查不到"在本服务里几乎全是**正常业务结果** ——
// 没有有效会话、client_id 不存在、授权码已用过、库里还没有签名密钥行
// （首次启动）。每个调用点各写一次 errors.Is(err, sql.ErrNoRows) 迟早会
// 漏一处，漏掉的那处会把 400/401 变成 500：用户看到"服务器错误"，
// 排障方向也被带偏成"库是不是挂了"。
//
// 这里用 One() + Record.IsEmpty() 判断而不是 Scan，正是因为 Record.Struct
// 对空记录**同样**返回 ErrNoRows —— 那正是本函数要消除的行为。
func ScanOne(ctx context.Context, model *gdb.Model, dest interface{}) (found bool, err error) {
	one, err := model.Ctx(ctx).One()
	if err != nil {
		return false, err
	}
	if one.IsEmpty() {
		return false, nil
	}
	if err = one.Struct(dest); err != nil {
		return false, err
	}
	return true, nil
}

// InitOptions 初始化参数
type InitOptions struct {
	// DSN 连接串，支持 postgres:// URL 形式与 pgsql: link 形式
	DSN string
	// GSACRedirectURIs gs-ac 回调白名单（空格分隔），随环境变化
	GSACRedirectURIs string
	// GSACPostLogoutURIs gs-ac 登出回跳白名单（空格分隔）
	GSACPostLogoutURIs string
}

// Init 建立连接、确保 schema、建表、写种子数据。
func Init(ctx context.Context, opt InitOptions) error {
	node, schemaName, err := ParseDSN(opt.DSN)
	if err != nil {
		return err
	}

	// 重复 Init（测试里同一进程多次调用）时先关掉上一个连接池，
	// 否则每调一次就漏一个池。
	if instance != nil {
		_ = instance.Close(ctx)
		instance = nil
	}

	conn, err := gdb.New(node)
	if err != nil {
		return fmt.Errorf("连接 PostgreSQL 失败: %w\n       目标: %s\n       请检查 IDP_DSN", err, MaskDSN(opt.DSN))
	}
	instance = conn

	// 建 schema 必须走全限定标识符：此刻 search_path 指向的 schema 还不存在，
	// 直接建表会失败（PostgreSQL 不会自动创建 search_path 里的 schema）。
	if err := ensureSchema(ctx, schemaName); err != nil {
		return err
	}
	if err := execDDL(ctx); err != nil {
		return err
	}
	if err := seed(ctx, opt); err != nil {
		return err
	}
	g.Log().Infof(ctx, "[auth-hub] 数据库就绪: schema=%s", schemaName)
	return nil
}

// ParseDSN 把两种 DSN 形式统一成 gdb 配置节点，并解析出要用的 schema。
//
// 支持两种形式的原因：历史部署（GitHub secrets 与服务器容器 env）里
// IDP_DSN 是 postgres:// 的 URL；而 GoFrame 的惯用写法是 pgsql: 的 link。
// 两者都接受，迁移期间不必改动任何一处部署配置。
func ParseDSN(raw string) (node gdb.ConfigNode, schemaName string, err error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return node, "", fmt.Errorf("IDP_DSN 为空")
	}

	switch {
	case strings.HasPrefix(raw, "postgres://"), strings.HasPrefix(raw, "postgresql://"):
		u, perr := url.Parse(raw)
		if perr != nil {
			return node, "", fmt.Errorf("IDP_DSN 解析失败: %w", perr)
		}
		if u.User == nil {
			return node, "", fmt.Errorf("IDP_DSN 缺少用户名: %s", MaskDSN(raw))
		}
		pwd, _ := u.User.Password()
		port, _ := strconv.Atoi(u.Port())
		if port == 0 {
			port = 5432
		}
		q, qerr := parseQuery(u.RawQuery)
		if qerr != nil {
			return node, "", fmt.Errorf("IDP_DSN 的查询串非法: %w\n       DSN: %s", qerr, MaskDSN(raw))
		}
		// 未显式指定 search_path 时补上默认 schema：隔离是默认行为，
		// 不能因为漏配而把表建进共享的 public。
		if q.Get("search_path") == "" {
			q.Set("search_path", consts.DefaultSchema)
		}
		schemaName = firstSchema(q.Get("search_path"))
		node = gdb.ConfigNode{
			Type:  "pgsql",
			Host:  u.Hostname(),
			Port:  strconv.Itoa(port),
			User:  u.User.Username(),
			Pass:  pwd,
			Name:  strings.TrimPrefix(u.Path, "/"),
			Extra: q.Encode(),
		}

	case strings.HasPrefix(raw, "pgsql:"):
		// link 形式原样交给 gf；schema 从 query 里取
		if m := searchPathRe.FindStringSubmatch(raw); len(m) == 2 {
			schemaName = m[1]
		} else {
			schemaName = consts.DefaultSchema
			sep := "?"
			if strings.Contains(raw, "?") {
				sep = "&"
			}
			raw = raw + sep + "search_path=" + consts.DefaultSchema
		}
		node = gdb.ConfigNode{Type: "pgsql", Link: raw}

	default:
		return node, "", fmt.Errorf("无法识别的 IDP_DSN 形式（需 postgres:// 或 pgsql: 开头）: %s", MaskDSN(raw))
	}

	if !schemaNameRe.MatchString(schemaName) {
		return node, "", fmt.Errorf("非法的 schema 名 %q（只允许字母/数字/下划线，且不以数字开头）", schemaName)
	}
	return node, schemaName, nil
}

// parseQuery 解析 DSN 的查询串，并把解析错误**暴露出来**。
//
// 不能用 url.URL.Query()：它内部丢弃 url.ParseQuery 的错误，而 ParseQuery
// 遇到含分号的片段是「跳过该片段」而不是返回可用结果。于是
//
//	postgres://u:p@h/db?search_path=auth_hub;DROP
//
// 会被静默丢掉，代码随即走进「调用方没写 search_path」的分支、兜底成默认
// schema —— 一个非法 DSN 就这样变成了合法启动，与包约定的「非法 DSN 一律
// 启动即失败，不静默降级」正好相反。这里显式检查，让它启动即失败。
func parseQuery(rawQuery string) (url.Values, error) {
	if rawQuery == "" {
		return url.Values{}, nil
	}
	return url.ParseQuery(rawQuery)
}

// firstSchema 取 search_path 里的第一个 schema
func firstSchema(searchPath string) string {
	if first := strings.TrimSpace(strings.Split(searchPath, ",")[0]); first != "" {
		return first
	}
	return consts.DefaultSchema
}

// SchemaFromDSN 取出 DSN 里要用的 schema 名（对外暴露，便于测试与日志）
func SchemaFromDSN(raw string) string {
	if _, s, err := ParseDSN(raw); err == nil {
		return s
	}
	return consts.DefaultSchema
}

// SchemaFromDSNExplicit 只取 DSN 里**显式写出**的 search_path；没写返回 ""。
//
// 与 SchemaFromDSN 的区别：后者会兜底成默认 schema，回答"实际会用哪个"；
// 这里回答"调用方自己指定过没有"。测试环境需要后一个语义 ——
// 指定过 search_path 的连接串不能拿去当一次性库用（会删到真实数据）。
func SchemaFromDSNExplicit(raw string) string {
	raw = strings.TrimSpace(raw)
	switch {
	case strings.HasPrefix(raw, "postgres://"), strings.HasPrefix(raw, "postgresql://"):
		u, err := url.Parse(raw)
		if err != nil || u.User == nil {
			return ""
		}
		q, err := parseQuery(u.RawQuery)
		if err != nil {
			// 查询串本身不合法：调用方显然"写过东西"，只是写错了。
			// 返回非空值，避免被当成"没指定过"而拿去建一次性 schema。
			return u.RawQuery
		}
		return strings.TrimSpace(q.Get("search_path"))
	case strings.HasPrefix(raw, "pgsql:"):
		if m := searchPathRe.FindStringSubmatch(raw); len(m) == 2 {
			return m[1]
		}
	}
	return ""
}

// WithSearchPath 在保留原有 query 的前提下，把 search_path 换成指定 schema。
//
// 供测试把连接指向一次性 schema。schema 名先过标识符白名单：不合法就原样
// 返回，让真正的连接失败去暴露问题 —— 而不是在这里拼一个可能被注入的标识符。
func WithSearchPath(raw, schema string) string {
	if !schemaNameRe.MatchString(schema) {
		return raw
	}
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || u.User == nil {
		return raw
	}
	q, err := parseQuery(u.RawQuery)
	if err != nil {
		// 连原有 query 都解析不了，就不要在这里"修"它：
		// 原样返回，让真正建立连接时报错。
		return raw
	}
	q.Set("search_path", schema)
	u.RawQuery = q.Encode()
	return u.String()
}

// ensureSchema 确保目标 schema 已存在
func ensureSchema(ctx context.Context, schema string) error {
	if !schemaNameRe.MatchString(schema) {
		return fmt.Errorf("非法的 schema 名 %q（只允许字母/数字/下划线，且不以数字开头）", schema)
	}
	// 标识符无法参数化，安全性由上面的白名单校验保证
	if _, err := instance.Exec(ctx, `CREATE SCHEMA IF NOT EXISTS "`+schema+`"`); err != nil {
		return fmt.Errorf("创建 schema %s 失败: %w", schema, err)
	}
	return nil
}

// execDDL 执行内嵌的幂等建表语句。
//
// 逐条执行而不是一次提交整段：驱动对多语句的支持依实现而定，
// 而 DDL 一旦"部分成功"，报错信息会指向奇怪的位置。
func execDDL(ctx context.Context) error {
	for _, stmt := range splitStatements(schemaDDL) {
		if _, err := instance.Exec(ctx, stmt); err != nil {
			return fmt.Errorf("执行建表语句失败: %w\n       语句: %s", err, firstLine(stmt))
		}
	}
	return nil
}

// splitStatements 按分号切分 SQL，丢弃注释行与空段
func splitStatements(sql string) []string {
	var b strings.Builder
	for _, line := range strings.Split(sql, "\n") {
		if strings.HasPrefix(strings.TrimSpace(line), "--") {
			continue
		}
		b.WriteString(line)
		b.WriteString("\n")
	}
	var out []string
	for _, s := range strings.Split(b.String(), ";") {
		if t := strings.TrimSpace(s); t != "" {
			out = append(out, t)
		}
	}
	return out
}

// firstLine 取首行，用于把报错信息压到一行（建表语句是多行的）
func firstLine(s string) string {
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		return s[:i] + " …"
	}
	return s
}

// MaskDSN 打日志前抹掉连接串里的密码
func MaskDSN(raw string) string {
	u, err := url.Parse(raw)
	if err != nil || u.User == nil {
		return "(dsn 解析失败)"
	}
	if _, hasPwd := u.User.Password(); hasPwd {
		u.User = url.UserPassword(u.User.Username(), "***")
	}
	return u.Redacted()
}

// seed 写入预置数据：测试账号 test/test123456（管理员）与各客户端。
//
// 幂等：已存在的记录不覆盖（gs-ac 客户端除外 —— 它的回调白名单随部署环境
// 变化，必须同步成最新值，否则换域名/端口后登录会以 redirect_uri 不匹配失败）。
func seed(ctx context.Context, opt InitOptions) error {
	now := time.Now()
	users := "users"
	clients := "o_auth_clients"

	// ── 预置账号 ────────────────────────────────────────────────────────────
	count, err := instance.Model(users).Ctx(ctx).
		Where("username", consts.SeedUsername).Count()
	if err != nil {
		return fmt.Errorf("查询预置账号失败: %w", err)
	}
	if count == 0 {
		if _, err := instance.Model(users).Ctx(ctx).Data(g.Map{
			"username":      consts.SeedUsername,
			"password_hash": utility.HashPassword(consts.SeedPassword),
			"email":         "test@example.com",
			"nickname":      "测试用户",
			"is_admin":      true,
			"created_at":    now,
			"updated_at":    now,
		}).Insert(); err != nil {
			return fmt.Errorf("创建预置账号失败: %w", err)
		}
		g.Log().Info(ctx, "[auth-hub] 已创建预置账号: test / test123456（管理员）")
	} else {
		// 兼容旧库：确保 test 是管理员
		if _, err := instance.Model(users).Ctx(ctx).Safe().
			Where("username", consts.SeedUsername).Where("is_admin", false).
			Data(g.Map{"is_admin": true, "updated_at": now}).Update(); err != nil {
			return fmt.Errorf("提升预置账号权限失败: %w", err)
		}
	}

	// ── 模板业务平台（SPA 公共客户端，PKCE）────────────────────────────────
	if err := ensureClient(ctx, clients, consts.ClientTemplateWeb, now, g.Map{
		"client_id":        consts.ClientTemplateWeb,
		"client_name":      "模板业务平台",
		"redirect_uris":    "http://127.0.0.1:8081/oauth/callback",
		"scopes":           "openid profile email",
		"is_public":        true,
		"pkce_required":    true,
		"enabled":          true,
		"post_logout_uris": "http://127.0.0.1:8081/",
	}); err != nil {
		return err
	}

	// ── gs-ac 权限管理平台（真实接入方，回调白名单随环境变化）──────────────
	// 已存在则同步最新白名单：换域名/端口时无需手动改库
	gsacRows := g.Map{
		"client_id":        consts.ClientGSAC,
		"client_name":      "GSAC 权限管理平台",
		"redirect_uris":    opt.GSACRedirectURIs,
		"scopes":           "openid profile email",
		"is_public":        true,
		"pkce_required":    true,
		"enabled":          true,
		"post_logout_uris": opt.GSACPostLogoutURIs,
	}
	n, err := instance.Model(clients).Ctx(ctx).Where("client_id", consts.ClientGSAC).Count()
	if err != nil {
		return fmt.Errorf("查询 gs-ac 客户端失败: %w", err)
	}
	if n == 0 {
		gsacRows["created_at"] = now
		gsacRows["updated_at"] = now
		if _, err := instance.Model(clients).Ctx(ctx).Data(gsacRows).Insert(); err != nil {
			return fmt.Errorf("注册 gs-ac 客户端失败: %w", err)
		}
		g.Log().Infof(ctx, "[auth-hub] 已注册客户端: gs-ac (PKCE 公共客户端, redirect=%s)", opt.GSACRedirectURIs)
	} else {
		if _, err := instance.Model(clients).Ctx(ctx).Safe().
			Where("client_id", consts.ClientGSAC).
			Data(g.Map{
				"redirect_uris":    opt.GSACRedirectURIs,
				"post_logout_uris": opt.GSACPostLogoutURIs,
				"updated_at":       now,
			}).Update(); err != nil {
			return fmt.Errorf("同步 gs-ac 客户端白名单失败: %w", err)
		}
	}

	// ── 命令行客户端（回调端口由 CLI 运行时分配，注册回环通配）─────────────
	// 仅放开端口，主机与路径严格受限（见 logic/oidc 的白名单匹配）
	if err := ensureClient(ctx, clients, consts.ClientCLI, now, g.Map{
		"client_id":        consts.ClientCLI,
		"client_name":      "oidc-cli 命令行客户端",
		"redirect_uris":    "http://127.0.0.1:*/callback http://localhost:*/callback",
		"scopes":           "openid profile email",
		"is_public":        true,
		"pkce_required":    true,
		"enabled":          true,
		"post_logout_uris": "http://127.0.0.1:*/* http://localhost:*/*",
	}); err != nil {
		return err
	}

	_ = do.OAuthClient{} // 保留 do 包引用：写入侧结构体在此包内使用
	return nil
}

// ensureClient 客户端不存在时才插入（已存在保持原样）
func ensureClient(ctx context.Context, table, clientID string, now time.Time, data g.Map) error {
	n, err := instance.Model(table).Ctx(ctx).Where("client_id", clientID).Count()
	if err != nil {
		return fmt.Errorf("查询客户端 %s 失败: %w", clientID, err)
	}
	if n > 0 {
		return nil
	}
	data["created_at"] = now
	data["updated_at"] = now
	if _, err := instance.Model(table).Ctx(ctx).Data(data).Insert(); err != nil {
		return fmt.Errorf("注册客户端 %s 失败: %w", clientID, err)
	}
	g.Log().Infof(ctx, "[auth-hub] 已注册客户端: %s", clientID)
	return nil
}
