// Package db 是业务侧数据库的**唯一入口**：连接、建表、以及所有对业务表
// 的读写。
//
// 为什么把 SQL 收在这里，而不是让 api 包直接用句柄查库：本服务有三个地方
// 要读写会话（登录回调、主动续期、后台巡检），一处写法不一致就会出现
// "某个接口忘了带 expires_at 条件"这类只有生产才暴露的问题。收进来之后
// 每条查询只有一个声明处，也顺带给未来换存储留了一个接缝。
//
// 存储用 SQLite：模板业务平台是"接入示例"，不该要求使用方先准备数据库。
// 驱动是 gf 官方的 sqlite 驱动（底层 glebarez/go-sqlite，**纯 Go，不需要 CGO**），
// 因此可以和 auth-hub 一样用 CGO_ENABLED=0 交叉编译。
package db

import (
	"context"
	_ "embed"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/gogf/gf/v2/database/gdb"
	"github.com/gogf/gf/v2/frame/g"
	"github.com/gogf/gf/v2/os/gfile"

	// SQLite 驱动在这里注册，而不是放在 main.go ——
	// 注册动作跟着"唯一会创建连接的包"走，测试二进制（db / api 的用例）
	// 才不会因为入口不同而拿不到驱动，报出"did you forget importing
	// the database driver"这种只有测试期间才出现的错误。
	_ "github.com/gogf/gf/contrib/drivers/sqlite/v2"
)

//go:embed ddl/schema.sql
var schemaDDL string

// 表名常量。不依赖结构体名的自动推导（推导规则一变，SQL 就指向别的表）
const (
	TableBusinessUser    = "business_users"
	TableBusinessSession = "business_sessions"
)

// instance 当前生效的数据库实例
var instance gdb.DB

// Instance 返回数据访问实例。未 Init 就取属于装配顺序错误。
func Instance() gdb.DB {
	if instance == nil {
		panic("[BIZ] db.Init 未调用，装配顺序错误")
	}
	return instance
}

// SetInstance 注入实例（测试用：把整棵树指向临时库）
func SetInstance(d gdb.DB) { instance = d }

// Init 打开 SQLite 并建表。
//
// 每次都跑一遍 DDL：语句是幂等的，重复执行不会丢数据，也让"首次启动"
// 和"升级启动"走同一条路径。
func Init(ctx context.Context, path string) error {
	if strings.TrimSpace(path) == "" {
		return fmt.Errorf("BIZ_DB 为空：请指定 SQLite 文件路径")
	}
	// 交给驱动前先转绝对路径：gf 的 sqlite 驱动会在当前目录及其父目录里
	// "搜索"这个文件名，相对路径可能命中一个意料之外的同名文件。
	source := path
	if path != ":memory:" {
		source = gfile.Abs(path)
	}

	conn, err := gdb.New(gdb.ConfigNode{Type: "sqlite", Name: source})
	if err != nil {
		return fmt.Errorf("打开业务数据库失败 (%s): %w", path, err)
	}

	// 同一进程内重复 Init（测试里每个用例一次）时先关掉上一个连接池
	if instance != nil {
		_ = instance.Close(ctx)
	}
	instance = conn

	if err := execDDL(ctx); err != nil {
		return err
	}
	g.Log().Infof(ctx, "[BIZ] 业务数据库就绪: %s", path)
	return nil
}

// execDDL 逐条执行内嵌建表语句。
//
// 逐条而不是整段提交：驱动对多语句的支持依实现而定，而 DDL 一旦"部分成功"，
// 报错位置会指到很奇怪的地方。
func execDDL(ctx context.Context) error {
	for _, stmt := range splitStatements(schemaDDL) {
		if _, err := instance.Exec(ctx, stmt); err != nil {
			return fmt.Errorf("执行业务建表语句失败: %w\n       语句: %s", err, firstLine(stmt))
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

// firstLine 取首行，把多行的建表语句压到一行报错里
func firstLine(s string) string {
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		return s[:i] + " …"
	}
	return s
}

// Env 读取环境变量，带默认值。
//
// 本服务坚持 env 而不是配置文件：BIZ_TOKEN_SECRET 必须由部署侧注入
// （不能随代码或配置文件分发），把配置源统一成 env 才不会有人"顺手"
// 把密钥写进 yaml。
func Env(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

// ── 业务用户 ────────────────────────────────────────────────────────────────

// scanOne 查单行，零行算"没查到"而不是错误。
//
// 为什么不能直接用 Model.Scan：gf 的 Scan 在零行时返回 sql.ErrNoRows
// （gdb_type_record.go 的 Record.Struct、gdb_type_result_scanlist.go 都这么走），
// 而 GORM 的 First 是把"没查到"当作一个正常分支的。这个差别会让所有
// "不存在就返回 nil"的路径变成 500 —— 其中最要命的是"新库首次启动"：
// 库里一行都没有，接口全挂。
//
// 所以单行查询统一走 One() + IsEmpty() 判断，Slice 查询才直接用 Scan。
func scanOne(ctx context.Context, model *gdb.Model, dest interface{}) (bool, error) {
	one, err := model.Ctx(ctx).One()
	if err != nil {
		return false, err
	}
	if one.IsEmpty() {
		return false, nil
	}
	if err := one.Struct(dest); err != nil {
		return false, err
	}
	return true, nil
}

// UserBySub 按 IDP 的 sub 查业务用户；不存在返回 (nil, nil)
func UserBySub(ctx context.Context, sub string) (*BusinessUser, error) {
	var u BusinessUser
	found, err := scanOne(ctx, instance.Model(TableBusinessUser).Where("sub", sub), &u)
	if err != nil {
		return nil, err
	}
	if !found {
		return nil, nil
	}
	return &u, nil
}

// CreateUser 新建业务用户，成功后回填自增主键
func CreateUser(ctx context.Context, u *BusinessUser) error {
	now := time.Now()
	res, err := instance.Model(TableBusinessUser).Ctx(ctx).Data(g.Map{
		"sub":           u.Sub,
		"username":      u.Username,
		"nickname":      u.Nickname,
		"email":         u.Email,
		"last_login_at": u.LastLoginAt,
		"created_at":    now,
		"updated_at":    now,
	}).Insert()
	if err != nil {
		return err
	}
	u.CreatedAt, u.UpdatedAt = now, now
	if id, err := res.LastInsertId(); err == nil {
		u.Id = uint(id)
	}
	return nil
}

// SyncUserProfile 用 IDP 的最新资料刷新业务侧用户，并记录本次登录时间。
//
// 只写这几个字段：业务侧没有自己的资料编辑入口，username/nickname/email
// 的权威来源始终是 IDP，本地只是缓存。
func SyncUserProfile(ctx context.Context, u *BusinessUser) error {
	now := time.Now()
	_, err := instance.Model(TableBusinessUser).Ctx(ctx).Where("sub", u.Sub).Data(g.Map{
		"username":      u.Username,
		"nickname":      u.Nickname,
		"email":         u.Email,
		"last_login_at": u.LastLoginAt,
		"updated_at":    now,
	}).Update()
	if err != nil {
		return err
	}
	u.UpdatedAt = now
	return nil
}

// ── 业务会话 ────────────────────────────────────────────────────────────────

// SessionByID 查未过期的会话；不存在或已过期返回 (nil, nil)。
//
// 过期判定放在 SQL 里（而不是查出来再比时间）：调用方拿到 nil 就是"该重新
// 登录"，不存在"忘了检查过期"的写法。
func SessionByID(ctx context.Context, sessionID string) (*BusinessSession, error) {
	var s BusinessSession
	found, err := scanOne(ctx, instance.Model(TableBusinessSession).
		Where("session_id", sessionID).
		Where("expires_at >", time.Now()), &s)
	if err != nil {
		return nil, err
	}
	if !found {
		return nil, nil
	}
	return &s, nil
}

// UpsertSession 保存会话：Id 为 0 时插入，否则按主键更新。
//
// 不用"先查再决定"，因为调用方本来就持有这个对象 —— 登录回调时它是新的，
// 续期时它是查出来的。
func UpsertSession(ctx context.Context, s *BusinessSession) error {
	now := time.Now()
	data := g.Map{
		"session_id":               s.SessionID,
		"user_sub":                 s.UserSub,
		"id_token":                 s.IDToken,
		"access_token":             s.AccessToken,
		"refresh_token":            s.RefreshToken,
		"encrypted":                s.Encrypted,
		"access_token_expires_at":  s.AccessTokenExpiresAt,
		"refresh_token_expires_at": s.RefreshTokenExpiresAt,
		"expires_at":               s.ExpiresAt,
		"updated_at":               now,
	}

	if s.Id == 0 {
		data["created_at"] = now
		res, err := instance.Model(TableBusinessSession).Ctx(ctx).Data(data).Insert()
		if err != nil {
			return err
		}
		s.CreatedAt, s.UpdatedAt = now, now
		if id, err := res.LastInsertId(); err == nil {
			s.Id = uint(id)
		}
		return nil
	}

	if _, err := instance.Model(TableBusinessSession).Ctx(ctx).
		Where("id", s.Id).Data(data).Update(); err != nil {
		return err
	}
	s.UpdatedAt = now
	return nil
}

// DeleteSession 删除单个会话（登出、续期失败止血）
func DeleteSession(ctx context.Context, sessionID string) error {
	_, err := instance.Model(TableBusinessSession).Ctx(ctx).
		Where("session_id", sessionID).Delete()
	return err
}

// DeleteExpiredSessions 清理已整体过期的会话，避免表无限增长
func DeleteExpiredSessions(ctx context.Context, now time.Time) (int64, error) {
	res, err := instance.Model(TableBusinessSession).Ctx(ctx).Where("expires_at <", now).Delete()
	if err != nil {
		return 0, err
	}
	n, err := res.RowsAffected()
	if err != nil {
		// 拿不到影响行数不算失败：清理动作本身已经执行了
		return 0, nil
	}
	return n, nil
}

// ActiveSessions 取出所有未整体过期的会话（后台巡检的输入）
func ActiveSessions(ctx context.Context, now time.Time) ([]BusinessSession, error) {
	var out []BusinessSession
	if err := instance.Model(TableBusinessSession).Ctx(ctx).
		Where("expires_at >", now).Scan(&out); err != nil {
		return nil, err
	}
	return out, nil
}
