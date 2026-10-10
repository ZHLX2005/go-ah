// Package cmd 是服务的装配层：把配置、数据库、签名密钥、路由按正确顺序接起来。
//
// 装配顺序不可调换，且任何一步失败都必须**启动即失败**：
//
//	config.Load  → 没有配置就无从连库
//	db.Init      → 建 schema / 建表 / 写种子
//	signing.Load → 读写 signing_key_records（依赖 db）
//	router + Run → 开始对外服务
//
// 任一步失败都直接返回错误终止进程：带着半截状态（比如连了空 DSN、
// 或用了临时生成的签名密钥）继续跑，客户端看到的是零散的验签失败，
// 排查成本远高于"容器起不来"。
package cmd

import (
	"context"
	"time"

	"github.com/gogf/gf/v2/frame/g"
	"github.com/gogf/gf/v2/os/gcmd"

	"github.com/ZHLX2005/go-ah/auth-hub/internal/config"
	"github.com/ZHLX2005/go-ah/auth-hub/internal/db"
	"github.com/ZHLX2005/go-ah/auth-hub/internal/logic/qr"
	"github.com/ZHLX2005/go-ah/auth-hub/internal/logic/signing"
	"github.com/ZHLX2005/go-ah/auth-hub/internal/router"
)

// Main 服务主命令
var Main = gcmd.Command{
	Name:  "auth-hub",
	Usage: "auth-hub",
	Brief: "统一登录平台（OIDC Provider）",
	Func: func(ctx context.Context, parser *gcmd.Parser) error {
		return run(ctx)
	},
}

func run(ctx context.Context) error {
	cfg := config.Load(ctx)

	if err := db.Init(ctx, db.InitOptions{
		DSN:                cfg.DSN,
		GSACRedirectURIs:   cfg.GSACRedirectURI,
		GSACPostLogoutURIs: cfg.GSACPostLogoutURI,
		AdminUsername:      cfg.AdminUsername,
		AdminEmail:         cfg.AdminEmail,
		AdminPassword:      cfg.AdminPassword,
	}); err != nil {
		return err
	}

	// 必须在 db.Init 之后：② 读库、③ 落库都要用到连接
	if err := signing.Load(ctx, cfg.SigningKeyPEM); err != nil {
		return err
	}

	s := g.Server()
	s.SetAddr(cfg.Addr)
	router.Register(ctx, s, cfg.WebDist)

	startJanitor(ctx)

	g.Log().Infof(ctx, "[auth-hub] 统一登录平台已启动: http://%s (issuer=%s)", cfg.Addr, cfg.Issuer)
	s.Run()
	return nil
}

// janitorInterval 后台清理的运行间隔。
//
// 一小时一次而不是每分钟：要清的是"过期 7 天以上"的行，跑得快没有额外收益，
// 只会多占连接。启动时先跑一次，是为了让重启顺带把积压补掉 ——
// 服务停机期间没有进程在跑批，重启后那一秒就是积压最多的时刻。
const janitorInterval = time.Hour

// startJanitor 启动过期数据清理。
//
// 为什么必须有它，而且为什么是从这里开始而不是"以后再说"：
// 本服务此前**完全没有**清理任务（user_sessions 的过期行一直堆着），
// 这在旧表上勉强说得过去 —— 它们只在登录时增长，一行能撑很久。
// 但 qr_login_sessions 是**匿名可写**的：一个脚本不登录就能往里灌行，
// 而且绝大多数行是失败的（没扫、没批、换码）。不给它配清理，
// 等于给认证中心加了一个"谁都能写、没人负责删"的表 —— 那是要出事故的。
//
// 口径与 template-business-server 的 DeleteExpiredSessions 一致（那边已有先例）；
// 顺手把老表一起清了，是因为只清一张表会留下"以为都清了"的错觉。
func startJanitor(ctx context.Context) {
	sweep := func() {
		// 用独立的 context：清理发生在服务运行期，不能继承请求的取消信号；
		// 但要把 ctx 的值（trace id 等）带过去，所以走 WithoutCancel 而不是 Background。
		c := context.WithoutCancel(ctx)
		n, err := qr.Purge(c)
		if err != nil {
			// 清理失败绝不影响对外服务：它丢的是未来的可查性，不是当前的可用性。
			// 但必须喊出来，否则会静默堆成一张几百万行的表，等到某天查询变慢才发现。
			g.Log().Errorf(c, "[auth-hub] 清理过期扫码票据失败: %v", err)
			return
		}
		if n > 0 {
			g.Log().Infof(c, "[auth-hub] 已清理过期扫码票据 %d 行", n)
		}
	}

	go func() {
		sweep()
		t := time.NewTicker(janitorInterval)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				g.Log().Info(ctx, "[auth-hub] 清理任务随服务退出")
				return
			case <-t.C:
				sweep()
			}
		}
	}()
}
