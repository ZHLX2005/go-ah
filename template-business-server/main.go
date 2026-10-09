// Command template-business-server 是"业务方如何接入统一登录"的参考实现。
//
// 全部装配都在这里，顺序不可调换，且任何一步失败都必须**启动即失败**：
//
//	db.Init        → 打开业务库、建表（没有库就无从存会话）
//	api.InitCrypto → 加密引擎；没配密钥就不该提供服务
//	refresher      → 后台续期巡检
//	SetupOIDC      → 连 IDP（失败不阻塞启动，见 api.SetupOIDC）
//	s.Run          → 开始对外服务
//
// 前三步失败直接终止进程：带着半截状态（没加密能力、或指向一个不存在的库）
// 继续跑，用户看到的是"登录成功但一会儿就掉线"，排查成本远高于容器起不来。
package main

import (
	"context"
	"fmt"
	"time"

	"github.com/gogf/gf/v2/frame/g"
	"github.com/gogf/gf/v2/os/gcmd"
	"github.com/gogf/gf/v2/os/gctx"

	"github.com/ZHLX2005/go-ah/template-business-server/api"
	"github.com/ZHLX2005/go-ah/template-business-server/db"
)

// version 由发布流水线通过 -ldflags "-X main.version=x.y.z" 注入，
// 本地 go run / go build 时保持为 dev。
var version = "dev"

// Main 服务主命令
var Main = gcmd.Command{
	Name:  "template-business-server",
	Usage: "template-business-server",
	Brief: "模板业务平台（统一登录接入参考实现）",
	Func: func(ctx context.Context, parser *gcmd.Parser) error {
		return run(ctx)
	},
}

func run(ctx context.Context) error {
	// 1) 业务数据库（SQLite）
	if err := db.Init(ctx, db.Env("BIZ_DB", "template.db")); err != nil {
		return err
	}

	g.Log().Infof(ctx, "[BIZ] version=%s 启动中…", version)

	// 2) Token 加密引擎：密钥缺失或过弱直接终止启动 ——
	//    宁可不启动，也不能在没有加密能力的情况下把 refresh_token 明文落库。
	if err := api.InitCrypto(); err != nil {
		return fmt.Errorf("加密初始化失败，服务无法安全启动: %w\n"+
			"       请设置环境变量，例如：export BIZ_TOKEN_SECRET=$(openssl rand -hex 32)", err)
	}
	g.Log().Info(ctx, "[BIZ] Token 加密引擎已就绪（AES-256-GCM + PBKDF2-SHA256）")

	// 3) 后台自动续期巡检
	refresher := api.NewRefresher(30 * time.Second)
	refresher.OnSessionRevoked = func(sessionID, userSub string, reason error) {
		g.Log().Warningf(ctx, "[BIZ][续期] 会话已失效，用户需重新登录: session=%s sub=%s 原因=%v",
			sessionID, userSub, reason)
	}
	refresher.Start(ctx)
	defer refresher.Stop()

	// 4) 尝试连接 IDP。失败不阻塞启动，接口调用时会重试（SetupOIDC 不缓存失败），
	//    这样"业务平台先于 IDP 起来"也能自愈。
	go func() {
		for i := 0; i < 3; i++ {
			if err := api.SetupOIDC(); err == nil {
				return
			} else if i == 2 {
				g.Log().Warningf(ctx, "[BIZ] 初始化 OIDC 客户端失败（IDP 可能未启动）: %v", err)
			}
			time.Sleep(2 * time.Second)
		}
	}()

	// 5) HTTP 服务
	addr := db.Env("BIZ_ADDR", "127.0.0.1:8081")
	s := g.Server()
	s.SetAddr(addr)
	// 关掉 gf 自带的面板类端点：gin 版本没有它们，凭空多几个入口就是扩大暴露面
	s.SetOpenApiPath("")
	s.SetSwaggerPath("")
	s.SetDumpRouterMap(false)

	api.Register(ctx, s, db.Env("BIZ_WEB_DIST", "./web/template-web/dist"))

	g.Log().Infof(ctx, "[BIZ] 模板业务平台已启动: http://%s", addr)
	s.Run()
	return nil
}

func main() {
	Main.Run(gctx.GetInitCtx())
}
