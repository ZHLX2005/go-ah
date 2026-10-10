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

	"github.com/gogf/gf/v2/frame/g"
	"github.com/gogf/gf/v2/os/gcmd"

	"github.com/ZHLX2005/go-ah/auth-hub/internal/config"
	"github.com/ZHLX2005/go-ah/auth-hub/internal/db"
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

	g.Log().Infof(ctx, "[auth-hub] 统一登录平台已启动: http://%s (issuer=%s)", cfg.Addr, cfg.Issuer)
	s.Run()
	return nil
}
