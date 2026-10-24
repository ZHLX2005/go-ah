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
	"fmt"
	"time"

	"github.com/gogf/gf/v2/frame/g"
	"github.com/gogf/gf/v2/os/gcmd"

	"github.com/ZHLX2005/go-ah/auth-hub/internal/config"
	"github.com/ZHLX2005/go-ah/auth-hub/internal/consts"
	"github.com/ZHLX2005/go-ah/auth-hub/internal/db"
	"github.com/ZHLX2005/go-ah/auth-hub/internal/logic/oidc"
	"github.com/ZHLX2005/go-ah/auth-hub/internal/logic/qr"
	"github.com/ZHLX2005/go-ah/auth-hub/internal/logic/session"
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

	// 管理员默认口令闸门：默认口令写在公开仓库里（consts.SeedAdminPassword），
	// 指向非本机的库还用它，等于把全平台的权限根（唯一管理员，能发邀请码）
	// 交给任何读过这个仓库的人。"注释里提醒部署必须覆盖"挡不住忘配 env，
	// 只有启动失败挡得住。本机开发库（127.0.0.1/localhost）不受影响。
	if !db.IsLoopbackDSN(cfg.DSN) && cfg.AdminPassword == consts.SeedAdminPassword {
		return fmt.Errorf(
			"IDP_ADMIN_PASSWORD 仍是公开的默认值，拒绝连接非本机数据库启动；" +
				"请在环境中设置真实口令（管理员已存在时该值仅用于 seed 新库，不会覆盖现有口令）")
	}

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
	// 传输层的 body 上限必须**大于** /api/qr/decode 自己的图片上限（8MB），
	// 否则超大图片会先被传输层拦下、连接被直接中断，客户端拿到的是
	// "无法连接认证中心"这种网络错误，而不是端点写好的"图片太大，请重拍"。
	// 理由与取值见 consts.MaxRequestBodyBytes。
	s.SetClientMaxBodySize(consts.MaxRequestBodyBytes)
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
// 本服务此前**完全没有**清理任务，只有 QR 票据表配了清理。
// 但 o_auth_access_tokens 是每 10 分钟 TTL 一行、业务方后台续期
// 还会持续放大的表——它才是第一个会把库撑爆的（线性堆积、无上限）。
// 授权码 / refresh_token / user_sessions 同理，只是慢一些。
//
// 口径与 template-business-server 的 DeleteExpiredSessions 一致；
// 保留期定义在 consts（TokenPurge*），各表按审计需求长短不一。
func startJanitor(ctx context.Context) {
	sweep := func() {
		// 用独立的 context：清理发生在服务运行期，不能继承请求的取消信号；
		// 但要把 ctx 的值（trace id 等）带过去，所以走 WithoutCancel 而不是 Background。
		c := context.WithoutCancel(ctx)

		// 顺序无关紧要，但把 QR 放最前：它是唯一"匿名可写"的表，
		// 灌入速率不受登录人数约束。
		type purgeJob struct {
			name string
			fn   func(context.Context) (int64, error)
		}
		jobs := []purgeJob{
			{"扫码票据", func(c context.Context) (int64, error) { return qr.Purge(c) }},
			{"access_token", oidc.PurgeExpiredAccessTokens},
			{"refresh_token", oidc.PurgeGoneRefreshTokens},
			{"授权码", oidc.PurgeExpiredAuthCodes},
			{"全局会话", session.PurgeExpired},
		}
		for _, job := range jobs {
			n, err := job.fn(c)
			if err != nil {
				// 清理失败绝不影响对外服务：它丢的是未来的可查性，不是当前的可用性。
				// 但必须喊出来，否则会静默堆成一张几百万行的表，等到某天查询变慢才发现。
				g.Log().Errorf(c, "[auth-hub] 清理过期%s失败: %v", job.name, err)
				continue
			}
			if n > 0 {
				g.Log().Infof(c, "[auth-hub] 已清理过期%s %d 行", job.name, n)
			}
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
