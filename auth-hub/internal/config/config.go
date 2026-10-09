// Package config 是全平台配置读取的唯一出口。
//
// 优先级：环境变量 → manifest/config/config.yaml → 内置默认值。
//
// 为什么不用 g.Cfg().Get 直接读而要多这一层：GoFrame 的 g.Cfg().Get
// **不读环境变量**（只有名字带 GF_ 前缀的 GetWithEnv 系列会读），
// 而本平台的部署契约是 IDP_DSN / IDP_ISSUER / GSAC_REDIRECT_URI 这类
// 无前缀变量，且它们已经写进 GitHub Actions 的 secrets 与服务器
// 的容器 env 里，不能改。所以这里显式读 env，再用 config.yaml 兜底，
// 既保持部署契约不变，又让配置有个可读的落点。
package config

import (
	"context"
	"os"
	"strings"

	"github.com/gogf/gf/v2/frame/g"

	"github.com/ZHLX2005/go-ah/auth-hub/internal/consts"
)

// Config 启动期只读的配置快照
type Config struct {
	// DSN 数据库连接串。支持 postgres:// 的 URL 形式（历史部署用的就是它）
	// 与 pgsql: 的 link 形式，由 db 包统一解析。
	DSN string
	// Issuer IdP 对外标识，必须公网可达：发现文档、id_token 的 iss、
	// 各端点地址都由它拼出。配错会让业务侧报
	// 「id token issued by a different provider」。
	Issuer string
	// Addr 监听地址
	Addr string
	// WebDist 前端产物目录（可选）。容器部署下前端由 nginx 托管，
	// 这个目录通常不存在，Go 侧就只提供 API。
	WebDist string
	// SigningKeyPEM 显式注入的签名私钥（多副本部署共用同一把）；空则由 db 层落库/加载
	SigningKeyPEM string
	// GSACRedirectURI gs-ac 客户端的回调白名单（空格分隔多个）
	GSACRedirectURI string
	// GSACPostLogoutURI gs-ac 客户端的登出回跳白名单（空格分隔多个）
	GSACPostLogoutURI string
}

var current *Config

// Load 读取配置并缓存。必须在任何 Get 之前调用一次。
func Load(ctx context.Context) *Config {
	current = &Config{
		DSN:           pick(ctx, "IDP_DSN", "idp.dsn", consts.DefaultDSN),
		Issuer:        strings.TrimRight(pick(ctx, "IDP_ISSUER", "idp.issuer", "http://127.0.0.1:8080"), "/"),
		Addr:          pick(ctx, "IDP_ADDR", "idp.addr", "127.0.0.1:8080"),
		WebDist:       pick(ctx, "IDP_WEB_DIST", "idp.webDist", "./web/idp-web/dist"),
		SigningKeyPEM: pick(ctx, "IDP_SIGNING_KEY_PEM", "idp.signingKeyPem", ""),
		GSACRedirectURI: pick(ctx, "GSAC_REDIRECT_URI", "idp.gsac.redirectUri",
			"http://127.0.0.1:5173/oauth/callback http://127.0.0.1:5173/access/oidc/callback"),
		GSACPostLogoutURI: pick(ctx, "GSAC_POST_LOGOUT_URI", "idp.gsac.postLogoutUri",
			"http://127.0.0.1:5173/login http://127.0.0.1:5173/access/login"),
	}
	return current
}

// Get 返回已加载的配置。
//
// 未 Load 就取属于装配顺序错误，直接 panic —— 拿一份零值配置继续跑，
// 结果会是「连到了空 DSN」或「issuer 为空」，排查成本远高于启动即失败。
func Get() *Config {
	if current == nil {
		panic("[auth-hub] config.Load 未调用，装配顺序错误")
	}
	return current
}

// pick 按 环境变量 → 配置文件 → 默认值 的顺序取一项
func pick(ctx context.Context, envKey, cfgPath, def string) string {
	if v := strings.TrimSpace(os.Getenv(envKey)); v != "" {
		return v
	}
	if v, err := g.Cfg().Get(ctx, cfgPath); err == nil {
		if s := strings.TrimSpace(v.String()); s != "" {
			return s
		}
	}
	return def
}
