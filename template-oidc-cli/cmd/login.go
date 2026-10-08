package cmd

import (
	"context"
	"fmt"
	"log"
	"os"
	"time"

	"github.com/ZHLX2005/go-ah/template-oidc-cli/internal"
)

// LoginConfig login 子命令参数
type LoginConfig struct {
	Issuer    string
	ClientID  string
	StorePath string
	Timeout   time.Duration
	// OpenBrowser 可注入（测试时替换）
	OpenBrowser func(string) error
	// KeepAlive 登录后是否保持后台续期常驻
	KeepAlive bool
}

// RunLogin 执行浏览器 PKCE 登录流程
func RunLogin(cfg LoginConfig) error {
	if cfg.Timeout == 0 {
		cfg.Timeout = 3 * time.Minute
	}
	if cfg.OpenBrowser == nil {
		cfg.OpenBrowser = internal.OpenBrowser
	}

	// ---- 1) 自动查找空闲端口，启动仅监听 127.0.0.1 的临时服务 ----
	port, err := internal.FindFreePort()
	if err != nil {
		return err
	}
	srv := internal.NewCallbackServer(port)
	if err := srv.Start(); err != nil {
		return err
	}
	// 无论成功失败都确保服务关闭
	defer srv.Shutdown()

	fmt.Printf("🖥  临时回调服务已启动：http://127.0.0.1:%d/callback（仅本机可访问）\n", srv.Port())

	// ---- 2) 生成 PKCE 参数 ----
	p, err := internal.NewPKCE()
	if err != nil {
		return err
	}

	// ---- 3) 构造授权地址并唤起浏览器 ----
	client := internal.NewOIDCClient(cfg.Issuer, cfg.ClientID, srv.RedirectURI())
	ctx := context.Background()
	if _, err := client.Discover(ctx); err != nil {
		return err
	}
	authURL, err := client.AuthorizationURL(p)
	if err != nil {
		return err
	}

	fmt.Println("🌐 正在唤起浏览器完成授权…")
	fmt.Println("   若浏览器未自动打开，请手动访问：")
	fmt.Printf("   %s\n\n", authURL)
	if err := cfg.OpenBrowser(authURL); err != nil {
		fmt.Printf("⚠ 自动唤起浏览器失败：%v（请手动访问上面的链接）\n", err)
	}

	// ---- 4) 等待回调捕获 code/state ----
	fmt.Println("⏳ 等待授权回调…")
	res, err := srv.Wait(cfg.Timeout)
	if err != nil {
		return err
	}
	// 拿到结果立刻关闭临时服务（安全要求）
	srv.Shutdown()

	if res.Error != "" {
		return fmt.Errorf("授权被拒绝或失败：%s %s", res.Error, res.Desc)
	}
	// ---- 5) 校验 state 防 CSRF ----
	if !internal.ConstantTimeEqual(res.State, p.State) {
		return fmt.Errorf("state 校验失败，可能存在 CSRF 风险，已终止登录")
	}
	fmt.Println("✅ 已捕获授权码，state 校验通过")

	// ---- 6) 用 code + code_verifier 换取 token ----
	resp, err := client.ExchangeCode(ctx, res.Code, p.CodeVerifier)
	if err != nil {
		return err
	}
	fmt.Println("🔑 令牌交换成功")

	// ---- 7) 解析 id_token 获取身份信息 ----
	ts := &internal.TokenSet{
		AccessToken:      resp.AccessToken,
		IDToken:          resp.IDToken,
		RefreshToken:     resp.RefreshToken,
		TokenType:        resp.TokenType,
		Scope:            resp.Scope,
		ExpiresAt:        time.Now().Add(internal.AccessTokenTTL),
		RefreshExpiresAt: time.Now().Add(internal.RefreshTokenTTL),
		Issuer:           cfg.Issuer,
		ClientID:         cfg.ClientID,
	}
	if resp.ExpiresIn > 0 {
		ts.ExpiresAt = time.Now().Add(time.Duration(resp.ExpiresIn) * time.Second)
	}
	if claims, err := internal.ParseIDTokenClaims(resp.IDToken); err == nil {
		if sub, ok := claims["sub"].(string); ok {
			ts.Subject = sub
		}
		if u, ok := claims["preferred_username"].(string); ok {
			ts.Username = u
		}
	}

	// ---- 8) AES-GCM 加密持久化 ----
	store, err := internal.NewTokenStore(cfg.StorePath)
	if err != nil {
		return err
	}
	if err := store.Save(ts); err != nil {
		return err
	}
	fmt.Printf("💾 令牌已 AES-GCM 加密保存至：%s\n", store.Path())

	// ---- 9) 启动后台自动续期协程 ----
	refresher := internal.NewRefresher(client, store, ts)
	refresher.OnLogout = func(reason error) {
		fmt.Printf("\n⚠ 后台续期失败，本地会话已清除：%v\n请重新执行 oidc-cli login\n", reason)
	}
	refresher.Start(30 * time.Second)
	fmt.Println("♻️  后台自动续期已启动（access_token 剩余 < 2 分钟时自动刷新）")

	fmt.Printf("\n登录成功：%s（sub=%s）\n", ts.Username, ts.Subject)

	if !cfg.KeepAlive {
		// 默认不常驻：给续期协程留出短暂时间完成首次写入后退出
		refresher.Stop()
		return nil
	}

	// 常驻模式：阻塞直到手动中断
	fmt.Println("已进入常驻模式（Ctrl+C 退出），后台将持续维持登录态…")
	sig := make(chan os.Signal, 1)
	waitSignal(sig)
	refresher.Stop()
	fmt.Println("\n👋 已退出常驻模式")
	return nil
}

var logger = log.New(os.Stderr, "", log.LstdFlags)
