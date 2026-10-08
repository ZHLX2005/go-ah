package cmd

import (
	"context"
	"fmt"
	"time"

	"github.com/ZHLX2005/go-ah/template-oidc-cli/internal"
)

// WhoamiConfig whoami 子命令参数
type WhoamiConfig struct {
	StorePath string
	// LocalOnly 仅读取本地加密存储，不请求 /userinfo
	LocalOnly bool
}

// RunWhoami 读取本地加密 token 并展示用户信息
// 优先调用 IDP /oauth2/userinfo 获取权威信息；若 access_token 已过期，
// 会先尝试用 refresh_token 静默续期再查询。
func RunWhoami(cfg WhoamiConfig) error {
	store, err := internal.NewTokenStore(cfg.StorePath)
	if err != nil {
		return err
	}
	ts, err := store.Load()
	if err != nil {
		return err
	}

	fmt.Println("🔐 已从本地加密存储读取凭据")
	fmt.Printf("   存储文件：%s\n", store.Path())
	fmt.Printf("   签发方：%s\n", ts.Issuer)
	fmt.Printf("   客户端：%s\n", ts.ClientID)
	fmt.Printf("   access_token 过期时间：%s（剩余 %s）\n",
		ts.ExpiresAt.Format("2006-01-02 15:04:05"), ts.ExpiresIn().Round(time.Second))
	fmt.Printf("   refresh_token 过期时间：%s\n", ts.RefreshExpiresAt.Format("2006-01-02 15:04:05"))

	// 展示 id_token 载荷中的身份信息
	if claims, err := internal.ParseIDTokenClaims(ts.IDToken); err == nil {
		fmt.Println("\n📄 id_token 载荷：")
		for _, k := range []string{"sub", "preferred_username", "name", "email", "iss", "aud"} {
			if v, ok := claims[k]; ok {
				fmt.Printf("   %-20s %v\n", k+":", v)
			}
		}
	}

	if cfg.LocalOnly {
		return nil
	}

	client := internal.NewOIDCClient(ts.Issuer, ts.ClientID, "")
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	// access_token 即将或已过期 -> 先续期
	if ts.ShouldRefresh() {
		fmt.Println("\n♻️  access_token 即将过期，正在静默续期…")
		resp, err := client.Refresh(ctx, ts.RefreshToken)
		if err != nil {
			return fmt.Errorf("续期失败（refresh_token 可能已被吊销）：%w\n请重新执行 oidc-cli login", err)
		}
		ts.AccessToken = resp.AccessToken
		ts.IDToken = resp.IDToken
		if resp.RefreshToken != "" {
			ts.RefreshToken = resp.RefreshToken
		}
		ts.ExpiresAt = time.Now().Add(internal.AccessTokenTTL)
		if resp.ExpiresIn > 0 {
			ts.ExpiresAt = time.Now().Add(time.Duration(resp.ExpiresIn) * time.Second)
		}
		if err := store.Save(ts); err != nil {
			return err
		}
		fmt.Println("   ✅ 续期成功，已更新加密存储")
	}

	// 调用 /oauth2/userinfo
	info, err := client.UserInfo(ctx, ts.AccessToken)
	if err != nil {
		return fmt.Errorf("调用 /oauth2/userinfo 失败：%w", err)
	}
	fmt.Println("\n👤 /oauth2/userinfo 返回：")
	for _, k := range []string{"sub", "preferred_username", "name", "email", "email_verified"} {
		if v, ok := info[k]; ok {
			fmt.Printf("   %-20s %v\n", k+":", v)
		}
	}
	return nil
}
