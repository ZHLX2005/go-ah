package cmd

import (
	"context"
	"fmt"
	"time"

	"github.com/ZHLX2005/go-ah/template-oidc-cli/internal"
)

// LogoutConfig logout 子命令参数
type LogoutConfig struct {
	StorePath string
	// KeepLocal 吊销失败时是否保留本地凭据（默认删除）
	KeepLocal bool
}

// RunLogout 吊销 refresh_token 并删除本地加密存储
func RunLogout(cfg LogoutConfig) error {
	store, err := internal.NewTokenStore(cfg.StorePath)
	if err != nil {
		return err
	}
	ts, err := store.Load()
	if err != nil {
		// 本地无凭据：直接清理并提示
		if delErr := store.Delete(); delErr == nil {
			fmt.Println("ℹ️  本地无有效凭据，已确认清理完成")
			return nil
		}
		return err
	}

	client := internal.NewOIDCClient(ts.Issuer, ts.ClientID, "")
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	revokeErr := error(nil)
	if ts.RefreshToken != "" {
		if err := client.Revoke(ctx, ts.RefreshToken, "refresh_token"); err != nil {
			revokeErr = err
			fmt.Printf("⚠ 吊销 refresh_token 失败：%v\n", err)
		} else {
			fmt.Println("🚫 已在 IDP 侧吊销 refresh_token")
		}
	} else {
		fmt.Println("ℹ️  本地无 refresh_token，跳过吊销")
	}

	if revokeErr != nil && cfg.KeepLocal {
		fmt.Println("⚠ 因启用 KeepLocal，保留本地加密凭据")
		return revokeErr
	}

	// 删除本地加密存储
	if err := store.Delete(); err != nil {
		return err
	}
	fmt.Printf("🗑  已删除本地加密存储：%s\n", store.Path())
	fmt.Println("✅ 登出完成")
	return nil
}
