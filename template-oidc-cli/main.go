// template-oidc-cli 是统一登录平台的命令行客户端：
// 通过本机临时 HTTP 回调 + 浏览器完成 OIDC PKCE 授权码登录，
// token 以 AES-GCM 加密持久化到 ~/.oidc-cli/store.enc，并支持后台自动续期。
//
// 可执行文件名仍为 oidc-cli（见 go build -o oidc-cli）。
//
// 用法：
//
//	oidc-cli login    # 浏览器登录（自动查找空闲端口启动临时回调服务）
//	oidc-cli whoami   # 读取本地加密 token 并展示用户信息
//	oidc-cli logout   # 吊销 refresh_token 并删除本地凭据
package main

import (
	"flag"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/ZHLX2005/go-ah/template-oidc-cli/cmd"
)

const usage = `oidc-cli - 统一登录平台命令行客户端（OIDC PKCE）

用法:
  oidc-cli login  [选项]     浏览器登录，token 加密保存到本地
  oidc-cli whoami [选项]     展示当前登录用户信息
  oidc-cli logout [选项]     吊销 refresh_token 并删除本地凭据
  oidc-cli version           显示版本
  oidc-cli help              显示帮助

全局环境变量:
  OIDC_CLI_ISSUER       IDP 地址（默认 http://127.0.0.1:8080）
  OIDC_CLI_CLIENT_ID    客户端 ID（默认 oidc-cli）
  OIDC_CLI_STORE        本地加密存储路径（默认 ~/.oidc-cli/store.enc）
  OIDC_CLI_PASSPHRASE   可选用户口令，参与 AES 密钥派生（更强安全性）

示例:
  oidc-cli login
  oidc-cli login --keep-alive          # 登录后常驻，后台持续自动续期
  OIDC_CLI_CLIENT_ID=oidc-cli oidc-cli whoami
  oidc-cli logout
`

// version 由发布流水线通过 -ldflags "-X main.version=x.y.z" 注入，
// 本地 go run / go build 时保持为 dev。
var version = "dev"

func main() {
	if len(os.Args) < 2 {
		fmt.Print(usage)
		os.Exit(1)
	}
	sub := os.Args[1]
	args := os.Args[2:]

	switch sub {
	case "version", "-v", "--version":
		fmt.Printf("oidc-cli %s\n", version)
		os.Exit(0)
	case "login":
		os.Exit(runLogin(args))
	case "whoami":
		os.Exit(runWhoami(args))
	case "logout":
		os.Exit(runLogout(args))
	case "help", "-h", "--help":
		fmt.Print(usage)
		os.Exit(0)
	default:
		fmt.Fprintf(os.Stderr, "未知子命令: %s\n\n", sub)
		fmt.Print(usage)
		os.Exit(1)
	}
}

func env(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

func runLogin(args []string) int {
	fs := flag.NewFlagSet("login", flag.ExitOnError)
	issuer := fs.String("issuer", env("OIDC_CLI_ISSUER", "http://127.0.0.1:8080"), "IDP 地址")
	clientID := fs.String("client-id", env("OIDC_CLI_CLIENT_ID", "oidc-cli"), "OIDC 客户端 ID")
	storePath := fs.String("store", env("OIDC_CLI_STORE", ""), "本地加密存储路径")
	timeout := fs.Duration("timeout", 3*time.Minute, "等待浏览器回调的超时时间")
	keepAlive := fs.Bool("keep-alive", false, "登录后常驻，后台持续自动续期")
	_ = fs.Parse(args)

	err := cmd.RunLogin(cmd.LoginConfig{
		Issuer:    strings.TrimSuffix(*issuer, "/"),
		ClientID:  *clientID,
		StorePath: *storePath,
		Timeout:   *timeout,
		KeepAlive: *keepAlive,
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "\n❌ 登录失败：%v\n", err)
		return 1
	}
	return 0
}

func runWhoami(args []string) int {
	fs := flag.NewFlagSet("whoami", flag.ExitOnError)
	storePath := fs.String("store", env("OIDC_CLI_STORE", ""), "本地加密存储路径")
	localOnly := fs.Bool("local-only", false, "仅读取本地加密存储，不请求 /userinfo")
	_ = fs.Parse(args)

	err := cmd.RunWhoami(cmd.WhoamiConfig{StorePath: *storePath, LocalOnly: *localOnly})
	if err != nil {
		fmt.Fprintf(os.Stderr, "\n❌ 获取用户信息失败：%v\n", err)
		return 1
	}
	return 0
}

func runLogout(args []string) int {
	fs := flag.NewFlagSet("logout", flag.ExitOnError)
	storePath := fs.String("store", env("OIDC_CLI_STORE", ""), "本地加密存储路径")
	keepLocal := fs.Bool("keep-local", false, "吊销失败时保留本地凭据")
	_ = fs.Parse(args)

	err := cmd.RunLogout(cmd.LogoutConfig{StorePath: *storePath, KeepLocal: *keepLocal})
	if err != nil {
		fmt.Fprintf(os.Stderr, "\n❌ 登出失败：%v\n", err)
		return 1
	}
	return 0
}
