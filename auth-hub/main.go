// Command auth-hub 是统一登录平台（IdP）的服务端入口。
//
// 全部装配逻辑在 internal/cmd，这里只保留 gf 惯例的最小入口：
// 数据库驱动由 internal/db 注册（谁建连接谁注册驱动），入口不再关心。
package main

import (
	"github.com/gogf/gf/v2/os/gctx"

	"github.com/ZHLX2005/go-ah/auth-hub/internal/cmd"
)

func main() {
	cmd.Main.Run(gctx.GetInitCtx())
}
