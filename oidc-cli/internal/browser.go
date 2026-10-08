package internal

import (
	"fmt"
	"net"
	"os/exec"
	"runtime"
)

// ============================================================
// 浏览器唤起 + 空闲端口查找
// ============================================================

// FindFreePort 自动查找本机空闲端口
// 通过监听 127.0.0.1:0 让内核分配端口后立即释放
func FindFreePort() (int, error) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return 0, fmt.Errorf("查找空闲端口失败: %w", err)
	}
	defer l.Close()
	return l.Addr().(*net.TCPAddr).Port, nil
}

// OpenBrowser 唤起系统默认浏览器打开指定 URL
// 支持 macOS / Linux / Windows
func OpenBrowser(url string) error {
	var cmd *exec.Cmd
	switch runtime.GOOS {
	case "darwin":
		cmd = exec.Command("open", url)
	case "windows":
		cmd = exec.Command("rundll32", "url.dll,FileProtocolHandler", url)
	default: // linux 及其他类 Unix
		// 依次尝试常见浏览器打开器
		for _, candidate := range []string{"xdg-open", "sensible-browser", "x-www-browser", "firefox", "chromium", "google-chrome"} {
			if _, err := exec.LookPath(candidate); err == nil {
				cmd = exec.Command(candidate, url)
				break
			}
		}
		if cmd == nil {
			return fmt.Errorf("未找到可用的浏览器打开器（xdg-open / sensible-browser 等）")
		}
	}
	if err := cmd.Start(); err != nil {
		return fmt.Errorf("唤起浏览器失败: %w", err)
	}
	// 后台运行，不阻塞等待
	go func() { _ = cmd.Wait() }()
	return nil
}
