package internal

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"time"
)

// ============================================================
// 临时 HTTP 回调服务
// 只监听 127.0.0.1，外部网络无法访问
// 捕获 code/state 后立即关闭服务
// ============================================================

// CallbackResult 回调结果
type CallbackResult struct {
	Code  string
	State string
	Error string // OAuth 错误码，如 access_denied
	Desc  string // 错误描述
}

// CallbackServer 临时回调服务
type CallbackServer struct {
	port     int
	listener net.Listener
	server   *http.Server
	resultCh chan *CallbackResult
}

// NewCallbackServer 在指定端口创建仅监听 127.0.0.1 的临时服务
func NewCallbackServer(port int) *CallbackServer {
	return &CallbackServer{
		port:     port,
		resultCh: make(chan *CallbackResult, 1),
	}
}

// Port 返回实际监听端口
func (s *CallbackServer) Port() int { return s.port }

// RedirectURI 回调地址
func (s *CallbackServer) RedirectURI() string {
	return fmt.Sprintf("http://127.0.0.1:%d/callback", s.port)
}

// Start 启动服务（非阻塞）
func (s *CallbackServer) Start() error {
	// 关键安全点：显式绑定 127.0.0.1，不监听 0.0.0.0
	ln, err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", s.port))
	if err != nil {
		return fmt.Errorf("监听 127.0.0.1:%d 失败: %w", s.port, err)
	}
	s.listener = ln
	if tcpAddr, ok := ln.Addr().(*net.TCPAddr); ok {
		s.port = tcpAddr.Port
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/callback", s.handleCallback)

	s.server = &http.Server{
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
	}
	go func() {
		_ = s.server.Serve(ln)
	}()
	return nil
}

// handleCallback 处理 OAuth 回调
func (s *CallbackServer) handleCallback(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	res := &CallbackResult{
		Code:  q.Get("code"),
		State: q.Get("state"),
		Error: q.Get("error"),
		Desc:  q.Get("error_description"),
	}

	if res.Error != "" {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = w.Write([]byte(pageHTML("授权失败", "第三方登录未完成："+res.Error+" "+res.Desc, false)))
	} else if res.Code == "" {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = w.Write([]byte(pageHTML("回调异常", "未收到授权码 code，请重试。", false)))
	} else {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = w.Write([]byte(pageHTML("登录成功", "已成功获取授权码，请返回终端继续操作（本窗口可关闭）。", true)))
	}

	// 非阻塞投递结果，避免重复回调阻塞
	select {
	case s.resultCh <- res:
	default:
	}
}

// Wait 等待回调结果，超时返回错误
func (s *CallbackServer) Wait(timeout time.Duration) (*CallbackResult, error) {
	select {
	case r := <-s.resultCh:
		return r, nil
	case <-time.After(timeout):
		return nil, fmt.Errorf("等待浏览器回调超时（%s），请重试", timeout)
	}
}

// Shutdown 立即关闭临时服务（拿到 code 后调用）
func (s *CallbackServer) Shutdown() {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if s.server != nil {
		_ = s.server.Shutdown(ctx)
	} else if s.listener != nil {
		_ = s.listener.Close()
	}
}

// pageHTML 生成简单的回调结果页面
func pageHTML(title, msg string, ok bool) string {
	color := "#dc2626"
	icon := "⚠"
	if ok {
		color = "#059669"
		icon = "✓"
	}
	return `<!doctype html><html lang="zh-CN"><head><meta charset="utf-8">
<title>` + title + `</title></head>
<body style="margin:0;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif;
display:flex;align-items:center;justify-content:center;height:100vh;background:#f1f5f9">
<div style="background:#fff;padding:40px 48px;border-radius:16px;text-align:center;
box-shadow:0 10px 30px rgba(0,0,0,.08);max-width:420px">
<div style="font-size:40px;color:` + color + `">` + icon + `</div>
<h1 style="font-size:20px;color:#1e293b;margin:12px 0 8px">` + title + `</h1>
<p style="color:#64748b;font-size:14px;margin:0">` + msg + `</p>
</div></body></html>`
}
