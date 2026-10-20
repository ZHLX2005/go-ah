// /api/qr/decode 的 HTTP 契约测试。
//
// 这一层测的是**对外形状**：状态码、响应信封、multipart 字段名。
// 它刻意不碰数据库 —— 这条端点只把上传的图片解码成字符串，不读写任何
// 服务端状态，所以它可以在没有 PG 的环境里被完整验证（装配错误不应该
// 只能在部署后才被发现）。
//
// 限额行为（429）与超大图片（400 image_too_large）由 .tool/qr-decode-probe
// 的黑盒探针覆盖：前者会耗尽进程级限流配额，后者需要把 body 推到 8MB 以上，
// 放在 Go 测试里都会拖慢或污染同进程的其他用例。
package router_test

import (
	"bytes"
	"mime/multipart"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// qrFixturePath 是测试用二维码图。
//
// 图放在 logic/qr 那边（解码器所在地），这里跨目录读它，避免同一张二进制
// 在两个包里各存一份 —— 副本一旦不同步，两边的断言会各说各话。
const qrFixturePath = "../logic/qr/testdata/qr_login.png"

// qrFixtureText 是那张图里的内容，与 logic/qr/decode_test.go 保持一致。
const qrFixtureText = "http://127.0.0.1:8988/login?ticket=fixture_ticket_0001"

// multipartBody 拼一个 multipart 请求体。
func multipartBody(t *testing.T, field, filename string, content []byte) (string, []byte) {
	t.Helper()
	var buf bytes.Buffer
	w := multipart.NewWriter(&buf)
	if field != "" {
		fw, err := w.CreateFormFile(field, filename)
		if err != nil {
			t.Fatalf("建 multipart 字段失败: %v", err)
		}
		if _, err := fw.Write(content); err != nil {
			t.Fatalf("写 multipart 字段失败: %v", err)
		}
	}
	if err := w.Close(); err != nil {
		t.Fatalf("关闭 multipart 失败: %v", err)
	}
	return w.FormDataContentType(), buf.Bytes()
}

func TestQRDecodeEndpoint(t *testing.T) {
	srv := startServer(t)

	t.Run("正常二维码解出内容", func(t *testing.T) {
		png, err := os.ReadFile(filepath.Clean(qrFixturePath))
		if err != nil {
			t.Fatalf("读测试用二维码图失败: %v", err)
		}
		ct, body := multipartBody(t, "file", "qr.png", png)
		resp, parsed := request(t, "POST", srv.base+"/api/qr/decode", ct, string(body))
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("状态码应为 200，得到 %d", resp.StatusCode)
		}
		if parsed["code"] != float64(0) {
			t.Fatalf("业务信封 code 应为 0，得到 %v", parsed["code"])
		}
		data, _ := parsed["data"].(map[string]any)
		if data == nil || data["content"] != qrFixtureText {
			t.Fatalf("解出的内容不对: %#v", data)
		}
	})

	t.Run("不带文件字段报 no_file", func(t *testing.T) {
		ct, body := multipartBody(t, "", "", nil)
		resp, parsed := request(t, "POST", srv.base+"/api/qr/decode", ct, string(body))
		if resp.StatusCode != http.StatusBadRequest {
			t.Fatalf("状态码应为 400，得到 %d", resp.StatusCode)
		}
		if got := parsed["error"]; got != "no_file" {
			t.Fatalf("error 应为 no_file，得到 %v", got)
		}
	})

	t.Run("非图片字节报 decode_failed", func(t *testing.T) {
		ct, body := multipartBody(t, "file", "x.jpg", []byte("not an image"))
		resp, parsed := request(t, "POST", srv.base+"/api/qr/decode", ct, string(body))
		if resp.StatusCode != http.StatusBadRequest {
			t.Fatalf("状态码应为 400，得到 %d", resp.StatusCode)
		}
		if got := parsed["error"]; got != "decode_failed" {
			t.Fatalf("error 应为 decode_failed，得到 %v", got)
		}
	})

	t.Run("响应带 no-store 不被缓存", func(t *testing.T) {
		// 这条端点回显的是"用户自己拍到的图里有什么"，一旦被中间代理缓存住，
		// 下一个用户可能拿到上一张图的内容 —— 与扫码轮询同一类问题。
		ct, body := multipartBody(t, "file", "x.jpg", []byte("not an image"))
		resp, _ := request(t, "POST", srv.base+"/api/qr/decode", ct, string(body))
		if got := resp.Header.Get("Cache-Control"); !strings.Contains(got, "no-store") {
			t.Fatalf("Cache-Control 应含 no-store，得到 %q", got)
		}
	})
}
