// Package qr 的二维码图片解码测试。
//
// 这一层测的是**纯解码能力**（不依赖 HTTP、不依赖数据库）：
// 什么字节算图片、什么算二维码、超限时怎么报错。
// HTTP 层的契约（状态码、信封、字段名）由 internal/router 的测试负责。
package qr

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/ZHLX2005/go-ah/auth-hub/internal/consts"
)

// fixtureQRText 是 testdata/qr_login.png 里那张码的内容。
//
// 固定成一句话而不是随手生成：断言里直接写死它，改图就必然改断言，
// 不会出现"图换了、期望值没换"这种静默失配。
const fixtureQRText = "http://127.0.0.1:8988/login?ticket=fixture_ticket_0001"

// fixturePNG 读测试用的二维码图。
//
// 图是用 segno（纯 Python QR 编码器）离线生成的，来源见
// .tool/qr-decode-probe（工具隔离目录，不入库）。
func fixturePNG(t *testing.T) []byte {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("testdata", "qr_login.png"))
	if err != nil {
		t.Fatalf("读测试用二维码图失败: %v", err)
	}
	return data
}

func TestDecodeImageReadsQRContent(t *testing.T) {
	got, err := DecodeImage(fixturePNG(t))
	if err != nil {
		t.Fatalf("解码应成功: %v", err)
	}
	if got != fixtureQRText {
		t.Fatalf("解出的内容不对:\n  得到 %q\n  期望 %q", got, fixtureQRText)
	}
}

func TestDecodeImageRejectsNonImage(t *testing.T) {
	// 传一段不是图片的字节：不是"图里没有码"，而是"这压根不是图"。
	// 两者必须分开报 —— 前者是用户没拍到码，后者是用户传错了文件。
	for _, tc := range []struct {
		name string
		data []byte
	}{
		{"空内容", nil},
		{"非图片字节", []byte("this is definitely not an image")},
		{"只有 PNG 魔数", []byte{0x89, 'P', 'N', 'G'}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := DecodeImage(tc.data)
			if !errors.Is(err, ErrBadImage) {
				t.Fatalf("应报 ErrBadImage，得到 %v", err)
			}
		})
	}
}

func TestDecodeImageReportsNoQRCode(t *testing.T) {
	// 一张合法 PNG，但里面没有二维码。
	// 这张 1x1 的 PNG 是 PNG 规范里最小的合法图，足够让 image.Decode 通过。
	png := []byte{
		0x89, 'P', 'N', 'G', 0x0d, 0x0a, 0x1a, 0x0a,
		0x00, 0x00, 0x00, 0x0d, 'I', 'H', 'D', 'R',
		0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01,
		0x08, 0x02, 0x00, 0x00, 0x00, 0x90, 0x77, 0x53,
		0xde, 0x00, 0x00, 0x00, 0x0c, 'I', 'D', 'A', 'T',
		0x08, 0xd7, 0x63, 0xf8, 0xcf, 0xc0, 0x00, 0x00,
		0x03, 0x01, 0x01, 0x00, 0x18, 0xdd, 0x8d, 0xb0,
		0x00, 0x00, 0x00, 0x00, 'I', 'E', 'N', 'D',
		0xae, 0x42, 0x60, 0x82,
	}
	_, err := DecodeImage(png)
	if !errors.Is(err, ErrNoQRCode) {
		t.Fatalf("应报 ErrNoQRCode，得到 %v", err)
	}
}

func TestDecodeImageFromEnforcesSizeLimit(t *testing.T) {
	// 超限时必须报 ErrImageTooLarge，**不能**先把整个文件读进内存再判断。
	// 图片解码是内存密集操作：先读后判等于"用超大文件把内存撑爆"，
	// 那正是限长要防的事。
	oversize := bytes.Repeat([]byte{0x00}, MaxDecodeImageBytes+1)
	_, err := DecodeImageFrom(bytes.NewReader(oversize), MaxDecodeImageBytes)
	if !errors.Is(err, ErrImageTooLarge) {
		t.Fatalf("应报 ErrImageTooLarge，得到 %v", err)
	}

	// 恰好等于上限不该报"太大"（虽然它也不是图，但错误类型必须是解码失败）。
	exact := bytes.Repeat([]byte{0x00}, MaxDecodeImageBytes)
	_, err = DecodeImageFrom(bytes.NewReader(exact), MaxDecodeImageBytes)
	if errors.Is(err, ErrImageTooLarge) {
		t.Fatalf("等于上限时不应报 ErrImageTooLarge")
	}
}

// TestTransportLimitExceedsImageLimit 守一条不变式：
// **传输层的 body 上限必须大于端点自己的图片上限。**
//
// 这条不变式被破坏时的症状极其难查：超大请求在传输层被掐断，连接直接
// 断开，客户端看到的是"网络错误"，端点写好的"图片太大，请重拍"永远
// 送不出去；而且只有用户真的拍了一张超大照片才会触发，测试环境里几乎
// 碰不到。所以把它写成一条断言。
func TestTransportLimitExceedsImageLimit(t *testing.T) {
	if consts.MaxRequestBodyBytes <= MaxDecodeImageBytes {
		t.Fatalf("传输层上限 %d 必须大于图片上限 %d，否则超大图片会在传输层被掐断",
			consts.MaxRequestBodyBytes, MaxDecodeImageBytes)
	}
}

// TestDecodeImageReadsQRFromHardPhoto 真实拍照级退化图必须能解出。
//
// 这张夹具（testdata/qr_photo_hard.jpg）离线生成，模拟手机拍屏幕登录页的
// 完整退化链：码只占画面 3.4%（整页 + 屏幕边框）+ 摩尔纹 + 反光斑压在
// 码上 + 轻透视 + 旋转 + 失焦模糊 + 低对比 + 噪点 + JPEG 伪影。goqr 时代它解不出（线上真实症状
// "图片里没有识别到二维码"），换 gozxing + 多尺度重试后必须稳定解出——
// 断言的就是这次修复本身，删掉这个用例等于删掉回归防线。
func TestDecodeImageReadsQRFromHardPhoto(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("testdata", "qr_photo_hard.jpg"))
	if err != nil {
		t.Fatalf("读拍照风格夹具失败: %v", err)
	}
	got, err := DecodeImage(data)
	if err != nil {
		t.Fatalf("拍照风格图应能解出: %v", err)
	}
	const want = "http://47.110.80.47:8082/scan?ticket=qrt_3kF9mQ2xVb8sLd7NpR4tWuYz1aE6hG0jC5iXoK2vBnM"
	if got != want {
		t.Fatalf("解出的内容不对:\n  得到 %q\n  期望 %q", got, want)
	}
}
