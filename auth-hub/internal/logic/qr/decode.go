// 二维码图片解码 —— 纯 Go 实现，客户端零原生依赖。
//
// 为什么放在服务端：原生 App 为了读一张"电脑屏幕上的登录码"，
// 得背着 ML Kit 的 libbarhopper_v3.so（4.2MB）+ 0.8MB 的 .tflite 模型。
// 改成"手机拍一张照 → 服务端解码"，客户端那 5MB 整块消失，
// 而拍照本身 image_picker 已经带在项目里，不额外增加原生体积。
//
// 只解 QR（不认其它码制）：这个端点的唯一用途是读"本平台发出的登录码"，
// 认其它码制只会带来"拍到一张别人的商品条码然后报看不懂的错"。
//
// 纯 Go（goqr）→ 不引入 cgo、不引入原生库、不挑平台 —— 后端本来就没有
// 平台限制，客户端要的是"少背几 MB"。

package qr

import (
	"bytes"
	"errors"
	"image"
	_ "image/jpeg" // 注册 JPEG 解码器
	_ "image/png"  // 注册 PNG 解码器
	"io"

	"github.com/liyue201/goqr"
)

// ErrNoQRCode 是"图里没有二维码"这一类失败的统一错误。
//
// 单独一个哨兵错误而不是字符串匹配：调用方要据此给用户不同的提示
// （"没拍到码" vs "这张图打不开"），靠字符串匹配迟早会漏。
var ErrNoQRCode = errors.New("图片里没有识别到二维码")

// ErrBadImage 是"这不是一张能解码的图片"。
var ErrBadImage = errors.New("无法解析图片（仅支持 JPEG / PNG）")

// DecodeImage 从图片字节里识别二维码，返回其中的原始字符串。
//
// 取第一个非空结果：一张图里理论上只应有一个二维码，但拍歪了可能
// 框进两张 —— 取第一个能让用户看到内容，剩下那张由后续的 ticket
// 解析挡掉（解析不出 ticket 会被忽略），比直接报错友好。
func DecodeImage(data []byte) (string, error) {
	if len(data) == 0 {
		return "", ErrBadImage
	}
	img, _, err := image.Decode(bytes.NewReader(data))
	if err != nil {
		return "", ErrBadImage
	}
	codes, err := goqr.Recognize(img)
	if err != nil || len(codes) == 0 {
		return "", ErrNoQRCode
	}
	for _, c := range codes {
		if c == nil || len(c.Payload) == 0 {
			continue
		}
		return string(c.Payload), nil
	}
	return "", ErrNoQRCode
}

// DecodeImageFrom 从流里读上限内的字节再解码。
//
// 为什么要限长：图片解码是**解压炸弹**的经典入口（一张几 MB 的 PNG
// 解码后能占几百 MB 内存）。在读的时候就截断，而不是先全读进来再判断。
func DecodeImageFrom(r io.Reader, maxBytes int64) (string, error) {
	if maxBytes <= 0 {
		maxBytes = MaxDecodeImageBytes
	}
	data, err := io.ReadAll(io.LimitReader(r, maxBytes+1))
	if err != nil {
		return "", ErrBadImage
	}
	if int64(len(data)) > maxBytes {
		return "", ErrImageTooLarge
	}
	return DecodeImage(data)
}

// ErrImageTooLarge 是"图片超过体积上限"。
var ErrImageTooLarge = errors.New("图片太大了")

// MaxDecodeImageBytes 是单张图片的体积上限（8MB）。
//
// 取 8MB 的依据：手机随手拍一张二维码照片（1080p JPEG）约 1–3MB，
// 8MB 给足了余量；而 8MB 以下的图片解码后占用也在可控范围。
//
// 它必须**小于** consts.MaxRequestBodyBytes（传输层的 body 上限）——
// 否则超大请求会先被传输层拦下、连接被直接中断，端点自己的
// ErrImageTooLarge 分支永远走不到（客户端拿到的是"网络错误"而不是
// "图片太大，请重拍"）。这条不变式由 decode_test.go 守着。
const MaxDecodeImageBytes = 8 << 20
