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
// ── 为什么是 gozxing（ZXing 移植）而不是更小的 goqr ─────────────────────
//
// goqr 只认"接近理想的图"：渲染出来的二维码、清晰截屏。真实手机拍屏幕
// 带来四种它处理不了的退化——屏幕像素网格与传感器互拍出的摩尔纹、
// 弱光下的低对比、斜拍的透视畸变、失焦模糊。曾用它上线，症状就是
// "用户明明对着码拍，服务端却报图片里没有识别到二维码"。
// gozxing 的 HybridBinarizer 对光照不均有免疫力，配 TRY_HARDER 后
// 对上述四类退化都有战斗力；代价是慢一些，所以配合多尺度重试
// （见 decodeScales）把 CPU 控制在有界范围内。

package qr

import (
	"bytes"
	"errors"
	"image"
	_ "image/jpeg" // 注册 JPEG 解码器
	_ "image/png"  // 注册 PNG 解码器
	"io"

	xdraw "golang.org/x/image/draw"

	gozxing "github.com/makiuchi-d/gozxing"
	"github.com/makiuchi-d/gozxing/qrcode"
)

// ErrNoQRCode 是"图里没有二维码"这一类失败的统一错误。
//
// 单独一个哨兵错误而不是字符串匹配：调用方要据此给用户不同的提示
// （"没拍到码" vs "这张图打不开"），靠字符串匹配迟早会漏。
var ErrNoQRCode = errors.New("图片里没有识别到二维码")

// ErrBadImage 是"这不是一张能解码的图片"。
var ErrBadImage = errors.New("无法解析图片（仅支持 JPEG / PNG）")

// decodeScales 逐个尝试的"最长边"像素序列（从大到小）。
//
// 2400 是给"码只占画面一小块"的照片的：手机拍整屏登录页时，4000px
// 的照片里码可能只有五六百像素，再往下缩码就只剩几个像素的模块，
// 定位无从谈起——所以第一档要贴着原尺度（但有界，防 8000px 大图
// 把 CPU 打满）。1600 是全幅码的舒适区；900 / 500 给"离得远、码在
// 图里占比极小"的照片留——缩小后信噪比反而变好。截图类输入本来就
// ≤1600，第一轮等价于原尺度解码，不会退化。
var decodeScales = []int{2400, 1600, 900, 500}

// maxDecodeSide 解码前先把大图压到这个最长边以内（等比）。
//
// 它必须 ≥ decodeScales 的最大值：等于"先归一化、再多尺度重试"，
// 两套数字耦合着改会造出一个永远跳过的尺度。2400 同时是 CPU 上界：
// HybridBinarizer 的开销与像素数线性相关，2400² 以内的单次解码
// 在限流（10 次/分钟/IP）配合下可控。
const maxDecodeSide = 2400

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
	return recognizeAnyScale(img)
}

// recognizeAnyScale 在归一化后的多个尺度上依次尝试识别，任一命中即返回。
//
// 每次缩放都是等比的（CatmullRom 保平滑，避免缩放本身制造锯齿噪声），失败才试下一个尺度，
// 全部失败统一报 ErrNoQRCode——调用方不关心是哪个尺度没认出来。
func recognizeAnyScale(img image.Image) (string, error) {
	base := fitWithin(img, maxDecodeSide)
	for _, side := range decodeScales {
		if text, err := recognize(fitWithin(base, side)); err == nil && text != "" {
			return text, nil
		}
	}
	return "", ErrNoQRCode
}

// recognize 在单张图上跑一次 gozxing 解码（TRY_HARDER）。
func recognize(img image.Image) (string, error) {
	bm, err := gozxing.NewBinaryBitmapFromImage(img)
	if err != nil {
		return "", err
	}
	hints := map[gozxing.DecodeHintType]interface{}{
		gozxing.DecodeHintType_TRY_HARDER: true,
	}
	res, err := qrcode.NewQRCodeReader().Decode(bm, hints)
	if err != nil {
		return "", err
	}
	return res.GetText(), nil
}

// fitWithin 把图等比缩到"最长边 ≤ side"；已满足时原样返回（零拷贝路径，
// 截图类小图不会为此多分配一次内存）。
func fitWithin(img image.Image, side int) image.Image {
	b := img.Bounds()
	w, h := b.Dx(), b.Dy()
	if w <= side && h <= side {
		return img
	}
	scale := float64(side) / float64(max(w, h))
	nw, nh := max(1, int(float64(w)*scale)), max(1, int(float64(h)*scale))
	dst := image.NewRGBA(image.Rect(0, 0, nw, nh))
	xdraw.CatmullRom.Scale(dst, dst.Bounds(), img, b, xdraw.Over, nil)
	return dst
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
