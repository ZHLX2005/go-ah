// 本文件负责把"被登录的那台机器"的信息压缩成人能看懂的一句话。
//
// 为什么这件事值得单独一个文件，而且是安全相关而不是显示相关：
// 扫码登录唯一防住"二维码转发攻击"的手段，就是让用户在手机屏幕上认出
// "这张二维码是不是我电脑上弹出来的"。给他看原始 User-Agent
// （Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 …）
// 等于没给 —— 没有人在手机上能核对这么一串。所以这不是美化输出，
// 是整个功能里唯一那道人类可校验的关卡，解析质量直接等于安全强度。
//
// 也因此有一条硬约束：**这些信息由服务端从请求头解析，绝不采信客户端自报**。
// 若让 PC 前端自己传"我是 Windows Chrome"，攻击者就能构造一张谎报成
// "macOS · Safari"的二维码，而用户对着谎言核对，防转发机制当场失效。

package utility

import "strings"

// SummarizeUserAgent 把原始 UA 压成 "浏览器 · 操作系统"。
//
// 认不出来时返回 "未知设备"（而不是返回原始串）：把 200 字符的 UA 塞进
// VARCHAR(255) 并显示到手机上，既不美观也让用户无从核对，
// 何况"认不出来"本身就是该暴露给用户的信号。
func SummarizeUserAgent(ua string) string {
	ua = strings.TrimSpace(ua)
	if ua == "" {
		return "未知设备"
	}

	// 浏览器判定顺序有意把 Edge/OPR 放在 Chrome 之前：
	// 两者的 UA 里都含 "Chrome/"，先匹 Chrome 会把 Edge 一律显示成 Chrome。
	// 同理 Edg/ 有 Chromium 版（Edg/）与 EdgeHTML 版（Edge/）两种拼法。
	browser := "未知浏览器"
	switch {
	case strings.Contains(ua, "MicroMessenger"):
		browser = "微信内置浏览器"
	case strings.Contains(ua, "DingTalk"):
		browser = "钉钉"
	case strings.Contains(ua, "Edg/"), strings.Contains(ua, "Edge/"):
		browser = "Edge"
	case strings.Contains(ua, "OPR/"), strings.Contains(ua, "Opera"):
		browser = "Opera"
	case strings.Contains(ua, "Firefox/"):
		browser = "Firefox"
	case strings.Contains(ua, "Safari/") && strings.Contains(ua, "Version/"):
		browser = "Safari"
	case strings.Contains(ua, "Chrome/"), strings.Contains(ua, "CriOS/"):
		browser = "Chrome"
	case strings.Contains(ua, "curl/"), strings.Contains(ua, "python-requests"),
		strings.Contains(ua, "Go-http-client"), strings.Contains(ua, "HTTPie"):
		// 命令行客户端伪装成浏览器的情况不少，单独标出来：
		// 用户在手机上看到"命令行工具"时几乎一定会警觉，这正是我们要的。
		browser = "命令行工具"
	}

	os := "未知系统"
	switch {
	case strings.Contains(ua, "iPhone"):
		os = "iOS"
	case strings.Contains(ua, "iPad"):
		os = "iPadOS"
	case strings.Contains(ua, "Android"):
		os = "Android"
	case strings.Contains(ua, "Windows NT 10.0"):
		// Windows 11 的 UA 仍写 Windows NT 10.0（兼容性伪装），
		// 单靠 UA 分不开 10 与 11。这里不猜：显示成 Windows，
		// 让用户核对"是不是我那台 Windows 机器"就够了。
		os = "Windows"
	case strings.Contains(ua, "Mac OS X"), strings.Contains(ua, "Macintosh"):
		os = "macOS"
	case strings.Contains(ua, "Linux"):
		os = "Linux"
	}

	return browser + " · " + os
}

// ClassifyIP 给 IP 一个粗分类标注（本机 / 内网 / 公网 / 未知）。
//
// 只做到"分类"而不做"归属地"，是有意的取舍：归属地要带一份 IP 库
// （几 MB 到几十 MB）或在请求路径上打一次外部查询 —— 前者给认证中心
// 添了个体积不小的二进制依赖，后者会在登录链路上引入外部服务超时，
// 两个代价都比"少显示一个城市"大。用户核对设备靠的是"浏览器 · 系统 + IP"，
// 归属地列为设计文档 §12 的 P2 增强。
//
// 但内网与公网必须分开标：把 127.0.0.1 显示成一个普通 IP，
// 用户没法意识到"这只是一台开发机"。
func ClassifyIP(ip string) string {
	ip = strings.TrimSpace(ip)
	if ip == "" {
		return "未知来源"
	}
	switch {
	case ip == "127.0.0.1", ip == "::1", strings.HasPrefix(ip, "127."):
		return "本机"
	case strings.HasPrefix(ip, "10."), strings.HasPrefix(ip, "192.168."),
		strings.HasPrefix(ip, "172.16."), strings.HasPrefix(ip, "172.17."),
		strings.HasPrefix(ip, "172.18."), strings.HasPrefix(ip, "172.19."),
		strings.HasPrefix(ip, "172.2"), strings.HasPrefix(ip, "169.254."),
		strings.HasPrefix(ip, "fc"), strings.HasPrefix(ip, "fd"),
		strings.HasPrefix(ip, "fe80"):
		return "内网"
	default:
		return "公网"
	}
}
