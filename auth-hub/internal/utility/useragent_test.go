package utility

import "testing"

// SummarizeUserAgent 的输出是手机确认页上用户唯一能核对的信息，
// 所以它不是"美化"，是安全相关代码。下面两条各锁住一类真实回归。
func TestSummarizeUserAgent(t *testing.T) {
	cases := []struct {
		name string
		ua   string
		want string
	}{
		// 判定顺序：Edge / Opera 的 UA 里都含 "Chrome/"，若先匹 Chrome，
		// 用户会看到"Chrome"而实际是 Edge —— 核对信息说谎。
		{"Edge 不能被认成 Chrome",
			"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36 Edg/141.0.0.0",
			"Edge · Windows"},
		{"Opera 不能被认成 Chrome",
			"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120.0.0.0 Safari/537.36 OPR/106.0.0.0",
			"Opera · Windows"},
		{"真 Chrome",
			"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36",
			"Chrome · Windows"},
		{"微信内置浏览器优先于 Chrome",
			"Mozilla/5.0 (Linux; Android 13) MicroMessenger/8.0.40 Chrome/107",
			"微信内置浏览器 · Android"},
		// 命令行/SDK 必须单独成类：用户在手机上看到"命令行工具"时几乎一定会警觉，
		// 而这正是我们想要的反应。把它们显示成"未知浏览器"则完全丢失这个信号。
		{"Flutter/Dart 客户端", "Dart/3.5 (dart:io)", "命令行工具 · 未知系统"},
		{"Android 原生栈", "okhttp/4.12.0", "命令行工具 · 未知系统"},
		{"Go 客户端", "Go-http-client/2.0", "命令行工具 · 未知系统"},
		{"空 UA 不能返回空串", "", "未知设备"},
		{"认不出的 UA：保留结构但不回显原文", "SomeBot/9.9 weird", "未知浏览器 · 未知系统"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := SummarizeUserAgent(c.ua); got != c.want {
				t.Errorf("SummarizeUserAgent(%q) = %q, 期望 %q", c.ua, got, c.want)
			}
		})
	}
}

// 认不出来时必须返回一个**短**的可读标签，而不是把 200 字符的原始 UA 塞进
// VARCHAR(255) 并显示到手机上 —— 那等于没给，而且会撑坏确认页布局。
func TestSummarizeUserAgent_NeverEchoesRawUA(t *testing.T) {
	long := "Mozilla/5.0 (" + string(make([]byte, 300)) + ") WeirdBrowser/1.0"
	got := SummarizeUserAgent(long)
	if len([]rune(got)) > 40 {
		t.Errorf("未知 UA 的返回值过长（%d 字符），疑似回显了原始串：%q", len([]rune(got)), got)
	}
}

func TestClassifyIP(t *testing.T) {
	cases := map[string]string{
		"127.0.0.1":    "本机",
		"::1":          "本机",
		"127.0.0.53":   "本机",
		"10.1.2.3":     "内网",
		"192.168.31.9": "内网",
		"172.16.0.1":   "内网",
		"172.32.0.1":   "公网", // 172.16/12 才是私网，172.32 不是
		"8.8.8.8":      "公网",
		"169.254.1.1":  "内网",
		"fe80::1":      "内网",
		"":             "未知来源",
		"  10.0.0.1  ": "内网", // 两侧空格要 trim，否则分类全落到"未知来源"
	}
	for ip, want := range cases {
		if got := ClassifyIP(ip); got != want {
			t.Errorf("ClassifyIP(%q) = %q, 期望 %q", ip, got, want)
		}
	}
}
