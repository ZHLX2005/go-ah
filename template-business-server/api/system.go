package api

import (
	"context"
	"net/http"
	"strconv"
	"time"

	"github.com/gogf/gf/v2/frame/g"

	v1 "github.com/ZHLX2005/go-ah/template-business-server/api/v1"
	"github.com/ZHLX2005/go-ah/template-business-server/cryptox"
)

// ============================================================
// 运维接口：存活探测与安全能力自检
//
// 两者都是**裸对象**（没有 code 信封）：给监控和排障用的接口不该要求
// 调用方先理解业务信封。
// ============================================================

// Health 存活探测
func (c *Controller) Health(ctx context.Context) error {
	r := g.RequestFromCtx(ctx)
	writeJSON(r, http.StatusOK, &v1.HealthRes{
		Status:  "ok",
		Service: "template-business-server",
	})
	return nil
}

// SecurityStatus 暴露加密与续期能力状态（不泄漏密钥）
//
// 存在的意义是让"落库无明文 + 自动续期"这两件事可被外部验证：
// ready=false 说明 BIZ_TOKEN_SECRET 没配好，此时服务本不该起来；
// 真起来了（比如被人跳过了校验），这里也能看出来。
func (c *Controller) SecurityStatus(ctx context.Context) error {
	r := g.RequestFromCtx(ctx)
	writeJSON(r, http.StatusOK, &v1.SecurityStatusRes{
		TokenEncryption: v1.TokenEncryption{
			Algorithm:  "AES-256-GCM",
			KDF:        "PBKDF2-HMAC-SHA256",
			Iterations: cryptox.PBKDF2Iterations,
			KeySource:  "env:" + cryptox.EnvSecret,
			Ready:      CryptoReady(),
		},
		AutoRefresh: v1.AutoRefresh{
			Enabled:        true,
			AccessTokenTTL: humanDuration(AccessTokenTTL),
			RefreshTTL:     humanDuration(RefreshTokenTTL),
			Threshold:      humanDuration(RefreshThreshold),
		},
	})
	return nil
}

// humanDuration 把 TTL 常量渲染成响应里的字样（"10m"、"168h"）。
//
// 不用 time.Duration.String()：它会给出 "10m0s"、"168h0m0s"、"2m0s"，
// 与迁移前下发的 "10m"、"168h"、"2m" 不一致 —— 这三个值是响应契约的一部分，
// 由常量推导是为了改常量时不会漏改，而不是为了换个格式。
func humanDuration(d time.Duration) string {
	switch {
	case d%time.Hour == 0:
		return strconv.Itoa(int(d/time.Hour)) + "h"
	case d%time.Minute == 0:
		return strconv.Itoa(int(d/time.Minute)) + "m"
	default:
		return d.String()
	}
}
