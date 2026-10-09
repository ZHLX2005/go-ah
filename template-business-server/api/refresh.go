package api

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/gogf/gf/v2/frame/g"

	v1 "github.com/ZHLX2005/go-ah/template-business-server/api/v1"
	"github.com/ZHLX2005/go-ah/template-business-server/db"
)

// ============================================================
// IDP 令牌刷新调用（业务侧唯一的对外调用）
// ============================================================

type refreshedTokens struct {
	IDToken      string
	AccessToken  string
	RefreshToken string
}

// refreshIDToken 直接调用 IDP /oauth2/token (grant_type=refresh_token)
//
// 不用 oauth2.Config.TokenSource：那套会自动缓存并"续"出过期时间，
// 而这里需要的是"这一次到底换了什么回来"，好决定业务会话怎么更新。
func refreshIDToken(refreshToken string) (*refreshedTokens, error) {
	form := url.Values{}
	form.Set("grant_type", "refresh_token")
	form.Set("refresh_token", refreshToken)
	form.Set("client_id", ClientID)

	req, err := http.NewRequest("POST",
		strings.TrimSuffix(IDPIssuer, "/")+"/oauth2/token",
		strings.NewReader(form.Encode()))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	// 带上超时：IDP 挂住时不能让后台巡检协程一直卡在这一步
	resp, err := (&http.Client{Timeout: 10 * time.Second}).Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("IDP 返回 %d: %s", resp.StatusCode, string(body))
	}
	var out struct {
		IDToken      string `json:"id_token"`
		AccessToken  string `json:"access_token"`
		RefreshToken string `json:"refresh_token"`
	}
	if err := json.Unmarshal(body, &out); err != nil {
		return nil, err
	}
	return &refreshedTokens{out.IDToken, out.AccessToken, out.RefreshToken}, nil
}

// ============================================================
// 接口 6：POST /api/refresh —— 主动续期
//
// 与后台自动续期共用 refreshIDToken，但这里要的是"用户点一下立刻生效"，
// 所以同步执行并把新的过期时间回给前端。
// ============================================================

// Refresh 用 refresh_token 换新的 id_token / access_token
func (c *Controller) Refresh(ctx context.Context) error {
	r := g.RequestFromCtx(ctx)

	sess, err := currentSession(ctx)
	if err != nil {
		writeError(r, http.StatusInternalServerError, "db_error", err.Error())
		return nil
	}
	if sess == nil {
		writeError(r, http.StatusUnauthorized, "unauthorized", "")
		return nil
	}

	// refresh_token 为密文存储，续期前先解密
	tokens, err := ReadTokens(sess)
	if err != nil {
		writeError(r, http.StatusInternalServerError, "token_decrypt_failed", err.Error())
		return nil
	}
	if tokens.RefreshToken == "" {
		writeError(r, http.StatusBadRequest, "no_refresh_token", "")
		return nil
	}

	tok, err := refreshIDToken(tokens.RefreshToken)
	if err != nil {
		writeError(r, http.StatusBadRequest, "refresh_failed", err.Error())
		return nil
	}

	sess.IDToken = tok.IDToken
	sess.AccessToken = tok.AccessToken
	if tok.RefreshToken != "" {
		sess.RefreshToken = tok.RefreshToken
	}
	now := time.Now()
	sess.AccessTokenExpiresAt = now.Add(AccessTokenTTL)
	sess.ExpiresAt = now.Add(SessionLifetime) // 滑动续期

	// 加密回写
	if err := saveSession(ctx, sess); err != nil {
		writeError(r, http.StatusInternalServerError, "session_save_failed", err.Error())
		return nil
	}

	writeJSON(r, http.StatusOK, &v1.RefreshRes{
		Code:                 0,
		Message:              "token 刷新成功",
		AccessTokenExpiresAt: sess.AccessTokenExpiresAt,
	})
	return nil
}

// ============================================================
// 业务侧后台自动续期
//
// 与 CLI 的持续驻留模型不同，业务服务是常驻进程、会话数量不定，
// 因此采用"单例巡检协程 + 会话级判定"：
//
//   - 进程启动时拉起一个 ticker（默认 30s）；
//   - 每轮扫描所有未过期业务会话；
//   - 命中 shouldRefresh() 的会话（access_token < 2min 到期）执行续期；
//   - 续期成功：加密回写新的 access/id token，延长会话；
//   - 续期失败（refresh_token 被吊销/过期）：删除该业务会话，
//     前端下一次请求 /api/profile 即得到 401，自然回到登录页。
//
// 之所以不是"每个会话一个 goroutine"，是因为会话数量随用户增长，
// 逐会话协程会带来不可控的协程数量；巡检方式的成本只与轮询间隔相关。
// ============================================================

// Refresher 后台续期器
type Refresher struct {
	interval time.Duration

	mu      sync.Mutex
	started bool
	stopCh  chan struct{}
	wg      sync.WaitGroup

	// OnSessionRevoked 续期失败导致会话被销毁时的回调（可选，便于测试与审计）
	OnSessionRevoked func(sessionID, userSub string, reason error)

	// stats 便于测试与可观测性
	checks    int64
	refreshed int64
	revoked   int64
}

// NewRefresher 创建续期器，interval <= 0 时默认 30 秒
func NewRefresher(interval time.Duration) *Refresher {
	if interval <= 0 {
		interval = 30 * time.Second
	}
	return &Refresher{interval: interval, stopCh: make(chan struct{})}
}

// Start 启动巡检协程（幂等）
func (r *Refresher) Start(ctx context.Context) {
	r.mu.Lock()
	if r.started {
		r.mu.Unlock()
		return
	}
	r.started = true
	r.mu.Unlock()

	r.wg.Add(1)
	go r.loop(ctx)
	log.Printf("[BIZ][续期] 后台自动续期已启动，检查间隔 %s（续期阈值 %s）", r.interval, RefreshThreshold)
}

// Stop 停止巡检协程
func (r *Refresher) Stop() {
	r.mu.Lock()
	defer r.mu.Unlock()
	if !r.started {
		return
	}
	r.started = false
	close(r.stopCh)
	r.wg.Wait()
	log.Printf("[BIZ][续期] 后台自动续期已停止")
}

func (r *Refresher) loop(ctx context.Context) {
	defer r.wg.Done()
	ticker := time.NewTicker(r.interval)
	defer ticker.Stop()

	// 启动后先等一个周期，避免与应用启动期争抢资源
	for {
		select {
		case <-r.stopCh:
			return
		case <-ticker.C:
			r.sweep(ctx)
		}
	}
}

// sweep 扫描并续期一轮；返回本轮续期的会话数（供测试直接调用）
func (r *Refresher) sweep(ctx context.Context) int {
	now := time.Now()

	// 先清理已整体过期的业务会话，避免无限增长
	if _, err := db.DeleteExpiredSessions(ctx, now); err != nil {
		log.Printf("[BIZ][续期] 清理过期会话失败: %v", err)
	}

	sessions, err := db.ActiveSessions(ctx, now)
	if err != nil {
		log.Printf("[BIZ][续期] 查询会话失败: %v", err)
		return 0
	}

	r.mu.Lock()
	r.checks++
	r.mu.Unlock()

	count := 0
	for i := range sessions {
		if !shouldRefresh(&sessions[i]) {
			continue
		}
		if r.refreshOne(ctx, &sessions[i]) {
			count++
		}
	}
	return count
}

// refreshOne 续期单个会话，返回是否成功
func (r *Refresher) refreshOne(ctx context.Context, sess *db.BusinessSession) bool {
	tokens, err := ReadTokens(sess)
	if err != nil {
		// 解密失败通常意味着密钥被更换过，此时无法恢复会话
		log.Printf("[BIZ][续期] 会话 %s 解密失败，销毁该会话: %v", sess.SessionID, err)
		r.revoke(ctx, sess, err)
		return false
	}
	if tokens.RefreshToken == "" {
		return false
	}

	remaining := time.Until(sess.AccessTokenExpiresAt).Round(time.Second)
	log.Printf("[BIZ][续期] 会话 %s (sub=%s) access_token 剩余 %s，开始续期…",
		sess.SessionID, sess.UserSub, remaining)

	tok, err := refreshIDToken(tokens.RefreshToken)
	if err != nil {
		log.Printf("[BIZ][续期] 会话 %s 续期失败，销毁该会话: %v", sess.SessionID, err)
		r.revoke(ctx, sess, err)
		return false
	}

	// 更新 token（IDP 的刷新响应可能不带 refresh_token，此时沿用旧的）
	sess.AccessToken = tok.AccessToken
	if tok.IDToken != "" {
		sess.IDToken = tok.IDToken
	}
	if tok.RefreshToken != "" {
		sess.RefreshToken = tok.RefreshToken
	}
	sess.AccessTokenExpiresAt = time.Now().Add(AccessTokenTTL)
	sess.ExpiresAt = time.Now().Add(SessionLifetime) // 滑动续期

	if err := saveSession(ctx, sess); err != nil {
		log.Printf("[BIZ][续期] 会话 %s 回写失败: %v", sess.SessionID, err)
		return false
	}

	r.mu.Lock()
	r.refreshed++
	r.mu.Unlock()

	log.Printf("[BIZ][续期] 会话 %s 续期成功，新的 access_token 过期时间 %s",
		sess.SessionID, sess.AccessTokenExpiresAt.Format("15:04:05"))
	return true
}

// revoke 续期失败时销毁会话
func (r *Refresher) revoke(ctx context.Context, sess *db.BusinessSession, reason error) {
	if err := db.DeleteSession(ctx, sess.SessionID); err != nil {
		log.Printf("[BIZ][续期] 销毁会话 %s 失败: %v", sess.SessionID, err)
	}

	r.mu.Lock()
	r.revoked++
	r.mu.Unlock()

	if r.OnSessionRevoked != nil {
		r.OnSessionRevoked(sess.SessionID, sess.UserSub, reason)
	}
}
