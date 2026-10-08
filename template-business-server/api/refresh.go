package api

import (
	"log"
	"sync"
	"time"

	"github.com/ZHLX2005/go-ah/template-business-server/db"
)

// ============================================================
// 业务侧后台自动续期（Task4）
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
func (r *Refresher) Start() {
	r.mu.Lock()
	if r.started {
		r.mu.Unlock()
		return
	}
	r.started = true
	r.mu.Unlock()

	r.wg.Add(1)
	go r.loop()
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

func (r *Refresher) loop() {
	defer r.wg.Done()
	ticker := time.NewTicker(r.interval)
	defer ticker.Stop()

	// 启动后先等一个周期，避免与应用启动期争抢资源
	for {
		select {
		case <-r.stopCh:
			return
		case <-ticker.C:
			r.sweep()
		}
	}
}

// sweep 扫描并续期一轮；返回本轮续期的会话数（供测试直接调用）
func (r *Refresher) sweep() int {
	now := time.Now()

	// 先清理已整体过期的业务会话，避免无限增长
	db.DB.Where("expires_at < ?", now).Delete(&db.BusinessSession{})

	var sessions []db.BusinessSession
	if err := db.DB.Where("expires_at > ?", now).Find(&sessions).Error; err != nil {
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
		if r.refreshOne(&sessions[i]) {
			count++
		}
	}
	return count
}

// refreshOne 续期单个会话，返回是否成功
func (r *Refresher) refreshOne(sess *db.BusinessSession) bool {
	tokens, err := ReadTokens(sess)
	if err != nil {
		// 解密失败通常意味着密钥被更换过，此时无法恢复会话
		log.Printf("[BIZ][续期] 会话 %s 解密失败，销毁该会话: %v", sess.SessionID, err)
		r.revoke(sess, err)
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
		r.revoke(sess, err)
		return false
	}

	// 更新 token（fe 的刷新响应可能不带 refresh_token，此时沿用旧的）
	sess.AccessToken = tok.AccessToken
	if tok.IDToken != "" {
		sess.IDToken = tok.IDToken
	}
	if tok.RefreshToken != "" {
		sess.RefreshToken = tok.RefreshToken
	}
	sess.AccessTokenExpiresAt = time.Now().Add(AccessTokenTTL)
	sess.ExpiresAt = time.Now().Add(SessionLifetime) // 滑动续期

	if err := saveSession(sess); err != nil {
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
func (r *Refresher) revoke(sess *db.BusinessSession, reason error) {
	db.DB.Where("session_id = ?", sess.SessionID).Delete(&db.BusinessSession{})

	r.mu.Lock()
	r.revoked++
	r.mu.Unlock()

	if r.OnSessionRevoked != nil {
		r.OnSessionRevoked(sess.SessionID, sess.UserSub, reason)
	}
}
