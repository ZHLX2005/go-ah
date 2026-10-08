package internal

import (
	"context"
	"log"
	"sync"
	"time"
)

// ============================================================
// 后台自动续期协程（Task4）
//
// 规则：
//   - access_token 有效期 10 分钟，refresh_token 7 天
//   - 距离 access_token 过期 < 2 分钟 -> 自动用 refresh_token 续期
//   - 续期成功：更新本地加密存储
//   - 续期失败（被吊销/过期）：清空本地会话，触发登出回调
//
// 生命周期：login 成功后启动，随进程退出而结束
// ============================================================

// Refresher 后台续期器
type Refresher struct {
	client *OIDCClient
	store  *TokenStore

	mu      sync.Mutex
	current *TokenSet
	stopped bool
	stopCh  chan struct{}

	// OnRefreshed 续期成功回调（可选）
	OnRefreshed func(ts *TokenSet)
	// OnLogout 续期失败触发的登出回调（可选）
	OnLogout func(reason error)
}

// NewRefresher 创建续期器
func NewRefresher(client *OIDCClient, store *TokenStore, initial *TokenSet) *Refresher {
	return &Refresher{
		client:  client,
		store:   store,
		current: initial,
		stopCh:  make(chan struct{}),
	}
}

// Current 返回当前令牌集合的副本引用（调用方只读）
func (r *Refresher) Current() *TokenSet {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.current
}

// Update 外部更新令牌（例如手动刷新后）
func (r *Refresher) Update(ts *TokenSet) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.current = ts
}

// Start 启动后台续期协程
// interval 为检查间隔，建议 30 秒；<=0 时默认 30 秒
func (r *Refresher) Start(interval time.Duration) {
	if interval <= 0 {
		interval = 30 * time.Second
	}
	go r.loop(interval)
}

// Stop 停止续期协程
func (r *Refresher) Stop() {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.stopped {
		return
	}
	r.stopped = true
	close(r.stopCh)
}

// loop 周期性检查并在需要时续期
func (r *Refresher) loop(interval time.Duration) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	// 启动时先立即检查一次
	r.tick()

	for {
		select {
		case <-r.stopCh:
			return
		case <-ticker.C:
			r.tick()
		}
	}
}

// tick 单次检查与续期
func (r *Refresher) tick() {
	r.mu.Lock()
	ts := r.current
	r.mu.Unlock()

	if ts == nil || ts.RefreshToken == "" {
		return
	}
	if !ts.ShouldRefresh() {
		return
	}

	remaining := time.Until(ts.ExpiresAt).Round(time.Second)
	log.Printf("[续期] access_token 剩余 %s（< %s），开始自动续期…", remaining, RefreshThreshold)

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	resp, err := r.client.Refresh(ctx, ts.RefreshToken)
	if err != nil {
		log.Printf("[续期] 失败：%v", err)
		// refresh_token 失效 -> 清空本地会话
		_ = r.store.Delete()
		r.mu.Lock()
		r.current = nil
		r.mu.Unlock()
		if r.OnLogout != nil {
			r.OnLogout(err)
		}
		r.Stop()
		return
	}

	// 更新令牌集合
	r.mu.Lock()
	cur := r.current
	r.mu.Unlock()

	updated := &TokenSet{
		AccessToken:  resp.AccessToken,
		IDToken:      resp.IDToken,
		RefreshToken: resp.RefreshToken,
		TokenType:    resp.TokenType,
		Scope:        resp.Scope,
		ExpiresAt:    time.Now().Add(AccessTokenTTL),
		Issuer:       cur.Issuer,
		ClientID:     cur.ClientID,
		Subject:      cur.Subject,
		Username:     cur.Username,
	}
	// 刷新响应可能不返回 expires_in，统一按 AccessTokenTTL 计算
	if resp.ExpiresIn > 0 {
		updated.ExpiresAt = time.Now().Add(time.Duration(resp.ExpiresIn) * time.Second)
	}
	// 保留原 refresh_token 有效期（IDP 未滚动则沿用）
	updated.RefreshExpiresAt = cur.RefreshExpiresAt
	if resp.RefreshToken == "" {
		updated.RefreshToken = cur.RefreshToken
	}

	if err := r.store.Save(updated); err != nil {
		log.Printf("[续期] 保存加密 token 失败：%v", err)
	}

	r.mu.Lock()
	r.current = updated
	r.mu.Unlock()

	log.Printf("[续期] 成功，新的 access_token 过期时间 %s", updated.ExpiresAt.Format("15:04:05"))
	if r.OnRefreshed != nil {
		r.OnRefreshed(updated)
	}
}
