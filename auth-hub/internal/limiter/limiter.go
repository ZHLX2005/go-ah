// Package limiter 是一个进程内的参数令牌桶。
//
// 为什么自己写而不引 x/time/rate：本仓库刻意不引入分布式状态
// （README §14 把"分布式会话/集群"列为非目标），限流因此也只该是进程内的
// 一层廉价防护。为这么点语义拉一个新依赖不划算，而这个实现本身就 <100 行。
//
// ── 它能挡什么、挡不住什么，必须说清楚 ──────────────────────────────────
//
// 能挡：单个来源（一个 IP、一个账号）写脚本无脑刷匿名可写端点，
// 把 qr_login_sessions 撑爆、或把认证中心打成自己的 DDoS 目标。
//
// 挡不住：分布式来源（肉鸡池）、以及伪造 X-Forwarded-For。
// 后者取决于取 IP 的方式，见 middleware/controller 里的说明。
//
// 所以这一层的定位是"把滥用从免费变成有成本"，不是"抗 DDoS"。
// 把它当成后者来看待，会得出"上了限流就安全了"的错误结论。
package limiter

import (
	"sync"
	"time"
)

// Spec 描述一种令牌桶的速率。
type Spec struct {
	// Capacity 桶容量，即允许的瞬间突发量。
	//
	// 给突发留余量是为了不惩罚正常行为：一次页面加载可能连着建两张码
	// （用户点了刷新），固定窗口计数会把这种"一秒内两次"直接判成超限。
	Capacity float64

	// PerMinute 每分钟回补的令牌数，即长期平均速率上限。
	PerMinute float64
}

// idleEvictAfter 空闲超过这个时长的桶会被回收。
//
// 键是 IP 或用户 ID，攻击者可以不断制造新键 —— 不回收就是
// "用一个限制器换来一个更容易打的内存泄漏"，那就本末倒置了。
const idleEvictAfter = 10 * time.Minute

// evictThreshold 条目数超过它才触发一次清扫。
//
// 只有"新建键"这一条路径会让 map 增长，所以清扫挂在它身上：
// 于是内存天然有界（约 evictThreshold 个活跃键），**不需要**任何外部定时任务
// 来驱动回收。这一点值得写明 —— 曾打算把回收搭进 cmd 的 janitor，
// 但那会让装配层反向 import 持有 limiter 的控制器层，为一个已经自洽的
// 机制付出不该有的依赖代价。
const evictThreshold = 1024

type bucket struct {
	tokens float64
	last   time.Time
}

// Limiter 一个速率下的独立计数器集合。
//
// 不同用途要各建一个实例（建票与批准登录的合理频率差一个量级），
// 共用一个桶会让高频的那类把低频的那类挤到不可用。
type Limiter struct {
	spec Spec

	mu      sync.Mutex
	buckets map[string]*bucket

	// clock 让测试可以注入时间。生产恒为 time.Now。
	// 不是为了"可测性"这个抽象理由：令牌桶的正确性全在时间算术上，
	// 而用真实时钟测它，意味着要么 sleep 几十秒、要么测一个根本不确定的东西。
	clock func() time.Time
}

// New 创建一个限流器。
func New(spec Spec) *Limiter {
	return &Limiter{
		spec:    spec,
		buckets: make(map[string]*bucket),
		clock:   time.Now,
	}
}

// Allow 判断 key 这次是否放行，并消耗一枚令牌。
func (l *Limiter) Allow(key string) bool {
	return l.AllowAt(key, l.clock())
}

// AllowAt 是 Allow 的可注入时钟版本，供测试使用。
func (l *Limiter) AllowAt(key string, now time.Time) bool {
	l.mu.Lock()
	defer l.mu.Unlock()

	b := l.buckets[key]
	if b == nil {
		// 新键从满桶起算：第一次访问不该被惩罚。
		b = &bucket{tokens: l.spec.Capacity, last: now}
		l.buckets[key] = b
		// 只有"新建键"这条路径会增长 map，所以清扫挂在这里，
		// 而不是每次 Allow 都查一遍长度。
		l.maybeEvictLocked(now)
	}

	// 回补。用浮点累加而不是"攒够 60 秒补一轮"：后者会让速率在窗口边界
	// 呈现锯齿，攻击者可以贴着补给的瞬间集中发难。
	if elapsed := now.Sub(b.last); elapsed > 0 {
		b.tokens += elapsed.Minutes() * l.spec.PerMinute
		if b.tokens > l.spec.Capacity {
			b.tokens = l.spec.Capacity
		}
		b.last = now
	}

	if b.tokens < 1 {
		return false
	}
	b.tokens--
	return true
}

// RetryAfter 建议客户端隔多久再试（秒）。桶空时给出"补够一枚令牌"的时间。
//
// 只用于响应头，不参与判定 —— 判定唯一依赖的是 Allow。
func (l *Limiter) RetryAfter(key string) int {
	l.mu.Lock()
	defer l.mu.Unlock()

	b := l.buckets[key]
	if b == nil || b.tokens >= 1 {
		return 1
	}
	// 补一枚需要的秒数 = 1 / (每秒补给速率)
	perSec := l.spec.PerMinute / 60
	if perSec <= 0 {
		return 60
	}
	secs := int(1 / perSec)
	if secs < 1 {
		secs = 1
	}
	return secs
}

// Evict 回收长期空闲的桶。由调用方的周期任务带动（见 cmd 的 janitor）。
func (l *Limiter) Evict() {
	l.EvictAt(l.clock())
}

// EvictAt 是 Evict 的可注入时钟版本。
func (l *Limiter) EvictAt(now time.Time) {
	l.mu.Lock()
	defer l.mu.Unlock()

	for k, b := range l.buckets {
		if now.Sub(b.last) > idleEvictAfter {
			delete(l.buckets, k)
		}
	}
}

// maybeEvictLocked 在条目数越界时顺手清扫。调用方必须已持有 l.mu。
func (l *Limiter) maybeEvictLocked(now time.Time) {
	if len(l.buckets) <= evictThreshold {
		return
	}
	for k, b := range l.buckets {
		if now.Sub(b.last) > idleEvictAfter {
			delete(l.buckets, k)
		}
	}
}

// Count 返回当前桶数，仅用于测试与观测。
func (l *Limiter) Count() int {
	l.mu.Lock()
	defer l.mu.Unlock()
	return len(l.buckets)
}
