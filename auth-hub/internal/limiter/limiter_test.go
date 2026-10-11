package limiter

import (
	"testing"
	"time"
)

// 令牌桶的正确性全在时间算术上，所以测试一律走 AllowAt 注入时钟。
// 用真实时钟测它，要么 sleep 几十秒、要么测一个本身不确定的东西 ——
// 后者会造出一类"偶尔红"的测试，那种测试比没有测试更消耗人。

func TestBurstThenDeny(t *testing.T) {
	l := New(Spec{Capacity: 3, PerMinute: 60})
	t0 := time.Now()

	for i := 0; i < 3; i++ {
		if !l.AllowAt("k", t0) {
			t.Fatalf("第 %d 次应放行（容量 3 的突发），却被拒", i+1)
		}
	}
	if l.AllowAt("k", t0) {
		t.Fatal("突发用完后仍放行 —— 限流完全没起作用")
	}
}

func TestRefillProportionalToElapsed(t *testing.T) {
	// 容量 5，每分钟补 60 枚 = 每秒 1 枚
	l := New(Spec{Capacity: 5, PerMinute: 60})
	t0 := time.Now()

	for i := 0; i < 5; i++ {
		l.AllowAt("k", t0)
	}
	if l.AllowAt("k", t0) {
		t.Fatal("桶应已空")
	}
	// 过 1 秒恰好补回 1 枚
	if !l.AllowAt("k", t0.Add(time.Second)) {
		t.Fatal("过了 1 秒（应补 1 枚）仍被拒")
	}
	if l.AllowAt("k", t0.Add(time.Second)) {
		t.Fatal("只该补回 1 枚，第二枚不该放行")
	}
	// 过 2.5 秒补 2.5 枚 → 可放行 2 次
	if !l.AllowAt("k", t0.Add(3*time.Second)) || !l.AllowAt("k", t0.Add(3*time.Second)) {
		t.Fatal("累计过 3 秒应可再放行 2 次")
	}
}

// 空闲期间不该攒出超过容量的额度。
//
// 少了这个上限，一个"每分钟 10 次"的桶在闲置一小时后会攒 600 枚，
// 攻击者只要先静默一小时、再瞬间打 600 发，限流就形同虚设。
func TestRefillCappedAtCapacity(t *testing.T) {
	l := New(Spec{Capacity: 4, PerMinute: 10})
	t0 := time.Now()

	for i := 0; i < 4; i++ {
		l.AllowAt("k", t0)
	}
	later := t0.Add(time.Hour)
	allowed := 0
	for i := 0; i < 20; i++ {
		if l.AllowAt("k", later) {
			allowed++
		}
	}
	if allowed != 4 {
		t.Fatalf("闲置一小时后突发量 = %d, 期望恰好等于容量 4（回补必须封顶）", allowed)
	}
}

func TestKeysAreIndependent(t *testing.T) {
	l := New(Spec{Capacity: 1, PerMinute: 1})
	t0 := time.Now()

	if !l.AllowAt("a", t0) {
		t.Fatal("a 首次应放行")
	}
	if l.AllowAt("a", t0) {
		t.Fatal("a 第二次应被拒")
	}
	// b 不该被 a 的消耗拖累 —— 这正是"按 IP / 按账号分键"的全部意义：
	// 一个 NAT 后面的正常用户不该因为邻居在刷而一起被关在外面。
	if !l.AllowAt("b", t0) {
		t.Fatal("不同键之间互相影响，共享出口的正常用户会被误伤")
	}
}

func TestEvictRemovesOnlyIdle(t *testing.T) {
	l := New(Spec{Capacity: 5, PerMinute: 5})
	t0 := time.Now()

	l.AllowAt("stale", t0)
	// active 距清扫点只空闲 5 分钟（< idleEvictAfter 10 分钟），所以该留下；
	// 上一版把这里写成相隔一小时，于是它也成了"空闲"被回收 ——
	// 那是测试的时间线搭错了，不是实现的错。
	l.AllowAt("active", t0.Add(10*time.Minute))

	l.EvictAt(t0.Add(15 * time.Minute))

	if l.Count() != 1 {
		t.Fatalf("剩余桶数 = %d, 期望 1（只该留下活跃键）", l.Count())
	}
	// 被回收的键下次访问应当重新从满桶起算，而不是继承旧的亏空
	if !l.AllowAt("stale", t0.Add(20*time.Minute)) {
		t.Fatal("被回收的键应视为全新访问")
	}
}

// 内存必须有界：键是 IP，攻击者可以无限制造新键。
// 若不做摊还清扫，"加了一道限流"就换来一个更容易打的内存泄漏。
func TestGrowthIsBounded(t *testing.T) {
	l := New(Spec{Capacity: 2, PerMinute: 2})
	t0 := time.Now()

	for i := 0; i < evictThreshold+500; i++ {
		l.AllowAt(string(rune('A'+i%26))+time.Duration(i).String(), t0)
	}
	// 刚写入的键都"活跃"（last == t0），所以此刻不会被回收；
	// 但把时间推进过 idleEvictAfter 后再访问一个新键，就应当触发大批清扫。
	if got := l.Count(); got < evictThreshold {
		t.Fatalf("桶数 = %d，低于阈值 %d 时不该触发清扫，此断言用于确认测试前提",
			got, evictThreshold)
	}
	l.AllowAt("trigger", t0.Add(idleEvictAfter+time.Minute))
	if got := l.Count(); got > 64 {
		t.Fatalf("越过阈值并推进时间后桶数仍为 %d，清扫未生效", got)
	}
}

func TestRetryAfter(t *testing.T) {
	// 每分钟 30 枚 = 每 2 秒一枚
	l := New(Spec{Capacity: 1, PerMinute: 30})
	if got := l.RetryAfter("nobody"); got != 1 {
		t.Errorf("未知键应给最小建议值 1，实际 %d", got)
	}
	t0 := time.Now()
	l.AllowAt("k", t0)
	if got := l.RetryAfter("k"); got != 2 {
		t.Errorf("空桶的 Retry-After = %d, 期望 2（每分钟 30 → 每 2 秒一枚）", got)
	}
}
