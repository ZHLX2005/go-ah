package db

import (
	"testing"
	"time"

	"github.com/gogf/gf/v2/database/gdb"
	"github.com/gogf/gf/v2/frame/g"
	"github.com/gogf/gf/v2/os/gtime"
)

// TestDataConversionSemantics 锁住本服务依赖的两条 gf「写入侧」语义。
//
// 为什么要为一个依赖库的行为写测试：这两条都不是"用错会报错"的行为，而是
// **用错会静默写错数据**。一旦某次升级改了它们，症状是"清空过期时间点不动"
// 和"邀请码次数扣不动"，两者都不会报错，只会让人怀疑自己的操作。
//
// 这个测试不碰数据库：MapOrStructToMapDeep 是把 Data(...) 的参数转成待写入
// map 的那一步（gdb.ConvertDataForRecord 的第一行就是它），正是"值有没有被
// 丢掉/被改型"发生的地方。真正的落库结果由 logic/invite 的 PG 集成测试覆盖
// （见 redeem_pg_test.go 的 ClearExpires 用例）。
func TestDataConversionSemantics(t *testing.T) {
	t.Run("nil 会被保留并写成 NULL", func(t *testing.T) {
		// 用途：把 invitation_codes.expires_at 改成"长期有效"（置 NULL）。
		// 若这里 key 消失了，UPDATE 语句里根本不会出现 expires_at ——
		// 旧值原样留着，调用方却以为已经清空了。
		//
		// 第二个参数是 gf 的 omitempty，**不是**"是否转换时间类型"
		// （源码：MapOrStructToMapDeep(value, omitempty) 内部直接传给
		// gconv.Map 的 MapOption.OmitEmpty）。这里照抄真实调用点
		// ConvertDataForRecord 传的 true，测的才是生产路径。
		for name, value := range map[string]any{
			"无类型 nil":  nil,
			"类型化 nil":  (*time.Time)(nil),
			"零值 time":  time.Time{},
			"零值 gtime": gtime.Time{},
		} {
			m := gdb.MapOrStructToMapDeep(g.Map{"expires_at": value}, true)
			got, present := m["expires_at"]
			if !present {
				t.Errorf("%s：expires_at 被丢弃，清空过期时间会静默失效", name)
				continue
			}
			switch {
			case value == nil:
				// 无类型 nil 必须原样是 nil：把它"贴心"地换成零值时间，
				// 语义就从"清空"变成了"写入一个具体时刻"。
				if got != nil {
					t.Errorf("%s：nil 被改型为 %T（%v）", name, got, got)
				}
			case !isTimeLike(got):
				// 值必须仍是时间类型：gdb 的下一站 ConvertValueForField 靠类型
				// 才能把零值/空指针翻成 SQL NULL。若这里已被转成字符串，
				// 落库的会是一串无意义文本。
				t.Errorf("%s：值被改型为 %T，期望四种时间类型之一", name, got)
			}
		}
	})

	t.Run("Counter 原样传到 SQL 生成阶段", func(t *testing.T) {
		// 用途：邀请码核销时 `used_count = used_count + 1` 的自增。
		// Counter 被改型的话，gdb 会退化成 `used_count = ?`，
		// 把自增写成一个固定值 —— 并发下直接丢更新。
		m := gdb.MapOrStructToMapDeep(g.Map{"used_count": gdb.Counter{Field: "used_count", Value: 1}}, true)
		counter, ok := m["used_count"].(gdb.Counter)
		if !ok {
			t.Fatalf("Counter 被改型为 %T，自增会退化成赋值", m["used_count"])
		}
		if counter.Field != "used_count" || counter.Value != 1 {
			t.Errorf("Counter = %+v, 期望 {used_count 1}", counter)
		}
	})

	t.Run("false 不会被 omitempty 丢掉", func(t *testing.T) {
		// 用途：把 is_admin 从 true 改成 false —— 唯一核心管理员的降级动作
		// 就是它。这是本服务里**唯一**要把布尔字段写成 false 的地方，
		// 而 omitempty 的语义恰恰是"空值不写"：一旦它连 map 输入也生效，
		// UPDATE 的 SET 里就不会出现 is_admin，降级悄无声息地不发生，
		// 而日志里那条「已降级 N 个账号」仍然是 0，看不出任何异常。
		//
		// 结论（已核对 gf v2.10.3 源码）：OmitEmpty 只在**结构体**反射分支里
		// 被读取，且只作用于带 `json:",omitempty"` 标签的字段
		// （gconv/internal/converter/converter_map.go:472）。map 输入走的是
		// reflect.Map 分支，逐键原样拷贝，不受影响。
		// 换句话说：写 false 必须用 g.Map，不能换成 do.XxxUpdate 结构体 ——
		// 那就是 model/do 里 IsAdmin 被特意声明成 interface{} 的原因。
		m := gdb.MapOrStructToMapDeep(g.Map{"is_admin": false}, true)
		got, present := m["is_admin"]
		if !present {
			t.Fatal("is_admin 被丢弃：写 false 会静默失效，管理员降级不生效")
		}
		b, ok := got.(bool)
		if !ok {
			t.Fatalf("is_admin 被改型为 %T，期望 bool", got)
		}
		if b {
			t.Error("is_admin 变成了 true")
		}
	})
}

// isTimeLike 判断转换后的值是否仍是时间类型。
//
// 四种都要认：gf 在这四种之间派生（源码 gdb_func.go 的 MapOrStructToMapDeep
// 里那个 switch 列举的正是这四种 + gjson）。曾经只写了后两种值类型，
// 结果 `(*time.Time)(nil)` 走不通 —— 它保留为指针，而不是被解引用成值；
// 本地没跑这个二进制，直到 CI 才暴露。
func isTimeLike(v any) bool {
	switch v.(type) {
	case time.Time, *time.Time, gtime.Time, *gtime.Time:
		return true
	}
	return false
}
