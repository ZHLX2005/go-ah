// Package db — 批量删除 helper。
//
// 为什么清理必须分批：janitor 清的是积压了几个月过期行的表，
// 一条无上限的 DELETE 在 PG 里是**单事务**——行锁与死元组一次堆满，
// 轻则拖慢同表的所有并发查询，重则长事务阻塞 VACUUM、把库顶到告警。
// 分批（每批几千行、批间自然提交）把这两个代价都摊平。
package db

import (
	"context"
	"fmt"
	"time"
)

// deleteBatchSize 每批删除的行数。
//
// 5000 是"单批事务足够小"与"别把总时长拖到分钟级"之间的经验值；
// 它不需要精调——批与批之间没有 sleep，循环跑完只受 DB 吞吐限制。
const deleteBatchSize = 5000

// DeleteOlderThan 分批删除表中 expires_at 早于 cutoff 的行，返回总删除行数。
//
// 表名/列名来自本包可信常量（consts.Table*），不来自外部输入，
// 因此字符串拼装是安全的——这也是它放在 db 包的原因：
// 全平台"拼表名"的口径本来就收敛在这里与 dao 层。
func DeleteOlderThan(ctx context.Context, table string, cutoff time.Time) (int64, error) {
	var total int64
	for {
		res, err := Instance().Exec(ctx, fmt.Sprintf(
			`DELETE FROM %s WHERE id IN (SELECT id FROM %s WHERE expires_at < ? LIMIT %d)`,
			table, table, deleteBatchSize,
		), cutoff)
		if err != nil {
			return total, err
		}
		n, err := res.RowsAffected()
		if err != nil {
			return total, err
		}
		total += n
		if n < deleteBatchSize {
			return total, nil
		}
	}
}

// DeleteRefreshTokensGone 分批删除"过期已超过保留期**或**吊销已超过保留期"的
// refresh_token 行。吊销行与过期行同等对待：两者的剩余价值都只剩审计，
// 而审计价值同样以保留期为限。
func DeleteRefreshTokensGone(ctx context.Context, expiredBefore, revokedBefore time.Time) (int64, error) {
	var total int64
	for {
		res, err := Instance().Exec(ctx, fmt.Sprintf(
			`DELETE FROM %s WHERE id IN (SELECT id FROM %s WHERE (expires_at IS NOT NULL AND expires_at < ?) OR (revoked_at IS NOT NULL AND revoked_at < ?) LIMIT %d)`,
			"o_auth_refresh_tokens", "o_auth_refresh_tokens", deleteBatchSize,
		), expiredBefore, revokedBefore)
		if err != nil {
			return total, err
		}
		n, err := res.RowsAffected()
		if err != nil {
			return total, err
		}
		total += n
		if n < deleteBatchSize {
			return total, nil
		}
	}
}
