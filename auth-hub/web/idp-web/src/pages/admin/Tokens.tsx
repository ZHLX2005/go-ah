import { useState } from 'react'
import { adminApi } from '@/api/endpoints'
import { TOKEN_STATUS_OPTIONS } from '@/api/types'
import type { RefreshTokenRow } from '@/api/types'
import { Alert, Badge, Button, Confirm, DataTable, Select, Stat } from '@/ui'
import type { Column } from '@/ui'
import { PanelHeader } from '@/layout/AdminLayout'
import { fmtTime, truncMiddle } from '@/lib/format'
import { errText, useAsync, useSubmit } from '@/lib/hooks'

/**
 * 令牌面板 /admin/tokens
 *
 * 过滤交给后端（status 参数）：被吊销/过期的令牌数量可能远大于有效令牌，
 * 全量拉回前端再筛既浪费带宽又让「统计条」的数字含义变得暧昧——这里统计的
 * 就是「当前筛选视图」里的分布，与列表严格一致。
 */
export default function TokensPage() {
  const [status, setStatus] = useState('all')
  const tokens = useAsync(() => adminApi.refreshTokens(status), [status])

  const [target, setTarget] = useState<RefreshTokenRow | null>(null)
  const [err, setErr] = useState('')
  const { busy, run } = useSubmit()

  const rows = tokens.data ?? []
  const activeCount = rows.filter((t) => !t.revoked && !t.expired).length
  const revokedCount = rows.filter((t) => t.revoked).length
  const expiredCount = rows.filter((t) => t.expired).length

  async function doRevoke() {
    if (!target) return
    setErr('')
    try {
      await run(() => adminApi.revokeToken(target.id))
      setTarget(null)
      tokens.reload()
    } catch (e) {
      setTarget(null)
      setErr(errText(e))
    }
  }

  const columns: Column<RefreshTokenRow>[] = [
    { key: 'id', title: 'ID', width: 56, render: (t) => <span className="dim">{t.id}</span> },
    {
      key: 'token',
      title: 'token',
      render: (t) => (
        <span className="row" style={{ gap: 6 }}>
          <span className="mono">{truncMiddle(t.token)}</span>
          <Badge variant="quiet">已脱敏</Badge>
        </span>
      ),
    },
    { key: 'username', title: '用户', render: (t) => t.username || <span className="dim">—</span> },
    { key: 'user_sub', title: 'user_sub', render: (t) => <span className="mono">{t.user_sub}</span> },
    { key: 'client_id', title: 'client_id', render: (t) => <span className="mono">{t.client_id}</span> },
    { key: 'scope', title: 'scope', render: (t) => <span className="muted">{t.scope}</span> },
    {
      key: 'expires_at',
      title: '过期时间',
      render: (t) => <span className="dim nowrap">{fmtTime(t.expires_at)}</span>,
    },
    { key: 'status', title: '状态', render: TokenStatusBadge },
    {
      key: 'created_at',
      title: '创建时间',
      render: (t) => <span className="dim nowrap">{fmtTime(t.created_at)}</span>,
    },
    {
      key: 'revoked_at',
      title: '吊销时间',
      render: (t) => <span className="dim nowrap">{fmtTime(t.revoked_at)}</span>,
    },
  ]

  return (
    <>
      <PanelHeader
        title="令牌"
        desc="refresh_token 全量视图；吊销后该令牌立即失效，关联会话需重新登录"
        extra={
          <Button onClick={() => tokens.reload()} disabled={tokens.loading}>
            刷新
          </Button>
        }
      />

      <div className="stack">
        {tokens.error && <Alert kind="error">{tokens.error}</Alert>}
        {err && <Alert kind="error">{err}</Alert>}

        <div className="stats">
          <Stat label="当前视图总数" value={rows.length} />
          <Stat label="有效" value={activeCount} />
          <Stat label="已吊销" value={revokedCount} />
          <Stat label="已过期" value={expiredCount} />
        </div>

        <div className="card">
          <div className="card__head">
            <div className="card__title">refresh_token</div>
            <Select value={status} onChange={(e) => setStatus(e.target.value)} style={{ maxWidth: 160 }}>
              {TOKEN_STATUS_OPTIONS.map((o) => (
                <option key={o.value} value={o.value}>
                  {o.label}
                </option>
              ))}
            </Select>
          </div>
          <div className="card__body card__body--flush">
            <DataTable
              columns={columns}
              rows={rows}
              rowKey={(t) => t.id}
              loading={tokens.loading}
              empty="暂无 refresh_token。先到业务平台或 CLI 完成一次登录即可产生。"
              actions={(t) => (
                <Button size="sm" disabled={t.revoked || busy} onClick={() => setTarget(t)}>
                  吊销
                </Button>
              )}
            />
          </div>
        </div>
      </div>

      <Confirm
        open={target != null}
        title="吊销 refresh_token"
        danger
        busy={busy}
        confirmText="吊销"
        message={
          target
            ? `确认吊销 refresh_token #${target.id}？用户 ${target.username || target.user_sub}，客户端 ${target.client_id}。吊销后该令牌立即失效。`
            : ''
        }
        onCancel={() => setTarget(null)}
        onConfirm={doRevoke}
      />
    </>
  )
}

/** 状态徽标：吊销 / 过期 / 有效。有效用实心突出，是三者中唯一仍生效的态。 */
function TokenStatusBadge(t: RefreshTokenRow) {
  if (t.revoked) return <Badge>已吊销</Badge>
  if (t.expired) return <Badge variant="quiet">已过期</Badge>
  return <Badge variant="solid">有效</Badge>
}
