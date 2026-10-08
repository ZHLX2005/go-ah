import { useMemo, useState } from 'react'
import { adminApi } from '@/api/endpoints'
import type { RefreshTokenRow, SessionRow, UserRow } from '@/api/types'
import { Alert, Badge, Button, Confirm, DataTable, Input, Loading, Modal, Stat } from '@/ui'
import type { Column } from '@/ui'
import { PanelHeader } from '@/layout/AdminLayout'
import { fmtTime, truncMiddle } from '@/lib/format'
import { errText, useAsync, useSubmit } from '@/lib/hooks'

/**
 * 用户面板 /admin/users
 *
 * 列表把「账号属性」与「会话 / 令牌计数」放同一行——这两类信息是同一个人的两副面孔，
 * 拆成两页会让管理员为了看清一个账号而来回跳。明细（尤其是关联令牌的吊销）才有独立
 * 价值，所以收进按需挂载的弹窗：弹窗关闭即卸载，`useAsync` 也就不会在无人查看时发请求。
 */
export default function UsersPage() {
  const users = useAsync(() => adminApi.users(), [])
  const [keyword, setKeyword] = useState('')
  const [detail, setDetail] = useState<{ kind: 'sessions' | 'tokens'; user: UserRow } | null>(null)

  const rows = users.data ?? []

  // 后端全量返回，过滤在前端做：省一次请求，也省得为「边输边筛」引入防抖。
  const filtered = useMemo(() => {
    const k = keyword.trim().toLowerCase()
    if (!k) return rows
    return rows.filter(
      (u) => u.username.toLowerCase().includes(k) || (u.email ?? '').toLowerCase().includes(k),
    )
  }, [rows, keyword])

  const adminCount = rows.filter((u) => u.is_admin).length
  const sessionTotal = rows.reduce((n, u) => n + u.session_count, 0)
  const activeTokenTotal = rows.reduce((n, u) => n + u.active_refresh_count, 0)

  const columns: Column<UserRow>[] = [
    { key: 'id', title: 'ID', width: 56, render: (u) => <span className="dim">{u.id}</span> },
    { key: 'username', title: 'username', render: (u) => u.username },
    { key: 'email', title: 'email', render: (u) => u.email || <span className="dim">—</span> },
    { key: 'nickname', title: 'nickname', render: (u) => u.nickname || <span className="dim">—</span> },
    {
      key: 'is_admin',
      title: '角色',
      render: (u) =>
        u.is_admin ? <Badge variant="solid">管理员</Badge> : <Badge variant="quiet">普通用户</Badge>,
    },
    {
      key: 'created_at',
      title: '创建时间',
      render: (u) => <span className="dim nowrap">{fmtTime(u.created_at)}</span>,
    },
    { key: 'session_count', title: '会话', align: 'right', render: (u) => u.session_count },
    { key: 'refresh_token_count', title: '令牌', align: 'right', render: (u) => u.refresh_token_count },
    { key: 'active_refresh_count', title: '活跃令牌', align: 'right', render: (u) => u.active_refresh_count },
  ]

  return (
    <>
      <PanelHeader title="用户" desc="统一登录平台的账号，以及各自的会话与令牌关联情况" />

      <div className="stack">
        {users.error && <Alert kind="error">{users.error}</Alert>}

        <div className="stats">
          <Stat label="用户总数" value={rows.length} />
          <Stat label="管理员" value={adminCount} />
          <Stat label="会话总数" value={sessionTotal} />
          <Stat label="活跃令牌总数" value={activeTokenTotal} />
        </div>

        <div className="card">
          <div className="card__head">
            <div className="card__title">账号列表</div>
            <Input
              placeholder="按 username / email 过滤"
              value={keyword}
              onChange={(e) => setKeyword(e.target.value)}
              style={{ maxWidth: 260 }}
            />
          </div>
          <div className="card__body card__body--flush">
            <DataTable
              columns={columns}
              rows={filtered}
              rowKey={(u) => u.id}
              loading={users.loading}
              empty="暂无用户"
              actions={(u) => (
                <div className="row" style={{ justifyContent: 'flex-end' }}>
                  <Button size="sm" variant="ghost" onClick={() => setDetail({ kind: 'sessions', user: u })}>
                    查看会话
                  </Button>
                  <Button size="sm" variant="ghost" onClick={() => setDetail({ kind: 'tokens', user: u })}>
                    查看令牌
                  </Button>
                </div>
              )}
            />
          </div>
        </div>
      </div>

      <Modal
        open={detail != null}
        wide
        title={detail ? `${detail.kind === 'sessions' ? '会话' : '令牌'} · ${detail.user.username}` : ''}
        onClose={() => setDetail(null)}
      >
        {detail?.kind === 'sessions' && <SessionsBody userId={detail.user.id} />}
        {detail?.kind === 'tokens' && <TokensBody userId={detail.user.id} onChanged={users.reload} />}
      </Modal>
    </>
  )
}

/**
 * 会话明细。session_id 后端已脱敏，仍用 truncMiddle 统一截断——脱敏串长度不固定，
 * 截断保证任何长度都不会把表格撑破；角标「已脱敏」是给管理员的提示，避免误当作完整 ID。
 */
function SessionsBody({ userId }: { userId: number }) {
  const st = useAsync(() => adminApi.userSessions(userId), [userId])

  if (st.loading) return <Loading />
  if (st.error) return <Alert kind="error">{st.error}</Alert>

  const columns: Column<SessionRow>[] = [
    {
      key: 'session_id',
      title: 'session_id',
      render: (s) => (
        <span className="row" style={{ gap: 6 }}>
          <span className="mono">{truncMiddle(s.session_id)}</span>
          <Badge variant="quiet">已脱敏</Badge>
        </span>
      ),
    },
    {
      key: 'expires_at',
      title: '过期时间',
      render: (s) => <span className="dim nowrap">{fmtTime(s.expires_at)}</span>,
    },
    {
      key: 'created_at',
      title: '创建时间',
      render: (s) => <span className="dim nowrap">{fmtTime(s.created_at)}</span>,
    },
  ]

  return (
    <DataTable
      columns={columns}
      rows={st.data ?? []}
      rowKey={(s) => s.session_id}
      compact
      empty="该用户当前无活跃会话"
    />
  )
}

/** 令牌明细：在弹窗内直接吊销，成功后同时刷新本弹窗与背后的用户列表计数。 */
function TokensBody({ userId, onChanged }: { userId: number; onChanged: () => void }) {
  const st = useAsync(() => adminApi.userTokens(userId), [userId])
  const { busy, run } = useSubmit()
  const [target, setTarget] = useState<RefreshTokenRow | null>(null)
  const [err, setErr] = useState('')

  async function doRevoke() {
    if (!target) return
    setErr('')
    try {
      await run(() => adminApi.revokeToken(target.id))
      setTarget(null)
      st.reload()
      onChanged()
    } catch (e) {
      setTarget(null)
      setErr(errText(e))
    }
  }

  const columns: Column<RefreshTokenRow>[] = [
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
    { key: 'client_id', title: 'client_id', render: (t) => <span className="mono">{t.client_id}</span> },
    { key: 'scope', title: 'scope', render: (t) => <span className="muted">{t.scope}</span> },
    { key: 'status', title: '状态', render: TokenStatusBadge },
    {
      key: 'expires_at',
      title: '过期时间',
      render: (t) => <span className="dim nowrap">{fmtTime(t.expires_at)}</span>,
    },
  ]

  return (
    <>
      {err && <Alert kind="error">{err}</Alert>}

      {st.loading ? (
        <Loading />
      ) : st.error ? (
        <Alert kind="error">{st.error}</Alert>
      ) : (
        <DataTable
          columns={columns}
          rows={st.data ?? []}
          rowKey={(t) => t.id}
          compact
          empty="该用户暂无 refresh_token"
          actions={(t) => (
            <Button size="sm" disabled={t.revoked || busy} onClick={() => setTarget(t)}>
              吊销
            </Button>
          )}
        />
      )}

      <Confirm
        open={target != null}
        title="吊销 refresh_token"
        danger
        busy={busy}
        confirmText="吊销"
        message={
          target
            ? `确认吊销令牌 #${target.id}？用户 ${target.username || target.user_sub}，客户端 ${target.client_id}。吊销后该令牌立即失效。`
            : ''
        }
        onCancel={() => setTarget(null)}
        onConfirm={doRevoke}
      />
    </>
  )
}

/** 令牌状态徽标：吊销 / 过期 / 有效。有效用实心以突出——这是唯一「还在生效」的态。 */
function TokenStatusBadge(t: RefreshTokenRow) {
  if (t.revoked) return <Badge>已吊销</Badge>
  if (t.expired) return <Badge variant="quiet">已过期</Badge>
  return <Badge variant="solid">有效</Badge>
}
