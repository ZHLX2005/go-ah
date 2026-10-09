import { useState } from 'react'
import type { FormEvent } from 'react'
import { adminApi } from '@/api/endpoints'
import { INVITE_STATUS_LABEL, INVITE_STATUS_OPTIONS } from '@/api/types'
import type { InviteRow, InviteStatus, InviteUsageRow } from '@/api/types'
import {
  Alert,
  Badge,
  Button,
  Checkbox,
  Confirm,
  DataTable,
  Field,
  Input,
  KeyValues,
  Loading,
  Modal,
  Select,
  Textarea,
} from '@/ui'
import type { Column } from '@/ui'
import { PanelHeader } from '@/layout/AdminLayout'
import { fmtTime } from '@/lib/format'
import { errText, useAsync, useSubmit } from '@/lib/hooks'

/** 新建表单草稿 */
type CreateForm = {
  maxUses: string
  expiresAt: string
  note: string
}

/** 编辑表单草稿 */
type EditForm = {
  maxUses: string
  expiresAt: string
  enabled: boolean
  note: string
}

const INITIAL_CREATE: CreateForm = { maxUses: '1', expiresAt: '', note: '' }

/**
 * 邀请码面板 /admin/invites
 *
 * 这是**发放注册资格**的地方：本平台没有开放注册，自助注册（/register）
 * 必须携带一张此刻仍能核销的邀请码，而码只能在这里生成。
 *
 * 两个刻意的取舍：
 *   ① 状态与剩余次数直接用后端给的 status / remaining，前端不自己从
 *      max_uses / used_count / expires_at 推 —— 推出来的规则一旦与注册接口
 *      的放行规则不一致，就会出现「列表显示可用、注册却被拒」；
 *   ② 修改用「不改」语义（只提交改动过的字段）：真值语义下漏传 max_uses
 *      会被写成 0，一次只想改备注的操作会把配额悄悄重置。
 */
export default function InvitesPage() {
  const [status, setStatus] = useState('all')
  const list = useAsync(() => adminApi.invites(status), [status])

  const [creating, setCreating] = useState(false)
  const [createErr, setCreateErr] = useState('')
  const [form, setForm] = useState<CreateForm>(INITIAL_CREATE)
  const createSub = useSubmit()

  const [editing, setEditing] = useState<InviteRow | null>(null)
  const [editErr, setEditErr] = useState('')
  const [editForm, setEditForm] = useState<EditForm>({
    maxUses: '1',
    expiresAt: '',
    enabled: true,
    note: '',
  })
  const editSub = useSubmit()

  const [delTarget, setDelTarget] = useState<InviteRow | null>(null)
  const [delErr, setDelErr] = useState('')
  const delSub = useSubmit()

  // 使用明细：点开某张码才去查（列表里只有"用了几次"，明细是稀罕需求）
  const [usageTarget, setUsageTarget] = useState<InviteRow | null>(null)
  const usages = useAsync(
    () => (usageTarget ? adminApi.inviteUsages(usageTarget.id) : Promise.resolve([])),
    [usageTarget?.id],
  )

  // 行内操作（复制/启停）的错误没有弹窗可承载，落到页面顶部
  const [actionErr, setActionErr] = useState('')
  const [copied, setCopied] = useState<number | null>(null)

  function patch(p: Partial<CreateForm>) {
    setForm((f) => ({ ...f, ...p }))
  }

  function openCreate() {
    setCreateErr('')
    setForm(INITIAL_CREATE)
    setCreating(true)
  }

  function openEdit(row: InviteRow) {
    setEditErr('')
    setEditing(row)
    setEditForm({
      maxUses: String(row.max_uses),
      // datetime-local 需要 "YYYY-MM-DDTHH:mm"；后端返回的是 RFC3339，
      // 直接塞进去浏览器会当成非法值而显示空白。截断到分钟即可。
      expiresAt: toLocalInput(row.expires_at),
      enabled: row.enabled,
      note: row.note,
    })
  }

  async function submitCreate(e: FormEvent) {
    e.preventDefault()
    setCreateErr('')

    const maxUses = Number(form.maxUses)
    if (!Number.isInteger(maxUses) || maxUses <= 0) {
      setCreateErr('可用次数必须是大于 0 的整数')
      return
    }

    try {
      await createSub.run(() =>
        adminApi.createInvite({
          max_uses: maxUses,
          expires_at: toInstant(form.expiresAt),
          note: form.note.trim(),
        }),
      )
      setCreating(false)
      setForm(INITIAL_CREATE)
      list.reload()
    } catch (err) {
      setCreateErr(errText(err))
    }
  }

  async function submitEdit(e: FormEvent) {
    e.preventDefault()
    if (!editing) return
    setEditErr('')

    const maxUses = Number(editForm.maxUses)
    if (!Number.isInteger(maxUses) || maxUses <= 0) {
      setEditErr('可用次数必须是大于 0 的整数')
      return
    }

    // 只提交**改动过**的字段（后端按"未给出即不改"处理）：
    // expiresAt 用空串表达"改为长期有效"，与"不动它"（不传）区分开。
    const payload: {
      max_uses?: number
      expires_at?: string
      enabled?: boolean
      note?: string
    } = {}
    if (maxUses !== editing.max_uses) payload.max_uses = maxUses
    if (editForm.expiresAt !== toLocalInput(editing.expires_at)) {
      payload.expires_at = toInstant(editForm.expiresAt)
    }
    if (editForm.enabled !== editing.enabled) payload.enabled = editForm.enabled
    if (editForm.note.trim() !== editing.note) payload.note = editForm.note.trim()

    if (Object.keys(payload).length === 0) {
      setEditing(null)
      return
    }

    try {
      await editSub.run(() => adminApi.updateInvite(editing.id, payload))
      setEditing(null)
      list.reload()
    } catch (err) {
      setEditErr(errText(err))
    }
  }

  async function doDelete() {
    if (!delTarget) return
    setDelErr('')
    try {
      await delSub.run(() => adminApi.deleteInvite(delTarget.id))
      setDelTarget(null)
      list.reload()
    } catch (err) {
      setDelErr(errText(err))
    }
  }

  async function toggleEnabled(row: InviteRow) {
    setActionErr('')
    try {
      await adminApi.updateInvite(row.id, { enabled: !row.enabled })
      list.reload()
    } catch (err) {
      setActionErr(errText(err))
    }
  }

  /** 复制邀请码：管理员的下一件事一定是把它发给某人 */
  async function copyCode(row: InviteRow) {
    setActionErr('')
    try {
      await navigator.clipboard.writeText(row.code)
      setCopied(row.id)
    } catch {
      // 非 HTTPS / 无剪贴板权限时降级为提示手动复制（与客户端密钥处一致）
      setActionErr('复制失败，请手动选中邀请码复制')
    }
  }

  const columns: Column<InviteRow>[] = [
    {
      key: 'code',
      title: '邀请码',
      render: (r) => <span className="mono">{r.code}</span>,
    },
    {
      key: 'status',
      title: '状态',
      render: (r) => <StatusBadge status={r.status} />,
    },
    {
      key: 'remaining',
      title: '可用 / 总次数',
      render: (r) => (
        <span className="mono">
          {r.remaining} / {r.max_uses}
        </span>
      ),
    },
    {
      key: 'used_count',
      title: '已使用',
      render: (r) =>
        r.used_count > 0 ? (
          <Button size="sm" variant="ghost" onClick={() => setUsageTarget(r)}>
            {r.used_count} 次 · 查看
          </Button>
        ) : (
          <span className="dim">未使用</span>
        ),
    },
    {
      key: 'expires_at',
      title: '有效期至',
      render: (r) =>
        r.expires_at ? (
          <span className="dim nowrap">{fmtTime(r.expires_at)}</span>
        ) : (
          <span className="dim">长期有效</span>
        ),
    },
    {
      key: 'note',
      title: '备注',
      render: (r) => r.note || <span className="dim">—</span>,
    },
    {
      key: 'created_at',
      title: '创建时间',
      render: (r) => <span className="dim nowrap">{fmtTime(r.created_at)}</span>,
    },
  ]

  return (
    <>
      <PanelHeader
        title="注册邀请码"
        desc="本平台不开放注册：新账号必须由受邀者凭这里生成的邀请码自助创建"
        extra={
          <Button variant="primary" onClick={openCreate}>
            生成邀请码
          </Button>
        }
      />

      <div className="stack">
        {list.error && <Alert kind="error">{list.error}</Alert>}
        {actionErr && <Alert kind="error">{actionErr}</Alert>}
        {copied != null && <Alert kind="ok">邀请码已复制到剪贴板</Alert>}

        <div className="card">
          <div className="card__head">
            <div className="row" style={{ gap: 10 }}>
              <span className="dim" style={{ fontSize: 12 }}>
                状态筛选
              </span>
              <Select value={status} onChange={(e) => setStatus(e.target.value)} style={{ width: 140 }}>
                {INVITE_STATUS_OPTIONS.map((o) => (
                  <option key={o.value} value={o.value}>
                    {o.label}
                  </option>
                ))}
              </Select>
            </div>
            <Button size="sm" variant="ghost" onClick={list.reload}>
              刷新
            </Button>
          </div>
          <div className="card__body card__body--flush">
            <DataTable
              columns={columns}
              rows={list.data ?? []}
              rowKey={(r) => r.id}
              loading={list.loading}
              empty="还没有邀请码 —— 没有码就没人能注册"
              actions={(r) => (
                <div className="row" style={{ justifyContent: 'flex-end' }}>
                  <Button size="sm" variant="ghost" onClick={() => copyCode(r)}>
                    复制
                  </Button>
                  <Button size="sm" variant="ghost" onClick={() => openEdit(r)}>
                    编辑
                  </Button>
                  <Button size="sm" variant="ghost" onClick={() => toggleEnabled(r)}>
                    {r.enabled ? '停用' : '启用'}
                  </Button>
                  <Button
                    size="sm"
                    variant="ghost"
                    onClick={() => {
                      setDelErr('')
                      setDelTarget(r)
                    }}
                  >
                    删除
                  </Button>
                </div>
              )}
            />
          </div>
        </div>

        <Alert kind="info">
          邀请码是注册的唯一门槛，请只发给需要发的人。删除邀请码**不会**删除使用明细——
          「这个账号当初是用哪张码注册的」会保留下来，便于事后追查。
        </Alert>
      </div>

      {/* 生成 */}
      <Modal
        open={creating}
        title="生成邀请码"
        onClose={() => setCreating(false)}
        footer={
          <>
            <Button onClick={() => setCreating(false)} disabled={createSub.busy}>
              取消
            </Button>
            <Button type="submit" form="create-invite-form" variant="primary" disabled={createSub.busy}>
              {createSub.busy ? '生成中…' : '生成'}
            </Button>
          </>
        }
      >
        <form id="create-invite-form" onSubmit={submitCreate} className="stack" style={{ gap: 14 }}>
          <Field label="可用次数" hint="默认 1 次（一人一码）。上限 1000 次">
            <Input
              autoFocus
              type="number"
              min={1}
              max={1000}
              value={form.maxUses}
              onChange={(e) => patch({ maxUses: e.target.value })}
            />
          </Field>

          <Field label="有效期至" hint="留空表示长期有效">
            <Input
              type="datetime-local"
              value={form.expiresAt}
              onChange={(e) => patch({ expiresAt: e.target.value })}
            />
          </Field>

          <Field label="备注" hint="写给谁、做什么用 —— 列表里唯一能区分两张码的信息">
            <Textarea
              rows={2}
              value={form.note}
              placeholder="例如：给后端组张三，入职开通账号"
              onChange={(e) => patch({ note: e.target.value })}
            />
          </Field>

          {createErr && <Alert kind="error">{createErr}</Alert>}
        </form>
      </Modal>

      {/* 编辑 */}
      <Modal
        open={editing != null}
        title={
          editing ? (
            <>
              编辑邀请码 <span className="mono">{editing.code}</span>
            </>
          ) : (
            ''
          )
        }
        onClose={() => setEditing(null)}
        footer={
          <>
            <Button onClick={() => setEditing(null)} disabled={editSub.busy}>
              取消
            </Button>
            <Button type="submit" form="edit-invite-form" variant="primary" disabled={editSub.busy}>
              {editSub.busy ? '保存中…' : '保存修改'}
            </Button>
          </>
        }
      >
        {editing && (
          <form id="edit-invite-form" onSubmit={submitEdit} className="stack" style={{ gap: 14 }}>
            <Field label="邀请码（生成后不可修改）">
              <Input value={editing.code} disabled />
            </Field>

            <Field
              label="可用次数"
              hint={`已使用 ${editing.used_count} 次，不能改到比它更小；如需作废请改用「停用」`}
            >
              <Input
                type="number"
                min={Math.max(1, editing.used_count)}
                max={1000}
                value={editForm.maxUses}
                onChange={(e) => setEditForm({ ...editForm, maxUses: e.target.value })}
              />
            </Field>

            <Field label="有效期至" hint="清空表示改为长期有效">
              <Input
                type="datetime-local"
                value={editForm.expiresAt}
                onChange={(e) => setEditForm({ ...editForm, expiresAt: e.target.value })}
              />
            </Field>

            <Field label="备注">
              <Textarea
                rows={2}
                value={editForm.note}
                onChange={(e) => setEditForm({ ...editForm, note: e.target.value })}
              />
            </Field>

            <Checkbox
              label="启用（停用后该码无法再用于注册，已注册的账号不受影响）"
              checked={editForm.enabled}
              onChange={(e) => setEditForm({ ...editForm, enabled: e.target.checked })}
            />

            {editErr && <Alert kind="error">{editErr}</Alert>}
          </form>
        )}
      </Modal>

      {/* 删除确认 */}
      <Confirm
        open={delTarget != null}
        title="删除邀请码"
        danger
        busy={delSub.busy}
        confirmText="删除"
        message={
          <>
            <div>
              确认删除邀请码 <span className="mono">{delTarget?.code}</span>？删除后无法再用于注册；
              已用它注册的账号不受影响，其使用明细也会保留。
            </div>
            {delErr && <Alert kind="error">{delErr}</Alert>}
          </>
        }
        onCancel={() => setDelTarget(null)}
        onConfirm={doDelete}
      />

      {/* 使用明细 */}
      <Modal
        open={usageTarget != null}
        wide
        title={
          usageTarget ? (
            <>
              使用明细 <span className="mono">{usageTarget.code}</span>
            </>
          ) : (
            ''
          )
        }
        onClose={() => setUsageTarget(null)}
      >
        {usageTarget && (
          <div className="stack" style={{ gap: 14 }}>
            <KeyValues
              items={[
                { k: '状态', v: <StatusBadge status={usageTarget.status} /> },
                { k: '已使用', v: `${usageTarget.used_count} / ${usageTarget.max_uses} 次` },
                { k: '有效期至', v: usageTarget.expires_at ? fmtTime(usageTarget.expires_at) : '长期有效' },
                { k: '备注', v: usageTarget.note || '—' },
              ]}
            />
            {usages.loading ? (
              <Loading text="正在加载使用明细…" />
            ) : usages.error ? (
              <Alert kind="error">{usages.error}</Alert>
            ) : (
              <DataTable
                compact
                columns={usageColumns}
                rows={usages.data ?? []}
                rowKey={(u) => u.id}
                empty="这张邀请码还没有被使用过"
              />
            )}
          </div>
        )}
      </Modal>
    </>
  )
}

const usageColumns: Column<InviteUsageRow>[] = [
  { key: 'username', title: '注册账号', render: (u) => <span className="mono">{u.username}</span> },
  { key: 'email', title: '邮箱', render: (u) => u.email || <span className="dim">—</span> },
  { key: 'user_id', title: '用户 ID', render: (u) => <span className="mono dim">{u.user_id}</span> },
  { key: 'used_at', title: '使用时间', render: (u) => <span className="dim nowrap">{fmtTime(u.used_at)}</span> },
]

/** 状态标记。黑白灰主题下靠字重与实心/空心区分，不引入色相。 */
function StatusBadge({ status }: { status: InviteStatus }) {
  return status === 'active' ? (
    <Badge variant="solid">{INVITE_STATUS_LABEL[status]}</Badge>
  ) : (
    <Badge variant="quiet">{INVITE_STATUS_LABEL[status]}</Badge>
  )
}

/**
 * RFC3339 → datetime-local 需要的 "YYYY-MM-DDTHH:mm"（本地时区）。
 *
 * 必须自己换算：后端返回的是带 Z 或带偏移的时间串，直接切前 16 个字符
 * 得到的是 UTC 的墙上时间，在东八区会差 8 小时 —— 表现为"编辑一下就把
 * 有效期改早了 8 小时"，而且不报错。
 */
function toLocalInput(v?: string | null): string {
  if (!v) return ''
  const d = new Date(v)
  if (Number.isNaN(d.getTime())) return ''
  const p = (n: number) => String(n).padStart(2, '0')
  return `${d.getFullYear()}-${p(d.getMonth() + 1)}-${p(d.getDate())}T${p(d.getHours())}:${p(d.getMinutes())}`
}

/**
 * datetime-local 的值 → 带时区的绝对时刻；空串原样返回（表示"长期有效"）。
 *
 * 为什么要转：datetime-local 给出来的是**没有时区**的墙上时间
 * （"2026-10-20T15:30"），直接发给后端就变成"由服务端的本地时区来解读"——
 * 服务端时区与浏览器不一致时，有效期会整体平移若干小时，而且两端都不报错。
 * new Date(无时区串) 按浏览器本地时区解析，toISOString 输出 UTC，
 * 于是链路上只存在一个明确含义的时刻。
 */
function toInstant(input: string): string {
  if (!input) return ''
  const d = new Date(input)
  if (Number.isNaN(d.getTime())) return input
  return d.toISOString()
}
