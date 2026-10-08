import { useState } from 'react'
import type { FormEvent } from 'react'
import { adminApi } from '@/api/endpoints'
import { SCOPE_OPTIONS } from '@/api/types'
import type { ClientInput, ClientRow } from '@/api/types'
import {
  Alert,
  Badge,
  Button,
  Checkbox,
  Confirm,
  DataTable,
  Field,
  Input,
  Modal,
  TagList,
  Textarea,
} from '@/ui'
import type { Column } from '@/ui'
import { PanelHeader } from '@/layout/AdminLayout'
import { fmtTime, joinList, parseList } from '@/lib/format'
import { errText, useAsync, useSubmit } from '@/lib/hooks'

/** 新建表单草稿。改用普通对象 state 而非 useForm：字段既有字符串也有数组与布尔，逐字段 patch 更直观。 */
type CreateForm = {
  clientId: string
  clientName: string
  redirects: string
  scopes: string[]
  postLogout: string
  isPublic: boolean
  pkceRequired: boolean
  enabled: boolean
}

/** 编辑表单草稿（client_id 不在其中——创建后不可改）。 */
type EditForm = {
  clientName: string
  redirects: string
  scopes: string[]
  postLogout: string
  isPublic: boolean
  pkceRequired: boolean
  enabled: boolean
}

const INITIAL_CREATE: CreateForm = {
  clientId: '',
  clientName: '',
  redirects: '',
  scopes: ['openid', 'profile', 'email'],
  postLogout: '',
  isPublic: true,
  pkceRequired: true,
  enabled: true,
}

/**
 * OIDC 客户端面板 /admin/clients
 *
 * 写操作全部锚定后端语义：前端不做内置客户端的「白名单」判断——哪些不可删由后端说了算，
 * 它返回 protected_client 之类的原因时原样展示，避免前后端两处规则各自漂移。
 * 明文 client_secret 只在创建响应里出现一次（与 data 同级，非 data 内），
 * 所以创建成功后必须把它钉在页面上单独一块，直到用户手动关闭。
 */
export default function ClientsPage() {
  const list = useAsync(() => adminApi.clients(), [])

  const [creating, setCreating] = useState(false)
  const [createErr, setCreateErr] = useState('')
  const [form, setForm] = useState<CreateForm>(INITIAL_CREATE)
  const createSub = useSubmit()

  const [editing, setEditing] = useState<ClientRow | null>(null)
  const [editErr, setEditErr] = useState('')
  const [editForm, setEditForm] = useState<EditForm>({
    clientName: '',
    redirects: '',
    scopes: [],
    postLogout: '',
    isPublic: true,
    pkceRequired: true,
    enabled: true,
  })
  const editSub = useSubmit()

  const [delTarget, setDelTarget] = useState<ClientRow | null>(null)
  const [delErr, setDelErr] = useState('')
  const delSub = useSubmit()

  // 行内启用/禁用等「就地操作」的错误，没有弹窗可承载，落到页面顶部
  const [actionErr, setActionErr] = useState('')

  // 创建成功后的一次性密钥区块；存在即代表需长期提醒用户保存
  const [created, setCreated] = useState<{ clientId: string; secret?: string; notice?: string } | null>(null)

  const patch = (p: Partial<CreateForm>) => setForm((f) => ({ ...f, ...p }))

  function openCreate() {
    setCreateErr('')
    setForm(INITIAL_CREATE)
    setCreating(true)
  }

  function openEdit(c: ClientRow) {
    setEditErr('')
    setEditing(c)
    setEditForm({
      clientName: c.client_name,
      redirects: joinList(c.redirect_uris),
      scopes: c.scopes,
      postLogout: joinList(c.post_logout_uris),
      isPublic: c.is_public,
      pkceRequired: c.pkce_required,
      enabled: c.enabled,
    })
  }

  /** 回调地址的本地校验与后端提示文案保持一致，把明显错误挡在请求之前。 */
  function validateUris(uris: string[]): string {
    if (uris.length === 0) return '至少填写一个回调地址'
    const bad = uris.find((u) => !/^https?:\/\//i.test(u))
    if (bad) return `回调地址必须是完整 URL（http/https）：${bad}`
    return ''
  }

  async function submitCreate(e: FormEvent) {
    e.preventDefault()
    setCreateErr('')

    const cid = form.clientId.trim()
    if (!cid) {
      setCreateErr('client_id 不能为空')
      return
    }
    const uris = parseList(form.redirects)
    const uriErr = validateUris(uris)
    if (uriErr) {
      setCreateErr(uriErr)
      return
    }

    const payload: ClientInput = {
      client_id: cid,
      client_name: form.clientName.trim() || undefined,
      redirect_uris: uris,
      scopes: form.scopes,
      // 公共客户端必须 PKCE，这是协议要求而非可选项，故此处强制为 true
      is_public: form.isPublic,
      pkce_required: form.isPublic ? true : form.pkceRequired,
      enabled: form.enabled,
      post_logout_uris: parseList(form.postLogout),
    }

    try {
      // createClient 返回整个信封：明文 secret 与 code 同级，只取 data 会把它丢掉
      const res = await createSub.run(() => adminApi.createClient(payload))
      setCreated({ clientId: res.data?.client_id ?? cid, secret: res.client_secret, notice: res.notice })
      setCreating(false)
      setForm(INITIAL_CREATE)
      list.reload()
    } catch (err) {
      // 后端错误（invalid_request / conflict 等）就地展示，不关弹窗，用户改完可直接重试
      setCreateErr(errText(err))
    }
  }

  async function submitEdit(e: FormEvent) {
    e.preventDefault()
    if (!editing) return
    setEditErr('')

    const uris = parseList(editForm.redirects)
    const uriErr = validateUris(uris)
    if (uriErr) {
      setEditErr(uriErr)
      return
    }

    try {
      await editSub.run(() =>
        adminApi.updateClient(editing.id, {
          client_name: editForm.clientName.trim(),
          redirect_uris: uris,
          scopes: editForm.scopes,
          post_logout_uris: parseList(editForm.postLogout),
          is_public: editForm.isPublic,
          pkce_required: editForm.isPublic ? true : editForm.pkceRequired,
          enabled: editForm.enabled,
        }),
      )
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
      await delSub.run(() => adminApi.deleteClient(delTarget.id))
      setDelTarget(null)
      list.reload()
    } catch (err) {
      // 内置客户端等受保护对象由后端拦截，错误留在确认框里就地说明
      setDelErr(errText(err))
    }
  }

  async function toggleEnabled(c: ClientRow) {
    setActionErr('')
    try {
      await adminApi.updateClient(c.id, { enabled: !c.enabled })
      list.reload()
    } catch (err) {
      setActionErr(errText(err))
    }
  }

  const columns: Column<ClientRow>[] = [
    { key: 'client_id', title: 'client_id', render: (c) => <span className="mono">{c.client_id}</span> },
    { key: 'client_name', title: '应用名称', render: (c) => c.client_name || <span className="dim">—</span> },
    { key: 'redirect_uris', title: '回调地址', render: (c) => <TagList items={c.redirect_uris} /> },
    { key: 'scopes', title: 'scopes', render: (c) => <TagList items={c.scopes} /> },
    {
      key: 'is_public',
      title: '类型',
      render: (c) => (c.is_public ? <Badge variant="solid">公共</Badge> : <Badge variant="quiet">机密</Badge>),
    },
    {
      key: 'pkce_required',
      title: 'PKCE',
      render: (c) => (c.pkce_required ? <Badge variant="solid">必需</Badge> : <Badge variant="quiet">可选</Badge>),
    },
    {
      key: 'enabled',
      title: '状态',
      render: (c) => (c.enabled ? <Badge variant="solid">已启用</Badge> : <Badge variant="quiet">已禁用</Badge>),
    },
    {
      key: 'has_secret',
      title: '密钥',
      render: (c) => (c.has_secret ? <Badge variant="quiet">有密钥</Badge> : <span className="dim">—</span>),
    },
    {
      key: 'created_at',
      title: '创建时间',
      render: (c) => <span className="dim nowrap">{fmtTime(c.created_at)}</span>,
    },
  ]

  return (
    <>
      <PanelHeader
        title="OIDC 客户端"
        desc="注册在统一登录平台的业务客户端（PKCE 公共客户端 / 机密客户端）"
        extra={
          <Button variant="primary" onClick={openCreate}>
            新增客户端
          </Button>
        }
      />

      <div className="stack">
        {list.error && <Alert kind="error">{list.error}</Alert>}
        {actionErr && <Alert kind="error">{actionErr}</Alert>}
        {created && <CreatedSecret data={created} onClose={() => setCreated(null)} />}

        <div className="card">
          <div className="card__body card__body--flush">
            <DataTable
              columns={columns}
              rows={list.data ?? []}
              rowKey={(c) => c.id}
              loading={list.loading}
              empty="暂无客户端"
              actions={(c) => (
                <div className="row" style={{ justifyContent: 'flex-end' }}>
                  <Button size="sm" variant="ghost" onClick={() => openEdit(c)}>
                    编辑
                  </Button>
                  <Button size="sm" variant="ghost" onClick={() => toggleEnabled(c)}>
                    {c.enabled ? '禁用' : '启用'}
                  </Button>
                  <Button
                    size="sm"
                    variant="ghost"
                    onClick={() => {
                      setDelErr('')
                      setDelTarget(c)
                    }}
                  >
                    删除
                  </Button>
                </div>
              )}
            />
          </div>
        </div>
      </div>

      {/* 新建 */}
      <Modal
        open={creating}
        wide
        title="新增 OIDC 客户端"
        onClose={() => setCreating(false)}
        footer={
          <>
            <Button onClick={() => setCreating(false)} disabled={createSub.busy}>
              取消
            </Button>
            <Button type="submit" form="create-client-form" variant="primary" disabled={createSub.busy}>
              {createSub.busy ? '创建中…' : '创建客户端'}
            </Button>
          </>
        }
      >
        <form id="create-client-form" onSubmit={submitCreate} className="stack" style={{ gap: 14 }}>
          <div className="form-grid">
            <Field label="client_id *">
              <Input
                autoFocus
                value={form.clientId}
                placeholder="my-app-client"
                onChange={(e) => patch({ clientId: e.target.value })}
              />
            </Field>
            <Field label="应用名称">
              <Input
                value={form.clientName}
                placeholder="我的业务应用"
                onChange={(e) => patch({ clientName: e.target.value })}
              />
            </Field>
          </div>

          <Field
            label="回调地址 *"
            hint="必须完整 URL（http/https）；端口通配仅支持 127.0.0.1 / localhost"
          >
            <Textarea
              mono
              rows={3}
              value={form.redirects}
              placeholder={'http://127.0.0.1:9000/oauth/callback\nhttp://127.0.0.1:*/callback'}
              onChange={(e) => patch({ redirects: e.target.value })}
            />
          </Field>

          <Field label="scopes">
            <ScopePicker value={form.scopes} onChange={(v) => patch({ scopes: v })} />
          </Field>

          <Field label="登出后回调地址" hint="每行一个，可留空">
            <Textarea
              mono
              rows={2}
              value={form.postLogout}
              placeholder="http://127.0.0.1:9000/"
              onChange={(e) => patch({ postLogout: e.target.value })}
            />
          </Field>

          <div className="row wrap" style={{ gap: 18 }}>
            <Checkbox
              label="公共客户端（无 client_secret，强制 PKCE）"
              checked={form.isPublic}
              onChange={(e) => patch({ isPublic: e.target.checked })}
            />
            <Checkbox
              label="要求 PKCE"
              checked={form.isPublic ? true : form.pkceRequired}
              disabled={form.isPublic}
              onChange={(e) => patch({ pkceRequired: e.target.checked })}
            />
            <Checkbox
              label="启用"
              checked={form.enabled}
              onChange={(e) => patch({ enabled: e.target.checked })}
            />
          </div>

          <p className="field__hint">
            公共客户端（PKCE）不需要 client_secret：密钥放在浏览器或 CLI 侧无法保密，PKCE
            用一次性的 code_verifier 替代它。
          </p>

          {createErr && <Alert kind="error">{createErr}</Alert>}
        </form>
      </Modal>

      {/* 编辑 */}
      <Modal
        open={editing != null}
        wide
        title={
          editing ? (
            <>
              编辑客户端 <span className="mono">{editing.client_id}</span>
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
            <Button type="submit" form="edit-client-form" variant="primary" disabled={editSub.busy}>
              {editSub.busy ? '保存中…' : '保存修改'}
            </Button>
          </>
        }
      >
        {editing && (
          <form id="edit-client-form" onSubmit={submitEdit} className="stack" style={{ gap: 14 }}>
            <Field label="client_id（创建后不可修改）">
              <Input value={editing.client_id} disabled />
            </Field>

            <Field label="应用名称">
              <Input
                value={editForm.clientName}
                onChange={(e) => setEditForm({ ...editForm, clientName: e.target.value })}
              />
            </Field>

            <Field
              label="回调地址"
              hint="必须完整 URL（http/https）；端口通配仅支持 127.0.0.1 / localhost"
            >
              <Textarea
                mono
                rows={3}
                value={editForm.redirects}
                onChange={(e) => setEditForm({ ...editForm, redirects: e.target.value })}
              />
            </Field>

            <Field label="scopes">
              <ScopePicker value={editForm.scopes} onChange={(v) => setEditForm({ ...editForm, scopes: v })} />
            </Field>

            <Field label="登出后回调地址" hint="每行一个，可留空">
              <Textarea
                mono
                rows={2}
                value={editForm.postLogout}
                onChange={(e) => setEditForm({ ...editForm, postLogout: e.target.value })}
              />
            </Field>

            <div className="row wrap" style={{ gap: 18 }}>
              <Checkbox
                label="公共客户端（无 client_secret，强制 PKCE）"
                checked={editForm.isPublic}
                onChange={(e) => setEditForm({ ...editForm, isPublic: e.target.checked })}
              />
              <Checkbox
                label="要求 PKCE"
                checked={editForm.isPublic ? true : editForm.pkceRequired}
                disabled={editForm.isPublic}
                onChange={(e) => setEditForm({ ...editForm, pkceRequired: e.target.checked })}
              />
              <Checkbox
                label="启用"
                checked={editForm.enabled}
                onChange={(e) => setEditForm({ ...editForm, enabled: e.target.checked })}
              />
            </div>

            {editErr && <Alert kind="error">{editErr}</Alert>}
          </form>
        )}
      </Modal>

      {/* 删除确认。错误留在框内展示，用户可以改主意或直接重试 */}
      <Confirm
        open={delTarget != null}
        title="删除客户端"
        danger
        busy={delSub.busy}
        confirmText="删除"
        message={
          <>
            <div>
              确认删除客户端 <span className="mono">{delTarget?.client_id}</span>？该操作会同时清理其令牌，
              且不可恢复。
            </div>
            {delErr && <Alert kind="error">{delErr}</Alert>}
          </>
        }
        onCancel={() => setDelTarget(null)}
        onConfirm={doDelete}
      />
    </>
  )
}

/** scope 多选。把预置项与「行上已有但不在预置里的自定义 scope」合并，编辑时不丢后端返回的值。 */
function ScopePicker({ value, onChange }: { value: string[]; onChange: (v: string[]) => void }) {
  const all = Array.from(new Set([...SCOPE_OPTIONS, ...value]))
  return (
    <div className="row wrap" style={{ gap: 14 }}>
      {all.map((s) => (
        <Checkbox
          key={s}
          label={<span className="mono">{s}</span>}
          checked={value.includes(s)}
          onChange={(e) => onChange(e.target.checked ? [...value, s] : value.filter((x) => x !== s))}
        />
      ))}
    </div>
  )
}

/**
 * 一次性 client_secret 区块。
 * 刻意不做自动消失——secret 只此一次，误关就永久丢失，只能重建客户端。
 * 复制走 Clipboard API，在非 HTTPS / 无权限环境会 reject，此时降级为手动复制提示。
 */
function CreatedSecret({
  data,
  onClose,
}: {
  data: { clientId: string; secret?: string; notice?: string }
  onClose: () => void
}) {
  const [copy, setCopy] = useState<'idle' | 'ok' | 'fail'>('idle')

  async function copySecret() {
    if (!data.secret) return
    try {
      await navigator.clipboard.writeText(data.secret)
      setCopy('ok')
    } catch {
      setCopy('fail')
    }
  }

  return (
    <div className="card" style={{ borderColor: 'var(--c-invert)', borderWidth: 2 }}>
      <div className="card__head">
        <div>
          <div className="card__title">客户端 {data.clientId} 创建成功</div>
          {data.notice && <div className="card__sub">{data.notice}</div>}
        </div>
        <Button size="sm" variant="ghost" onClick={onClose}>
          关闭
        </Button>
      </div>
      <div className="card__body">
        {data.secret ? (
          <div className="stack" style={{ gap: 8 }}>
            <div className="field__hint">
              client_secret 仅在创建时显示一次，请立即保存；关闭此区块后无法再次查看。
            </div>
            <div className="code-block" style={{ fontSize: 18, fontWeight: 600, letterSpacing: 0.5 }}>
              {data.secret}
            </div>
            <div className="row">
              <Button size="sm" variant="primary" onClick={copySecret}>
                复制
              </Button>
              {copy === 'ok' && <span className="dim">已复制到剪贴板</span>}
              {copy === 'fail' && <span className="dim">复制失败，请手动选中上面的密钥并复制</span>}
            </div>
          </div>
        ) : (
          <div className="field__hint">
            该客户端为公共客户端（PKCE），后端不生成 client_secret，无需保存密钥。
          </div>
        )}
      </div>
    </div>
  )
}
