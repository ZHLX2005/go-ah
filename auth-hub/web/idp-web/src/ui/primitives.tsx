/**
 * 基础组件（黑白灰主题的原子层）。
 *
 * 与 gs-ac 控制台（go-ac/web/src/ui/primitives.tsx）刻意保持一致 ——
 * 两个项目共用一套设计语言。组件里**不出现任何色相**，
 * 状态差异一律交给 app.css 用明度、字重、边框粗细表达。
 */
import { Fragment } from 'react'
import type {
  ButtonHTMLAttributes,
  InputHTMLAttributes,
  ReactNode,
  SelectHTMLAttributes,
  TextareaHTMLAttributes,
} from 'react'

function cx(...parts: (string | false | null | undefined)[]): string {
  return parts.filter(Boolean).join(' ')
}

// ── 按钮 ────────────────────────────────────────────────────────────────────

type ButtonVariant = 'default' | 'primary' | 'danger' | 'ghost'

export function Button({
  variant = 'default',
  size,
  block,
  className,
  ...rest
}: ButtonHTMLAttributes<HTMLButtonElement> & {
  variant?: ButtonVariant
  size?: 'sm' | 'lg'
  block?: boolean
}) {
  return (
    <button
      {...rest}
      className={cx(
        'btn',
        variant === 'primary' && 'btn--primary',
        variant === 'danger' && 'btn--danger',
        variant === 'ghost' && 'btn--ghost',
        size === 'sm' && 'btn--sm',
        size === 'lg' && 'btn--lg',
        block && 'btn--block',
        className,
      )}
    />
  )
}

// ── 表单控件 ────────────────────────────────────────────────────────────────

/**
 * 注意 Omit<'size'>：HTML 原生 input 就有 size（字符宽度，number），
 * 不摘掉的话自定义的 size?: 'lg' 会与它交叉成 `number & 'lg'`，
 * 等于谁都传不进去。
 */
export function Input({
  className,
  size,
  type = 'text',
  ...rest
}: Omit<InputHTMLAttributes<HTMLInputElement>, 'size'> & { size?: 'lg' }) {
  // 显式写出 type：不写时浏览器也按 text 处理，但**属性不会出现在 DOM 里**，
  // 于是 `input[type=text]` 这类属性选择器永远匹配不到 —— e2e 里就是这么
  // 定位账号框的（tests/helpers.ts），外部验收脚本也按同样约定写。
  // 属性缺省值等价于 text，这里补上不改变任何行为，只是把隐式约定显式化。
  return (
    <input type={type} {...rest} className={cx('input', size === 'lg' && 'input--lg', className)} />
  )
}

export function Select({ className, children, ...rest }: SelectHTMLAttributes<HTMLSelectElement>) {
  return (
    <select {...rest} className={cx('select', className)}>
      {children}
    </select>
  )
}

export function Textarea({
  className,
  mono,
  ...rest
}: TextareaHTMLAttributes<HTMLTextAreaElement> & { mono?: boolean }) {
  return <textarea {...rest} className={cx('textarea', mono && 'textarea--mono', className)} />
}

export function Checkbox({
  label,
  ...rest
}: InputHTMLAttributes<HTMLInputElement> & { label: ReactNode }) {
  return (
    <label className="checkbox-row">
      <input type="checkbox" {...rest} />
      <span>{label}</span>
    </label>
  )
}

/** 表单字段壳：统一 标签 / 控件 / 提示 / 错误 的排版 */
export function Field({
  label,
  hint,
  error,
  full,
  children,
}: {
  label?: ReactNode
  hint?: ReactNode
  error?: ReactNode
  full?: boolean
  children: ReactNode
}) {
  return (
    <div className={cx('field', full && 'form-grid--full')}>
      {label != null && <label className="field__label">{label}</label>}
      {children}
      {error != null ? (
        <span className="field__error">{error}</span>
      ) : (
        hint != null && <span className="field__hint">{hint}</span>
      )}
    </div>
  )
}

// ── 展示 ────────────────────────────────────────────────────────────────────

export function Card({
  title,
  sub,
  extra,
  flush,
  children,
}: {
  title?: ReactNode
  sub?: ReactNode
  extra?: ReactNode
  flush?: boolean
  children?: ReactNode
}) {
  return (
    <section className="card">
      {(title != null || extra != null) && (
        <header className="card__head">
          <div>
            {title != null && <div className="card__title">{title}</div>}
            {sub != null && <div className="card__sub">{sub}</div>}
          </div>
          {extra}
        </header>
      )}
      {children != null && (
        <div className={cx('card__body', flush && 'card__body--flush')}>{children}</div>
      )}
    </section>
  )
}

export function Badge({
  children,
  variant = 'default',
  mono,
  strike,
  title,
}: {
  children: ReactNode
  variant?: 'default' | 'solid' | 'quiet'
  mono?: boolean
  strike?: boolean
  title?: string
}) {
  return (
    <span
      title={title}
      className={cx(
        'badge',
        variant === 'solid' && 'badge--solid',
        variant === 'quiet' && 'badge--quiet',
        mono && 'badge--mono',
        strike && 'badge--strike',
      )}
    >
      {children}
    </span>
  )
}

export function TagList({ items, empty }: { items?: string[]; empty?: string }) {
  if (!items || items.length === 0) return <span className="dim">{empty ?? '—'}</span>
  return (
    <span className="tag-list">
      {items.map((t) => (
        <Badge key={t} variant="quiet" mono>
          {t}
        </Badge>
      ))}
    </span>
  )
}

export function Alert({
  kind = 'info',
  children,
}: {
  kind?: 'info' | 'error' | 'ok'
  children: ReactNode
}) {
  return (
    <div className={cx('alert', kind === 'error' && 'alert--error', kind === 'ok' && 'alert--ok')}>
      <div>{children}</div>
    </div>
  )
}

export function Spinner() {
  return <span className="spinner" />
}

export function Loading({ text = '加载中…' }: { text?: string }) {
  return (
    <div className="loading-block">
      <Spinner />
      <span>{text}</span>
    </div>
  )
}

export function Empty({ text = '暂无数据' }: { text?: string }) {
  return <div className="empty">{text}</div>
}

export function Stat({ label, value, hint }: { label: ReactNode; value: ReactNode; hint?: ReactNode }) {
  return (
    <div className="stat">
      <div className="stat__label">{label}</div>
      <div className="stat__value">{value}</div>
      {hint != null && <div className="stat__hint">{hint}</div>}
    </div>
  )
}

/** 键值表：详情统一用它，避免每处各写一套 dl/dt/dd */
export function KeyValues({ items }: { items: { k: ReactNode; v: ReactNode }[] }) {
  return (
    <div className="kv">
      {items.map((it, i) => (
        <Fragment key={i}>
          <div className="kv__k">{it.k}</div>
          <div className="kv__v">{it.v}</div>
        </Fragment>
      ))}
    </div>
  )
}

export function CodeBlock({ children }: { children: ReactNode }) {
  return <pre className="code-block">{children}</pre>
}

export { cx }
