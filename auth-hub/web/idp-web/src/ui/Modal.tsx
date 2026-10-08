import { useEffect } from 'react'
import type { ReactNode } from 'react'
import { Button, cx } from './primitives'

/** 弹窗：固定定位 + 遮罩，不引 portal */
export function Modal({
  open,
  title,
  wide,
  onClose,
  footer,
  children,
}: {
  open: boolean
  title: ReactNode
  wide?: boolean
  onClose: () => void
  footer?: ReactNode
  children: ReactNode
}) {
  useEffect(() => {
    if (!open) return
    const onKey = (e: KeyboardEvent) => {
      if (e.key === 'Escape') onClose()
    }
    window.addEventListener('keydown', onKey)
    return () => window.removeEventListener('keydown', onKey)
  }, [open, onClose])

  if (!open) return null

  return (
    <div
      className="modal__mask"
      /* 只有点遮罩本身才关；点弹窗内部冒泡上来的不算 */
      onMouseDown={(e) => {
        if (e.target === e.currentTarget) onClose()
      }}
    >
      <div className={cx('modal', wide && 'modal--wide')} role="dialog" aria-modal="true">
        <header className="modal__head">
          <div className="modal__title">{title}</div>
          <Button variant="ghost" size="sm" onClick={onClose} aria-label="关闭">
            ✕
          </Button>
        </header>
        <div className="modal__body">{children}</div>
        {footer != null && <footer className="modal__foot">{footer}</footer>}
      </div>
    </div>
  )
}

/** 二次确认。破坏性操作一律走它。 */
export function Confirm({
  open,
  title,
  message,
  confirmText = '确认',
  danger,
  busy,
  onCancel,
  onConfirm,
}: {
  open: boolean
  title: ReactNode
  message: ReactNode
  confirmText?: string
  danger?: boolean
  busy?: boolean
  onCancel: () => void
  onConfirm: () => void
}) {
  return (
    <Modal
      open={open}
      title={title}
      onClose={onCancel}
      footer={
        <>
          <Button onClick={onCancel} disabled={busy}>
            取消
          </Button>
          <Button variant={danger ? 'danger' : 'primary'} onClick={onConfirm} disabled={busy}>
            {busy ? '处理中…' : confirmText}
          </Button>
        </>
      }
    >
      <div className="muted">{message}</div>
    </Modal>
  )
}
