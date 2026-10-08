import { createContext, useCallback, useContext, useMemo, useRef, useState } from 'react'
import type { ReactNode } from 'react'

type ToastItem = { id: number; text: string; kind: 'ok' | 'err' }

interface ToastApi {
  ok: (text: string) => void
  err: (text: string) => void
}

const ToastCtx = createContext<ToastApi | null>(null)

const DURATION: Record<ToastItem['kind'], number> = { ok: 3200, err: 5200 }

export function ToastProvider({ children }: { children: ReactNode }) {
  const [items, setItems] = useState<ToastItem[]>([])
  const seq = useRef(0)

  const push = useCallback((text: string, kind: ToastItem['kind']) => {
    const id = ++seq.current
    setItems((prev) => [...prev, { id, text, kind }])
    window.setTimeout(() => {
      setItems((prev) => prev.filter((t) => t.id !== id))
    }, DURATION[kind])
  }, [])

  const api = useMemo<ToastApi>(
    () => ({
      ok: (text) => push(text, 'ok'),
      err: (text) => push(text, 'err'),
    }),
    [push],
  )

  return (
    <ToastCtx.Provider value={api}>
      {children}
      <div className="toast-host">
        {items.map((t) => (
          <div key={t.id} className={`toast toast--${t.kind}`} role="status">
            {t.text}
          </div>
        ))}
      </div>
    </ToastCtx.Provider>
  )
}

export function useToast(): ToastApi {
  const ctx = useContext(ToastCtx)
  if (ctx == null) throw new Error('useToast 必须在 <ToastProvider> 内使用')
  return ctx
}
