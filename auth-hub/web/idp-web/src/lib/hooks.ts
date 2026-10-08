import { useCallback, useEffect, useRef, useState } from 'react'
import { ApiFailure } from '@/api/client'

export interface AsyncState<T> {
  data: T | null
  loading: boolean
  error: string | null
  reload: () => void
}

/**
 * 数据加载 hook：把「加载中 / 出错 / 重取」收敛到一处。
 * deps 变化自动重取；组件卸载后丢弃结果。
 */
export function useAsync<T>(fn: () => Promise<T>, deps: unknown[]): AsyncState<T> {
  const [data, setData] = useState<T | null>(null)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)
  const [tick, setTick] = useState(0)
  const alive = useRef(true)

  useEffect(() => {
    alive.current = true
    return () => {
      alive.current = false
    }
  }, [])

  useEffect(() => {
    setLoading(true)
    setError(null)
    fn()
      .then((r) => {
        if (alive.current) setData(r)
      })
      .catch((e: unknown) => {
        if (!alive.current) return
        setError(errText(e))
      })
      .finally(() => {
        if (alive.current) setLoading(false)
      })
    // fn 每次渲染都是新引用，故只依赖调用方声明的 deps
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [...deps, tick])

  const reload = useCallback(() => setTick((t) => t + 1), [])
  return { data, loading, error, reload }
}

/** 提交类操作：统一维护 busy 状态。异常原样抛出，由调用方决定怎么提示。 */
export function useSubmit() {
  const [busy, setBusy] = useState(false)
  const run = useCallback(async <R,>(fn: () => Promise<R>): Promise<R> => {
    setBusy(true)
    try {
      return await fn()
    } finally {
      setBusy(false)
    }
  }, [])
  return { busy, run }
}

/** 受控表单：避免每个字段写一个 useState */
export function useForm<T extends Record<string, unknown>>(initial: T) {
  const initialRef = useRef(initial)
  const [form, setForm] = useState<T>(initial)
  const set = useCallback(<K extends keyof T>(key: K, value: T[K]) => {
    setForm((prev) => ({ ...prev, [key]: value }))
  }, [])
  const reset = useCallback((next?: Partial<T>) => {
    setForm(next ? { ...initialRef.current, ...next } : initialRef.current)
  }, [])
  return { form, set, reset, setForm }
}

export function errText(e: unknown): string {
  if (e instanceof ApiFailure) return e.message
  return (e as Error)?.message ?? String(e)
}
