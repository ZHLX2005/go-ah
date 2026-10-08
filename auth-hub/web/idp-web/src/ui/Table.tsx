import type { ReactNode } from 'react'
import { Empty, Loading, cx } from './primitives'

export interface Column<T> {
  key: string
  title: ReactNode
  render: (row: T) => ReactNode
  width?: string | number
  align?: 'left' | 'right'
}

/**
 * 列表统一表格：只做「声明列 → 渲染行」。
 * 管理台三个面板都是后端全量返回，不需要分页层。
 */
export function DataTable<T>({
  columns,
  rows,
  rowKey,
  loading,
  empty = '暂无数据',
  onRowClick,
  actions,
  compact,
}: {
  columns: Column<T>[]
  rows: T[]
  rowKey: (row: T, index: number) => string | number
  loading?: boolean
  empty?: string
  onRowClick?: (row: T) => void
  actions?: (row: T) => ReactNode
  compact?: boolean
}) {
  if (loading) return <Loading />
  if (rows.length === 0) return <Empty text={empty} />

  return (
    <div className="table-wrap">
      <table className={cx('table', compact && 'table--compact', onRowClick != null && 'table--clickable')}>
        <thead>
          <tr>
            {columns.map((c) => (
              <th key={c.key} style={{ width: c.width, textAlign: c.align }}>
                {c.title}
              </th>
            ))}
            {actions != null && <th className="table__actions">操作</th>}
          </tr>
        </thead>
        <tbody>
          {rows.map((row, i) => (
            <tr key={rowKey(row, i)} onClick={onRowClick != null ? () => onRowClick(row) : undefined}>
              {columns.map((c) => (
                <td key={c.key} style={{ textAlign: c.align }}>
                  {c.render(row)}
                </td>
              ))}
              {actions != null && (
                /* 行内操作不能触发行点击 */
                <td className="table__actions" onClick={(e) => e.stopPropagation()}>
                  {actions(row)}
                </td>
              )}
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  )
}
