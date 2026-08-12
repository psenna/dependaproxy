import type { ReactNode } from 'react'

export interface EmptyStateProps {
  icon?: ReactNode
  title: string
  message?: string
  children?: ReactNode
}

export default function EmptyState({ icon, title, message, children }: EmptyStateProps) {
  return (
    <div className="flex flex-col items-center justify-center rounded border-2 border-dashed border-gray-300 p-8 text-center">
      {icon && <div className="mb-2 text-gray-400">{icon}</div>}
      <h3 className="text-lg font-semibold text-gray-700">{title}</h3>
      {message && <p className="mt-1 text-sm text-gray-500">{message}</p>}
      {children && <div className="mt-4">{children}</div>}
    </div>
  )
}
