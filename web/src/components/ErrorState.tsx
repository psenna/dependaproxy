import type { ReactNode } from 'react'

interface ErrorStateProps {
  message?: string
  onRetry?: () => void
  retryLabel?: string
  testId?: string
  children?: ReactNode
}

export default function ErrorState({
  message = 'Something went wrong.',
  onRetry,
  retryLabel = 'Retry',
  testId,
  children,
}: ErrorStateProps) {
  return (
    <div
      role="alert"
      data-testid={testId}
      className="rounded border border-red-500 bg-red-50 p-3 text-red-800"
    >
      <p>{message}</p>
      {children}
      {onRetry && (
        <button
          type="button"
          onClick={onRetry}
          className="mt-2 rounded bg-red-600 px-3 py-1 text-sm text-white hover:bg-red-700"
        >
          {retryLabel}
        </button>
      )}
    </div>
  )
}
