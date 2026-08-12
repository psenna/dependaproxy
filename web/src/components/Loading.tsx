interface LoadingProps {
  label?: string
  testId?: string
  variant?: 'spinner' | 'skeleton'
  className?: string
}

export default function Loading({
  label = 'Loading…',
  testId,
  variant = 'spinner',
  className = '',
}: LoadingProps) {
  if (variant === 'skeleton') {
    return (
      <div
        role="status"
        aria-busy="true"
        aria-live="polite"
        data-testid={testId}
        className={`animate-pulse ${className}`}
      >
        <div className="h-4 w-2/3 rounded bg-gray-200" />
        <div className="mt-2 h-4 w-1/2 rounded bg-gray-200" />
        <div className="mt-2 h-4 w-3/4 rounded bg-gray-200" />
        <span className="sr-only">{label}</span>
      </div>
    )
  }

  return (
    <div
      role="status"
      aria-busy="true"
      aria-live="polite"
      data-testid={testId}
      className={`flex items-center gap-2 ${className}`}
    >
      <svg
        aria-hidden="true"
        className="h-5 w-5 animate-spin text-gray-500"
        viewBox="0 0 24 24"
        fill="none"
      >
        <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4" />
        <path
          className="opacity-75"
          fill="currentColor"
          d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z"
        />
      </svg>
      <span>{label}</span>
    </div>
  )
}
