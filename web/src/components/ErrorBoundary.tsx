import { Component, type ErrorInfo, type ReactNode } from 'react'

interface ErrorBoundaryProps {
  children: ReactNode
  fallback?: (error: Error, reset: () => void) => ReactNode
}

interface ErrorBoundaryState {
  error: Error | null
}

export default class ErrorBoundary extends Component<ErrorBoundaryProps, ErrorBoundaryState> {
  state: ErrorBoundaryState = { error: null }

  static getDerivedStateFromError(error: Error): ErrorBoundaryState {
    return { error }
  }

  componentDidCatch(error: Error, info: ErrorInfo) {
    if (import.meta.env?.DEV) {
      console.error('ErrorBoundary caught an error:', error, info)
    }
  }

  reset = () => {
    this.setState({ error: null })
  }

  render() {
    const { error } = this.state
    if (error !== null) {
      if (this.props.fallback) {
        return this.props.fallback(error, this.reset)
      }
      return (
        <div
          role="alert"
          data-testid="error-boundary"
          className="rounded border border-red-500 bg-red-50 p-4 text-red-800"
        >
          <h1 className="text-lg font-semibold">Something went wrong</h1>
          <p className="mt-1 text-sm">{error.message}</p>
          <button
            type="button"
            onClick={this.reset}
            className="mt-3 rounded bg-red-600 px-3 py-1 text-sm text-white hover:bg-red-700"
          >
            Try again
          </button>
        </div>
      )
    }
    return this.props.children
  }
}
