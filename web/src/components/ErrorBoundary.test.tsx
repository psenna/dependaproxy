import { render, screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import ErrorBoundary from './ErrorBoundary'

// The error boundary unmounts the failed subtree, so component state cannot
// survive a reset. ThrowOnce throws on every render until the test flips the
// module-level flag (after the fallback appears), then renders normally.
let hasThrown = false

function ThrowOnce() {
  if (hasThrown) {
    return <div data-testid="recovered">recovered</div>
  }
  throw new Error('boom')
}

describe('ErrorBoundary', () => {
  let consoleSpy: ReturnType<typeof vi.spyOn>

  beforeEach(() => {
    hasThrown = false
    consoleSpy = vi.spyOn(console, 'error').mockImplementation(() => {})
  })

  afterEach(() => {
    consoleSpy.mockRestore()
  })

  it('renders the fallback when a child throws', () => {
    render(
      <ErrorBoundary>
        <ThrowOnce />
      </ErrorBoundary>,
    )
    expect(screen.getByTestId('error-boundary')).toBeInTheDocument()
    expect(screen.getByRole('heading', { name: 'Something went wrong' })).toBeInTheDocument()
    expect(screen.getByRole('button', { name: 'Try again' })).toBeInTheDocument()
  })

  it('recovers after clicking Try again', async () => {
    const user = userEvent.setup()
    render(
      <ErrorBoundary>
        <ThrowOnce />
      </ErrorBoundary>,
    )
    expect(screen.getByTestId('error-boundary')).toBeInTheDocument()
    hasThrown = true
    await user.click(screen.getByRole('button', { name: 'Try again' }))
    expect(screen.getByTestId('recovered')).toBeInTheDocument()
  })

  it('passes the error and reset to a custom fallback render prop', () => {
    let capturedError: Error | null = null
    let capturedReset: (() => void) | null = null
    render(
      <ErrorBoundary
        fallback={(error, reset) => {
          capturedError = error
          capturedReset = reset
          return <div data-testid="custom-fallback">{error.message}</div>
        }}
      >
        <ThrowOnce />
      </ErrorBoundary>,
    )
    expect(screen.getByTestId('custom-fallback')).toHaveTextContent('boom')
    expect(capturedError).toBeInstanceOf(Error)
    expect(capturedReset).toBeTypeOf('function')
  })
})
