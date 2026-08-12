import { render, screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { describe, expect, it, vi } from 'vitest'
import ErrorState from './ErrorState'

describe('ErrorState', () => {
  it('renders the default message with an alert role', () => {
    render(<ErrorState />)
    expect(screen.getByRole('alert')).toHaveTextContent('Something went wrong.')
  })

  it('renders a custom message and testId', () => {
    render(<ErrorState message="Failed to load projects." testId="projects-error" />)
    expect(screen.getByTestId('projects-error')).toHaveTextContent('Failed to load projects.')
  })

  it('calls onRetry when the Retry button is clicked', async () => {
    const onRetry = vi.fn()
    const user = userEvent.setup()
    render(<ErrorState message="Failed to load projects." onRetry={onRetry} />)
    await user.click(screen.getByRole('button', { name: 'Retry' }))
    expect(onRetry).toHaveBeenCalledTimes(1)
  })

  it('omits the Retry button when onRetry is not provided', () => {
    render(<ErrorState />)
    expect(screen.queryByRole('button', { name: 'Retry' })).not.toBeInTheDocument()
  })
})
