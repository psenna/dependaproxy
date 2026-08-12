import { render, screen } from '@testing-library/react'
import { describe, expect, it } from 'vitest'
import Loading from './Loading'

describe('Loading', () => {
  it('renders a default spinner with a status role and polite live region', () => {
    render(<Loading />)
    const status = screen.getByRole('status')
    expect(status).toHaveAttribute('aria-busy', 'true')
    expect(status).toHaveAttribute('aria-live', 'polite')
    expect(screen.getByText('Loading…')).toBeInTheDocument()
  })

  it('passes through a custom testId', () => {
    render(<Loading testId="projects-loading" />)
    expect(screen.getByTestId('projects-loading')).toBeInTheDocument()
  })

  it('renders a custom label', () => {
    render(<Loading label="Checking proxy status…" />)
    expect(screen.getByText('Checking proxy status…')).toBeInTheDocument()
  })

  it('renders the skeleton variant with an sr-only label', () => {
    render(<Loading variant="skeleton" label="Loading projects…" />)
    const status = screen.getByRole('status')
    expect(status).toHaveClass('animate-pulse')
    expect(screen.getByText('Loading projects…')).toHaveClass('sr-only')
  })
})
