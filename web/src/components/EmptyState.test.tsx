import { render, screen } from '@testing-library/react'
import { describe, expect, it } from 'vitest'
import EmptyState from './EmptyState'

describe('EmptyState', () => {
  it('renders title, message, icon, and children CTA', () => {
    render(
      <EmptyState
        title="No projects yet"
        message="Create your first project to start managing registries."
        icon={<span data-testid="empty-icon">icon</span>}
      >
        <button type="button">Create project</button>
      </EmptyState>,
    )
    expect(screen.getByRole('heading', { name: 'No projects yet' })).toBeInTheDocument()
    expect(screen.getByText('Create your first project to start managing registries.')).toBeInTheDocument()
    expect(screen.getByTestId('empty-icon')).toBeInTheDocument()
    expect(screen.getByRole('button', { name: 'Create project' })).toBeInTheDocument()
  })

  it('omits message, icon, and children when not provided', () => {
    render(<EmptyState title="No projects yet" />)
    expect(screen.getByRole('heading', { name: 'No projects yet' })).toBeInTheDocument()
    expect(screen.queryByText('Create your first project to start managing registries.')).not.toBeInTheDocument()
    expect(screen.queryByTestId('empty-icon')).not.toBeInTheDocument()
    expect(screen.queryByRole('button')).not.toBeInTheDocument()
  })
})
