import { render, screen } from '@testing-library/react'
import { afterEach, describe, expect, it } from 'vitest'
import { MemoryRouter } from 'react-router-dom'
import { AppRoutes } from './App'
import { clearToken } from './lib/storage'

afterEach(() => {
  clearToken()
  sessionStorage.clear()
})

describe('AppRoutes', () => {
  it('redirects to the login page when no admin token is stored', () => {
    render(
      <MemoryRouter initialEntries={['/']}>
        <AppRoutes />
      </MemoryRouter>,
    )
    expect(screen.getByPlaceholderText('Admin token')).toBeInTheDocument()
  })

  it('renders the dashboard when an admin token is stored', () => {
    sessionStorage.setItem('dependaproxy.admin_token', 'tok-123')
    render(
      <MemoryRouter initialEntries={['/']}>
        <AppRoutes />
      </MemoryRouter>,
    )
    expect(screen.getByRole('heading', { name: /dependaproxy/i })).toBeInTheDocument()
    expect(screen.queryByPlaceholderText('Admin token')).not.toBeInTheDocument()
  })
})
