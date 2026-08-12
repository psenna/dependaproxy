import { render, screen } from '@testing-library/react'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { afterEach, describe, expect, it } from 'vitest'
import { MemoryRouter } from 'react-router-dom'
import { AppRoutes } from './router'
import { clearToken } from './lib/storage'

function renderApp(initialPath: string) {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false, gcTime: 0, staleTime: 0 } } })
  render(
    <QueryClientProvider client={client}>
      <MemoryRouter initialEntries={[initialPath]}>
        <AppRoutes />
      </MemoryRouter>
    </QueryClientProvider>,
  )
}

afterEach(() => {
  clearToken()
  sessionStorage.clear()
})

describe('AppRoutes', () => {
  it('redirects to the login page when no admin token is stored', () => {
    renderApp('/')
    expect(screen.getByPlaceholderText('Admin token')).toBeInTheDocument()
  })

  it('renders the dashboard when an admin token is stored', async () => {
    sessionStorage.setItem('dependaproxy.admin_token', 'tok-123')
    renderApp('/')
    expect(await screen.findByText(/proxy healthy/i)).toBeInTheDocument()
    expect(screen.queryByPlaceholderText('Admin token')).not.toBeInTheDocument()
  })
})
