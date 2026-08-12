import { render, screen } from '@testing-library/react'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { http, HttpResponse } from 'msw'
import { afterEach, beforeEach, describe, expect, it } from 'vitest'
import { MemoryRouter } from 'react-router-dom'
import { server } from '../../vitest.setup'
import { createAdminHandlers, notConfigured401 } from '../test/handlers'
import { clearToken } from '../lib/storage'
import DashboardPage from './DashboardPage'

beforeEach(() => {
  server.use(...createAdminHandlers())
  sessionStorage.setItem('dependaproxy.admin_token', 'tok-123')
})

afterEach(() => {
  clearToken()
  sessionStorage.clear()
})

function renderDashboard() {
  const client = new QueryClient({
    defaultOptions: { queries: { retry: false, retryDelay: 0, gcTime: 0, staleTime: 0 } },
  })
  render(
    <QueryClientProvider client={client}>
      <MemoryRouter>
        <DashboardPage />
      </MemoryRouter>
    </QueryClientProvider>,
  )
}

describe('DashboardPage', () => {
  it('shows a healthy proxy and the project count', async () => {
    renderDashboard()
    expect(await screen.findByText(/proxy healthy/i)).toBeInTheDocument()
    expect(screen.getByText(/projects:\s*1/i)).toBeInTheDocument()
  })

  it('shows an unreachable proxy when healthz fails', async () => {
    server.use(http.get('/healthz', () => HttpResponse.text('down', { status: 500 })))
    renderDashboard()
    expect(await screen.findByText(/proxy unreachable/i)).toBeInTheDocument()
  })

  it('reflects the project count from the fixture', async () => {
    const p1 = { key: 'a', registries: {} }
    const p2 = { key: 'b', registries: {} }
    const p3 = { key: 'c', registries: {} }
    server.use(http.get('*/admin/projects', () => HttpResponse.json({ projects: [p1, p2, p3] })))
    renderDashboard()
    expect(await screen.findByText(/projects:\s*3/i)).toBeInTheDocument()
  })

  it('does not crash when the projects request fails', async () => {
    server.use(notConfigured401)
    renderDashboard()
    expect(await screen.findByText(/projects:\s*unavailable/i)).toBeInTheDocument()
    expect(screen.getByText(/proxy healthy/i)).toBeInTheDocument()
  })
})
