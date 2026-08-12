import { act, fireEvent, render, screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { http, HttpResponse } from 'msw'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { MemoryRouter, Route, Routes } from 'react-router-dom'
import { server } from '../../vitest.setup'
import { createAdminHandlers, defaultFixtures, type Fixtures } from '../test/handlers'
import { clearToken } from '../lib/storage'
import ProjectDetailPage from './ProjectDetailPage'

const originalClipboard = navigator.clipboard

beforeEach(() => {
  server.use(...createAdminHandlers())
  sessionStorage.setItem('dependaproxy.admin_token', 'tok-123')
})

afterEach(() => {
  clearToken()
  sessionStorage.clear()
  Object.defineProperty(navigator, 'clipboard', {
    configurable: true,
    value: originalClipboard,
  })
  vi.useRealTimers()
})

// userEvent.setup() attaches its own clipboard stub to navigator.clipboard, so
// the mock must be installed after setup() to take effect.
function setupUser() {
  const user = userEvent.setup()
  Object.defineProperty(navigator, 'clipboard', {
    configurable: true,
    value: { writeText: vi.fn().mockResolvedValue(undefined) },
  })
  return user
}

function renderDetail(initialPath = '/projects/my-app', debounceMs = 400) {
  const client = new QueryClient({
    defaultOptions: { queries: { retry: false, retryDelay: 0, gcTime: 0, staleTime: 0 } },
  })
  render(
    <QueryClientProvider client={client}>
      <MemoryRouter initialEntries={[initialPath]}>
        <Routes>
          <Route path="/projects/:key" element={<ProjectDetailPage debounceMs={debounceMs} />} />
        </Routes>
      </MemoryRouter>
    </QueryClientProvider>,
  )
}

describe('ProjectDetailPage', () => {
  it('renders the config overview with an edit link', async () => {
    renderDetail('/projects/my-app')
    expect(await screen.findByTestId('project-detail')).toBeInTheDocument()
    expect(screen.getByRole('heading', { name: 'Project my-app' })).toBeInTheDocument()
    expect(screen.getByTestId('project-registries')).toHaveTextContent('npm')
    expect(screen.getByRole('link', { name: 'Edit' })).toHaveAttribute('href', '/projects/my-app/edit')
  })

  it('renders the SBOM table with all columns', async () => {
    const user = setupUser()
    renderDetail('/projects/my-app')
    await screen.findByTestId('project-detail')
    await user.click(screen.getByRole('tab', { name: 'Dependencies' }))
    const table = await screen.findByTestId('dependencies-table')
    expect(table).toBeInTheDocument()
    const row = screen.getByTestId('dependency-row-0')
    expect(row).toHaveTextContent('npm')
    expect(row).toHaveTextContent('react')
    expect(row).toHaveTextContent('18.3.1')
    expect(row).toHaveTextContent('react-18.3.1.tgz')
    expect(row).toHaveTextContent('abc123…')
    expect(screen.getByTitle('abc123')).toBeInTheDocument()
    expect(row).toHaveTextContent('2026-01-01T00:00:00Z')
    expect(row).toHaveTextContent('2026-01-02T00:00:00Z')
    expect(row).toHaveTextContent('3')
  })

  it('shows the empty state when dependencies are unavailable', async () => {
    const fix: Fixtures = { ...defaultFixtures, dependencies: {} }
    server.use(...createAdminHandlers(fix))
    const user = setupUser()
    renderDetail('/projects/my-app')
    await screen.findByTestId('project-detail')
    await user.click(screen.getByRole('tab', { name: 'Dependencies' }))
    const empty = await screen.findByTestId('dependencies-empty')
    expect(empty).toHaveTextContent('No dependencies recorded yet')
    expect(empty).toHaveTextContent('flushed asynchronously')
    expect(screen.queryByTestId('dependencies-table')).not.toBeInTheDocument()
    expect(screen.queryByTestId('dependencies-error')).not.toBeInTheDocument()
  })

  it('filters dependencies by package', async () => {
    const urls: string[] = []
    server.use(
      http.get('*/admin/projects/:key/dependencies', ({ request }) => {
        urls.push(request.url)
        return HttpResponse.json({ dependencies: [] })
      }),
    )
    const user = setupUser()
    renderDetail('/projects/my-app', 0)
    await screen.findByTestId('project-detail')
    await user.click(screen.getByRole('tab', { name: 'Dependencies' }))
    await user.type(screen.getByTestId('filter-pkg'), 'rea')
    await waitFor(() => expect(urls.some((u) => new URL(u).searchParams.get('pkg') === 'rea')).toBe(true))
    await user.clear(screen.getByTestId('filter-pkg'))
    await waitFor(() => {
      const last = urls[urls.length - 1]
      expect(new URL(last).searchParams.has('pkg')).toBe(false)
    })
  })

  it('debounces filter input by the default 400ms', async () => {
    const urls: string[] = []
    server.use(
      http.get('*/admin/projects/:key/dependencies', ({ request }) => {
        urls.push(request.url)
        return HttpResponse.json({ dependencies: [] })
      }),
    )
    vi.useFakeTimers()
    renderDetail('/projects/my-app', 400)
    await act(async () => {
      await vi.advanceTimersByTimeAsync(0)
    })
    expect(screen.getByTestId('project-detail')).toBeInTheDocument()
    fireEvent.click(screen.getByRole('tab', { name: 'Dependencies' }))
    await act(async () => {
      await vi.advanceTimersByTimeAsync(0)
    })
    expect(urls).toHaveLength(1)
    fireEvent.change(screen.getByTestId('filter-pkg'), { target: { value: 'rea' } })
    await act(async () => {
      await vi.advanceTimersByTimeAsync(0)
    })
    expect(urls).toHaveLength(1)
    await act(async () => {
      await vi.advanceTimersByTimeAsync(400)
    })
    expect(urls).toHaveLength(2)
    expect(new URL(urls[1]).searchParams.get('pkg')).toBe('rea')
  })

  it('copies the full sha256 to the clipboard', async () => {
    const user = setupUser()
    renderDetail('/projects/my-app')
    await screen.findByTestId('project-detail')
    await user.click(screen.getByRole('tab', { name: 'Dependencies' }))
    await screen.findByTestId('dependencies-table')
    await user.click(screen.getByTestId('sha256-copy-0'))
    expect(navigator.clipboard.writeText).toHaveBeenCalledWith('abc123')
    expect(await screen.findByText('Copied')).toBeInTheDocument()
  })

  it('shows a not-found error for a missing project', async () => {
    renderDetail('/projects/nope')
    expect(await screen.findByTestId('project-error')).toHaveTextContent('Project not found')
    expect(screen.queryByRole('tab')).not.toBeInTheDocument()
  })
})
