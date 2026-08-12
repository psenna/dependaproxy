import { render, screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { http, HttpResponse } from 'msw'
import { useState } from 'react'
import { afterEach, beforeEach, describe, expect, it } from 'vitest'
import { server } from '../../../vitest.setup'
import { createAdminHandlers, jsonError } from '../../test/handlers'
import { clearToken } from '../../lib/storage'
import { useDependencies, type DependenciesFilters } from './useDependencies'

function Harness({ projectKey, filters }: { projectKey: string; filters?: DependenciesFilters }) {
  const result = useDependencies(projectKey, filters)
  return <div data-testid="result">{JSON.stringify({ data: result.data, isError: result.isError, status: result.status })}</div>
}

function renderHarness(key: string, filters?: DependenciesFilters) {
  const client = new QueryClient({
    defaultOptions: { queries: { retry: false, retryDelay: 0, gcTime: 0, staleTime: 0 } },
  })
  render(
    <QueryClientProvider client={client}>
      <Harness projectKey={key} filters={filters} />
    </QueryClientProvider>,
  )
}

function readResult() {
  return JSON.parse(screen.getByTestId('result').textContent!) as {
    data: { dependencies: unknown[] } | undefined
    isError: boolean
    status: string
  }
}

beforeEach(() => {
  server.use(...createAdminHandlers())
  sessionStorage.setItem('dependaproxy.admin_token', 'tok-123')
})

afterEach(() => {
  clearToken()
  sessionStorage.clear()
})

describe('useDependencies', () => {
  it('omits empty filters from the request URL and returns the dependency list', async () => {
    let capturedUrl: string | null = null
    server.use(
      http.get('*/admin/projects/:key/dependencies', ({ request }) => {
        capturedUrl = request.url
        return HttpResponse.json({ dependencies: [] })
      }),
    )
    renderHarness('my-app', {})
    await waitFor(() => expect(capturedUrl).not.toBeNull())
    const url = new URL(capturedUrl!)
    expect(url.searchParams.has('registry')).toBe(false)
    expect(url.searchParams.has('pkg')).toBe(false)
    await waitFor(() => expect(readResult().status).toBe('success'))
    expect(readResult().data).toEqual({ dependencies: [] })
  })

  it('includes non-empty filters in the request URL', async () => {
    let capturedUrl: string | null = null
    server.use(
      http.get('*/admin/projects/:key/dependencies', ({ request }) => {
        capturedUrl = request.url
        return HttpResponse.json({ dependencies: [] })
      }),
    )
    renderHarness('my-app', { registry: 'npm', pkg: 'react' })
    await waitFor(() => expect(capturedUrl).not.toBeNull())
    const url = new URL(capturedUrl!)
    expect(url.searchParams.get('registry')).toBe('npm')
    expect(url.searchParams.get('pkg')).toBe('react')
  })

  it('omits whitespace-only filters from the request URL', async () => {
    let capturedUrl: string | null = null
    server.use(
      http.get('*/admin/projects/:key/dependencies', ({ request }) => {
        capturedUrl = request.url
        return HttpResponse.json({ dependencies: [] })
      }),
    )
    renderHarness('my-app', { registry: '', pkg: '   ' })
    await waitFor(() => expect(capturedUrl).not.toBeNull())
    const url = new URL(capturedUrl!)
    expect(url.searchParams.has('registry')).toBe(false)
    expect(url.searchParams.has('pkg')).toBe(false)
  })

  it('treats a 404 as an empty dependency list', async () => {
    server.use(http.get('*/admin/projects/:key/dependencies', () => jsonError(404, 'no dependencies for project')))
    renderHarness('my-app', {})
    await waitFor(() => expect(readResult().status).toBe('success'))
    expect(readResult().isError).toBe(false)
    expect(readResult().data).toEqual({ dependencies: [] })
  })

  it('surfaces a real error', async () => {
    server.use(http.get('*/admin/projects/:key/dependencies', () => jsonError(500, 'boom')))
    renderHarness('my-app', {})
    await waitFor(() => expect(readResult().isError).toBe(true))
  })

  it('refetches when the filters change', async () => {
    const urls: string[] = []
    server.use(
      http.get('*/admin/projects/:key/dependencies', ({ request }) => {
        urls.push(request.url)
        return HttpResponse.json({ dependencies: [] })
      }),
    )
    function Wrapper() {
      const [filters, setFilters] = useState<DependenciesFilters>({})
      return (
        <div>
          <button type="button" onClick={() => setFilters({ pkg: 'react' })}>
            filter
          </button>
          <Harness projectKey="my-app" filters={filters} />
        </div>
      )
    }
    const client = new QueryClient({
      defaultOptions: { queries: { retry: false, retryDelay: 0, gcTime: 0, staleTime: 0 } },
    })
    const user = userEvent.setup()
    render(
      <QueryClientProvider client={client}>
        <Wrapper />
      </QueryClientProvider>,
    )
    await waitFor(() => expect(urls).toHaveLength(1))
    await user.click(screen.getByRole('button', { name: 'filter' }))
    await waitFor(() => expect(urls).toHaveLength(2))
    expect(new URL(urls[1]).searchParams.get('pkg')).toBe('react')
  })
})
