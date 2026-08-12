import { render, screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { http, HttpResponse } from 'msw'
import { afterEach, beforeEach, describe, expect, it } from 'vitest'
import { MemoryRouter, Route, Routes, useParams } from 'react-router-dom'
import { server } from '../../vitest.setup'
import { createAdminHandlers, defaultFixtures, jsonError, type Fixtures } from '../test/handlers'
import { clearToken } from '../lib/storage'
import type { RegistryConfig } from '../lib/types'
import ProjectEditPage from './ProjectEditPage'

function DetailSpy() {
  const { key } = useParams()
  return <div data-testid="detail-page">{key}</div>
}

function ListSpy() {
  return <div data-testid="list-page">list</div>
}

beforeEach(() => {
  server.use(...createAdminHandlers())
  sessionStorage.setItem('dependaproxy.admin_token', 'tok-123')
})

afterEach(() => {
  clearToken()
  sessionStorage.clear()
})

function renderEdit() {
  const client = new QueryClient({
    defaultOptions: { queries: { retry: false, retryDelay: 0, gcTime: 0, staleTime: 0 } },
  })
  render(
    <QueryClientProvider client={client}>
      <MemoryRouter initialEntries={['/projects/my-app/edit']}>
        <Routes>
          <Route path="/projects/:key/edit" element={<ProjectEditPage knownRegistries={['npm', 'pypi']} />} />
          <Route path="/projects/:key" element={<DetailSpy />} />
          <Route path="/projects" element={<ListSpy />} />
        </Routes>
      </MemoryRouter>
    </QueryClientProvider>,
  )
}

describe('ProjectEditPage', () => {
  it('prefills the form from the fetched project', async () => {
    renderEdit()
    expect(await screen.findByTestId('override-validation')).toBeChecked()
    const keyInput = screen.getByLabelText('Key')
    expect(keyInput).toHaveValue('my-app')
    expect(keyInput).toHaveAttribute('readonly')
    expect(screen.getByTestId('override-retrieval')).toBeChecked()
    expect(screen.getByTestId('override-mutation')).toBeChecked()
  })

  it('unchecks chains absent from the fetched config', async () => {
    const fix: Fixtures = {
      ...defaultFixtures,
      projects: [
        {
          key: 'my-app',
          registries: {
            npm: {
              validation: [{ type: 'allowlist', params: { packages: ['react'] } }],
            },
          },
        },
      ],
    }
    server.use(...createAdminHandlers(fix))
    renderEdit()
    expect(await screen.findByTestId('override-validation')).toBeChecked()
    expect(screen.getByTestId('override-retrieval')).not.toBeChecked()
    expect(screen.getByTestId('override-mutation')).not.toBeChecked()
    expect(screen.getAllByTestId('middleware-chain-editor')).toHaveLength(1)
  })

  it('omits toggled-off chains from the PUT body', async () => {
    const user = userEvent.setup()
    let captured: { key?: string; registries?: Record<string, RegistryConfig> } | null = null
    server.use(
      http.put('*/admin/projects/:key', async ({ request }) => {
        captured = (await request.json()) as typeof captured
        return HttpResponse.json({ key: 'my-app', registries: {} }, { status: 200 })
      }),
    )
    renderEdit()
    expect(await screen.findByTestId('override-validation')).toBeChecked()
    await user.click(screen.getByTestId('override-validation'))
    await user.click(screen.getByRole('button', { name: 'Save project' }))
    expect(await screen.findByTestId('detail-page')).toHaveTextContent('my-app')
    expect(captured).not.toBeNull()
    expect(captured!.registries!.npm).not.toHaveProperty('validation')
    expect(captured).not.toHaveProperty('key')
  })

  it('navigates to the detail page after a successful save', async () => {
    const user = userEvent.setup()
    renderEdit()
    expect(await screen.findByTestId('override-validation')).toBeChecked()
    await user.click(screen.getByRole('button', { name: 'Save project' }))
    expect(await screen.findByTestId('detail-page')).toHaveTextContent('my-app')
  })

  it('navigates to the detail page after a 201 upsert save', async () => {
    const user = userEvent.setup()
    server.use(
      http.put('*/admin/projects/:key', () => HttpResponse.json({ key: 'my-app', registries: {} }, { status: 201 })),
    )
    renderEdit()
    expect(await screen.findByTestId('override-validation')).toBeChecked()
    await user.click(screen.getByRole('button', { name: 'Save project' }))
    expect(await screen.findByTestId('detail-page')).toHaveTextContent('my-app')
  })

  it('shows "Project not found" when the project does not exist', async () => {
    server.use(http.get('*/admin/projects/:key', () => jsonError(404, 'project not found')))
    renderEdit()
    expect(await screen.findByTestId('project-error')).toHaveTextContent('Project not found')
    expect(screen.queryByTestId('override-validation')).not.toBeInTheDocument()
  })

  it('shows a generic error on network failure', async () => {
    server.use(http.get('*/admin/projects/:key', () => Response.error()))
    renderEdit()
    expect(await screen.findByTestId('project-error')).toHaveTextContent('Failed to load project.')
  })

  it('omits the key from the PUT body to avoid a 400', async () => {
    const user = userEvent.setup()
    server.use(
      http.put('*/admin/projects/:key', async ({ request }) => {
        const body = (await request.json()) as { key?: unknown }
        if ('key' in body) return jsonError(400, 'key in body does not match path key')
        return HttpResponse.json({ key: 'my-app', registries: {} }, { status: 200 })
      }),
    )
    renderEdit()
    expect(await screen.findByTestId('override-validation')).toBeChecked()
    await user.click(screen.getByRole('button', { name: 'Save project' }))
    expect(await screen.findByTestId('detail-page')).toHaveTextContent('my-app')
  })
})
