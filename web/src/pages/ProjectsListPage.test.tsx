import { render, screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { http, HttpResponse } from 'msw'
import { afterEach, beforeEach, describe, expect, it } from 'vitest'
import { MemoryRouter } from 'react-router-dom'
import { server } from '../../vitest.setup'
import { createAdminHandlers, jsonError } from '../test/handlers'
import { clearToken } from '../lib/storage'
import ProjectsListPage from './ProjectsListPage'

beforeEach(() => {
  server.use(...createAdminHandlers())
  sessionStorage.setItem('dependaproxy.admin_token', 'tok-123')
})

afterEach(() => {
  clearToken()
  sessionStorage.clear()
})

function renderProjects() {
  const client = new QueryClient({
    defaultOptions: { queries: { retry: false, retryDelay: 0, gcTime: 0, staleTime: 0 } },
  })
  render(
    <QueryClientProvider client={client}>
      <MemoryRouter initialEntries={['/projects']}>
        <ProjectsListPage />
      </MemoryRouter>
    </QueryClientProvider>,
  )
}

describe('ProjectsListPage', () => {
  it('renders the list with a registry summary and row actions', async () => {
    renderProjects()
    expect(await screen.findByTestId('projects-table')).toBeInTheDocument()
    expect(screen.getByTestId('project-row-my-app')).toBeInTheDocument()
    expect(screen.getByTestId('project-registries-my-app')).toHaveTextContent('npm')
    expect(screen.getByRole('link', { name: 'View' })).toHaveAttribute('href', '/projects/my-app')
    expect(screen.getByRole('link', { name: 'Edit' })).toHaveAttribute('href', '/projects/my-app/edit')
    expect(screen.getByTestId('project-delete-my-app')).toBeInTheDocument()
  })

  it('shows a multi-registry summary', async () => {
    const p1 = { key: 'my-app', registries: { npm: {}, pypi: {} } }
    server.use(http.get('*/admin/projects', () => HttpResponse.json({ projects: [p1] })))
    renderProjects()
    expect(await screen.findByTestId('project-registries-my-app')).toHaveTextContent('npm, pypi')
  })

  it('shows the empty state with a create-project CTA', async () => {
    server.use(http.get('*/admin/projects', () => HttpResponse.json({ projects: [] })))
    renderProjects()
    expect(await screen.findByTestId('projects-empty')).toBeInTheDocument()
    expect(screen.getByRole('link', { name: 'Create project' })).toHaveAttribute('href', '/projects/new')
  })

  it('deletes a project after confirmation', async () => {
    const fix = {
      projects: [{ key: 'my-app', registries: { npm: {} } }],
      dependencies: {},
      healthBody: 'ok',
    }
    let deletedKey: string | null = null
    server.use(
      http.get('*/admin/projects', () => HttpResponse.json({ projects: fix.projects })),
      http.delete('*/admin/projects/:key', ({ params }) => {
        deletedKey = String(params.key)
        fix.projects = fix.projects.filter((p) => p.key !== deletedKey)
        return new HttpResponse(null, { status: 204 })
      }),
    )
    const user = userEvent.setup()
    renderProjects()
    await screen.findByTestId('project-row-my-app')
    await user.click(screen.getByTestId('project-delete-my-app'))
    await user.click(screen.getByRole('button', { name: /^delete$/i }))
    await waitFor(() => expect(deletedKey).toBe('my-app'))
    await waitFor(() => expect(screen.queryByTestId('project-row-my-app')).not.toBeInTheDocument())
    expect(await screen.findByTestId('projects-empty')).toBeInTheDocument()
  })

  it('does not delete when the user cancels', async () => {
    let deleteCalled = false
    server.use(
      http.delete('*/admin/projects/:key', () => {
        deleteCalled = true
        return new HttpResponse(null, { status: 204 })
      }),
    )
    const user = userEvent.setup()
    renderProjects()
    await screen.findByTestId('project-row-my-app')
    await user.click(screen.getByTestId('project-delete-my-app'))
    await user.click(screen.getByRole('button', { name: /cancel/i }))
    expect(deleteCalled).toBe(false)
    expect(screen.getByTestId('project-row-my-app')).toBeInTheDocument()
  })

  it('shows a not-found error when the project was already deleted', async () => {
    server.use(http.delete('*/admin/projects/:key', () => jsonError(404, 'project not found')))
    const user = userEvent.setup()
    renderProjects()
    await screen.findByTestId('project-row-my-app')
    await user.click(screen.getByTestId('project-delete-my-app'))
    await user.click(screen.getByRole('button', { name: /^delete$/i }))
    expect(await screen.findByTestId('delete-error')).toHaveTextContent(/not found/i)
    expect(screen.getByTestId('project-row-my-app')).toBeInTheDocument()
  })

  it('shows an invalid-key error on a 400', async () => {
    server.use(http.delete('*/admin/projects/:key', () => jsonError(400, 'invalid project key')))
    const user = userEvent.setup()
    renderProjects()
    await screen.findByTestId('project-row-my-app')
    await user.click(screen.getByTestId('project-delete-my-app'))
    await user.click(screen.getByRole('button', { name: /^delete$/i }))
    expect(await screen.findByTestId('delete-error')).toHaveTextContent(/invalid project key/i)
  })

  it('retries loading projects after an error', async () => {
    // useProjects sets retry: 1 at the hook level, which overrides the per-test
    // QueryClient's retry: false, so the first two requests (initial + automatic
    // retry) must fail before the manual Retry refetch can succeed.
    let calls = 0
    server.use(
      http.get('*/admin/projects', () => {
        calls += 1
        if (calls < 3) return jsonError(500, 'boom')
        return HttpResponse.json({ projects: [{ key: 'my-app', registries: { npm: {} } }] })
      }),
    )
    const user = userEvent.setup()
    renderProjects()
    const error = await screen.findByTestId('projects-error')
    expect(error).toHaveTextContent('Failed to load projects.')
    await user.click(screen.getByRole('button', { name: 'Retry' }))
    expect(await screen.findByTestId('projects-table')).toBeInTheDocument()
  })
})
