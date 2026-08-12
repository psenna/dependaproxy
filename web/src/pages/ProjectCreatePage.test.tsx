import { fireEvent, render, screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { http } from 'msw'
import { afterEach, beforeEach, describe, expect, it } from 'vitest'
import { MemoryRouter, Route, Routes, useParams } from 'react-router-dom'
import { server } from '../../vitest.setup'
import { createAdminHandlers, jsonError } from '../test/handlers'
import { clearToken } from '../lib/storage'
import ProjectCreatePage from './ProjectCreatePage'

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

function renderCreate() {
  const client = new QueryClient({
    defaultOptions: { queries: { retry: false, retryDelay: 0, gcTime: 0, staleTime: 0 } },
  })
  render(
    <QueryClientProvider client={client}>
      <MemoryRouter initialEntries={['/projects/new']}>
        <Routes>
          <Route path="/projects/new" element={<ProjectCreatePage knownRegistries={['npm', 'pypi']} />} />
          <Route path="/projects/:key" element={<DetailSpy />} />
          <Route path="/projects" element={<ListSpy />} />
        </Routes>
      </MemoryRouter>
    </QueryClientProvider>,
  )
}

async function addNpmRegistry(user: ReturnType<typeof userEvent.setup>) {
  await user.click(screen.getByRole('button', { name: 'Add registry' }))
  await user.selectOptions(screen.getByLabelText('Registry type'), 'npm')
}

describe('ProjectCreatePage', () => {
  it('navigates to the new project detail page after a successful create', async () => {
    const user = userEvent.setup()
    renderCreate()
    await user.type(screen.getByLabelText('Key'), 'my-new-app')
    await addNpmRegistry(user)
    await user.click(screen.getByRole('button', { name: 'Create project' }))
    expect(await screen.findByTestId('detail-page')).toHaveTextContent('my-new-app')
  })

  it('shows "key already exists" on a 409 conflict', async () => {
    const user = userEvent.setup()
    renderCreate()
    await user.type(screen.getByLabelText('Key'), 'my-app')
    await addNpmRegistry(user)
    await user.click(screen.getByRole('button', { name: 'Create project' }))
    expect(await screen.findByTestId('submit-error')).toHaveTextContent('key already exists')
  })

  it('shows the server error message on a 400 invalid key', async () => {
    server.use(http.post('*/admin/projects', () => jsonError(400, 'invalid project key')))
    const user = userEvent.setup()
    renderCreate()
    await user.type(screen.getByLabelText('Key'), 'my-new-app')
    await addNpmRegistry(user)
    await user.click(screen.getByRole('button', { name: 'Create project' }))
    expect(await screen.findByTestId('submit-error')).toHaveTextContent('invalid project key')
  })

  it('shows the server error message on a 400 unknown registry', async () => {
    server.use(http.post('*/admin/projects', () => jsonError(400, 'unknown registry type "foobar"')))
    const user = userEvent.setup()
    renderCreate()
    await user.type(screen.getByLabelText('Key'), 'my-new-app')
    await addNpmRegistry(user)
    await user.click(screen.getByRole('button', { name: 'Create project' }))
    expect(await screen.findByTestId('submit-error')).toHaveTextContent(/unknown registry/)
  })

  it('validates the key client-side', async () => {
    const user = userEvent.setup()
    renderCreate()
    const keyInput = screen.getByLabelText('Key')
    const submit = screen.getByRole('button', { name: 'Create project' })

    await user.type(keyInput, '-')
    expect(screen.getByTestId('key-error')).toBeInTheDocument()
    expect(submit).toBeDisabled()

    await user.clear(keyInput)
    await user.type(keyInput, 'has space')
    expect(screen.getByTestId('key-error')).toBeInTheDocument()
    expect(submit).toBeDisabled()

    await user.clear(keyInput)
    await user.type(keyInput, 'good_key.1-2')
    expect(screen.queryByTestId('key-error')).not.toBeInTheDocument()
  })

  it('disables submit while a middleware params field is invalid', async () => {
    const user = userEvent.setup()
    renderCreate()
    await user.type(screen.getByLabelText('Key'), 'my-new-app')
    await addNpmRegistry(user)
    await user.click(screen.getAllByRole('button', { name: 'Add middleware' })[0])
    await user.selectOptions(screen.getByLabelText('Type'), 'deny-list-check')
    const submit = screen.getByRole('button', { name: 'Create project' })
    expect(submit).toBeEnabled()

    const params = screen.getByLabelText('Params (JSON)')
    fireEvent.change(params, { target: { value: '{bad' } })
    expect(submit).toBeDisabled()

    fireEvent.change(params, { target: { value: '{"mode":"deny"}' } })
    expect(submit).toBeEnabled()
  })

  it('blocks submit when no registries are configured', async () => {
    const user = userEvent.setup()
    renderCreate()
    await user.type(screen.getByLabelText('Key'), 'my-new-app')
    expect(screen.getByRole('button', { name: 'Create project' })).toBeDisabled()
  })
})
