import { render, screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { afterEach, beforeEach, describe, expect, it } from 'vitest'
import { MemoryRouter, Route, Routes } from 'react-router-dom'
import { server } from '../../vitest.setup'
import { createAdminHandlers, invalidToken401, notConfigured401 } from '../test/handlers'
import { clearToken, getToken } from '../lib/storage'
import ProtectedRoute from '../components/ProtectedRoute'
import LoginPage from './LoginPage'

beforeEach(() => {
  server.use(...createAdminHandlers())
})

afterEach(() => {
  clearToken()
  sessionStorage.clear()
})

function renderLogin() {
  render(
    <MemoryRouter initialEntries={['/login']}>
      <Routes>
        <Route path="/login" element={<LoginPage />} />
        <Route path="/" element={<div data-testid="home" />} />
        <Route path="/projects" element={<div data-testid="projects" />} />
      </Routes>
    </MemoryRouter>,
  )
}

describe('LoginPage', () => {
  it('stores the token and navigates home on success', async () => {
    const user = userEvent.setup()
    renderLogin()
    await user.type(screen.getByPlaceholderText('Admin token'), 'tok-123')
    await user.click(screen.getByRole('button', { name: /sign in/i }))
    expect(getToken()).toBe('tok-123')
    expect(screen.getByTestId('home')).toBeInTheDocument()
  })

  it('shows an error for an invalid token and stays on the login page', async () => {
    server.use(invalidToken401)
    const user = userEvent.setup()
    renderLogin()
    await user.type(screen.getByPlaceholderText('Admin token'), 'wrong')
    await user.click(screen.getByRole('button', { name: /sign in/i }))
    expect(screen.getByText('Invalid admin token.')).toBeInTheDocument()
    expect(screen.getByPlaceholderText('Admin token')).toBeInTheDocument()
  })

  it('shows a not-configured message when the server has no admin token', async () => {
    server.use(notConfigured401)
    const user = userEvent.setup()
    renderLogin()
    await user.type(screen.getByPlaceholderText('Admin token'), 'anything')
    await user.click(screen.getByRole('button', { name: /sign in/i }))
    expect(
      screen.getByText('Admin token not configured on the server; set `auth.admin_token` in config.'),
    ).toBeInTheDocument()
  })

  it('disables the submit button while the input is empty', async () => {
    const user = userEvent.setup()
    renderLogin()
    const button = screen.getByRole('button', { name: /sign in/i })
    expect(button).toBeDisabled()
    await user.type(screen.getByPlaceholderText('Admin token'), 'x')
    expect(button).toBeEnabled()
    await user.clear(screen.getByPlaceholderText('Admin token'))
    expect(button).toBeDisabled()
  })

  it('redirects back to the originally requested route after login', async () => {
    const user = userEvent.setup()
    render(
      <MemoryRouter initialEntries={['/projects']}>
        <Routes>
          <Route path="/login" element={<LoginPage />} />
          <Route element={<ProtectedRoute />}>
            <Route path="/" element={<div data-testid="home" />} />
            <Route path="/projects" element={<div data-testid="projects" />} />
          </Route>
        </Routes>
      </MemoryRouter>,
    )
    await user.type(screen.getByPlaceholderText('Admin token'), 'tok-123')
    await user.click(screen.getByRole('button', { name: /sign in/i }))
    expect(screen.getByTestId('projects')).toBeInTheDocument()
    expect(screen.queryByTestId('home')).not.toBeInTheDocument()
  })
})
