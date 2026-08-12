import { render, screen } from '@testing-library/react'
import { afterEach, describe, expect, it } from 'vitest'
import { MemoryRouter, Route, Routes, useLocation } from 'react-router-dom'
import { clearToken } from '../lib/storage'
import ProtectedRoute from './ProtectedRoute'

afterEach(() => {
  clearToken()
  sessionStorage.clear()
})

function renderStub(initialPath: string) {
  render(
    <MemoryRouter initialEntries={[initialPath]}>
      <Routes>
        <Route path="/login" element={<div data-testid="login" />} />
        <Route element={<ProtectedRoute />}>
          <Route path="/" element={<div data-testid="home" />} />
          <Route path="/projects" element={<div data-testid="protected" />} />
        </Route>
      </Routes>
    </MemoryRouter>,
  )
}

describe('ProtectedRoute', () => {
  it('redirects to /login when no token is stored', () => {
    renderStub('/projects')
    expect(screen.getByTestId('login')).toBeInTheDocument()
    expect(screen.queryByTestId('protected')).not.toBeInTheDocument()
  })

  it('renders the protected layout when a token is stored', () => {
    sessionStorage.setItem('dependaproxy.admin_token', 'tok-123')
    renderStub('/projects')
    expect(screen.getByTestId('protected')).toBeInTheDocument()
    expect(screen.getByRole('button', { name: 'Logout' })).toBeInTheDocument()
    expect(screen.queryByTestId('login')).not.toBeInTheDocument()
  })

  it('passes the attempted location in navigate state', () => {
    function FromStub() {
      const location = useLocation()
      const from = (location.state as { from?: { pathname: string } } | null)?.from?.pathname
      return <div data-testid="from">{from}</div>
    }
    render(
      <MemoryRouter initialEntries={['/projects']}>
        <Routes>
          <Route path="/login" element={<FromStub />} />
          <Route element={<ProtectedRoute />}>
            <Route path="/projects" element={<div data-testid="protected" />} />
          </Route>
        </Routes>
      </MemoryRouter>,
    )
    expect(screen.getByTestId('from')).toHaveTextContent('/projects')
  })
})
