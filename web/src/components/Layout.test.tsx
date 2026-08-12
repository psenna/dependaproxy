import { render, screen } from '@testing-library/react'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { describe, expect, it } from 'vitest'
import { MemoryRouter, Route, Routes } from 'react-router-dom'
import Layout from './Layout'

function renderLayout(initialPath: string) {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false, gcTime: 0, staleTime: 0 } } })
  render(
    <QueryClientProvider client={client}>
      <MemoryRouter initialEntries={[initialPath]}>
        <Routes>
          <Route element={<Layout />}>
            <Route path="/" element={<div data-testid="home" />} />
            <Route path="/projects" element={<div data-testid="projects" />} />
          </Route>
        </Routes>
      </MemoryRouter>
    </QueryClientProvider>,
  )
}

describe('Layout', () => {
  it('renders the nav links and logout button', () => {
    renderLayout('/')
    const dashboard = screen.getByRole('link', { name: 'Dashboard' })
    const projects = screen.getByRole('link', { name: 'Projects' })
    expect(dashboard).toHaveAttribute('href', '/')
    expect(projects).toHaveAttribute('href', '/projects')
    expect(screen.getByRole('button', { name: 'Logout' })).toBeInTheDocument()
    expect(screen.getByTestId('token-status')).toHaveTextContent('Signed in')
  })

  it('marks the Dashboard link active on /', () => {
    renderLayout('/')
    const dashboard = screen.getByRole('link', { name: 'Dashboard' })
    const projects = screen.getByRole('link', { name: 'Projects' })
    expect(dashboard).toHaveAttribute('aria-current', 'page')
    expect(projects).not.toHaveAttribute('aria-current')
  })

  it('marks the Projects link active on /projects', () => {
    renderLayout('/projects')
    const dashboard = screen.getByRole('link', { name: 'Dashboard' })
    const projects = screen.getByRole('link', { name: 'Projects' })
    expect(projects).toHaveAttribute('aria-current', 'page')
    expect(dashboard).not.toHaveAttribute('aria-current')
  })
})
