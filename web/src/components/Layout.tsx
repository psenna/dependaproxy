import { useState } from 'react'
import { NavLink, Outlet, useNavigate } from 'react-router-dom'
import { logout } from '../lib/auth'

const navLinkClass = ({ isActive }: { isActive: boolean }) =>
  isActive
    ? 'rounded bg-blue-100 px-3 py-2 font-medium text-blue-700'
    : 'rounded px-3 py-2 text-gray-600 hover:bg-gray-100'

export default function Layout() {
  const navigate = useNavigate()
  const [sidebarOpen, setSidebarOpen] = useState(false)

  function handleLogout() {
    logout()
    navigate('/login', { replace: true })
  }

  return (
    <div className="flex min-h-screen">
      {sidebarOpen && (
        <div
          className="fixed inset-0 z-30 bg-black/40 md:hidden"
          onClick={() => setSidebarOpen(false)}
          aria-hidden="true"
        />
      )}
      <aside
        id="sidebar"
        className={`fixed inset-y-0 left-0 z-40 w-56 transform border-r bg-gray-50 transition-transform md:static md:translate-x-0 ${
          sidebarOpen ? 'translate-x-0' : '-translate-x-full'
        }`}
      >
        <nav className="flex flex-col gap-1 p-4">
          <NavLink to="/" end className={navLinkClass} onClick={() => setSidebarOpen(false)}>
            Dashboard
          </NavLink>
          <NavLink to="/projects" className={navLinkClass} onClick={() => setSidebarOpen(false)}>
            Projects
          </NavLink>
        </nav>
      </aside>
      <div className="flex min-w-0 flex-1 flex-col">
        <header className="flex items-center justify-between border-b px-4 py-2">
          <div className="flex items-center gap-2">
            <button
              type="button"
              aria-label="Toggle navigation"
              aria-expanded={sidebarOpen}
              aria-controls="sidebar"
              onClick={() => setSidebarOpen((open) => !open)}
              className="dp-btn-secondary md:hidden"
            >
              <svg
                aria-hidden="true"
                className="h-5 w-5"
                fill="none"
                stroke="currentColor"
                strokeWidth="2"
                viewBox="0 0 24 24"
              >
                <path strokeLinecap="round" strokeLinejoin="round" d="M4 6h16M4 12h16M4 18h16" />
              </svg>
            </button>
            <span className="font-bold">DependaProxy</span>
          </div>
          <div className="flex items-center gap-4">
            <span data-testid="token-status">Signed in</span>
            <button
              type="button"
              onClick={handleLogout}
              className="dp-btn-secondary"
            >
              Logout
            </button>
          </div>
        </header>
        <main className="p-4">
          <Outlet />
        </main>
      </div>
    </div>
  )
}
