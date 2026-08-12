import { NavLink, Outlet, useNavigate } from 'react-router-dom'
import { logout } from '../lib/auth'

const navLinkClass = ({ isActive }: { isActive: boolean }) =>
  isActive
    ? 'rounded bg-blue-100 px-3 py-2 font-medium text-blue-700'
    : 'rounded px-3 py-2 text-gray-600 hover:bg-gray-100'

export default function Layout() {
  const navigate = useNavigate()

  function handleLogout() {
    logout()
    navigate('/login', { replace: true })
  }

  return (
    <div className="flex min-h-screen">
      <aside className="w-56 shrink-0 border-r bg-gray-50">
        <nav className="flex flex-col gap-1 p-4">
          <NavLink to="/" end className={navLinkClass}>
            Dashboard
          </NavLink>
          <NavLink to="/projects" className={navLinkClass}>
            Projects
          </NavLink>
        </nav>
      </aside>
      <div className="flex min-w-0 flex-1 flex-col">
        <header className="flex items-center justify-between border-b px-4 py-2">
          <span className="font-bold">DependaProxy</span>
          <div className="flex items-center gap-4">
            <span data-testid="token-status">Signed in</span>
            <button
              type="button"
              onClick={handleLogout}
              className="rounded border border-gray-300 px-3 py-1 text-sm hover:bg-gray-100"
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
