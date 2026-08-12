import { Outlet, useNavigate } from 'react-router-dom'
import { logout } from '../lib/auth'

export default function AdminLayout() {
  const navigate = useNavigate()
  return (
    <div className="min-h-screen">
      <header className="flex items-center justify-between border-b px-4 py-2">
        <span className="font-bold">DependaProxy</span>
        <button
          onClick={() => {
            logout()
            navigate('/login', { replace: true })
          }}
        >
          Logout
        </button>
      </header>
      <main className="p-4">
        <Outlet />
      </main>
    </div>
  )
}
