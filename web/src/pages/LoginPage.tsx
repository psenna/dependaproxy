import { useState, type FormEvent } from 'react'
import { useLocation, useNavigate } from 'react-router-dom'
import { login } from '../lib/auth'
import { ApiError } from '../lib/types'

export default function LoginPage() {
  const location = useLocation()
  const navigate = useNavigate()
  const [token, setToken] = useState('')
  const [error, setError] = useState<string | null>(null)
  const [submitting, setSubmitting] = useState(false)

  const from = (location.state as { from?: { pathname: string } } | null)?.from?.pathname ?? '/'

  async function handleSubmit(event: FormEvent) {
    event.preventDefault()
    setSubmitting(true)
    setError(null)
    try {
      await login(token)
      navigate(from, { replace: true })
    } catch (err) {
      if (err instanceof ApiError && err.message.includes('not configured')) {
        setError('Admin token not configured on the server; set `auth.admin_token` in config.')
      } else {
        setError('Invalid admin token.')
      }
    } finally {
      setSubmitting(false)
    }
  }

  return (
    <div data-testid="login" className="flex min-h-screen items-center justify-center">
      <form onSubmit={handleSubmit} className="mx-4 w-full max-w-sm rounded border p-6">
        <h1 className="text-red-500 mb-2 text-3xl font-bold">DependaProxy</h1>
        <p className="mb-4 text-sm text-gray-600">Enter your admin token to sign in.</p>
        <label className="mb-2 block text-sm font-medium" htmlFor="admin-token">
          Admin token
        </label>
        <input
          id="admin-token"
          type="password"
          value={token}
          onChange={(e) => setToken(e.target.value)}
          placeholder="Admin token"
          className="mb-4 w-full rounded border px-3 py-2"
          autoComplete="current-password"
        />
        {error && (
          <p className="mb-4 text-sm text-red-500" role="alert">
            {error}
          </p>
        )}
        <button
          type="submit"
          disabled={!token || submitting}
          className="w-full rounded bg-blue-600 px-3 py-2 text-white disabled:opacity-50"
        >
          {submitting ? 'Signing in…' : 'Sign in'}
        </button>
      </form>
    </div>
  )
}
