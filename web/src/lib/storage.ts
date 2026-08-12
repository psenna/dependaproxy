const KEY = 'dependaproxy.admin_token'

function available(): boolean {
  return typeof sessionStorage !== 'undefined'
}

export function getToken(): string | null {
  if (!available()) return null
  return sessionStorage.getItem(KEY)
}

export function setToken(token: string): void {
  if (!available()) return
  sessionStorage.setItem(KEY, token)
}

export function clearToken(): void {
  if (!available()) return
  sessionStorage.removeItem(KEY)
}
