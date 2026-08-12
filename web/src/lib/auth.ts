import { listProjects } from './api'
import { clearToken, setToken } from './storage'

export async function login(token: string): Promise<void> {
  await listProjects({ token }) // token passed explicitly — NOT read from storage
  setToken(token)
}

export function logout(): void {
  clearToken()
}
