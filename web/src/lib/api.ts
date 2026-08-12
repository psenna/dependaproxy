import type {
  DependencyListResponse,
  Health,
  Project,
  ProjectListResponse,
  RegistryConfig,
  RequestOptions,
} from './types'
import { ApiError } from './types'
import { getToken } from './storage'

const BASE_URL = import.meta.env.VITE_API_BASE ?? ''

interface RequestArgs {
  token?: string
  body?: unknown
  signal?: AbortSignal
}

async function request<T>(method: string, path: string, { token, body, signal }: RequestArgs = {}): Promise<T> {
  const headers: Record<string, string> = { 'Content-Type': 'application/json' }
  if (token) headers.Authorization = `Bearer ${token}`
  const res = await fetch(`${BASE_URL}${path}`, {
    method,
    headers,
    body: body === undefined ? undefined : JSON.stringify(body),
    signal,
  })
  if (!res.ok) {
    let message = res.statusText
    try {
      const text = await res.text()
      if (text) {
        try {
          const parsed = JSON.parse(text) as { error?: string }
          message = parsed.error ?? text
        } catch {
          message = text
        }
      }
    } catch {
      // ignore body read errors
    }
    throw new ApiError(res.status, message)
  }
  if (res.status === 204) return undefined as T
  const text = await res.text()
  const contentType = res.headers.get('content-type') ?? ''
  if (contentType.includes('application/json')) {
    return JSON.parse(text) as T
  }
  return text as unknown as T
}

const withToken = (opts?: RequestOptions): RequestArgs => ({
  token: opts?.token ?? getToken() ?? undefined,
  body: opts?.body,
  signal: opts?.signal,
})

export function listProjects(opts?: RequestOptions): Promise<ProjectListResponse> {
  return request<ProjectListResponse>('GET', '/admin/projects', withToken(opts))
}

export function getProject(key: string, opts?: RequestOptions): Promise<Project> {
  return request<Project>('GET', `/admin/projects/${encodeURIComponent(key)}`, withToken(opts))
}

export function createProject(
  body: { key: string; registries: Record<string, RegistryConfig> },
  opts?: RequestOptions,
): Promise<Project> {
  return request<Project>('POST', '/admin/projects', { ...withToken(opts), body })
}

export function updateProject(
  key: string,
  body: { registries: Record<string, RegistryConfig>; key?: string },
  opts?: RequestOptions,
): Promise<Project> {
  return request<Project>('PUT', `/admin/projects/${encodeURIComponent(key)}`, { ...withToken(opts), body })
}

export function deleteProject(key: string, opts?: RequestOptions): Promise<void> {
  return request<void>('DELETE', `/admin/projects/${encodeURIComponent(key)}`, withToken(opts))
}

export function getDependencies(
  key: string,
  query?: { registry?: string; pkg?: string },
  opts?: RequestOptions,
): Promise<DependencyListResponse> {
  const params = new URLSearchParams()
  if (query?.registry) params.set('registry', query.registry)
  if (query?.pkg) params.set('pkg', query.pkg)
  const qs = params.toString()
  return request<DependencyListResponse>(
    'GET',
    `/admin/projects/${encodeURIComponent(key)}/dependencies${qs ? `?${qs}` : ''}`,
    withToken(opts),
  )
}

export function getHealth(opts?: RequestOptions): Promise<Health> {
  return request<Health>('GET', '/healthz', opts)
}
