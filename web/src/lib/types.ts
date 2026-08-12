export interface Middleware {
  type: string
  params?: Record<string, unknown>
}

export interface RegistryConfig {
  validation?: Middleware[]
  retrieval?: Middleware[]
  mutation?: Middleware[]
}

export interface Project {
  key: string
  registries: Record<string, RegistryConfig>
}

export interface Dependency {
  registry: string
  pkg: string
  version: string
  artifact_id: string
  sha256: string
  first_downloaded_at: string
  last_downloaded_at: string
  download_count: number
}

export interface ProjectListResponse {
  projects: Project[]
}

export interface DependencyListResponse {
  dependencies: Dependency[]
}

export type Health = string

export interface ApiErrorBody {
  error: string
}

export class ApiError extends Error {
  readonly status: number

  constructor(status: number, message: string) {
    super(message)
    this.name = 'ApiError'
    this.status = status
  }
}

export interface RequestOptions {
  token?: string
  body?: unknown
  signal?: AbortSignal
}
