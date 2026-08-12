import { afterEach, beforeEach, describe, expect, it } from 'vitest'
import { http, HttpResponse } from 'msw'
import { server } from '../../vitest.setup'
import {
  badKey400,
  conflict409,
  createAdminHandlers,
  invalidToken401,
  notConfigured401,
  notFound404,
} from '../test/handlers'
import { createProject, deleteProject, getHealth, getProject, listProjects } from './api'
import { clearToken, setToken } from './storage'
import { ApiError } from './types'

beforeEach(() => server.use(...createAdminHandlers()))
afterEach(() => clearToken())

describe('admin API client', () => {
  it('listProjects returns projects with snake_case fields', async () => {
    const res = await listProjects()
    expect(res.projects).toHaveLength(1)
    const [project] = res.projects
    expect(project.key).toBe('my-app')
    expect(project.registries.npm.validation).toEqual([
      { type: 'allowlist', params: { packages: ['react'] } },
    ])
    expect(project.registries.npm.retrieval).toEqual([])
    expect(project.registries.npm.mutation).toEqual([])
  })

  it('getProject rejects with ApiError 404 when the project is missing', async () => {
    server.use(notFound404)
    const err = await getProject('missing').catch((e: unknown) => e)
    expect(err).toBeInstanceOf(ApiError)
    expect(err).toMatchObject({ name: 'ApiError', status: 404, message: 'project not found' })
  })

  it('createProject rejects with ApiError 409 when the project already exists', async () => {
    server.use(conflict409('my-app'))
    const err = await createProject({ key: 'my-app', registries: {} }).catch((e: unknown) => e)
    expect(err).toBeInstanceOf(ApiError)
    expect(err).toMatchObject({ status: 409 })
    expect((err as Error).message).toContain('already exists')
  })

  it('listProjects rejects with ApiError 401 when no admin token is configured', async () => {
    server.use(notConfigured401)
    const err = await listProjects().catch((e: unknown) => e)
    expect(err).toBeInstanceOf(ApiError)
    expect(err).toMatchObject({ status: 401, message: 'admin token not configured' })
  })

  it('listProjects rejects with ApiError 401 when the token is invalid, with a distinct message', async () => {
    server.use(invalidToken401)
    const err = await listProjects({ token: 'wrong' }).catch((e: unknown) => e)
    expect(err).toBeInstanceOf(ApiError)
    expect(err).toMatchObject({ status: 401, message: 'invalid token' })
    expect(err).not.toMatchObject({ message: 'admin token not configured' })
  })

  it('getProject rejects with ApiError 400 for an invalid key', async () => {
    server.use(badKey400)
    const err = await getProject('bad key!').catch((e: unknown) => e)
    expect(err).toBeInstanceOf(ApiError)
    expect(err).toMatchObject({ status: 400, message: 'invalid project key' })
  })

  it('deleteProject resolves with undefined on a 204 No Content', async () => {
    await expect(deleteProject('my-app')).resolves.toBeUndefined()
  })

  it('getHealth resolves the plain-text health body', async () => {
    await expect(getHealth()).resolves.toBe('ok')
  })

  it('listProjects uses the token stored via setToken as the Authorization header', async () => {
    let auth: string | null = null
    server.use(
      http.get('*/admin/projects', ({ request }) => {
        auth = request.headers.get('Authorization')
        return HttpResponse.json({ projects: [] })
      }),
    )
    setToken('tok-123')
    await listProjects()
    expect(auth).toBe('Bearer tok-123')
    clearToken()
  })
})
