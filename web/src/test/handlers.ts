import { http, HttpResponse } from 'msw'
import type { Dependency, Middleware, Project } from '../lib/types'

export interface Fixtures {
  projects: Project[]
  dependencies: Record<string, Dependency[]>
  healthBody: string
}

export const defaultFixtures: Fixtures = {
  projects: [
    {
      key: 'my-app',
      registries: {
        npm: {
          validation: [{ type: 'allowlist', params: { packages: ['react'] } }],
          retrieval: [],
          mutation: [],
        },
      },
    },
  ],
  dependencies: {
    'my-app': [
      {
        registry: 'npm',
        pkg: 'react',
        version: '18.3.1',
        artifact_id: 'react-18.3.1.tgz',
        sha256: 'abc123',
        first_downloaded_at: '2026-01-01T00:00:00Z',
        last_downloaded_at: '2026-01-02T00:00:00Z',
        download_count: 3,
      },
    ],
  },
  healthBody: 'ok',
}

export function jsonError(status: number, reason: string): HttpResponse<{ error: string }> {
  return HttpResponse.json({ error: reason }, { status })
}

const keyRe = /^[a-zA-Z0-9._-]+$/

export function validKey(key: string): boolean {
  return key !== '' && key !== '-' && keyRe.test(key)
}

const knownRegistries = ['npm', 'pypi']

function validateRegistries(registries: Record<string, { validation?: Middleware[]; retrieval?: Middleware[]; mutation?: Middleware[] }>): string | null {
  for (const [name, rr] of Object.entries(registries ?? {})) {
    if (name === '' || !knownRegistries.includes(name)) {
      return `unknown registry type "${name}"`
    }
    for (const list of [rr.validation, rr.retrieval, rr.mutation]) {
      for (const m of list ?? []) {
        if (!m.type) return 'middleware type is required'
      }
    }
  }
  return null
}

export function createAdminHandlers(fix: Fixtures = defaultFixtures) {
  return [
    // GET /admin/projects
    http.get('*/admin/projects', () => HttpResponse.json({ projects: fix.projects })),

    // GET /admin/projects/:key/dependencies (registered before the generic :key route)
    http.get('*/admin/projects/:key/dependencies', ({ request, params }) => {
      const key = String(params.key)
      if (!validKey(key)) return jsonError(400, 'invalid project key')
      const url = new URL(request.url)
      const registry = url.searchParams.get('registry')
      const pkg = url.searchParams.get('pkg')
      const deps = (fix.dependencies[key] ?? []).filter(
        (d) => (!registry || d.registry === registry) && (!pkg || d.pkg === pkg),
      )
      if (deps.length === 0) return jsonError(404, 'no dependencies for project')
      return HttpResponse.json({ dependencies: deps })
    }),

    // GET /admin/projects/:key
    http.get('*/admin/projects/:key', ({ params }) => {
      const key = String(params.key)
      if (!validKey(key)) return jsonError(400, 'invalid project key')
      const project = fix.projects.find((p) => p.key === key)
      if (!project) return jsonError(404, 'project not found')
      return HttpResponse.json(project)
    }),

    // POST /admin/projects
    http.post('*/admin/projects', async ({ request }) => {
      let body: { key?: unknown; registries?: Record<string, { validation?: Middleware[]; retrieval?: Middleware[]; mutation?: Middleware[] }> }
      try {
        body = (await request.json()) as typeof body
      } catch {
        return jsonError(400, 'invalid JSON body')
      }
      const key = body?.key
      if (typeof key !== 'string' || !validKey(key)) return jsonError(400, 'invalid project key')
      const regErr = validateRegistries(body?.registries ?? {})
      if (regErr) return jsonError(400, regErr)
      if (fix.projects.some((p) => p.key === key)) return jsonError(409, `project "${key}" already exists`)
      const project: Project = { key, registries: body?.registries ?? {} }
      fix.projects.push(project)
      return HttpResponse.json(project, { status: 201 })
    }),

    // PUT /admin/projects/:key (UPSERT)
    http.put('*/admin/projects/:key', async ({ request, params }) => {
      const key = String(params.key)
      if (!validKey(key)) return jsonError(400, 'invalid project key')
      let body: { key?: unknown; registries?: Record<string, { validation?: Middleware[]; retrieval?: Middleware[]; mutation?: Middleware[] }> }
      try {
        body = (await request.json()) as typeof body
      } catch {
        return jsonError(400, 'invalid JSON body')
      }
      if (body?.key !== undefined && body.key !== '' && body.key !== key) {
        return jsonError(400, 'key in body does not match path key')
      }
      const regErr = validateRegistries(body?.registries ?? {})
      if (regErr) return jsonError(400, regErr)
      const project: Project = { key, registries: body?.registries ?? {} }
      const idx = fix.projects.findIndex((p) => p.key === key)
      if (idx === -1) {
        fix.projects.push(project)
        return HttpResponse.json(project, { status: 201 })
      }
      fix.projects[idx] = project
      return HttpResponse.json(project, { status: 200 })
    }),

    // DELETE /admin/projects/:key
    http.delete('*/admin/projects/:key', ({ params }) => {
      const key = String(params.key)
      if (!validKey(key)) return jsonError(400, 'invalid project key')
      const idx = fix.projects.findIndex((p) => p.key === key)
      if (idx === -1) return jsonError(404, 'project not found')
      fix.projects.splice(idx, 1)
      return new HttpResponse(null, { status: 204 })
    }),
  ]
}

export const healthzHandler = http.get('*/healthz', () => HttpResponse.text('ok', { status: 200 }))

// The healthz handler is intentionally excluded: vitest.setup.ts serves /healthz
// with its own inline handler to avoid a cross-project import into tsconfig.node.json.
export const defaultHandlers = [...createAdminHandlers()]

// Named overrides for focused tests.
export const notConfigured401 = http.get('*/admin/projects', () => jsonError(401, 'admin token not configured'))
export const invalidToken401 = http.get('*/admin/projects', () => jsonError(401, 'invalid token'))
export const conflict409 = (key: string) =>
  http.post('*/admin/projects', () => jsonError(409, `project "${key}" already exists`))
export const notFound404 = http.get('*/admin/projects/:key', () => jsonError(404, 'project not found'))
export const badKey400 = http.get('*/admin/projects/:key', () => jsonError(400, 'invalid project key'))
