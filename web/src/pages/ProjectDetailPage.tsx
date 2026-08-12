import { useRef, useState } from 'react'
import { Link, useParams } from 'react-router-dom'
import EmptyState from '../components/EmptyState'
import ErrorState from '../components/ErrorState'
import Loading from '../components/Loading'
import { useDependencies } from '../features/dependencies/useDependencies'
import { useDebouncedValue } from '../features/dependencies/useDebouncedValue'
import { useProject } from '../features/projects/useProject'
import { ApiError, type RegistryConfig } from '../lib/types'

function registriesSummary(registries: Record<string, RegistryConfig>): string {
  const keys = Object.keys(registries)
  return keys.length > 0 ? keys.join(', ') : '—'
}

type TabValue = 'config' | 'dependencies'

const tabs: Array<{ id: string; panelId: string; value: TabValue; label: string }> = [
  { id: 'tab-config', panelId: 'panel-config', value: 'config', label: 'Config' },
  { id: 'tab-deps', panelId: 'panel-deps', value: 'dependencies', label: 'Dependencies' },
]

export default function ProjectDetailPage({ debounceMs = 400 }: { debounceMs?: number }) {
  const { key = '' } = useParams()
  const project = useProject(key)
  const [activeTab, setActiveTab] = useState<TabValue>('config')
  const [registryInput, setRegistryInput] = useState('')
  const [pkgInput, setPkgInput] = useState('')
  const [copiedSha, setCopiedSha] = useState<string | null>(null)
  const debRegistry = useDebouncedValue(registryInput, debounceMs)
  const debPkg = useDebouncedValue(pkgInput, debounceMs)
  const dependencies = useDependencies(key, { registry: debRegistry, pkg: debPkg })
  const tablistRef = useRef<HTMLDivElement>(null)

  function copySha256(sha: string) {
    try {
      void navigator.clipboard.writeText(sha).catch(() => {})
    } catch {
      // ignore clipboard errors
    }
    setCopiedSha(sha)
    window.setTimeout(() => setCopiedSha(null), 1500)
  }

  function handleTablistKeyDown(event: React.KeyboardEvent<HTMLDivElement>) {
    const tabButtons = Array.from(
      tablistRef.current?.querySelectorAll<HTMLButtonElement>('[role="tab"]') ?? [],
    )
    if (tabButtons.length === 0) return
    const currentIndex = tabButtons.indexOf(document.activeElement as HTMLButtonElement)
    if (event.key === 'ArrowRight') {
      event.preventDefault()
      const next = tabButtons[(currentIndex + 1) % tabButtons.length]
      next.focus()
      setActiveTab(next.dataset.tab === 'dependencies' ? 'dependencies' : 'config')
    } else if (event.key === 'ArrowLeft') {
      event.preventDefault()
      const prev = tabButtons[(currentIndex - 1 + tabButtons.length) % tabButtons.length]
      prev.focus()
      setActiveTab(prev.dataset.tab === 'dependencies' ? 'dependencies' : 'config')
    } else if (event.key === 'Enter' || event.key === ' ') {
      event.preventDefault()
      const active = tabButtons[currentIndex]
      if (active) setActiveTab(active.dataset.tab === 'dependencies' ? 'dependencies' : 'config')
    }
  }

  let errorMessage: string | null = null
  if (project.isError) {
    if (project.error instanceof ApiError) {
      if (project.error.status === 404) {
        errorMessage = 'Project not found'
      } else if (project.error.status === 400) {
        errorMessage = 'Invalid project key'
      } else {
        errorMessage = 'Failed to load project.'
      }
    } else {
      errorMessage = 'Failed to load project.'
    }
  }

  return (
    <div>
      {project.isLoading && <Loading testId="project-loading" />}
      {project.isError && (
        <ErrorState
          message={errorMessage ?? undefined}
          onRetry={() => project.refetch()}
          testId="project-error"
        />
      )}
      {project.isSuccess && (
        <div>
          <div className="flex items-center justify-between">
            <h1 className="text-2xl font-bold">Project {key}</h1>
            <Link
              to={`/projects/${encodeURIComponent(key)}/edit`}
              className="text-blue-600 hover:underline"
            >
              Edit
            </Link>
          </div>

          <div
            ref={tablistRef}
            role="tablist"
            onKeyDown={handleTablistKeyDown}
            className="mt-4 flex gap-2"
          >
            {tabs.map((tab) => (
              <button
                key={tab.id}
                type="button"
                role="tab"
                id={tab.id}
                aria-controls={tab.panelId}
                aria-selected={activeTab === tab.value}
                tabIndex={activeTab === tab.value ? 0 : -1}
                data-tab={tab.value}
                onClick={() => setActiveTab(tab.value)}
                className={
                  activeTab === tab.value
                    ? 'rounded bg-blue-600 px-3 py-1.5 text-sm text-white'
                    : 'rounded border border-gray-300 px-3 py-1.5 text-sm text-gray-600'
                }
              >
                {tab.label}
              </button>
            ))}
          </div>

          {activeTab === 'config' && (
            <section
              id="panel-config"
              role="tabpanel"
              aria-labelledby="tab-config"
              className="mt-4"
            >
              <div
                data-testid="project-detail"
                className="rounded border border-gray-200 bg-white p-4"
              >
                <p>
                  <span className="font-medium">Key:</span> {project.data.key}
                </p>
                <p>
                  <span className="font-medium">Registries:</span>{' '}
                  <span data-testid="project-registries">
                    {registriesSummary(project.data.registries)}
                  </span>
                </p>
              </div>
            </section>
          )}

          {activeTab === 'dependencies' && (
            <section
              id="panel-deps"
              role="tabpanel"
              aria-labelledby="tab-deps"
              className="mt-4"
            >
              <div className="flex flex-wrap gap-2">
                <input
                  type="text"
                  aria-label="Filter by registry"
                  data-testid="filter-registry"
                  value={registryInput}
                  onChange={(e) => setRegistryInput(e.target.value)}
                  placeholder="Filter by registry"
                  className="w-48 rounded border border-gray-300 px-2 py-1 text-sm"
                />
                <input
                  type="text"
                  aria-label="Filter by package"
                  data-testid="filter-pkg"
                  value={pkgInput}
                  onChange={(e) => setPkgInput(e.target.value)}
                  placeholder="Filter by package"
                  className="w-48 rounded border border-gray-300 px-2 py-1 text-sm"
                />
              </div>

              {dependencies.isLoading && (
                <Loading label="Loading dependencies…" testId="dependencies-loading" />
              )}
              {dependencies.isError && (
                <ErrorState
                  message="Failed to load dependencies."
                  onRetry={() => dependencies.refetch()}
                  testId="dependencies-error"
                />
              )}
              {dependencies.isSuccess && dependencies.data.dependencies.length === 0 && (
                <div data-testid="dependencies-empty" className="mt-4">
                  <EmptyState
                    title="No dependencies recorded yet"
                    message="Project-scoped downloads are flushed asynchronously; a freshly installed package may take a few seconds to appear."
                  />
                </div>
              )}
              {dependencies.isSuccess && dependencies.data.dependencies.length > 0 && (
                <div className="mt-4 overflow-x-auto">
                  <table
                    data-testid="dependencies-table"
                    className="w-full border-collapse text-left text-sm"
                  >
                    <thead>
                      <tr className="border-b text-gray-500">
                        <th scope="col" className="py-2 pr-4 font-medium">
                          registry
                        </th>
                        <th scope="col" className="py-2 pr-4 font-medium">
                          pkg
                        </th>
                        <th scope="col" className="py-2 pr-4 font-medium">
                          version
                        </th>
                        <th scope="col" className="py-2 pr-4 font-medium">
                          artifact_id
                        </th>
                        <th scope="col" className="py-2 pr-4 font-medium">
                          sha256
                        </th>
                        <th scope="col" className="py-2 pr-4 font-medium">
                          first_downloaded_at
                        </th>
                        <th scope="col" className="py-2 pr-4 font-medium">
                          last_downloaded_at
                        </th>
                        <th scope="col" className="py-2 font-medium">
                          download_count
                        </th>
                      </tr>
                    </thead>
                    <tbody>
                      {dependencies.data.dependencies.map((dep, i) => (
                        <tr
                          key={`${dep.registry}-${dep.pkg}-${dep.version}`}
                          data-testid={`dependency-row-${i}`}
                          className="border-b"
                        >
                          <td className="py-2 pr-4">{dep.registry}</td>
                          <td className="py-2 pr-4">{dep.pkg}</td>
                          <td className="py-2 pr-4">{dep.version}</td>
                          <td className="py-2 pr-4">{dep.artifact_id}</td>
                          <td className="py-2 pr-4" title={dep.sha256}>
                            {dep.sha256.slice(0, 12)}
                            {'…'}
                            <button
                              type="button"
                              data-testid={`sha256-copy-${i}`}
                              aria-label="Copy sha256"
                              onClick={() => copySha256(dep.sha256)}
                              className="ml-2 text-blue-600 hover:underline"
                            >
                              {copiedSha === dep.sha256 ? 'Copied' : 'Copy'}
                            </button>
                          </td>
                          <td className="py-2 pr-4">{dep.first_downloaded_at}</td>
                          <td className="py-2 pr-4">{dep.last_downloaded_at}</td>
                          <td className="py-2">{dep.download_count}</td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              )}
            </section>
          )}
        </div>
      )}
    </div>
  )
}
