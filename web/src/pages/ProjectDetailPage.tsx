import { useState } from 'react'
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

export default function ProjectDetailPage({ debounceMs = 400 }: { debounceMs?: number }) {
  const { key = '' } = useParams()
  const project = useProject(key)
  const [activeTab, setActiveTab] = useState<'config' | 'dependencies'>('config')
  const [registryInput, setRegistryInput] = useState('')
  const [pkgInput, setPkgInput] = useState('')
  const [copiedSha, setCopiedSha] = useState<string | null>(null)
  const debRegistry = useDebouncedValue(registryInput, debounceMs)
  const debPkg = useDebouncedValue(pkgInput, debounceMs)
  const dependencies = useDependencies(key, { registry: debRegistry, pkg: debPkg })

  function copySha256(sha: string) {
    try {
      void navigator.clipboard.writeText(sha).catch(() => {})
    } catch {
      // ignore clipboard errors
    }
    setCopiedSha(sha)
    window.setTimeout(() => setCopiedSha(null), 1500)
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

          <div data-testid="project-detail" className="mt-4 rounded border border-gray-200 bg-white p-4">
            <p>
              <span className="font-medium">Key:</span> {project.data.key}
            </p>
            <p>
              <span className="font-medium">Registries:</span>{' '}
              <span data-testid="project-registries">{registriesSummary(project.data.registries)}</span>
            </p>
          </div>

          <div role="tablist" className="mt-4 flex gap-2">
            <button
              type="button"
              role="tab"
              aria-selected={activeTab === 'config'}
              onClick={() => setActiveTab('config')}
              className={
                activeTab === 'config'
                  ? 'rounded bg-blue-500 px-3 py-1.5 text-sm text-white'
                  : 'rounded border border-gray-300 px-3 py-1.5 text-sm text-gray-600'
              }
            >
              Config
            </button>
            <button
              type="button"
              role="tab"
              aria-selected={activeTab === 'dependencies'}
              onClick={() => setActiveTab('dependencies')}
              className={
                activeTab === 'dependencies'
                  ? 'rounded bg-blue-500 px-3 py-1.5 text-sm text-white'
                  : 'rounded border border-gray-300 px-3 py-1.5 text-sm text-gray-600'
              }
            >
              Dependencies
            </button>
          </div>

          {activeTab === 'dependencies' && (
            <div className="mt-4">
              <div className="flex gap-2">
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
                <table
                  data-testid="dependencies-table"
                  className="mt-4 w-full border-collapse text-left text-sm"
                >
                  <thead>
                    <tr className="border-b text-gray-500">
                      <th className="py-2 pr-4 font-medium">registry</th>
                      <th className="py-2 pr-4 font-medium">pkg</th>
                      <th className="py-2 pr-4 font-medium">version</th>
                      <th className="py-2 pr-4 font-medium">artifact_id</th>
                      <th className="py-2 pr-4 font-medium">sha256</th>
                      <th className="py-2 pr-4 font-medium">first_downloaded_at</th>
                      <th className="py-2 pr-4 font-medium">last_downloaded_at</th>
                      <th className="py-2 font-medium">download_count</th>
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
              )}
            </div>
          )}
        </div>
      )}
    </div>
  )
}
