import ErrorState from '../components/ErrorState'
import Loading from '../components/Loading'
import { useHealth } from '../features/health/useHealth'
import { useProjects } from '../features/projects/useProjects'

export default function DashboardPage() {
  const health = useHealth()
  const projects = useProjects()

  return (
    <div>
      <h1 className="text-2xl font-bold">Dashboard</h1>
      <div className="mt-4 grid gap-4 sm:grid-cols-2">
        <div
          data-testid="health-card"
          className={
            health.isError
              ? 'rounded border border-red-500 bg-red-50 p-4 text-red-800'
              : 'rounded border border-green-500 bg-green-50 p-4 text-green-800'
          }
        >
          {health.isLoading && <Loading label="Checking proxy status…" />}
          {health.isSuccess && <p>Proxy healthy</p>}
          {health.isError && (
            <div className="flex items-center justify-between gap-3">
              <p>Proxy unreachable</p>
              <button
                type="button"
                onClick={() => health.refetch()}
                className="dp-btn-danger text-xs"
              >
                Retry
              </button>
            </div>
          )}
        </div>
        <div data-testid="project-count-card" className="dp-card">
          {projects.isLoading && <Loading label="Projects: …" />}
          {projects.isSuccess && <p>Projects: {projects.data.projects.length}</p>}
          {projects.isError && (
            <ErrorState
              message="Projects: unavailable"
              onRetry={() => projects.refetch()}
              testId="projects-error"
            />
          )}
        </div>
      </div>
    </div>
  )
}
