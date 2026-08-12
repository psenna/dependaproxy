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
          {health.isLoading && <p>Checking proxy status…</p>}
          {health.isSuccess && <p>Proxy healthy</p>}
          {health.isError && <p>Proxy unreachable</p>}
        </div>
        <div data-testid="project-count-card" className="rounded border border-gray-200 bg-white p-4">
          {projects.isLoading && <p>Projects: …</p>}
          {projects.isSuccess && <p>Projects: {projects.data.projects.length}</p>}
          {projects.isError && <p>Projects: unavailable</p>}
        </div>
      </div>
    </div>
  )
}
