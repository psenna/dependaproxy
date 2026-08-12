import { useRef, useState } from 'react'
import { Link } from 'react-router-dom'
import ConfirmDialog from '../components/ConfirmDialog'
import EmptyState from '../components/EmptyState'
import ErrorState from '../components/ErrorState'
import Loading from '../components/Loading'
import { useDeleteProject } from '../features/projects/useDeleteProject'
import { useProjects } from '../features/projects/useProjects'
import { ApiError, type RegistryConfig } from '../lib/types'

function registriesSummary(registries: Record<string, RegistryConfig>): string {
  const keys = Object.keys(registries)
  return keys.length > 0 ? keys.join(', ') : '—'
}

export default function ProjectsListPage() {
  const projects = useProjects()
  const deleteMutation = useDeleteProject()
  const [pendingDeleteKey, setPendingDeleteKey] = useState<string | null>(null)
  const [deleteError, setDeleteError] = useState<string | null>(null)
  const lastDeleteButtonRef = useRef<HTMLButtonElement>(null)

  function handleCancelDelete() {
    setPendingDeleteKey(null)
    lastDeleteButtonRef.current?.focus()
  }

  async function handleConfirmDelete() {
    const key = pendingDeleteKey
    if (key === null) return
    setPendingDeleteKey(null)
    setDeleteError(null)
    try {
      await deleteMutation.mutateAsync(key)
    } catch (err) {
      if (err instanceof ApiError) {
        if (err.status === 404) {
          setDeleteError(`Project "${key}" was not found — it may have already been deleted.`)
        } else if (err.status === 400) {
          setDeleteError(`Invalid project key: ${err.message}`)
        } else {
          setDeleteError(`Failed to delete project: ${err.message}`)
        }
      } else {
        setDeleteError('Failed to delete project.')
      }
    }
  }

  return (
    <div>
      <div className="flex items-center justify-between">
        <h1 className="text-2xl font-bold">Projects</h1>
        <Link
          to="/projects/new"
          className="rounded bg-blue-500 px-3 py-1.5 text-sm text-white hover:bg-blue-600"
        >
          New project
        </Link>
      </div>

      {deleteError && (
        <div
          role="alert"
          data-testid="delete-error"
          className="mt-4 rounded border border-red-500 bg-red-50 p-3 text-sm text-red-800"
        >
          {deleteError}
        </div>
      )}

      <div className="mt-4">
        {projects.isLoading && <Loading label="Loading projects…" testId="projects-loading" />}
        {projects.isError && (
          <ErrorState
            message="Failed to load projects."
            onRetry={() => projects.refetch()}
            testId="projects-error"
          />
        )}
        {projects.isSuccess && projects.data.projects.length === 0 && (
          <div data-testid="projects-empty">
            <EmptyState
              title="No projects yet"
              message="Create your first project to start managing registries."
            >
              <Link
                to="/projects/new"
                className="rounded bg-blue-500 px-3 py-1.5 text-sm text-white hover:bg-blue-600"
              >
                Create project
              </Link>
            </EmptyState>
          </div>
        )}
        {projects.isSuccess && projects.data.projects.length > 0 && (
          <table data-testid="projects-table" className="w-full border-collapse text-left text-sm">
            <thead>
              <tr className="border-b text-gray-500">
                <th className="py-2 pr-4 font-medium">Key</th>
                <th className="py-2 pr-4 font-medium">Registries</th>
                <th className="py-2 font-medium">Actions</th>
              </tr>
            </thead>
            <tbody>
              {projects.data.projects.map((project) => (
                <tr key={project.key} data-testid={`project-row-${project.key}`} className="border-b">
                  <td className="py-2 pr-4 font-medium">{project.key}</td>
                  <td className="py-2 pr-4" data-testid={`project-registries-${project.key}`}>
                    {registriesSummary(project.registries)}
                  </td>
                  <td className="py-2">
                    <div className="flex gap-2">
                      <Link
                        to={`/projects/${encodeURIComponent(project.key)}`}
                        className="text-blue-600 hover:underline"
                      >
                        View
                      </Link>
                      <Link
                        to={`/projects/${encodeURIComponent(project.key)}/edit`}
                        className="text-blue-600 hover:underline"
                      >
                        Edit
                      </Link>
                      <button
                        type="button"
                        ref={lastDeleteButtonRef}
                        data-testid={`project-delete-${project.key}`}
                        onClick={() => {
                          setDeleteError(null)
                          setPendingDeleteKey(project.key)
                        }}
                        className="text-red-600 hover:underline"
                      >
                        Delete {project.key}
                      </button>
                    </div>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>

      <ConfirmDialog
        open={pendingDeleteKey !== null}
        title="Delete project"
        message={
          <>
            Are you sure you want to delete project <strong>{pendingDeleteKey}</strong>? This is
            irreversible and drops the resolver cache.
          </>
        }
        confirmLabel="Delete"
        cancelLabel="Cancel"
        confirmTone="danger"
        onConfirm={handleConfirmDelete}
        onCancel={handleCancelDelete}
      />
    </div>
  )
}
