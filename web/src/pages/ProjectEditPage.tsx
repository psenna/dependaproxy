import { useEffect, useState } from 'react'
import type { FormEvent } from 'react'
import { Link, useNavigate, useParams } from 'react-router-dom'
import RegistryConfigEditor from '../components/RegistryConfigEditor'
import { useProject } from '../features/projects/useProject'
import { useUpdateProject } from '../features/projects/useUpdateProject'
import { KNOWN_REGISTRIES } from '../lib/knownRegistries'
import { ApiError, type RegistryConfig } from '../lib/types'

interface RegistryEntry {
  id: number
  type: string
  config: RegistryConfig
  valid: boolean
}

let entryIdCounter = 0

function nextEntryId(): number {
  entryIdCounter += 1
  return entryIdCounter
}

export default function ProjectEditPage({ knownRegistries = KNOWN_REGISTRIES }: { knownRegistries?: string[] }) {
  const { key = '' } = useParams()
  const navigate = useNavigate()
  const project = useProject(key)
  const update = useUpdateProject(key)
  const [entries, setEntries] = useState<RegistryEntry[]>([])
  const [prefilled, setPrefilled] = useState(false)
  const [submitError, setSubmitError] = useState<string | null>(null)
  const [submitting, setSubmitting] = useState(false)

  useEffect(() => {
    if (project.data && !prefilled) {
      const next = Object.entries(project.data.registries).map(([type, config]) => ({
        id: nextEntryId(),
        type,
        config,
        valid: type !== '',
      }))
      setEntries(next)
      setPrefilled(true)
    }
  }, [project.data, prefilled])

  const allEntriesValid = entries.length > 0 && entries.every((e) => e.valid && e.type !== '')
  const submitDisabled = submitting || !allEntriesValid

  function availableTypesFor(entry: RegistryEntry): string[] {
    return knownRegistries.filter(
      (t) => t === entry.type || !entries.some((e) => e.id !== entry.id && e.type === t),
    )
  }

  function addRegistry() {
    setEntries((prev) => [...prev, { id: nextEntryId(), type: '', config: {}, valid: false }])
  }

  function removeEntry(id: number) {
    setEntries((prev) => prev.filter((e) => e.id !== id))
  }

  function handleEntryChange(id: number, next: { registryType: string; value: RegistryConfig }) {
    setEntries((prev) => prev.map((e) => (e.id === id ? { ...e, type: next.registryType, config: next.value } : e)))
  }

  function handleEntryValidity(id: number, isValid: boolean) {
    setEntries((prev) => prev.map((e) => (e.id === id ? { ...e, valid: isValid } : e)))
  }

  async function handleSubmit(e: FormEvent) {
    e.preventDefault()
    if (submitDisabled) return
    setSubmitting(true)
    setSubmitError(null)
    const registries: Record<string, RegistryConfig> = {}
    for (const entry of entries) {
      registries[entry.type] = entry.config
    }
    try {
      await update.mutateAsync(registries)
      navigate(`/projects/${encodeURIComponent(key)}`)
    } catch (err) {
      if (err instanceof ApiError) {
        if (err.status === 400) {
          setSubmitError(err.message)
        } else if (err.status === 404) {
          setSubmitError('project not found')
        } else {
          setSubmitError('Failed to save project.')
        }
      } else {
        setSubmitError('Failed to save project.')
      }
    } finally {
      setSubmitting(false)
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
    <div data-testid="project-edit">
      <h1 className="text-2xl font-bold">Edit project</h1>
      {project.isLoading && <p data-testid="project-loading">Loading…</p>}
      {errorMessage && (
        <div
          role="alert"
          data-testid="project-error"
          className="rounded border border-red-500 bg-red-50 p-3 text-red-800"
        >
          {errorMessage}
        </div>
      )}
      {project.isSuccess && (
        <form onSubmit={handleSubmit} className="mt-4 max-w-2xl space-y-4">
          <div>
            <label htmlFor="project-key" className="mb-1 block text-sm font-medium text-gray-700">
              Key
            </label>
            <input
              id="project-key"
              type="text"
              value={key}
              readOnly
              aria-label="Key"
              className="w-full rounded border border-gray-300 bg-gray-100 px-2 py-1 text-sm"
            />
          </div>

          {submitError && (
            <div
              role="alert"
              data-testid="submit-error"
              className="rounded border border-red-500 bg-red-50 p-3 text-sm text-red-800"
            >
              {submitError}
            </div>
          )}

          <div className="space-y-4">
            {entries.map((entry) => (
              <RegistryConfigEditor
                key={entry.id}
                registryType={entry.type}
                knownTypes={availableTypesFor(entry)}
                value={entry.config}
                onChange={(next) => handleEntryChange(entry.id, next)}
                onValidityChange={(isValid) => handleEntryValidity(entry.id, isValid)}
                onRemove={() => removeEntry(entry.id)}
                overrideMode
              />
            ))}
          </div>

          <button
            type="button"
            onClick={addRegistry}
            className="rounded bg-blue-500 px-3 py-1.5 text-sm text-white hover:bg-blue-600"
          >
            Add registry
          </button>

          <div className="flex items-center gap-3">
            <button
              type="submit"
              disabled={submitDisabled}
              className="rounded bg-blue-500 px-3 py-1.5 text-sm text-white hover:bg-blue-600 disabled:cursor-not-allowed disabled:opacity-50"
            >
              {submitting ? 'Saving…' : 'Save project'}
            </button>
            <Link to={`/projects/${encodeURIComponent(key)}`} className="text-sm text-gray-600 hover:underline">
              Cancel
            </Link>
          </div>
        </form>
      )}
    </div>
  )
}
