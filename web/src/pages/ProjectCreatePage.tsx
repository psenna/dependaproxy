import { useState } from 'react'
import type { FormEvent } from 'react'
import { Link, useNavigate } from 'react-router-dom'
import { useQueryClient } from '@tanstack/react-query'
import RegistryConfigEditor from '../components/RegistryConfigEditor'
import { createProject } from '../lib/api'
import { KNOWN_REGISTRIES } from '../lib/knownRegistries'
import { ApiError, type RegistryConfig } from '../lib/types'

const KEY_RE = /^[a-zA-Z0-9._-]+$/
const REQUIRE_AT_LEAST_ONE_REGISTRY = true

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

export default function ProjectCreatePage({ knownRegistries = KNOWN_REGISTRIES }: { knownRegistries?: string[] }) {
  const navigate = useNavigate()
  const queryClient = useQueryClient()
  const [key, setKey] = useState('')
  const [entries, setEntries] = useState<RegistryEntry[]>([])
  const [submitError, setSubmitError] = useState<string | null>(null)
  const [submitting, setSubmitting] = useState(false)

  const keyValid = key !== '' && key !== '-' && KEY_RE.test(key)
  const allEntriesValid = entries.length > 0 && entries.every((e) => e.valid && e.type !== '')
  const submitDisabled = !keyValid || submitting || (REQUIRE_AT_LEAST_ONE_REGISTRY ? !allEntriesValid : false)

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
      await createProject({ key, registries })
      void queryClient.invalidateQueries({ queryKey: ['projects'] })
      navigate(`/projects/${encodeURIComponent(key)}`)
    } catch (err) {
      if (err instanceof ApiError) {
        if (err.status === 409) {
          setSubmitError('key already exists')
        } else if (err.status === 400) {
          setSubmitError(err.message)
        } else {
          setSubmitError('Failed to create project.')
        }
      } else {
        setSubmitError('Failed to create project.')
      }
    } finally {
      setSubmitting(false)
    }
  }

  return (
    <div data-testid="project-create">
      <h1 className="text-2xl font-bold">New project</h1>
      <form onSubmit={handleSubmit} className="mt-4 max-w-2xl space-y-4">
        <div>
          <label htmlFor="project-key" className="mb-1 block text-sm font-medium text-gray-700">
            Key
          </label>
          <input
            id="project-key"
            type="text"
            value={key}
            onChange={(e) => setKey(e.target.value)}
            className="w-full rounded border border-gray-300 px-2 py-1 text-sm"
          />
          {key !== '' && !keyValid && (
            <p data-testid="key-error" className="mt-1 text-xs text-red-600">
              Key must be 1+ characters of letters, digits, dot, underscore, or dash (and not &quot;-&quot;).
            </p>
          )}
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
            {submitting ? 'Creating…' : 'Create project'}
          </button>
          <Link to="/projects" className="text-sm text-gray-600 hover:underline">
            Cancel
          </Link>
        </div>
      </form>
    </div>
  )
}
