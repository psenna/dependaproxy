import { useEffect, useRef } from 'react'
import type { MiddlewareChain } from '../lib/middlewareCatalog'
import type { Middleware, RegistryConfig } from '../lib/types'
import MiddlewareChainEditor from './MiddlewareChainEditor'

export interface RegistryConfigEditorProps {
  registryType: string
  knownTypes: string[]
  value: RegistryConfig
  onChange: (next: { registryType: string; value: RegistryConfig }) => void
  onValidityChange: (isValid: boolean) => void
  onRemove: () => void
}

const CHAINS: MiddlewareChain[] = ['validation', 'retrieval', 'mutation']

export default function RegistryConfigEditor({
  registryType,
  knownTypes,
  value,
  onChange,
  onValidityChange,
  onRemove,
}: RegistryConfigEditorProps) {
  const chainValidRef = useRef<Record<MiddlewareChain, boolean>>({
    validation: true,
    retrieval: true,
    mutation: true,
  })
  const lastEmittedRef = useRef<boolean | null>(null)

  function emitValidity() {
    const valid = registryType !== '' && Object.values(chainValidRef.current).every(Boolean)
    if (lastEmittedRef.current !== valid) {
      lastEmittedRef.current = valid
      onValidityChange(valid)
    }
  }

  // Re-emit aggregate validity whenever the registry type changes.
  useEffect(() => {
    emitValidity()
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [registryType])

  function handleTypeChange(next: string) {
    onChange({ registryType: next, value })
  }

  function handleChainChange(chain: MiddlewareChain, next: Middleware[]) {
    const nextValue: RegistryConfig = { ...value }
    nextValue[chain] = next
    onChange({ registryType, value: nextValue })
  }

  function handleChainValidity(chain: MiddlewareChain, isValid: boolean) {
    chainValidRef.current = { ...chainValidRef.current, [chain]: isValid }
    emitValidity()
  }

  return (
    <div data-testid="registry-config-editor" className="rounded border border-gray-200 p-4">
      <div className="mb-3 flex items-center justify-between">
        <span className="text-sm font-medium text-gray-700">Registry type</span>
        <button
          type="button"
          aria-label="Remove registry"
          onClick={onRemove}
          className="rounded border border-gray-300 px-2 py-1 text-sm text-red-600 hover:bg-red-50"
        >
          Remove registry
        </button>
      </div>
      <select
        aria-label="Registry type"
        value={registryType}
        onChange={(e) => handleTypeChange(e.target.value)}
        className="mb-4 w-full rounded border border-gray-300 px-2 py-1 text-sm"
      >
        {registryType === '' && (
          <option value="" disabled>
            Select…
          </option>
        )}
        {knownTypes.map((t) => (
          <option key={t} value={t}>
            {t}
          </option>
        ))}
      </select>
      {CHAINS.map((chain) => (
        <MiddlewareChainEditor
          key={chain}
          chain={chain}
          value={value[chain] ?? []}
          onChange={(next) => handleChainChange(chain, next)}
          onValidityChange={(isValid) => handleChainValidity(chain, isValid)}
        />
      ))}
    </div>
  )
}
