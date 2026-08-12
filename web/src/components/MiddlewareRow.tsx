import { useEffect, useId, useRef, useState } from 'react'
import { catalogForChain, isKnownType, type MiddlewareChain } from '../lib/middlewareCatalog'
import JsonParamsField from './JsonParamsField'

export interface MiddlewareRowProps {
  chain: MiddlewareChain
  index: number
  total: number
  type: string
  paramsRaw: string
  onChange: (next: { type: string; paramsRaw: string }) => void
  onValidChange: (isValid: boolean) => void
  onRemove: () => void
  onMoveUp: () => void
  onMoveDown: () => void
}

export default function MiddlewareRow({
  chain,
  index,
  total,
  type,
  paramsRaw,
  onChange,
  onValidChange,
  onRemove,
  onMoveUp,
  onMoveDown,
}: MiddlewareRowProps) {
  const id = useId()
  const [customMode, setCustomMode] = useState(type !== '' && !isKnownType(type))
  const paramsValidRef = useRef(true)
  const lastValidRef = useRef<boolean | null>(null)

  const isCustomType = type !== '' && !isKnownType(type)
  const showCustomInput = customMode || isCustomType
  const selectValue = isCustomType ? type : customMode ? '__custom__' : type
  const entries = catalogForChain(chain)

  useEffect(() => {
    const valid = type.trim() !== '' && paramsValidRef.current
    if (lastValidRef.current !== valid) {
      lastValidRef.current = valid
      onValidChange(valid)
    }
  }, [type, onValidChange])

  function handleTypeSelect(next: string) {
    if (next === '__custom__') {
      setCustomMode(true)
      onChange({ type: '', paramsRaw })
    } else {
      setCustomMode(false)
      onChange({ type: next, paramsRaw })
    }
  }

  function handleCustomTypeChange(next: string) {
    onChange({ type: next, paramsRaw })
  }

  function handleParamsChange(next: string) {
    onChange({ type, paramsRaw: next })
  }

  function handleParamsValidChange(isValid: boolean) {
    paramsValidRef.current = isValid
    const valid = type.trim() !== '' && isValid
    if (lastValidRef.current !== valid) {
      lastValidRef.current = valid
      onValidChange(valid)
    }
  }

  return (
    <div className="rounded border border-gray-200 p-3">
      <div className="flex gap-3">
        <div className="flex-1 space-y-3">
          <div>
            <label htmlFor={`${id}-type`} className="mb-1 block text-sm font-medium text-gray-700">
              Type
            </label>
            <select
              id={`${id}-type`}
              value={selectValue}
              onChange={(e) => handleTypeSelect(e.target.value)}
              className="w-full rounded border border-gray-300 px-2 py-1 text-sm"
            >
              {type === '' && (
                <option value="" disabled>
                  Select…
                </option>
              )}
              {entries.map((entry) => (
                <option key={entry.type} value={entry.type}>
                  {entry.label}
                </option>
              ))}
              <option value="__custom__">Custom…</option>
              {isCustomType && <option value={type}>{type}</option>}
            </select>
            {showCustomInput && (
              <input
                type="text"
                value={type}
                onChange={(e) => handleCustomTypeChange(e.target.value)}
                placeholder="Custom middleware type"
                className="mt-1 w-full rounded border border-gray-300 px-2 py-1 text-sm"
              />
            )}
          </div>
          <JsonParamsField
            id={`${id}-params`}
            label="Params (JSON)"
            value={paramsRaw}
            onChange={handleParamsChange}
            onValidChange={handleParamsValidChange}
          />
        </div>
        <div className="flex flex-col gap-1">
          <button
            type="button"
            aria-label="Move up"
            disabled={index === 0}
            onClick={onMoveUp}
            className="rounded border border-gray-300 px-2 py-1 text-sm hover:bg-gray-100 disabled:cursor-not-allowed disabled:opacity-50"
          >
            ↑
          </button>
          <button
            type="button"
            aria-label="Move down"
            disabled={index === total - 1}
            onClick={onMoveDown}
            className="rounded border border-gray-300 px-2 py-1 text-sm hover:bg-gray-100 disabled:cursor-not-allowed disabled:opacity-50"
          >
            ↓
          </button>
          <button
            type="button"
            aria-label="Remove middleware"
            onClick={onRemove}
            className="rounded border border-gray-300 px-2 py-1 text-sm text-red-600 hover:bg-red-50"
          >
            ✕
          </button>
        </div>
      </div>
    </div>
  )
}
