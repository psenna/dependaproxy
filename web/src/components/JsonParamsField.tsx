import { useEffect, useRef } from 'react'

export interface JsonParamsFieldProps {
  value: string
  onChange: (next: string) => void
  onValidChange: (isValid: boolean) => void
  label?: string
  id?: string
}

type Validity = 'neutral' | 'valid' | 'invalid'

function validateParams(raw: string): { validity: Validity; error?: string } {
  const trimmed = raw.trim()
  if (trimmed === '') return { validity: 'neutral' }
  let parsed: unknown
  try {
    parsed = JSON.parse(trimmed)
  } catch (err) {
    return { validity: 'invalid', error: err instanceof Error ? err.message : 'Invalid JSON' }
  }
  if (parsed === null || typeof parsed !== 'object' || Array.isArray(parsed)) {
    return { validity: 'invalid', error: 'Params must be a JSON object' }
  }
  return { validity: 'valid' }
}

export default function JsonParamsField({ value, onChange, onValidChange, label, id }: JsonParamsFieldProps) {
  const lastReported = useRef<boolean | null>(null)
  const { validity, error } = validateParams(value)
  const isValid = validity !== 'invalid'

  useEffect(() => {
    if (lastReported.current !== isValid) {
      lastReported.current = isValid
      onValidChange(isValid)
    }
  }, [isValid, onValidChange])

  const borderClass =
    validity === 'invalid' ? 'border-red-500' : validity === 'valid' ? 'border-green-500' : 'border-gray-300'

  return (
    <div>
      {label && (
        <label htmlFor={id} className="mb-1 block text-sm font-medium text-gray-700">
          {label}
        </label>
      )}
      <textarea
        id={id}
        value={value}
        onChange={(e) => onChange(e.target.value)}
        rows={4}
        spellCheck={false}
        className={`w-full rounded border font-mono text-sm ${borderClass}`}
      />
      {validity === 'invalid' && error && <p className="mt-1 text-xs text-red-600">{error}</p>}
    </div>
  )
}
