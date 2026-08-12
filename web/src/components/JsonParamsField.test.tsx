import { fireEvent, render, screen } from '@testing-library/react'
import { describe, expect, it, vi } from 'vitest'
import JsonParamsField from './JsonParamsField'

describe('JsonParamsField', () => {
  it('treats empty input as neutral and valid', () => {
    const onValidChange = vi.fn()
    render(<JsonParamsField value="" onChange={() => {}} onValidChange={onValidChange} />)
    const textarea = screen.getByRole('textbox')
    expect(textarea).toHaveClass('border-gray-300')
    expect(onValidChange).toHaveBeenCalledWith(true)
  })

  it('shows a green border for a valid object', () => {
    const onValidChange = vi.fn()
    render(<JsonParamsField value='{"mode":"deny"}' onChange={() => {}} onValidChange={onValidChange} />)
    const textarea = screen.getByRole('textbox')
    expect(textarea).toHaveClass('border-green-500')
    expect(onValidChange).toHaveBeenCalledWith(true)
  })

  it('shows a red border and the parse error for invalid JSON', () => {
    const onValidChange = vi.fn()
    render(<JsonParamsField value="{bad" onChange={() => {}} onValidChange={onValidChange} />)
    const textarea = screen.getByRole('textbox')
    expect(textarea).toHaveClass('border-red-500')
    expect(screen.getByText(/Expected property name/)).toBeInTheDocument()
    expect(onValidChange).toHaveBeenCalledWith(false)
  })

  it.each(['[1,2]', '"hello"', '42', 'null'])('rejects non-object JSON %s', (raw) => {
    const onValidChange = vi.fn()
    render(<JsonParamsField value={raw} onChange={() => {}} onValidChange={onValidChange} />)
    expect(screen.getByText('Params must be a JSON object')).toBeInTheDocument()
    expect(onValidChange).toHaveBeenCalledWith(false)
  })

  it('accepts nested objects', () => {
    const onValidChange = vi.fn()
    render(<JsonParamsField value='{"a":{"b":1}}' onChange={() => {}} onValidChange={onValidChange} />)
    expect(screen.getByRole('textbox')).toHaveClass('border-green-500')
    expect(onValidChange).toHaveBeenCalledWith(true)
  })

  it('calls onChange when typing', () => {
    const onChange = vi.fn()
    render(<JsonParamsField value="" onChange={onChange} onValidChange={() => {}} />)
    const textarea = screen.getByRole('textbox')
    fireEvent.change(textarea, { target: { value: '{"a":1}' } })
    expect(onChange).toHaveBeenCalledWith('{"a":1}')
  })
})
