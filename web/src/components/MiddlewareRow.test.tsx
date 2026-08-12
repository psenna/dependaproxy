import { fireEvent, render, screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { describe, expect, it, vi } from 'vitest'
import MiddlewareRow from './MiddlewareRow'

describe('MiddlewareRow', () => {
  const baseProps = {
    chain: 'validation' as const,
    index: 0,
    total: 1,
    type: '',
    paramsRaw: '',
    onChange: vi.fn(),
    onValidChange: vi.fn(),
    onRemove: vi.fn(),
    onMoveUp: vi.fn(),
    onMoveDown: vi.fn(),
  }

  it('renders catalog options for the chain', () => {
    render(<MiddlewareRow {...baseProps} />)
    const select = screen.getByLabelText('Type')
    expect(select).toHaveValue('')
    expect(screen.getByRole('option', { name: 'Deny-list check' })).toBeInTheDocument()
    expect(screen.getByRole('option', { name: 'CVE check' })).toBeInTheDocument()
    expect(screen.getByRole('option', { name: 'Custom…' })).toBeInTheDocument()
  })

  it('selecting a catalog type calls onChange', async () => {
    const user = userEvent.setup()
    const onChange = vi.fn()
    render(<MiddlewareRow {...baseProps} onChange={onChange} />)
    await user.selectOptions(screen.getByLabelText('Type'), 'cve-check')
    expect(onChange).toHaveBeenCalledWith({ type: 'cve-check', paramsRaw: '' })
  })

  it('selecting Custom reveals input and typing produces the custom type', async () => {
    const user = userEvent.setup()
    const onChange = vi.fn()
    render(<MiddlewareRow {...baseProps} onChange={onChange} />)
    await user.selectOptions(screen.getByLabelText('Type'), '__custom__')
    const input = screen.getByPlaceholderText(/custom/i)
    expect(input).toBeInTheDocument()
    fireEvent.change(input, { target: { value: 'custom-thing' } })
    expect(onChange).toHaveBeenLastCalledWith({ type: 'custom-thing', paramsRaw: '' })
  })

  it('prefilled free-form type shows selected and input visible', () => {
    render(<MiddlewareRow {...baseProps} type="custom-thing" />)
    expect(screen.getByLabelText('Type')).toHaveValue('custom-thing')
    const input = screen.getByPlaceholderText(/custom/i)
    expect(input).toHaveValue('custom-thing')
  })

  it('params textarea change calls onChange', () => {
    const onChange = vi.fn()
    render(<MiddlewareRow {...baseProps} type="cve-check" onChange={onChange} />)
    const textarea = screen.getByLabelText('Params (JSON)')
    fireEvent.change(textarea, { target: { value: '{"mode":"deny"}' } })
    expect(onChange).toHaveBeenLastCalledWith({ type: 'cve-check', paramsRaw: '{"mode":"deny"}' })
  })

  it('calls remove/up/down handlers and disables at bounds', async () => {
    const user = userEvent.setup()
    const onRemove = vi.fn()
    const onMoveUp = vi.fn()
    const onMoveDown = vi.fn()
    render(
      <MiddlewareRow
        {...baseProps}
        index={0}
        total={1}
        type="cve-check"
        onRemove={onRemove}
        onMoveUp={onMoveUp}
        onMoveDown={onMoveDown}
      />,
    )
    expect(screen.getByRole('button', { name: 'Move up' })).toBeDisabled()
    expect(screen.getByRole('button', { name: 'Move down' })).toBeDisabled()
    await user.click(screen.getByRole('button', { name: 'Remove middleware' }))
    expect(onRemove).toHaveBeenCalledTimes(1)
  })

  it('reports invalid when type is empty', () => {
    const onValidChange = vi.fn()
    render(<MiddlewareRow {...baseProps} onValidChange={onValidChange} />)
    expect(onValidChange).toHaveBeenCalledWith(false)
  })

  it('reports validity from the params field', () => {
    const onValidChange = vi.fn()
    render(<MiddlewareRow {...baseProps} type="cve-check" paramsRaw="{bad" onValidChange={onValidChange} />)
    expect(onValidChange).toHaveBeenCalledWith(false)
  })
})
