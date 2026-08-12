import { fireEvent, render, screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { describe, expect, it, vi } from 'vitest'
import MiddlewareChainEditor from './MiddlewareChainEditor'

describe('MiddlewareChainEditor', () => {
  it('renders a prefilled chain with correct types and params', () => {
    const value = [{ type: 'deny-list-check' }, { type: 'cve-check', params: { mode: 'deny' } }]
    render(
      <MiddlewareChainEditor chain="validation" value={value} onChange={() => {}} onValidityChange={() => {}} />,
    )
    expect(screen.getByTestId('middleware-chain-editor')).toBeInTheDocument()
    const selects = screen.getAllByLabelText('Type')
    expect(selects).toHaveLength(2)
    expect(selects[0]).toHaveValue('deny-list-check')
    expect(selects[1]).toHaveValue('cve-check')
    const textareas = screen.getAllByLabelText('Params (JSON)')
    expect(textareas[1]).toHaveValue('{\n  "mode": "deny"\n}')
  })

  it('adds an empty row and reports invalid', async () => {
    const user = userEvent.setup()
    const onValidityChange = vi.fn()
    render(
      <MiddlewareChainEditor chain="validation" value={[]} onChange={() => {}} onValidityChange={onValidityChange} />,
    )
    expect(screen.getByText('No middleware configured')).toBeInTheDocument()
    await user.click(screen.getByRole('button', { name: 'Add middleware' }))
    expect(screen.getByLabelText('Type')).toBeInTheDocument()
    expect(onValidityChange).toHaveBeenLastCalledWith(false)
  })

  it('removes the right row', async () => {
    const user = userEvent.setup()
    const onChange = vi.fn()
    const value = [{ type: 'deny-list-check' }, { type: 'cve-check' }]
    render(<MiddlewareChainEditor chain="validation" value={value} onChange={onChange} onValidityChange={() => {}} />)
    const removeButtons = screen.getAllByRole('button', { name: 'Remove middleware' })
    await user.click(removeButtons[0])
    expect(onChange).toHaveBeenLastCalledWith([{ type: 'cve-check' }])
  })

  it('moves rows down and up', async () => {
    const user = userEvent.setup()
    const onChange = vi.fn()
    const value = [{ type: 'deny-list-check' }, { type: 'cve-check' }]
    render(<MiddlewareChainEditor chain="validation" value={value} onChange={onChange} onValidityChange={() => {}} />)
    await user.click(screen.getAllByRole('button', { name: 'Move down' })[0])
    expect(onChange).toHaveBeenLastCalledWith([{ type: 'cve-check' }, { type: 'deny-list-check' }])
    await user.click(screen.getAllByRole('button', { name: 'Move up' })[1])
    expect(onChange).toHaveBeenLastCalledWith([{ type: 'deny-list-check' }, { type: 'cve-check' }])
  })

  it('accepts a free-form custom type', () => {
    const value = [{ type: 'custom-thing' }]
    render(<MiddlewareChainEditor chain="validation" value={value} onChange={() => {}} onValidityChange={() => {}} />)
    expect(screen.getByLabelText('Type')).toHaveValue('custom-thing')
    expect(screen.getByPlaceholderText(/custom/i)).toHaveValue('custom-thing')
  })

  it('drives validity from params JSON', () => {
    const onValidityChange = vi.fn()
    const value = [{ type: 'cve-check', params: { mode: 'deny' } }]
    render(
      <MiddlewareChainEditor chain="validation" value={value} onChange={() => {}} onValidityChange={onValidityChange} />,
    )
    const textarea = screen.getByLabelText('Params (JSON)')
    fireEvent.change(textarea, { target: { value: '{bad' } })
    expect(onValidityChange).toHaveBeenLastCalledWith(false)
    fireEvent.change(textarea, { target: { value: '{"mode":"deny"}' } })
    expect(onValidityChange).toHaveBeenLastCalledWith(true)
  })

  it('omits empty params from emitted middleware', async () => {
    const user = userEvent.setup()
    const onChange = vi.fn()
    const value = [{ type: 'cve-check', params: { mode: 'deny' } }]
    render(<MiddlewareChainEditor chain="validation" value={value} onChange={onChange} onValidityChange={() => {}} />)
    const textarea = screen.getByLabelText('Params (JSON)')
    await user.clear(textarea)
    expect(onChange).toHaveBeenLastCalledWith([{ type: 'cve-check' }])
  })

  it('emits valid params', () => {
    const onChange = vi.fn()
    const value = [{ type: 'cve-check' }]
    render(<MiddlewareChainEditor chain="validation" value={value} onChange={onChange} onValidityChange={() => {}} />)
    const textarea = screen.getByLabelText('Params (JSON)')
    fireEvent.change(textarea, { target: { value: '{"mode":"deny"}' } })
    expect(onChange).toHaveBeenLastCalledWith([{ type: 'cve-check', params: { mode: 'deny' } }])
  })

  it('renders the empty state with an add button', () => {
    render(<MiddlewareChainEditor chain="validation" value={[]} onChange={() => {}} onValidityChange={() => {}} />)
    expect(screen.getByText('No middleware configured')).toBeInTheDocument()
    expect(screen.getByRole('button', { name: 'Add middleware' })).toBeInTheDocument()
  })
})
