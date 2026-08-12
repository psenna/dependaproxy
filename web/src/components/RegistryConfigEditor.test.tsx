import { useState } from 'react'
import { render, screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { describe, expect, it, vi } from 'vitest'
import type { RegistryConfig } from '../lib/types'
import RegistryConfigEditor from './RegistryConfigEditor'

describe('RegistryConfigEditor', () => {
  it('renders the three middleware chains and the selected registry type', () => {
    render(
      <RegistryConfigEditor
        registryType="npm"
        knownTypes={['npm', 'pypi']}
        value={{}}
        onChange={() => {}}
        onValidityChange={() => {}}
        onRemove={() => {}}
      />,
    )
    expect(screen.getAllByTestId('middleware-chain-editor')).toHaveLength(3)
    expect(screen.getByLabelText('Registry type')).toHaveValue('npm')
  })

  it('only offers the known registry types', () => {
    render(
      <RegistryConfigEditor
        registryType="npm"
        knownTypes={['npm', 'pypi']}
        value={{}}
        onChange={() => {}}
        onValidityChange={() => {}}
        onRemove={() => {}}
      />,
    )
    const options = screen
      .getAllByRole('option')
      .map((o) => (o as HTMLOptionElement).value)
    expect(options).toEqual(['npm', 'pypi'])
  })

  it('calls onRemove when the remove button is clicked', async () => {
    const user = userEvent.setup()
    const onRemove = vi.fn()
    render(
      <RegistryConfigEditor
        registryType="npm"
        knownTypes={['npm', 'pypi']}
        value={{}}
        onChange={() => {}}
        onValidityChange={() => {}}
        onRemove={onRemove}
      />,
    )
    await user.click(screen.getByRole('button', { name: 'Remove registry' }))
    expect(onRemove).toHaveBeenCalledTimes(1)
  })

  it('reports invalid until a registry type is chosen, then valid', async () => {
    const user = userEvent.setup()
    const onChange = vi.fn()
    const onValidityChange = vi.fn()
    function Harness() {
      const [registryType, setRegistryType] = useState('')
      const [value, setValue] = useState<RegistryConfig>({})
      return (
        <RegistryConfigEditor
          registryType={registryType}
          knownTypes={['npm', 'pypi']}
          value={value}
          onChange={(next) => {
            onChange(next)
            setRegistryType(next.registryType)
            setValue(next.value)
          }}
          onValidityChange={onValidityChange}
          onRemove={() => {}}
        />
      )
    }
    render(<Harness />)
    expect(onValidityChange).toHaveBeenLastCalledWith(false)

    await user.selectOptions(screen.getByLabelText('Registry type'), 'npm')
    expect(onChange).toHaveBeenLastCalledWith({ registryType: 'npm', value: {} })
    expect(onValidityChange).toHaveBeenLastCalledWith(true)
  })

  it('aggregates validity from a bad middleware chain', async () => {
    const user = userEvent.setup()
    const onValidityChange = vi.fn()
    render(
      <RegistryConfigEditor
        registryType="npm"
        knownTypes={['npm', 'pypi']}
        value={{}}
        onChange={() => {}}
        onValidityChange={onValidityChange}
        onRemove={() => {}}
      />,
    )
    expect(onValidityChange).toHaveBeenLastCalledWith(true)

    await user.click(screen.getAllByRole('button', { name: 'Add middleware' })[0])
    expect(onValidityChange).toHaveBeenLastCalledWith(false)

    await user.click(screen.getAllByRole('button', { name: 'Remove middleware' })[0])
    expect(onValidityChange).toHaveBeenLastCalledWith(true)
  })
})
