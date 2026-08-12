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

  it('override mode: checkbox reflects value[chain] presence', () => {
    render(
      <RegistryConfigEditor
        registryType="npm"
        knownTypes={['npm', 'pypi']}
        value={{ validation: [{ type: 'deny-list-check' }] }}
        onChange={() => {}}
        onValidityChange={() => {}}
        onRemove={() => {}}
        overrideMode
      />,
    )
    expect(screen.getByTestId('override-validation')).toBeChecked()
    expect(screen.getByTestId('override-retrieval')).not.toBeChecked()
    expect(screen.getByTestId('override-mutation')).not.toBeChecked()
  })

  it('override mode: unchecking deletes the chain key from the value', async () => {
    const user = userEvent.setup()
    const onChange = vi.fn()
    render(
      <RegistryConfigEditor
        registryType="npm"
        knownTypes={['npm', 'pypi']}
        value={{ validation: [{ type: 'deny-list-check' }] }}
        onChange={onChange}
        onValidityChange={() => {}}
        onRemove={() => {}}
        overrideMode
      />,
    )
    await user.click(screen.getByTestId('override-validation'))
    expect(onChange).toHaveBeenLastCalledWith({ registryType: 'npm', value: {} })
  })

  it('override mode: re-checking restores the stashed draft', async () => {
    const user = userEvent.setup()
    function Harness() {
      const [value, setValue] = useState<RegistryConfig>({ validation: [{ type: 'deny-list-check' }] })
      return (
        <RegistryConfigEditor
          registryType="npm"
          knownTypes={['npm', 'pypi']}
          value={value}
          onChange={(next) => setValue(next.value)}
          onValidityChange={() => {}}
          onRemove={() => {}}
          overrideMode
        />
      )
    }
    render(<Harness />)
    const checkbox = screen.getByTestId('override-validation')
    expect(checkbox).toBeChecked()

    await user.click(checkbox)
    expect(checkbox).not.toBeChecked()
    expect(screen.queryByTestId('middleware-chain-editor')).not.toBeInTheDocument()

    await user.click(checkbox)
    expect(checkbox).toBeChecked()
    expect(screen.getByLabelText('Type')).toHaveValue('deny-list-check')
  })

  it('override mode: unchecked chains contribute valid even when another chain is invalid', async () => {
    const user = userEvent.setup()
    const onValidityChange = vi.fn()
    render(
      <RegistryConfigEditor
        registryType="npm"
        knownTypes={['npm', 'pypi']}
        value={{ validation: [{ type: 'deny-list-check' }] }}
        onChange={() => {}}
        onValidityChange={onValidityChange}
        onRemove={() => {}}
        overrideMode
      />,
    )
    expect(onValidityChange).toHaveBeenLastCalledWith(true)

    await user.click(screen.getAllByRole('button', { name: 'Add middleware' })[0])
    expect(onValidityChange).toHaveBeenLastCalledWith(false)

    await user.click(screen.getByTestId('override-validation'))
    expect(onValidityChange).toHaveBeenLastCalledWith(true)
  })

  it('create mode (no overrideMode) renders all three editors and no checkboxes', () => {
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
    expect(screen.queryByTestId('override-validation')).not.toBeInTheDocument()
    expect(screen.queryByTestId('override-retrieval')).not.toBeInTheDocument()
    expect(screen.queryByTestId('override-mutation')).not.toBeInTheDocument()
  })
})
