import { fireEvent, render, screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { useRef, useState } from 'react'
import { describe, expect, it, vi } from 'vitest'
import ConfirmDialog from './ConfirmDialog'

function FocusReturnHarness() {
  const [open, setOpen] = useState(false)
  const triggerRef = useRef<HTMLButtonElement>(null)
  return (
    <div>
      <button type="button" ref={triggerRef} onClick={() => setOpen(true)}>
        Open dialog
      </button>
      <ConfirmDialog
        open={open}
        title="Delete project"
        message="Are you sure?"
        onConfirm={() => setOpen(false)}
        onCancel={() => {
          setOpen(false)
          triggerRef.current?.focus()
        }}
      />
    </div>
  )
}

describe('ConfirmDialog', () => {
  it('renders nothing when open is false', () => {
    render(
      <ConfirmDialog
        open={false}
        title="Delete project"
        message="Are you sure?"
        onConfirm={() => {}}
        onCancel={() => {}}
      />,
    )
    expect(screen.queryByRole('dialog')).not.toBeInTheDocument()
  })

  it('calls onConfirm when the confirm button is clicked', async () => {
    const user = userEvent.setup()
    const onConfirm = vi.fn()
    render(
      <ConfirmDialog
        open
        title="Delete project"
        message="Are you sure?"
        confirmLabel="Delete"
        onConfirm={onConfirm}
        onCancel={() => {}}
      />,
    )
    await user.click(screen.getByRole('button', { name: 'Delete' }))
    expect(onConfirm).toHaveBeenCalledTimes(1)
  })

  it('calls onCancel when the cancel button is clicked', async () => {
    const user = userEvent.setup()
    const onCancel = vi.fn()
    render(
      <ConfirmDialog
        open
        title="Delete project"
        message="Are you sure?"
        onConfirm={() => {}}
        onCancel={onCancel}
      />,
    )
    await user.click(screen.getByRole('button', { name: 'Cancel' }))
    expect(onCancel).toHaveBeenCalledTimes(1)
  })

  it('calls onCancel when Escape is pressed', () => {
    const onCancel = vi.fn()
    render(
      <ConfirmDialog
        open
        title="Delete project"
        message="Are you sure?"
        onConfirm={() => {}}
        onCancel={onCancel}
      />,
    )
    fireEvent.keyDown(document, { key: 'Escape' })
    expect(onCancel).toHaveBeenCalledTimes(1)
  })

  it('auto-focuses the confirm button', () => {
    render(
      <ConfirmDialog
        open
        title="Delete project"
        message="Are you sure?"
        confirmLabel="Delete"
        onConfirm={() => {}}
        onCancel={() => {}}
      />,
    )
    expect(screen.getByRole('button', { name: 'Delete' })).toHaveFocus()
  })

  it('traps Tab focus within the dialog', async () => {
    const user = userEvent.setup()
    render(
      <ConfirmDialog
        open
        title="Delete project"
        message="Are you sure?"
        confirmLabel="Delete"
        cancelLabel="Cancel"
        onConfirm={() => {}}
        onCancel={() => {}}
      />,
    )
    const confirm = screen.getByRole('button', { name: 'Delete' })
    const cancel = screen.getByRole('button', { name: 'Cancel' })
    expect(confirm).toHaveFocus()

    await user.tab()
    expect(cancel).toHaveFocus()

    await user.tab()
    expect(confirm).toHaveFocus()
  })

  it('traps Shift+Tab focus within the dialog', async () => {
    const user = userEvent.setup()
    render(
      <ConfirmDialog
        open
        title="Delete project"
        message="Are you sure?"
        confirmLabel="Delete"
        cancelLabel="Cancel"
        onConfirm={() => {}}
        onCancel={() => {}}
      />,
    )
    const confirm = screen.getByRole('button', { name: 'Delete' })
    const cancel = screen.getByRole('button', { name: 'Cancel' })
    expect(confirm).toHaveFocus()

    await user.tab({ shift: true })
    expect(cancel).toHaveFocus()

    await user.tab({ shift: true })
    expect(confirm).toHaveFocus()
  })

  it('returns focus to the trigger after Escape closes', () => {
    render(<FocusReturnHarness />)
    const trigger = screen.getByRole('button', { name: 'Open dialog' })
    fireEvent.click(trigger)
    expect(screen.getByRole('dialog')).toBeInTheDocument()
    fireEvent.keyDown(document, { key: 'Escape' })
    expect(screen.queryByRole('dialog')).not.toBeInTheDocument()
    expect(trigger).toHaveFocus()
  })

  it('renders custom labels', () => {
    render(
      <ConfirmDialog
        open
        title="Remove item"
        message="Really remove?"
        confirmLabel="Remove"
        cancelLabel="Keep"
        onConfirm={() => {}}
        onCancel={() => {}}
      />,
    )
    expect(screen.getByRole('button', { name: 'Remove' })).toBeInTheDocument()
    expect(screen.getByRole('button', { name: 'Keep' })).toBeInTheDocument()
  })
})
