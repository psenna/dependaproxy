import { render, screen } from '@testing-library/react'
import { describe, expect, it } from 'vitest'
import App from './App'

describe('App', () => {
  it('renders the DependaProxy heading with the text-red-500 Tailwind class', () => {
    render(<App />)
    const heading = screen.getByRole('heading', { name: /dependaproxy/i })
    expect(heading).toBeInTheDocument()
    expect(heading.className).toContain('text-red-500')
  })
})
