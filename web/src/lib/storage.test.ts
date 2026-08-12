import { afterEach, describe, expect, it } from 'vitest'
import { clearToken, getToken, setToken } from './storage'

describe('admin token storage', () => {
  afterEach(() => sessionStorage.clear())

  it('returns null when no token has been set', () => {
    expect(getToken()).toBeNull()
  })

  it('round-trips a token through setToken/getToken', () => {
    setToken('tok-abc')
    expect(getToken()).toBe('tok-abc')
  })

  it('clears a previously stored token', () => {
    setToken('tok-abc')
    clearToken()
    expect(getToken()).toBeNull()
  })

  it('stores under the exact key dependaproxy.admin_token', () => {
    setToken('tok-abc')
    expect(sessionStorage.length).toBe(1)
    expect(sessionStorage.key(0)).toBe('dependaproxy.admin_token')
    expect(sessionStorage.getItem('dependaproxy.admin_token')).toBe('tok-abc')
  })

  it('overwrites a previously stored token', () => {
    setToken('first')
    setToken('second')
    expect(sessionStorage.length).toBe(1)
    expect(getToken()).toBe('second')
  })

  it('isolates tokens from other sessionStorage keys', () => {
    sessionStorage.setItem('some.other.key', 'value')
    setToken('tok-abc')
    expect(getToken()).toBe('tok-abc')
    clearToken()
    expect(sessionStorage.getItem('some.other.key')).toBe('value')
  })
})
