import { expect, test } from '@playwright/test'

test('logs in and shows the dashboard', async ({ page }) => {
  await page.goto('/')
  await page.getByPlaceholder('Admin token').fill('test-token')
  await page.getByRole('button', { name: /sign in/i }).click()
  await expect(page.getByRole('button', { name: 'Logout' })).toBeVisible()
  await expect(page.getByText(/proxy healthy/i)).toBeVisible()
})

test('serves /healthz via the MSW service worker', async ({ page }) => {
  await page.goto('/')
  await page
    .waitForFunction(() => window.__mswStarted !== undefined, null, { timeout: 5000 })
    .catch(() => {})
  const result = await page.evaluate(async () => {
    const r = await fetch('/healthz')
    return { status: r.status, body: await r.text() }
  })
  expect(result.status).toBe(200)
  expect(result.body).toBe('ok')
})
