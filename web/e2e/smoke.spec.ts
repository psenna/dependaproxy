import { expect, test } from '@playwright/test'

test('loads the app and shows the DependaProxy heading', async ({ page }) => {
  await page.goto('/')
  await expect(page.getByRole('heading', { name: /dependaproxy/i })).toBeVisible()
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
