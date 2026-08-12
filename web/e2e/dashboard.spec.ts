import { expect, test } from '@playwright/test'

async function login(page: import('@playwright/test').Page) {
  await page.goto('/')
  await page.getByPlaceholder('Admin token').fill('test-token')
  await page.getByRole('button', { name: /sign in/i }).click()
}

test('shows a healthy proxy and project count on the dashboard', async ({ page }) => {
  await login(page)
  await expect(page.getByText(/proxy healthy/i)).toBeVisible({ timeout: 10_000 })
  await expect(page.getByText(/projects:\s*2/i)).toBeVisible()
})

test('reflects a healthz failure after refetch', async ({ page }) => {
  await login(page)
  await expect(page.getByText(/proxy healthy/i)).toBeVisible({ timeout: 10_000 })
  await page.evaluate(() => window.__mswSetHealth!(500, 'down'))
  await page.evaluate(() => window.__refetchHealth!())
  await expect(page.getByText(/proxy unreachable/i)).toBeVisible({ timeout: 5_000 })
})
