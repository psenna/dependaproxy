import { expect, test } from '@playwright/test'

test('redirects unauthenticated users to the login page', async ({ page }) => {
  await page.goto('/')
  await expect(page).toHaveURL(/\/login$/)
})

test('logs in, stores the admin token, and logs out', async ({ page }) => {
  await page.goto('/')
  await page.getByPlaceholder('Admin token').fill('secret-token')
  await page.getByRole('button', { name: /sign in/i }).click()
  await expect(page.getByRole('button', { name: 'Logout' })).toBeVisible()

  const token = await page.evaluate(() => sessionStorage.getItem('dependaproxy.admin_token'))
  expect(token).toBe('secret-token')

  await page.getByRole('button', { name: 'Logout' }).click()
  await expect(page).toHaveURL(/\/login$/)
  const afterLogout = await page.evaluate(() => sessionStorage.getItem('dependaproxy.admin_token'))
  expect(afterLogout).toBeNull()
})

test('protected routes redirect back to login after logout', async ({ page }) => {
  await page.goto('/')
  await page.getByPlaceholder('Admin token').fill('secret-token')
  await page.getByRole('button', { name: /sign in/i }).click()
  await expect(page.getByRole('button', { name: 'Logout' })).toBeVisible()

  await page.getByRole('button', { name: 'Logout' }).click()
  await expect(page).toHaveURL(/\/login$/)

  await page.goto('/projects')
  await expect(page).toHaveURL(/\/login$/)
})
