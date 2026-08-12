import { expect, test } from '@playwright/test'

test.describe.configure({ mode: 'serial' })

async function login(page: import('@playwright/test').Page) {
  await page.goto('/')
  await page.getByPlaceholder('Admin token').fill('test-token')
  await page.getByRole('button', { name: /sign in/i }).click()
  await expect(page.getByRole('button', { name: 'Logout' })).toBeVisible()
}

test('shows the SBOM table for a project with dependencies', async ({ page }) => {
  await login(page)
  await page.goto('/projects/my-app')
  await page.getByRole('tab', { name: 'Dependencies' }).click()
  await expect(page.getByTestId('dependencies-table')).toBeVisible()
  await expect(page.getByTestId('dependencies-table')).toContainText('react')
  await expect(page.getByTestId('dependencies-table')).toContainText('18.3.1')
})

test('filters the SBOM by package', async ({ page }) => {
  await login(page)
  await page.goto('/projects/my-app')
  await page.getByRole('tab', { name: 'Dependencies' }).click()
  await expect(page.getByTestId('dependencies-table')).toBeVisible()
  await page.getByTestId('filter-pkg').fill('react')
  await expect(page.getByTestId('dependencies-table')).toContainText('react')
  await page.getByTestId('filter-pkg').fill('nonexistent')
  await expect(page.getByTestId('dependencies-empty')).toBeVisible()
  await expect(page.getByTestId('dependencies-empty')).toContainText('flushed asynchronously')
})

test('shows the empty state for a project without dependencies', async ({ page }) => {
  await login(page)
  await page.goto('/projects/empty-app')
  await page.getByRole('tab', { name: 'Dependencies' }).click()
  await expect(page.getByTestId('dependencies-empty')).toBeVisible()
  await expect(page.getByTestId('dependencies-table')).not.toBeVisible()
})
