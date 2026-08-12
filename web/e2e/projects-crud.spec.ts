import { expect, test } from '@playwright/test'

test.describe.configure({ mode: 'serial' })

async function login(page: import('@playwright/test').Page) {
  await page.goto('/')
  await page.getByPlaceholder('Admin token').fill('test-token')
  await page.getByRole('button', { name: /sign in/i }).click()
  await expect(page.getByRole('button', { name: 'Logout' })).toBeVisible()
}

test('cancel does not delete the project', async ({ page }) => {
  await login(page)
  await page.goto('/projects')
  await page.getByTestId('project-delete-my-app').click()
  await page.getByRole('button', { name: /cancel/i }).click()
  await expect(page.getByTestId('project-delete-my-app')).toBeVisible()
})

test('delete removes the project row', async ({ page }) => {
  await login(page)
  await page.goto('/projects')
  await page.getByTestId('project-delete-my-app').click()
  await page.getByRole('button', { name: /^delete$/i }).click()
  await expect(page.getByTestId('project-delete-my-app')).not.toBeVisible()
  await expect(page.getByTestId('projects-empty')).toBeVisible()
})

test('creates a project and shows it in the list', async ({ page }) => {
  await login(page)
  await page.goto('/projects/new')
  await page.getByLabel('Key').fill('new-e2e-app')
  await page.getByRole('button', { name: 'Add registry' }).click()
  await page.getByLabel('Registry type').selectOption('npm')
  await page.getByRole('button', { name: 'Create project' }).click()
  await expect(page).toHaveURL(/\/projects\/new-e2e-app$/)
  await page.getByRole('link', { name: 'Projects' }).click()
  await expect(page.getByTestId('project-row-new-e2e-app')).toBeVisible()
})
