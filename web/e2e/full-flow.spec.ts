import { expect, test } from '@playwright/test'

// One serial test drives the whole lifecycle so the MSW worker's in-memory
// fixtures survive across steps (client-side navigation only after the initial
// goto — a page.goto would reload the worker and reset the fixtures).
test.describe.configure({ mode: 'serial' })

test('full flow: login, create, edit, view SBOM, delete', async ({ page }) => {
  const key = 'full-flow-app'

  // 1. Login
  await page.goto('/')
  await page.getByPlaceholder('Admin token').fill('test-token')
  await page.getByRole('button', { name: /sign in/i }).click()
  await expect(page.getByRole('button', { name: 'Logout' })).toBeVisible()

  // 2. Create a project
  await page.getByRole('link', { name: 'Projects' }).click()
  await page.getByRole('link', { name: 'New project' }).click()
  await page.getByLabel('Key').fill(key)
  await page.getByRole('button', { name: 'Add registry' }).click()
  await page.getByLabel('Registry type').selectOption('npm')
  await page.getByRole('button', { name: 'Create project' }).click()
  await expect(page).toHaveURL(new RegExp(`/projects/${key}$`))

  // 3. Edit the project: override the retrieval chain and add a middleware
  await page.getByRole('link', { name: 'Edit' }).click()
  await expect(page.getByTestId('override-retrieval')).not.toBeChecked()
  await page.getByTestId('override-retrieval').check()
  const retrievalEditor = page.getByTestId('middleware-chain-editor').filter({ hasText: 'retrieval' })
  await retrievalEditor.getByRole('button', { name: 'Add middleware' }).click()
  await retrievalEditor.getByLabel('Type').selectOption('upstream-registry')
  await page.getByRole('button', { name: 'Save project' }).click()
  await expect(page).toHaveURL(new RegExp(`/projects/${key}$`))

  // 4. View the SBOM (a freshly created project has no dependencies yet)
  await page.getByRole('tab', { name: 'Dependencies' }).click()
  await expect(page.getByTestId('dependencies-empty')).toBeVisible()
  await expect(page.getByTestId('dependencies-empty')).toContainText(/no dependencies/i)

  // 5. Delete the project
  await page.getByRole('link', { name: 'Projects' }).click()
  await page.getByTestId(`project-delete-${key}`).click()
  await page.getByRole('button', { name: /^delete$/i }).click()
  await expect(page.getByTestId(`project-delete-${key}`)).not.toBeVisible()
})
