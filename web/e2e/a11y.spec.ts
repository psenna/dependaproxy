import { AxeBuilder } from '@axe-core/playwright'
import { expect, test, type Page } from '@playwright/test'

async function login(page: Page) {
  await page.goto('/')
  await page.getByPlaceholder('Admin token').fill('test-token')
  await page.getByRole('button', { name: /sign in/i }).click()
  await expect(page.getByRole('button', { name: 'Logout' })).toBeVisible()
}

async function expectNoSeriousViolations(page: Page) {
  const results = await new AxeBuilder({ page }).analyze()
  const serious = results.violations.filter(
    (v) => v.impact === 'serious' || v.impact === 'critical',
  )
  expect(
    serious,
    serious.map((v) => `${v.id} (${v.impact}): ${v.help}`).join('\n'),
  ).toEqual([])
}

test('dashboard has no serious axe violations', async ({ page }) => {
  await login(page)
  await expect(page.getByText(/proxy healthy/i)).toBeVisible({ timeout: 10_000 })
  await expectNoSeriousViolations(page)
})

test('projects list has no serious axe violations', async ({ page }) => {
  await login(page)
  await page.goto('/projects')
  await expect(page.getByTestId('projects-table')).toBeVisible()
  await expectNoSeriousViolations(page)
})

test('project create has no serious axe violations', async ({ page }) => {
  await login(page)
  await page.goto('/projects/new')
  await expect(page.getByTestId('project-create')).toBeVisible()
  await expectNoSeriousViolations(page)
})

test('project detail has no serious axe violations', async ({ page }) => {
  await login(page)
  await page.goto('/projects/my-app')
  await page.getByRole('tab', { name: 'Dependencies' }).click()
  await expect(page.getByTestId('dependencies-table')).toBeVisible()
  await expectNoSeriousViolations(page)
})

test('tab-key walkthrough of delete confirmation', async ({ page }) => {
  await login(page)
  await page.goto('/projects')
  await expect(page.getByTestId('projects-table')).toBeVisible()

  await page.getByTestId('project-delete-my-app').focus()
  await page.keyboard.press('Enter')
  await expect(page.getByRole('dialog')).toBeVisible()
  await expect(page.getByRole('button', { name: /^delete$/i })).toBeFocused()

  await page.keyboard.press('Tab')
  await expect(page.getByRole('button', { name: /^cancel$/i })).toBeFocused()

  await page.keyboard.press('Shift+Tab')
  await expect(page.getByRole('button', { name: /^delete$/i })).toBeFocused()

  await page.keyboard.press('Escape')
  await expect(page.getByRole('dialog')).not.toBeVisible()
  await expect(page.getByTestId('project-delete-my-app')).toBeFocused()
})

test('no horizontal scroll at 375px', async ({ page }) => {
  await page.setViewportSize({ width: 375, height: 812 })
  await login(page)

  await page.goto('/projects')
  await expect(page.getByTestId('projects-table')).toBeVisible()
  const projectsScrollWidth = await page.evaluate(() => document.documentElement.scrollWidth)
  expect(projectsScrollWidth).toBeLessThanOrEqual(375)

  await page.goto('/projects/my-app')
  await page.getByRole('tab', { name: 'Dependencies' }).click()
  await expect(page.getByTestId('dependencies-table')).toBeVisible()
  const depsScrollWidth = await page.evaluate(() => document.documentElement.scrollWidth)
  expect(depsScrollWidth).toBeLessThanOrEqual(375)
})
