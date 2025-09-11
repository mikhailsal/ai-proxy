import { test, expect } from '@playwright/test'

test('Connect page loads', async ({ page }) => {
  await page.goto('/')
  await expect(page.locator('h1')).toHaveText('AI Proxy Logs UI')
  await expect(page.locator('text=Connect to your Logs API')).toBeVisible()
})


