import { test, expect } from '@playwright/test'

test('Connect page loads', async ({ page }) => {
  await page.goto('/')
  await expect(page.locator('h1')).toHaveText('AI Proxy Logs UI')
  await expect(page.locator('text=Connect to your Logs API')).toBeVisible()
})

test('Connects and shows connected badge (mocked API)', async ({ page }) => {
  await page.route('https://api.example/ui/v1/health', async (route) => {
    await route.fulfill({ status: 200, body: JSON.stringify({ status: 'ok' }), contentType: 'application/json' })
  })
  await page.route('https://api.example/ui/v1/config', async (route) => {
    await route.fulfill({ status: 200, body: JSON.stringify({ features: { admin_enabled: false } }), contentType: 'application/json' })
  })

  await page.goto('/')
  await page.getByLabel('base-url').fill('https://api.example')
  await page.getByLabel('api-key').fill('user-key')
  await page.getByRole('button', { name: 'Connect' }).click()
  await expect(page.getByLabel('connected-badge')).toBeVisible()
  await expect(page.getByText('Connected to https://api.example as user')).toBeVisible()
})


