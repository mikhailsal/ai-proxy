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
  await page.route('https://api.example/ui/v1/whoami', async (route) => {
    await route.fulfill({ status: 200, body: JSON.stringify({ role: 'user' }), contentType: 'application/json' })
  })

  await page.goto('/')
  await page.getByLabel('base-url').fill('https://api.example')
  await page.getByLabel('api-key').fill('user-key')
  await page.getByRole('button', { name: 'Connect' }).click()
  await expect(page.getByLabel('connected-badge')).toBeVisible()
  await expect(page.getByText('Connected to https://api.example as user')).toBeVisible()
})


test('List → Details → Back navigation (mocked API)', async ({ page }) => {
  await page.route('https://api.example/ui/v1/health', async (route) => {
    await route.fulfill({ status: 200, body: JSON.stringify({ status: 'ok' }), contentType: 'application/json' })
  })
  await page.route('https://api.example/ui/v1/whoami', async (route) => {
    await route.fulfill({ status: 200, body: JSON.stringify({ role: 'user' }), contentType: 'application/json' })
  })
  // First list response (match with query params)
  await page.route(/https:\/\/api\.example\/ui\/v1\/requests.*/, async (route) => {
    await route.fulfill({
      status: 200,
      body: JSON.stringify({
        items: [
          { request_id: 'r1', ts: 2, endpoint: '/v1/x', model: 'm', status_code: 200, latency_ms: 10 },
        ],
        nextCursor: null,
      }),
      contentType: 'application/json',
    })
  })
  // Details response
  await page.route('https://api.example/ui/v1/requests/r1', async (route) => {
    await route.fulfill({
      status: 200,
      body: JSON.stringify({
        request_id: 'r1', server_id: 's', ts: 2, endpoint: '/v1/x',
        model_original: 'm', model_mapped: 'm', status_code: 200, latency_ms: 10,
        api_key_hash: 'k', request_json: { a: 1 }, response_json: { b: 2 }, dialog_id: null
      }),
      contentType: 'application/json',
    })
  })

  await page.goto('/')
  await page.getByLabel('base-url').fill('https://api.example')
  await page.getByLabel('api-key').fill('user-key')
  await page.getByRole('button', { name: 'Connect' }).click()
  await expect(page.getByLabel('connected-badge')).toBeVisible()

  // Load list
  await page.getByLabel('load-requests').click()
  await expect(page.getByLabel('requests-table')).toBeVisible()
  await expect(page.getByText('/v1/x')).toBeVisible()

  // Click row to open details
  await page.getByText('/v1/x').click()
  await expect(page.getByText('Request Details')).toBeVisible()
  await expect(page.getByText('Request JSON')).toBeVisible()

  // Back to list
  await page.getByLabel('close-details').click()
  await expect(page.getByLabel('requests-table')).toBeVisible()
})


