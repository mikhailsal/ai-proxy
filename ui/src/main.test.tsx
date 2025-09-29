import React from 'react'
import { render, screen, fireEvent, waitFor } from '@testing-library/react'
import App from './App'

function mockFetchImpl(handlers: Record<string, (init?: RequestInit) => { status: number; body: unknown }>) {
  vi.spyOn(global, 'fetch').mockImplementation(async (input: RequestInfo | URL, init?: RequestInit) => {
    const url = String(input)
    // Prefer the longest matching prefix to avoid '/requests' overshadowing '/requests/ID'
    const match = Object.keys(handlers)
      .filter((key) => url.startsWith(key))
      .sort((a, b) => b.length - a.length)[0]
    const handler = handlers[match || '']
    if (!handler) throw new Error(`No mock for ${url}`)
    const { status, body } = handler(init)
    return new Response(JSON.stringify(body), { status, headers: { 'content-type': 'application/json' } })
  })
}

it('renders Connect screen text', () => {
  render(<App />)
  expect(screen.getByText('AI Proxy Logs UI')).toBeInTheDocument()
  expect(screen.getByText(/Connect to your Logs API/)).toBeInTheDocument()
  expect(screen.getByLabelText('connect-form')).toBeInTheDocument()
})

it('connects successfully and shows connected badge', async () => {
  mockFetchImpl({
    'https://api.example/ui/v1/health': () => ({ status: 200, body: { status: 'ok' } }),
    'https://api.example/ui/v1/whoami': () => ({ status: 200, body: { role: 'user' } }),
  })
  render(<App />)
  fireEvent.change(screen.getByLabelText('base-url'), { target: { value: 'https://api.example' } })
  fireEvent.change(screen.getByLabelText('api-key'), { target: { value: 'user-key' } })
  fireEvent.click(screen.getByRole('button', { name: 'Connect' }))
  await waitFor(() => expect(screen.getByLabelText('connected-badge')).toBeInTheDocument())
  expect(screen.getByText(/Connected to https:\/\/api\.example as user/)).toBeInTheDocument()
  // localStorage persistence
  expect(localStorage.getItem('aiProxyLogs.baseUrl')).toBe('https://api.example')
  expect(localStorage.getItem('aiProxyLogs.apiKey')).toBe('user-key')
})

it('shows unauthorized error on 401', async () => {
  mockFetchImpl({
    'https://api.example/ui/v1/health': () => ({ status: 401, body: { code: 401, message: 'Unauthorized' } }),
  })
  render(<App />)
  fireEvent.change(screen.getByLabelText('base-url'), { target: { value: 'https://api.example' } })
  fireEvent.change(screen.getByLabelText('api-key'), { target: { value: 'bad-key' } })
  // Submit the form directly to avoid racing with disabled state label
  fireEvent.submit(screen.getByLabelText('connect-form'))
  await waitFor(() => expect(screen.getByRole('alert')).toBeInTheDocument())
  expect(screen.getByText('Unauthorized (check API key)')).toBeInTheDocument()
})

it('loads requests and uses load-more mode by default', async () => {
  const firstPage = {
    items: [
      { request_id: 'a', ts: 2, endpoint: '/v1/x', model: 'm', status_code: 200, latency_ms: 10 },
      { request_id: 'b', ts: 1, endpoint: '/v1/y', model: 'm', status_code: 200, latency_ms: 12 },
    ],
    nextCursor: 'CUR1',
  }
  const secondPage = {
    items: [
      { request_id: 'c', ts: 1, endpoint: '/v1/z', model: 'm', status_code: 500, latency_ms: 20 },
    ],
    nextCursor: null,
  }
  mockFetchImpl({
    'https://api.example/ui/v1/health': () => ({ status: 200, body: { status: 'ok' } }),
    'https://api.example/ui/v1/whoami': () => ({ status: 200, body: { role: 'user' } }),
    'https://api.example/ui/v1/requests': () => {
      // Simulate two sequential calls by toggling internal state
      (global as { __calls?: number }).__calls = ((global as { __calls?: number }).__calls || 0) + 1
      return { status: 200, body: ((global as { __calls?: number }).__calls === 1 ? firstPage : secondPage) }
    },
  })

  render(<App />)
  // Connect
  fireEvent.change(screen.getByLabelText('base-url'), { target: { value: 'https://api.example' } })
  fireEvent.change(screen.getByLabelText('api-key'), { target: { value: 'user-key' } })
  fireEvent.submit(screen.getByLabelText('connect-form'))
  await waitFor(() => expect(screen.getByLabelText('connected-badge')).toBeInTheDocument())

  // Switch to load-more mode
  const modeSelect = screen.getByDisplayValue('Pages')
  fireEvent.change(modeSelect, { target: { value: 'loadMore' } })

  // Load first page
  fireEvent.click(screen.getByLabelText('load-requests'))
  await waitFor(() => expect(screen.getByLabelText('requests-table')).toBeInTheDocument())
  expect(screen.getByText('/v1/x')).toBeInTheDocument()
  expect(screen.getByText('/v1/y')).toBeInTheDocument()

  // Load more - should append data
  fireEvent.click(screen.getByLabelText('load-more'))
  await waitFor(() => expect(screen.getByText('/v1/z')).toBeInTheDocument())
  // All items should still be visible (appended)
  expect(screen.getByText('/v1/x')).toBeInTheDocument()
  expect(screen.getByText('/v1/y')).toBeInTheDocument()
  expect(screen.getByText('/v1/z')).toBeInTheDocument()
})

it('supports page-based pagination with navigation', async () => {
  const firstPage = {
    items: [
      { request_id: 'a', ts: 2, endpoint: '/v1/x', model: 'm', status_code: 200, latency_ms: 10 },
      { request_id: 'b', ts: 1, endpoint: '/v1/y', model: 'm', status_code: 200, latency_ms: 12 },
    ],
    nextCursor: 'CUR1',
  }
  const secondPage = {
    items: [
      { request_id: 'c', ts: 1, endpoint: '/v1/z', model: 'm', status_code: 500, latency_ms: 20 },
    ],
    nextCursor: null,
  }

  let callCount = 0
  mockFetchImpl({
    'https://api.example/ui/v1/health': () => ({ status: 200, body: { status: 'ok' } }),
    'https://api.example/ui/v1/whoami': () => ({ status: 200, body: { role: 'user' } }),
    'https://api.example/ui/v1/requests': () => {
      callCount++
      return { status: 200, body: (callCount === 1 || callCount === 3 ? firstPage : secondPage) }
    },
  })

  render(<App />)
  // Connect
  fireEvent.change(screen.getByLabelText('base-url'), { target: { value: 'https://api.example' } })
  fireEvent.change(screen.getByLabelText('api-key'), { target: { value: 'user-key' } })
  fireEvent.submit(screen.getByLabelText('connect-form'))
  await waitFor(() => expect(screen.getByLabelText('connected-badge')).toBeInTheDocument())

  // Pages mode is default, load first page
  fireEvent.click(screen.getByLabelText('load-requests'))
  await waitFor(() => expect(screen.getByLabelText('requests-table')).toBeInTheDocument())
  expect(screen.getByText('/v1/x')).toBeInTheDocument()
  expect(screen.getByText('/v1/y')).toBeInTheDocument()
  expect(screen.getByText('Page 1')).toBeInTheDocument()

  // Go to next page - should replace data
  fireEvent.click(screen.getByLabelText('next-page'))
  await waitFor(() => expect(screen.getByText('/v1/z')).toBeInTheDocument())
  expect(screen.getByText('Page 2')).toBeInTheDocument()
  // Previous page items should not be visible (replaced)
  expect(screen.queryByText('/v1/x')).not.toBeInTheDocument()
  expect(screen.queryByText('/v1/y')).not.toBeInTheDocument()

  // Go back to previous page
  fireEvent.click(screen.getByLabelText('prev-page'))
  await waitFor(() => expect(screen.getByText('/v1/x')).toBeInTheDocument())
  expect(screen.getByText('/v1/y')).toBeInTheDocument()
  expect(screen.getByText('Page 1')).toBeInTheDocument()
  // Second page item should not be visible
  expect(screen.queryByText('/v1/z')).not.toBeInTheDocument()
})

it('opens request details and renders JSON viewer', async () => {
  const listPage = {
    items: [
      { request_id: 'r1', ts: 2, endpoint: '/v1/x', model: 'm', status_code: 200, latency_ms: 10 },
    ],
    nextCursor: null,
  }
  const details = {
    request_id: 'r1',
    server_id: 's',
    ts: 2,
    endpoint: '/v1/x',
    model_original: 'm',
    model_mapped: 'm',
    status_code: 200,
    latency_ms: 10,
    api_key_hash: 'k',
    request_json: { messages: [{ role: 'user', content: 'hi' }] },
    response_json: { choices: [{ message: { role: 'assistant', content: 'hello' } }] },
    dialog_id: null,
  }

  mockFetchImpl({
    'https://api.example/ui/v1/health': () => ({ status: 200, body: { status: 'ok' } }),
    'https://api.example/ui/v1/whoami': () => ({ status: 200, body: { role: 'user' } }),
    'https://api.example/ui/v1/requests': () => ({ status: 200, body: listPage }),
    'https://api.example/ui/v1/requests/r1': () => ({ status: 200, body: details }),
  })

  render(<App />)
  // Connect
  fireEvent.change(screen.getByLabelText('base-url'), { target: { value: 'https://api.example' } })
  fireEvent.change(screen.getByLabelText('api-key'), { target: { value: 'user-key' } })
  fireEvent.submit(screen.getByLabelText('connect-form'))
  await waitFor(() => expect(screen.getByLabelText('connected-badge')).toBeInTheDocument())

  // Load list
  fireEvent.click(screen.getByLabelText('load-requests'))
  await waitFor(() => expect(screen.getByLabelText('requests-table')).toBeInTheDocument())
  // Click row to open details
  const row = screen.getByText('/v1/x').closest('tr') as HTMLElement
  fireEvent.click(row)

  await waitFor(() => expect(screen.getByText('Request Details')).toBeInTheDocument())
  expect(screen.getByText('Request JSON')).toBeInTheDocument()
  expect(screen.getByText('Response JSON')).toBeInTheDocument()
})

it('collapses long JSON by default and toggles open', async () => {
  const longText = 'x'.repeat(400)
  const listPage = {
    items: [
      { request_id: 'r2', ts: 2, endpoint: '/v1/long', model: 'm', status_code: 200, latency_ms: 10 },
    ],
    nextCursor: null,
  }
  const details = {
    request_id: 'r2',
    server_id: 's',
    ts: 2,
    endpoint: '/v1/long',
    model_original: 'm',
    model_mapped: 'm',
    status_code: 200,
    latency_ms: 10,
    api_key_hash: 'k',
    request_json: { text: longText },
    response_json: {},
    dialog_id: null,
  }

  mockFetchImpl({
    'https://api.example/ui/v1/health': () => ({ status: 200, body: { status: 'ok' } }),
    'https://api.example/ui/v1/whoami': () => ({ status: 200, body: { role: 'user' } }),
    'https://api.example/ui/v1/requests': () => ({ status: 200, body: listPage }),
    'https://api.example/ui/v1/requests/r2': () => ({ status: 200, body: details }),
  })

  render(<App />)
  // Connect
  fireEvent.change(screen.getByLabelText('base-url'), { target: { value: 'https://api.example' } })
  fireEvent.change(screen.getByLabelText('api-key'), { target: { value: 'user-key' } })
  fireEvent.submit(screen.getByLabelText('connect-form'))
  await waitFor(() => expect(screen.getByLabelText('connected-badge')).toBeInTheDocument())

  // Load list
  fireEvent.click(screen.getByLabelText('load-requests'))
  await waitFor(() => expect(screen.getByLabelText('requests-table')).toBeInTheDocument())
  // Click row to open details
  const row = screen.getByText('/v1/long').closest('tr') as HTMLElement
  fireEvent.click(row)

  await waitFor(() => expect(screen.getByText('Request Details')).toBeInTheDocument())
  // Collapsed by default: nested key 'text' should not be visible
  expect(screen.queryByText(/text:/)).not.toBeInTheDocument()
  // Toggle open (first toggle button belongs to root node)
  const toggles = screen.getAllByLabelText('toggle-node')
  fireEvent.click(toggles[0])
  expect(await screen.findByText(/text:/)).toBeInTheDocument()
  // Copy buttons present
  expect(screen.getAllByLabelText('copy-json').length).toBeGreaterThan(0)
})
