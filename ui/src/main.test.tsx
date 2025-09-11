import { render, screen, fireEvent, waitFor } from '@testing-library/react'
import App from './App'

function mockFetchImpl(handlers: Record<string, (init?: RequestInit) => { status: number; body: any }>) {
  vi.spyOn(global, 'fetch').mockImplementation(async (input: RequestInfo | URL, init?: RequestInit) => {
    const url = String(input)
    const handler = handlers[Object.keys(handlers).find(key => url.startsWith(key)) || '']
    if (!handler) throw new Error(`No mock for ${url}`)
    const { status, body } = handler(init)
    return new Response(JSON.stringify(body), { status, headers: { 'content-type': 'application/json' } }) as any
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
    'https://api.example/ui/v1/config': () => ({ status: 200, body: { features: { admin_enabled: false } } }),
  })
  render(<App />)
  fireEvent.change(screen.getByLabelText('base-url'), { target: { value: 'https://api.example' } })
  fireEvent.change(screen.getByLabelText('api-key'), { target: { value: 'user-key' } })
  fireEvent.click(screen.getByRole('button', { name: 'Connect' }))
  await waitFor(() => expect(screen.getByLabelText('connected-badge')).toBeInTheDocument())
  expect(screen.getByText(/Connected to https:\/\/api\.example as user/)).toBeInTheDocument()
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


