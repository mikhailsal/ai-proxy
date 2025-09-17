import React from 'react'
import JsonViewer from './JsonViewer'

type ConnectionState =
  | { status: 'disconnected' }
  | { status: 'connecting' }
  | { status: 'connected'; baseUrl: string; role: 'user' | 'admin' }
  | { status: 'error'; message: string }

async function checkHealth(baseUrl: string, apiKey: string): Promise<'ok'> {
  const res = await fetch(`${baseUrl.replace(/\/$/, '')}/ui/v1/health`, {
    headers: { Authorization: `Bearer ${apiKey}` },
  })
  if (!res.ok) {
    throw new Error(`HTTP ${res.status}`)
  }
  const data = await res.json().catch(() => ({}))
  if (data && data.status === 'ok') return 'ok'
  throw new Error('Bad response')
}


async function getWhoAmI(baseUrl: string, apiKey: string): Promise<'user'|'admin'> {
  const res = await fetch(`${baseUrl.replace(/\/$/, '')}/ui/v1/whoami`, {
    headers: { Authorization: `Bearer ${apiKey}` },
  })
  if (!res.ok) throw new Error(`HTTP ${res.status}`)
  const data = await res.json()
  return data?.role === 'admin' ? 'admin' : 'user'
}

export default function App() {
  const [baseUrl, setBaseUrl] = React.useState<string>(() => localStorage.getItem('aiProxyLogs.baseUrl') || '')
  const [apiKey, setApiKey] = React.useState<string>(() => localStorage.getItem('aiProxyLogs.apiKey') || '')
  const [state, setState] = React.useState<ConnectionState>({ status: 'disconnected' })
  const [requests, setRequests] = React.useState<Array<{
    request_id: string
    ts: number
    endpoint: string
    model: string
    status_code: number
    latency_ms: number
  }> | null>(null)
  const [nextCursor, setNextCursor] = React.useState<string | null>(null)
  const [selected, setSelected] = React.useState<{
    request_id: string
    endpoint: string
    model_mapped?: string
    model_original?: string
    status_code: number
    latency_ms: number
    request_json: unknown
    response_json: unknown
  } | null>(null)
  const [dateRange, setDateRange] = React.useState<{ since: string; to: string }>(() => {
    const today = new Date()
    const ymd = today.toISOString().slice(0, 10)
    return { since: ymd, to: ymd }
  })

  React.useEffect(() => {
    if (baseUrl && apiKey) {
      // Try autoconnect
      handleConnect(new Event('init'))
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [])

  async function handleConnect(e: Event | React.FormEvent) {
    e.preventDefault()
    if (!baseUrl || !apiKey) return
    setState({ status: 'connecting' })
    try {
      await checkHealth(baseUrl, apiKey)
      // Determine effective role from whoami endpoint
      const role = await getWhoAmI(baseUrl, apiKey)
      localStorage.setItem('aiProxyLogs.baseUrl', baseUrl)
      localStorage.setItem('aiProxyLogs.apiKey', apiKey)
      setState({ status: 'connected', baseUrl, role })
    } catch (err: unknown) {
      const msg = (err instanceof Error ? err.message : 'Failed to connect')
      setState({ status: 'error', message: msg })
    }
  }

  function handleDisconnect() {
    setState({ status: 'disconnected' })
  }

  async function loadRequests(reset: boolean = false) {
    if (state.status !== 'connected') return
    const base = state.baseUrl.replace(/\/$/, '')
    const url = new URL(`${base}/ui/v1/requests`)
    url.searchParams.set('since', dateRange.since)
    url.searchParams.set('to', dateRange.to)
    url.searchParams.set('limit', '10')
    if (!reset && nextCursor) url.searchParams.set('cursor', nextCursor)
    const res = await fetch(url.toString(), {
      headers: { Authorization: `Bearer ${localStorage.getItem('aiProxyLogs.apiKey') || apiKey}` },
    })
    if (!res.ok) throw new Error(`HTTP ${res.status}`)
    const data = await res.json() as {
      items: Array<{
        request_id: string
        ts: number
        endpoint: string
        model: string
        status_code: number
        latency_ms: number
      }>
      nextCursor: string | null
    }
    setRequests((prev) => (reset || !prev ? data.items : [...prev, ...data.items]))
    setNextCursor(data.nextCursor || null)
  }

  async function loadRequestDetails(requestId: string) {
    if (state.status !== 'connected') return
    const base = state.baseUrl.replace(/\/$/, '')
    const res = await fetch(`${base}/ui/v1/requests/${encodeURIComponent(requestId)}` , {
      headers: { Authorization: `Bearer ${localStorage.getItem('aiProxyLogs.apiKey') || apiKey}` },
    })
    if (!res.ok) throw new Error(`HTTP ${res.status}`)
    const data = await res.json()
    setSelected(data)
  }

  return (
    <div style={{ fontFamily: 'sans-serif', padding: 24 }}>
      <h1>AI Proxy Logs UI</h1>

      {state.status === 'connected' ? (
        <div aria-label="connected-badge" style={{ marginBottom: 16 }}>
          <span
            style={{
              background: '#e6ffed',
              color: '#0a7f2e',
              border: '1px solid #b7eb8f',
              padding: '4px 8px',
              borderRadius: 6,
              fontSize: 14,
            }}
          >
            Connected to {state.baseUrl} as {state.role}
          </span>
          <button style={{ marginLeft: 8 }} onClick={handleDisconnect}>Disconnect</button>
        </div>
      ) : (
        <p>
          Connect to your Logs API at <code>https://logs-api.&lt;your-domain&gt;</code>.
        </p>
      )}

      {state.status !== 'connected' && (
        <form onSubmit={handleConnect} aria-label="connect-form" style={{ display: 'grid', gap: 8, maxWidth: 520 }}>
          <label>
            Base URL
            <input
              aria-label="base-url"
              placeholder="https://logs-api.example.com"
              value={baseUrl}
              onChange={(e) => setBaseUrl(e.target.value)}
            />
          </label>
          <label>
            API Key
            <input
              aria-label="api-key"
              placeholder="paste key"
              value={apiKey}
              onChange={(e) => setApiKey(e.target.value)}
            />
          </label>
          <div>
            <button type="submit" disabled={state.status === 'connecting'}>
              {state.status === 'connecting' ? 'Connecting…' : 'Connect'}
            </button>
          </div>
          {state.status === 'error' && (
            <div role="alert" style={{ color: '#c00' }}>
              {state.message.includes('401') ? 'Unauthorized (check API key)' : 'Failed to connect'}
            </div>
          )}
        </form>
      )}

      {state.status === 'connected' && (
        <div>
          <h2>Requests</h2>
          <div style={{ display: 'flex', gap: 8, alignItems: 'center', marginBottom: 8 }}>
            <label>
              Since
              <input
                aria-label="since-date"
                type="date"
                value={dateRange.since}
                onChange={(e) => setDateRange((r) => ({ ...r, since: e.target.value }))}
              />
            </label>
            <label>
              To
              <input
                aria-label="to-date"
                type="date"
                value={dateRange.to}
                onChange={(e) => setDateRange((r) => ({ ...r, to: e.target.value }))}
              />
            </label>
            <button aria-label="load-requests" onClick={() => loadRequests(true)}>Load</button>
          </div>

          <table aria-label="requests-table" style={{ borderCollapse: 'collapse', width: '100%' }}>
            <thead>
              <tr>
                <th style={{ textAlign: 'left', borderBottom: '1px solid #ddd', padding: 4 }}>ts</th>
                <th style={{ textAlign: 'left', borderBottom: '1px solid #ddd', padding: 4 }}>endpoint</th>
                <th style={{ textAlign: 'left', borderBottom: '1px solid #ddd', padding: 4 }}>model</th>
                <th style={{ textAlign: 'left', borderBottom: '1px solid #ddd', padding: 4 }}>status</th>
                <th style={{ textAlign: 'left', borderBottom: '1px solid #ddd', padding: 4 }}>latency</th>
              </tr>
            </thead>
            <tbody>
              {(requests || []).map((r) => (
                <tr key={r.request_id} onClick={() => loadRequestDetails(r.request_id)} style={{ cursor: 'pointer' }}>
                  <td style={{ padding: 4 }}>{new Date(r.ts * 1000).toISOString()}</td>
                  <td style={{ padding: 4 }}>{r.endpoint}</td>
                  <td style={{ padding: 4 }}>{r.model}</td>
                  <td style={{ padding: 4 }}>{String(r.status_code)}</td>
                  <td style={{ padding: 4 }}>{r.latency_ms}</td>
                </tr>
              ))}
              {(!requests || requests.length === 0) && (
                <tr>
                  <td colSpan={5} style={{ padding: 8, color: '#666' }}>No data</td>
                </tr>
              )}
            </tbody>
          </table>
          <div style={{ marginTop: 8 }}>
            <button aria-label="load-more" disabled={!nextCursor} onClick={() => loadRequests(false)}>
              Next
            </button>
          </div>
        </div>
      )}

      {state.status === 'connected' && selected && (
        <div style={{ marginTop: 24 }}>
          <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
            <h2>Request Details</h2>
            <button aria-label="close-details" onClick={() => setSelected(null)}>Back</button>
          </div>
          <div style={{ display: 'grid', gap: 8 }}>
            <div>
              <strong>ID:</strong> <code>{selected.request_id}</code>
            </div>
            <div>
              <strong>Endpoint:</strong> <code>{selected.endpoint}</code>
            </div>
            <div>
              <strong>Model:</strong> <code>{selected.model_mapped || selected.model_original || ''}</code>
            </div>
            <div>
              <strong>Status:</strong> <code>{String(selected.status_code)}</code>
            </div>
            <div>
              <strong>Latency:</strong> <code>{String(selected.latency_ms)}</code>
            </div>
          </div>
          <div style={{ marginTop: 12 }}>
            <JsonViewer label="Request JSON" value={selected.request_json} />
          </div>
          <div style={{ marginTop: 12 }}>
            <JsonViewer label="Response JSON" value={selected.response_json} />
          </div>
        </div>
      )}
    </div>
  )
}
