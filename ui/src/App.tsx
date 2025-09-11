import React from 'react'

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

async function getConfig(baseUrl: string, apiKey: string): Promise<{ admin_enabled: boolean }> {
  const res = await fetch(`${baseUrl.replace(/\/$/, '')}/ui/v1/config`, {
    headers: { Authorization: `Bearer ${apiKey}` },
  })
  if (!res.ok) throw new Error(`HTTP ${res.status}`)
  const data = await res.json()
  return { admin_enabled: !!data?.features?.admin_enabled }
}

export default function App() {
  const [baseUrl, setBaseUrl] = React.useState<string>(() => localStorage.getItem('aiProxyLogs.baseUrl') || '')
  const [apiKey, setApiKey] = React.useState<string>(() => localStorage.getItem('aiProxyLogs.apiKey') || '')
  const [state, setState] = React.useState<ConnectionState>({ status: 'disconnected' })

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
      const cfg = await getConfig(baseUrl, apiKey)
      const role = cfg.admin_enabled ? 'admin' : 'user'
      localStorage.setItem('aiProxyLogs.baseUrl', baseUrl)
      localStorage.setItem('aiProxyLogs.apiKey', apiKey)
      setState({ status: 'connected', baseUrl, role })
    } catch (err: any) {
      const msg = err?.message || 'Failed to connect'
      setState({ status: 'error', message: msg })
    }
  }

  function handleDisconnect() {
    setState({ status: 'disconnected' })
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
    </div>
  )
}


