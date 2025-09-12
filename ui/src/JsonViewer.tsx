import React from 'react'

type JsonViewerProps = {
  value: unknown
  label?: string
  collapseThreshold?: number // collapse strings/arrays/objects whose serialized length exceeds this
}

type NodeProps = {
  k: string | null
  v: unknown
  level: number
  collapseThreshold: number
}

function isPrimitive(x: unknown): x is string | number | boolean | null | undefined {
  return x === null || x === undefined || typeof x !== 'object'
}

function stringifyPreview(v: unknown): string {
  try {
    const j = JSON.stringify(v)
    return typeof j === 'string' ? j : String(v)
  } catch {
    return String(v)
  }
}

function KeyLabel({ text }: { text: string }) {
  return <span style={{ color: '#b58900' }}>{text}</span>
}

function StringVal({ text }: { text: string }) {
  return <span style={{ color: '#2aa198' }}>&quot;{text}&quot;</span>
}

function NumberVal({ num }: { num: number }) {
  return <span style={{ color: '#268bd2' }}>{String(num)}</span>
}

function BooleanVal({ b }: { b: boolean }) {
  return <span style={{ color: '#dc322f' }}>{String(b)}</span>
}

function NullVal() {
  return <span style={{ color: '#859900' }}>null</span>
}

function CopyButton({ data }: { data: unknown }) {
  const handleCopy = async () => {
    const text = typeof data === 'string' ? data : JSON.stringify(data, null, 2)
    try {
      await (navigator as { clipboard?: { writeText?: (text: string) => Promise<void> } }).clipboard?.writeText?.(text)
    } catch {
      // noop
    }
  }
  return (
    <button aria-label="copy-json" onClick={handleCopy} style={{ marginLeft: 8, fontSize: 12 }}>
      Copy
    </button>
  )
}

function Node({ k, v, level, collapseThreshold }: NodeProps) {
  const [open, setOpen] = React.useState<boolean>(() => {
    const preview = stringifyPreview(v)
    return (preview?.length ?? 0) <= collapseThreshold
  })

  if (isPrimitive(v)) {
    return (
      <div style={{ marginLeft: level * 12 }}>
        {k !== null && <><KeyLabel text={`${k}: `} /></>}
        {v === null ? (
          <NullVal />
        ) : typeof v === 'string' ? (
          <StringVal text={v} />
        ) : typeof v === 'number' ? (
          <NumberVal num={v} />
        ) : typeof v === 'boolean' ? (
          <BooleanVal b={v} />
        ) : (
          <span>{String(v)}</span>
        )}
      </div>
    )
  }

  const isArray = Array.isArray(v)
  const entries:[string, unknown][] = isArray ? (v as unknown[]).map((item, idx) => [String(idx), item]) : Object.entries(v as Record<string, unknown>)
  const typeLabel = isArray ? `Array(${entries.length})` : 'Object'

  return (
    <div style={{ marginLeft: level * 12 }}>
      {k !== null && <KeyLabel text={`${k}: `} />}
      <button
        aria-label="toggle-node"
        onClick={() => setOpen((o) => !o)}
        style={{ fontSize: 12, marginRight: 6 }}
      >
        {open ? '▾' : '▸'}
      </button>
      <span style={{ color: '#657b83' }}>{typeLabel}</span>
      <CopyButton data={v} />
      {open && (
        <div>
          {entries.map(([ck, cv]) => (
            <Node key={ck} k={ck} v={cv} level={level + 1} collapseThreshold={collapseThreshold} />
          ))}
        </div>
      )}
    </div>
  )
}

export default function JsonViewer({ value, label, collapseThreshold = 256 }: JsonViewerProps) {
  return (
    <div>
      {label && (
        <div style={{ display: 'flex', alignItems: 'center', marginBottom: 4 }}>
          <strong>{label}</strong>
          <CopyButton data={value} />
        </div>
      )}
      <div
        style={{
          background: '#fdf6e3',
          border: '1px solid #eee8d5',
          borderRadius: 6,
          padding: 8,
          fontFamily: 'ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, \'Liberation Mono\', \'Courier New\', monospace',
          fontSize: 13,
          overflow: 'auto',
          maxHeight: 360,
        }}
      >
        <Node k={null} v={value} level={0} collapseThreshold={collapseThreshold} />
      </div>
    </div>
  )
}


