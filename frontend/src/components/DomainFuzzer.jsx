import { useState, useRef } from 'react'

export default function DomainFuzzer() {
  const [domain, setDomain] = useState('')
  const [results, setResults] = useState([])
  const [running, setRunning] = useState(false)
  const [status, setStatus] = useState('')
  const [summary, setSummary] = useState(null)
  const [selected, setSelected] = useState(null)
  const abortRef = useRef(null)

async function run() {
  console.log('run called, domain:', domain)  // ADD THIS
  if (!domain.trim() || running) return
    if (abortRef.current) abortRef.current.abort()
    abortRef.current = new AbortController()
    setRunning(true); setResults([]); setSummary(null); setSelected(null)

    try {
      const res = await fetch('/api/fuzz', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ domain: domain.trim() }),
        signal: abortRef.current.signal,
      })

      const reader = res.body.getReader()
      const decoder = new TextDecoder()
      let buf = ''

      while (true) {
        const { done, value } = await reader.read()
        if (done) break
        buf += decoder.decode(value, { stream: true })
        const lines = buf.split('\n'); buf = lines.pop()

        for (const line of lines) {
          if (!line.startsWith('data: ')) continue
          try {
            const d = JSON.parse(line.slice(6))
            if (d.type === 'status') setStatus(d.message)
            else if (d.type === 'result') {
              setResults(prev => [...prev, d])
              setStatus(`Testing ${d.index + 1}/${d.total}...`)
            }
            else if (d.type === 'complete') { setSummary(d); setStatus('') }
            else if (d.type === 'error') setStatus(`Error: ${d.message}`)
          } catch {}
        }
      }
    } catch (err) {
      if (err.name !== 'AbortError') setStatus('Error: ' + err.message)
    } finally { setRunning(false) }
  }

  const vulnCount  = results.filter(r => r.vulnerable).length
  const safeCount  = results.filter(r => !r.vulnerable && !r.error).length
  const errorCount = results.filter(r => r.error).length

  return (
    <div>
      {/* Domain input */}
      <div style={{ display:'flex', gap:8, marginBottom:12 }}>
        <input
          value={domain}
          onChange={e => setDomain(e.target.value)}
          onKeyDown={e => e.key === 'Enter' && run()}
          placeholder="https://vvce.ac.in"
          style={{ flex:1, background:'var(--surface2)', border:'1px solid var(--border)',
            borderRadius:8, padding:'8px 12px', color:'var(--text)',
            fontSize:13, outline:'none', fontFamily:'monospace' }}
        />
        <button onClick={run} disabled={running || !domain.trim()} style={{
          background: running ? 'var(--surface2)' : 'var(--amber)',
          border:'none', borderRadius:8, padding:'8px 16px',
          color: running ? 'var(--text3)' : '#000',
          fontSize:13, fontWeight:700,
          cursor: running ? 'not-allowed' : 'pointer' }}>
          {running ? 'Scanning...' : 'Scan domain'}
        </button>
      </div>

      {/* Stats */}
      {results.length > 0 && (
        <div style={{ display:'grid', gridTemplateColumns:'repeat(3,1fr)', gap:6, marginBottom:10 }}>
          {[
            { label:'Vulnerable', count:vulnCount,  color:'var(--red)' },
            { label:'Safe',       count:safeCount,   color:'var(--green)' },
            { label:'Errors',     count:errorCount,  color:'var(--text3)' },
          ].map((s,i) => (
            <div key={i} style={{ background:'var(--surface2)', borderRadius:8,
              padding:'8px', textAlign:'center',
              border:`1px solid ${s.count > 0 && s.label==='Vulnerable' ? 'var(--red-border)' : 'var(--border)'}` }}>
              <div style={{ fontSize:20, fontWeight:700, color:s.color }}>{s.count}</div>
              <div style={{ fontSize:10, color:'var(--text3)' }}>{s.label}</div>
            </div>
          ))}
        </div>
      )}

      {/* Summary banner */}
      {summary && (
        <div style={{ padding:'8px 12px', borderRadius:8, marginBottom:10,
          background: summary.vulnerable > 0 ? 'var(--red-bg)' : 'var(--green-bg)',
          border:`1px solid ${summary.vulnerable > 0 ? 'var(--red-border)' : 'var(--green-border)'}`,
          fontSize:12, fontWeight:600,
          color: summary.vulnerable > 0 ? 'var(--red)' : 'var(--green)' }}>
          {summary.message}
        </div>
      )}

      {/* Status */}
      {status && (
        <div style={{ fontSize:11, color:'var(--text2)', marginBottom:8 }}>{status}</div>
      )}

      {/* Results list */}
      {results.length > 0 && (
        <div style={{ display:'flex', flexDirection:'column', gap:3, maxHeight:300, overflowY:'auto' }}>
          {results.map((r, i) => (
            <div key={i} onClick={() => setSelected(r)} style={{
              display:'flex', alignItems:'center', gap:8,
              padding:'6px 10px', borderRadius:6, cursor:'pointer',
              border:`1px solid ${r.vulnerable ? 'var(--red-border)' : selected?.index===r.index ? 'var(--border)' : 'transparent'}`,
              background: r.vulnerable ? 'var(--red-bg)' : r.error ? 'transparent' : 'var(--surface2)',
            }}>
              <div style={{ width:6, height:6, borderRadius:'50%', flexShrink:0,
                background: r.vulnerable ? 'var(--red)' : r.error ? 'var(--text3)' : 'var(--green)' }} />
              <div className="mono" style={{ fontSize:10, color: r.vulnerable ? 'var(--red)' : 'var(--text2)',
                flex:1, overflow:'hidden', textOverflow:'ellipsis', whiteSpace:'nowrap' }}>
                {r.url}
              </div>
              <div style={{ fontSize:9, color: r.vulnerable ? 'var(--red)' : 'var(--text3)', flexShrink:0, fontWeight: r.vulnerable ? 700 : 400 }}>
                {r.vulnerable ? 'VULN' : r.error ? 'ERR' : r.status || 'OK'}
              </div>
            </div>
          ))}
        </div>
      )}

      {/* Selected detail */}
      {selected && (
        <div style={{ marginTop:10, border:'1px solid var(--border)', borderRadius:8,
          padding:10, background:'var(--surface2)' }}>
          <div className="mono" style={{ fontSize:10, color:'var(--text)', wordBreak:'break-all', marginBottom:6 }}>
            {selected.url}
          </div>
          <div style={{ fontSize:11, color: selected.vulnerable ? 'var(--red)' : 'var(--text2)' }}>
            {selected.reason}
          </div>
          {selected.vulnerable && (
            <div style={{ marginTop:6, fontSize:11, fontWeight:700, color:'var(--red)' }}>
              SSRF VULNERABILITY DETECTED — Report this to your security team
            </div>
          )}
        </div>
      )}
    </div>
  )
}