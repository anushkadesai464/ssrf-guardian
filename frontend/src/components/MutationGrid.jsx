import { useState, useRef } from 'react'

const COLOR = {
  protocol_switch:'var(--red)', private_ip:'var(--red)',
  octal_octet:'var(--amber)', decimal_integer:'var(--amber)',
  hex_octet:'var(--amber)', ipv4_mapped_ipv6:'var(--purple)',
  loopback_alias:'var(--purple)', default:'var(--red)',
}
const SHORT = {
  protocol_switch:'Proto', private_ip:'PrivIP', octal_octet:'Octal',
  decimal_integer:'Dec', hex_octet:'Hex', ipv4_mapped_ipv6:'IPv6',
  loopback_alias:'Loop', allowlist_violation:'Allow', invalid_url:'Invalid',
}

export default function MutationGrid({ seedUrl }) {
  const [results, setResults] = useState([])
  const [running, setRunning] = useState(false)
  const [status, setStatus] = useState('')
  const [summary, setSummary] = useState(null)
  const [selected, setSelected] = useState(null)
  const abortRef = useRef(null)

  async function run() {
    if (!seedUrl || running) return
    if (abortRef.current) abortRef.current.abort()
    abortRef.current = new AbortController()
    setRunning(true); setResults([]); setSummary(null); setSelected(null)

    try {
      const res = await fetch('/api/mutate', {
        method:'POST', headers:{'Content-Type':'application/json'},
        body: JSON.stringify({ seedUrl }), signal: abortRef.current.signal,
      })
      const reader = res.body.getReader()
      const decoder = new TextDecoder()
      let buf = ''

      while (true) {
        const { done, value } = await reader.read()
        if (done) break
        buf += decoder.decode(value, { stream:true })
        const lines = buf.split('\n'); buf = lines.pop()
        for (const line of lines) {
          if (!line.startsWith('data: ')) continue
          try {
            const d = JSON.parse(line.slice(6))
            if (d.type === 'status') setStatus(d.message)
            else if (d.type === 'result') { setResults(prev => [...prev, d]); setStatus(`Testing ${d.index+1}/${d.total}...`) }
            else if (d.type === 'complete') { setSummary(d); setStatus('') }
            else if (d.type === 'error') setStatus(`Error: ${d.message}`)
          } catch {}
        }
      }
    } catch(err) { if (err.name!=='AbortError') setStatus('Error: '+err.message) }
    finally { setRunning(false) }
  }

  const blocked = results.filter(r=>r.blocked).length
  const passed  = results.filter(r=>!r.blocked).length

  return (
    <div>
      <div style={{ display:'flex', alignItems:'center', gap:10, marginBottom:12 }}>
        <button onClick={run} disabled={running||!seedUrl} style={{
          background: running ? 'var(--surface2)' : 'var(--red)',
          border:'none', borderRadius:8, padding:'8px 16px',
          color: running ? 'var(--text3)' : '#000',
          fontSize:13, fontWeight:700, cursor: running?'not-allowed':'pointer' }}>
          {running ? 'Running...' : 'Generate 50 variants'}
        </button>
        {results.length > 0 && (
          <div style={{ fontSize:12, display:'flex', gap:10 }}>
            <span style={{ color:'var(--green)' }}>{blocked} blocked</span>
            <span style={{ color: passed>0?'var(--red)':'var(--text3)' }}>{passed} passed</span>
          </div>
        )}
        {status && <span style={{ fontSize:11, color:'var(--text2)', flex:1 }}>{status}</span>}
      </div>

      {summary && (
        <div style={{ padding:'8px 12px', borderRadius:8, marginBottom:10,
          background: summary.passed===0?'var(--green-bg)':'var(--red-bg)',
          border:`1px solid ${summary.passed===0?'var(--green-border)':'var(--red-border)'}`,
          fontSize:13, fontWeight:600,
          color: summary.passed===0?'var(--green)':'var(--red)' }}>
          {summary.passed===0 ? `All ${summary.total} variants blocked ✓` : `${summary.passed} variant${summary.passed>1?'s':''} passed — review needed`}
        </div>
      )}

      {results.length > 0 && (
        <div style={{ display:'grid', gridTemplateColumns:'repeat(10,1fr)', gap:3, marginBottom:10 }}>
          {results.map((r, i) => {
            const c = r.blocked ? (COLOR[r.attackType]||COLOR.default) : 'var(--green)'
            return (
              <div key={i} onClick={()=>setSelected(r)} title={r.url}
                style={{ border:`1px solid ${c}`, borderRadius:5, padding:'4px 2px',
                  cursor:'pointer', textAlign:'center',
                  background: selected?.index===r.index ? `${c}22` : 'transparent' }}>
                <div style={{ fontSize:8, fontWeight:700, color:c, overflow:'hidden', textOverflow:'ellipsis', whiteSpace:'nowrap' }}>
                  {r.blocked ? (SHORT[r.attackType]||'BLOCK') : 'SAFE'}
                </div>
                <div style={{ fontSize:7, color:'var(--text3)' }}>
                  {r.blocked ? `S${r.blockedAtStage}` : 'ok'}
                </div>
              </div>
            )
          })}
        </div>
      )}

      {selected && (
        <div style={{ border:'1px solid var(--border)', borderRadius:8, padding:10, background:'var(--surface2)' }}>
          <div style={{ display:'flex', gap:8, alignItems:'center', marginBottom:6 }}>
            <span style={{ fontSize:10, fontWeight:700, padding:'2px 6px', borderRadius:4,
              background: selected.blocked?'var(--red-bg)':'var(--green-bg)',
              color: selected.blocked?'var(--red)':'var(--green)',
              border:`1px solid ${selected.blocked?'var(--red-border)':'var(--green-border)'}` }}>
              {selected.blocked ? `BLOCKED S${selected.blockedAtStage}` : 'PASSED'}
            </span>
            {selected.attackType && <span style={{ fontSize:11, color:'var(--text2)' }}>{selected.attackType.replace(/_/g,' ')}</span>}
          </div>
          <div className="mono" style={{ fontSize:10, color:'var(--text)', background:'var(--surface)', borderRadius:6, padding:'6px 10px', wordBreak:'break-all', marginBottom:6 }}>{selected.url}</div>
          {selected.reason && <div style={{ fontSize:11, color:'var(--text2)' }}>{selected.reason}</div>}
        </div>
      )}

      {!seedUrl && <div style={{ fontSize:12, color:'var(--text3)', textAlign:'center', padding:'20px 0' }}>Enter a URL above first</div>}
    </div>
  )
}