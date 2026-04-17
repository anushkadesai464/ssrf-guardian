import { useEffect, useState, useRef } from 'react'

const DOT = {
  protocol_switch:'var(--red)', private_ip:'var(--red)',
  octal_octet:'var(--amber)', decimal_integer:'var(--amber)',
  hex_octet:'var(--amber)', ipv4_mapped_ipv6:'var(--purple)',
  dns_rebinding:'var(--purple)', allowlist_violation:'var(--blue)',
}

const LABEL = {
  protocol_switch:'Protocol switch', private_ip:'Private IP',
  octal_octet:'Octal IP', decimal_integer:'Decimal IP',
  hex_octet:'Hex IP', ipv4_mapped_ipv6:'IPv6 mapped',
  dns_rebinding:'DNS rebind', allowlist_violation:'Allowlist',
  too_many_redirects:'Redirect loop', loopback_alias:'Loopback',
}

function ago(ts) {
  const d = Date.now() - new Date(ts).getTime()
  if (d < 60000) return `${Math.floor(d/1000)}s ago`
  return `${Math.floor(d/60000)}m ago`
}

export default function AttackFeed({ onSelect, selectedUrl }) {
  const [events, setEvents] = useState([])
  const esRef = useRef(null)

  useEffect(() => {
    // Load existing session
    fetch('/api/session').then(r=>r.json()).then(({ log }) => {
      setEvents((log||[]).filter(e=>e.blocked).reverse().map(e=>({...e, receivedAt:e.timestamp})))
    }).catch(()=>{})

    // Live SSE feed
    const es = new EventSource('/api/events')
    esRef.current = es
    es.addEventListener('attack', e => {
      try {
        const data = JSON.parse(e.data)
        if (data.blocked) setEvents(prev => [{ ...data, receivedAt: new Date().toISOString() }, ...prev].slice(0,100))
      } catch {}
    })
    return () => es.close()
  }, [])

  if (!events.length) return (
    <div style={{ padding:'24px 0', textAlign:'center', color:'var(--text3)', fontSize:13 }}>
      No attacks yet — submit a URL to start
    </div>
  )

  return (
    <div style={{ display:'flex', flexDirection:'column', gap:4 }}>
      {events.map((ev, i) => {
        const dot = DOT[ev.attackType] || 'var(--red)'
        const label = LABEL[ev.attackType] || ev.attackType
        const selected = ev.url === selectedUrl
        let domain = ev.url
        try { domain = new URL(ev.url).hostname } catch {}

        return (
          <div key={i} onClick={() => onSelect(ev)} style={{
            display:'flex', alignItems:'center', gap:8,
            padding:'8px 10px', borderRadius:8, cursor:'pointer',
            border:`1px solid ${selected ? 'var(--red-border)' : 'var(--border)'}`,
            background: selected ? 'var(--red-bg)' : 'var(--surface2)',
            transition:'all 0.12s'
          }}>
            <div style={{ width:7, height:7, borderRadius:'50%', background:dot, flexShrink:0 }} />
            <div style={{ flex:1, minWidth:0 }}>
              <div className="mono" style={{ fontSize:11, color:'var(--text)', overflow:'hidden', textOverflow:'ellipsis', whiteSpace:'nowrap' }}>{domain}</div>
              <div style={{ fontSize:10, color:'var(--text3)', marginTop:1 }}>
                {label} · stage {ev.blockedAtStage}
                {ev.source==='proxy' && ' · proxy'}
                {ev.source==='mutation' && ' · mutation'}
              </div>
            </div>
            <div style={{ fontSize:10, color:'var(--text3)', flexShrink:0 }}>{ago(ev.receivedAt||ev.timestamp)}</div>
          </div>
        )
      })}
    </div>
  )
}