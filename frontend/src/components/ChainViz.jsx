import { useEffect, useState } from 'react'

function HopNode({ hop, isLast, blocked, attackType, delay }) {
  const [visible, setVisible] = useState(false)
  useEffect(() => {
    const t = setTimeout(() => setVisible(true), delay * 150)
    return () => clearTimeout(t)
  }, [delay])

  let domain = hop.url || ''
  try { domain = new URL(hop.url).hostname } catch {}

  const color = blocked && isLast
    ? { border:'var(--red-border)', bg:'var(--red-bg)', text:'var(--red)' }
    : { border:'var(--green-border)', bg:'var(--green-bg)', text:'var(--green)' }

  return (
    <div style={{ display:'flex', alignItems:'center', opacity: visible?1:0, transform: visible?'none':'translateX(-8px)', transition:'all 0.25s ease' }}>
      <div style={{ border:`1px solid ${color.border}`, background:color.bg, borderRadius:8, padding:'8px 12px', minWidth:130 }}>
        <div style={{ fontSize:11, fontWeight:700, color:color.text, marginBottom:2 }}>
          {blocked && isLast ? '✗ BLOCKED' : `${hop.status||200}`}
        </div>
        <div className="mono" style={{ fontSize:10, color:'var(--text)', wordBreak:'break-all', marginBottom:2 }}>{domain}</div>
        {hop.resolvedIPs?.[0] && <div style={{ fontSize:9, color:'var(--text2)' }}>{hop.resolvedIPs[0]}</div>}
      </div>
      {!isLast && (
        <div style={{ margin:'0 6px', textAlign:'center' }}>
          <div style={{ fontSize:9, color:'var(--text3)' }}>302</div>
          <div style={{ color:'var(--amber)', fontSize:16 }}>→</div>
        </div>
      )}
    </div>
  )
}

export default function ChainViz({ redirectChain, blocked, attackType }) {
  if (!redirectChain?.length) return null
  return (
    <div style={{ marginTop:12 }}>
      <div style={{ fontSize:11, color:'var(--text2)', fontWeight:600, marginBottom:8, textTransform:'uppercase', letterSpacing:'0.06em' }}>
        Redirect chain ({redirectChain.length} hop{redirectChain.length!==1?'s':''})
      </div>
      <div style={{ display:'flex', alignItems:'center', flexWrap:'wrap', gap:4, overflowX:'auto' }}>
        {redirectChain.map((hop, i) => (
          <HopNode key={i} hop={hop} isLast={i===redirectChain.length-1}
            blocked={blocked} attackType={attackType} delay={i} />
        ))}
      </div>
    </div>
  )
}