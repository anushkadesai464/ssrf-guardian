import { useEffect, useState, useRef } from 'react'

const PRIVATE = /^(10\.|172\.(1[6-9]|2\d|3[01])\.|192\.168\.|127\.|169\.254\.|0\.)/
const OCTAL   = /(?:^|\.)0[0-7]+/
const DECIMAL = /^\d{8,10}$/
const HEX     = /0x[0-9a-f]+/i
const IPV6MAP = /::ffff:/i

function analyze(url) {
  const stages = [
    { stage:1, name:'Scheme',     pass:null, detail:'' },
    { stage:2, name:'DNS format', pass:null, detail:'' },
    { stage:3, name:'IP check',   pass:null, detail:'' },
    { stage:4, name:'Allowlist',  pass:null, detail:'' },
    { stage:5, name:'Redirects',  pass:null, detail:'runtime' },
    { stage:6, name:'Socket',     pass:null, detail:'runtime' },
    { stage:7, name:'Response',   pass:null, detail:'runtime' },
  ]
  if (!url || url.length < 4) return { stages, prediction: null }

  let parsed
  try { parsed = new URL(url) } catch {
    stages[0].pass = false; stages[0].detail = 'Invalid URL'
    return { stages, prediction:'BLOCKED', attackType:'invalid_url', blockedAtStage:1 }
  }

  // Stage 1
  if (!['http:','https:'].includes(parsed.protocol)) {
    stages[0].pass = false; stages[0].detail = `"${parsed.protocol}" blocked`
    return { stages, prediction:'BLOCKED', attackType:'protocol_switch', blockedAtStage:1 }
  }
  stages[0].pass = true; stages[0].detail = parsed.protocol

  // Stage 2
  const raw = url.replace(/^https?:\/\//i,'').split('/')[0].split('?')[0]
  const host = parsed.hostname.replace(/^\[|\]$/g,'')
  stages[1].pass = true; stages[1].detail = host

  // Stage 3
  if (OCTAL.test(raw)) {
    stages[2].pass = false; stages[2].detail = `Octal: "${raw}"`
    return { stages, prediction:'BLOCKED', attackType:'octal_octet', blockedAtStage:3 }
  }
  if (DECIMAL.test(raw)) {
    stages[2].pass = false; stages[2].detail = `Decimal int: ${raw}`
    return { stages, prediction:'BLOCKED', attackType:'decimal_integer', blockedAtStage:3 }
  }
  if (HEX.test(raw)) {
    stages[2].pass = false; stages[2].detail = `Hex IP: ${raw}`
    return { stages, prediction:'BLOCKED', attackType:'hex_octet', blockedAtStage:3 }
  }
  if (IPV6MAP.test(raw)) {
    stages[2].pass = false; stages[2].detail = `IPv6-mapped: ${raw}`
    return { stages, prediction:'BLOCKED', attackType:'ipv4_mapped_ipv6', blockedAtStage:3 }
  }
  if (host === '::1' || host === 'localhost') {
    stages[2].pass = false; stages[2].detail = `Loopback: ${host}`
    return { stages, prediction:'BLOCKED', attackType:'loopback_alias', blockedAtStage:3 }
  }
  if (PRIVATE.test(host)) {
    stages[2].pass = false; stages[2].detail = `Private: ${host}`
    return { stages, prediction:'BLOCKED', attackType:'private_ip', blockedAtStage:3 }
  }
  stages[2].pass = true; stages[2].detail = `${host} → public`

  // Stage 4
  stages[3].pass = true; stages[3].detail = 'Open mode'

  return { stages, prediction:'LIKELY_SAFE', attackType:null }
}

const TYPE_LABEL = {
  invalid_url:'Invalid URL', protocol_switch:'Protocol switch',
  octal_octet:'Octal IP', decimal_integer:'Decimal IP',
  hex_octet:'Hex IP', ipv4_mapped_ipv6:'IPv6-mapped',
  loopback_alias:'Loopback', private_ip:'Private IP range',
}

export default function PreflightBar({ url }) {
  const [result, setResult] = useState({ stages: Array(7).fill(null).map((_,i) => ({ stage:i+1, name:['Scheme','DNS format','IP check','Allowlist','Redirects','Socket','Response'][i], pass:null, detail: i>=4?'runtime':'' })), prediction: null })
  const prev = useRef('')

  useEffect(() => {
    if (url === prev.current) return
    prev.current = url
    setResult(analyze(url))
  }, [url])

  const { stages, prediction, attackType, blockedAtStage } = result

  return (
    <div style={{ border:'1px solid var(--border)', borderRadius:10, overflow:'hidden', marginBottom:14 }}>
      <div style={{ padding:'7px 12px', background:'var(--surface2)', borderBottom:'1px solid var(--border)', display:'flex', alignItems:'center', justifyContent:'space-between' }}>
        <span style={{ fontSize:11, fontWeight:600, color:'var(--text2)', textTransform:'uppercase', letterSpacing:'0.06em' }}>Pre-flight</span>
        {prediction && (
          <span style={{ fontSize:10, fontWeight:700, padding:'2px 8px', borderRadius:4,
            background: prediction==='BLOCKED' ? 'var(--red-bg)' : 'var(--green-bg)',
            color: prediction==='BLOCKED' ? 'var(--red)' : 'var(--green)',
            border: `1px solid ${prediction==='BLOCKED' ? 'var(--red-border)' : 'var(--green-border)'}` }}>
            {prediction==='BLOCKED' ? `BLOCKED S${blockedAtStage} — ${TYPE_LABEL[attackType]||attackType}` : 'LIKELY SAFE'}
          </span>
        )}
      </div>
      <div style={{ display:'grid', gridTemplateColumns:'repeat(7,1fr)' }}>
        {stages.map((s, i) => (
          <div key={i} style={{
            padding:'7px 4px', textAlign:'center',
            borderRight: i<6 ? '1px solid var(--border)' : 'none',
            background: s.pass===false ? 'var(--red-bg)' : s.pass===true ? 'var(--green-bg)' : 'transparent',
            transition:'background 0.2s'
          }}>
            <div style={{ width:18, height:18, borderRadius:'50%', margin:'0 auto 4px',
              display:'flex', alignItems:'center', justifyContent:'center', fontSize:9, fontWeight:700,
              background: s.pass===false ? 'var(--red)' : s.pass===true ? 'var(--green)' : 'var(--surface2)',
              color: (s.pass===false||s.pass===true) ? '#000' : 'var(--text3)' }}>
              {s.pass===false ? '✗' : s.pass===true ? '✓' : s.stage}
            </div>
            <div style={{ fontSize:9, fontWeight:600, color: s.pass===false?'var(--red)':s.pass===true?'var(--green)':'var(--text3)', marginBottom:2 }}>{s.name}</div>
            <div style={{ fontSize:8, color:'var(--text2)', wordBreak:'break-all', lineHeight:1.3 }}>{s.detail||'—'}</div>
          </div>
        ))}
      </div>
    </div>
  )
}