import { useState, useCallback } from 'react'
import PreflightBar from './components/PreflightBar.jsx'
import ChainViz from './components/ChainViz.jsx'
import AiExplainer from './components/AiExplainer.jsx'
import ChatAnalyst from './components/ChatAnalyst.jsx'
import MutationGrid from './components/MutationGrid.jsx'
import AttackFeed from './components/AttackFeed.jsx'
import DomainFuzzer from './components/DomainFuzzer.jsx'

// mode:'vuln' = needs Guardian OFF to show data leak
// mode:'safe' = needs Guardian ON to show blocking
// mode:'allow' = shows Guardian allows safe URLs (no false positives)
const PRESETS = [
  { label: '⚠ Open redirect — DATA LEAK', url: 'http://127.0.0.1:3001/redirect?to=http://127.0.0.1:3001/latest/meta-data/iam/security-credentials/prod-ec2-admin-role', mode: 'vuln' },
  { label: 'Octal IP',            url: 'http://0177.0.0.1/admin',                                                    mode: 'safe' },
  { label: 'Decimal integer IP',  url: 'http://2130706433/secret',                                                    mode: 'safe' },
  { label: 'IPv4-mapped IPv6',    url: 'http://[::ffff:127.0.0.1]/internal',                                          mode: 'safe' },
  { label: 'Protocol switch',     url: 'http://127.0.0.1:3001/redirect?to=file:///etc/passwd',                        mode: 'safe' },
  { label: 'Direct metadata',     url: 'http://169.254.169.254/latest/meta-data/',                                    mode: 'safe' },
  { label: 'Private class A',     url: 'http://10.0.0.1/admin',                                                       mode: 'safe' },
  { label: 'Hex IP',              url: 'http://0x7f.0x0.0x0.0x1/secret',                                              mode: 'safe' },
  { label: 'Safe public URL',     url: 'https://httpbin.org/get',                                                     mode: 'allow' },
  { label: 'Real SSRF (httpbin)', url: 'https://httpbin.org/redirect-to?url=http://169.254.169.254/',                 mode: 'safe' },
]

const RIGHT_TABS = ['AI Explainer', 'Chat Analyst', 'Mutation Grid', 'Domain Fuzzer']

// Reusable card wrapper with optional title header
function Card({ title, children, style }) {
  return (
    <div style={{ border:'1px solid var(--border)', borderRadius:10,
      background:'var(--surface)', overflow:'hidden', marginBottom:12, ...style }}>
      {title && (
        <div style={{ padding:'8px 14px', background:'var(--surface2)',
          borderBottom:'1px solid var(--border)' }}>
          <span style={{ fontSize:11, fontWeight:600, color:'var(--text2)',
            textTransform:'uppercase', letterSpacing:'0.06em' }}>{title}</span>
        </div>
      )}
      <div style={{ padding:14 }}>{children}</div>
    </div>
  )
}

// Shows fetch result below the button
// Two modes:
//   guardianEnabled=false → show raw response, highlight if credentials leaked
//   guardianEnabled=true  → show BLOCKED badge or ALLOWED badge
function ResultPanel({ result, guardianEnabled }) {
  if (!result) return null

  // VULNERABLE MODE — raw fetch result
  if (!guardianEnabled) {
    const isLeak = result.body?.includes('AccessKeyId') || result.body?.includes('SecretAccessKey')
    return (
      <div style={{ border:`1px solid ${isLeak ? 'var(--red-border)' : 'var(--border)'}`,
        borderRadius:8, overflow:'hidden',
        background: isLeak ? 'var(--red-bg)' : 'var(--surface2)',
        animation: isLeak ? 'flashRed 0.5s ease' : 'none' }}>
        {isLeak && (
          <div style={{ padding:'8px 12px', background:'var(--red)', textAlign:'center' }}>
            <span style={{ fontSize:12, fontWeight:700, color:'#000' }}>
              ⚠ DATA LEAKED — AWS CREDENTIALS EXPOSED
            </span>
          </div>
        )}
        <pre className="mono" style={{ padding:12, fontSize:11, margin:0,
          color: isLeak ? 'var(--red)' : 'var(--text)',
          overflowX:'auto', whiteSpace:'pre-wrap', wordBreak:'break-word',
          maxHeight:220, overflowY:'auto' }}>
          {result.body || result.error || 'No response'}
        </pre>
      </div>
    )
  }

  // PROTECTED MODE — blocked result with attack type and stage
  if (result.blocked) {
    return (
      <div>
        <div style={{ display:'flex', alignItems:'center', gap:8, padding:'8px 12px',
          background:'var(--red-bg)', border:'1px solid var(--red-border)',
          borderRadius:8, marginBottom:8 }}>
          <div style={{ width:8, height:8, borderRadius:'50%', background:'var(--red)' }} />
          <span style={{ fontSize:13, fontWeight:700, color:'var(--red)' }}>BLOCKED</span>
          <span style={{ fontSize:11, color:'var(--text2)' }}>
            {result.attackType?.replace(/_/g,' ')} · stage {result.blockedAtStage}
          </span>
        </div>
        <div style={{ fontSize:12, color:'var(--text2)', marginBottom:8 }}>{result.reason}</div>
        {/* Animated redirect chain — only shows if there were hops */}
        <ChainViz redirectChain={result.redirectChain} blocked={true} attackType={result.attackType} />
      </div>
    )
  }

  // PROTECTED MODE — allowed result (safe URL passed all 7 stages)
  return (
    <div style={{ padding:'8px 12px', background:'var(--green-bg)',
      border:'1px solid var(--green-border)', borderRadius:8,
      fontSize:12, color:'var(--green)' }}>
      Allowed · {result.statusCode || 200}
      {result.finalUrl && result.finalUrl !== result.url && (
        <div className="mono" style={{ fontSize:10, color:'var(--text3)', marginTop:4 }}>
          Final URL: {result.finalUrl}
        </div>
      )}
    </div>
  )
}

export default function App() {
  const [url, setUrl] = useState('')
  const [guardianEnabled, setGuardianEnabled] = useState(false)
  const [loading, setLoading] = useState(false)
  const [result, setResult] = useState(null)
  const [selectedAttack, setSelectedAttack] = useState(null)
  const [rightTab, setRightTab] = useState(0)

  // Main fetch function — sends URL to backend with guardian flag
  // Uses current guardianEnabled state at the time of click
  const doFetch = useCallback(async (fetchUrl, overrideGuardian) => {
    const target = fetchUrl || url
    if (!target.trim()) return
    setLoading(true); setResult(null)

    // overrideGuardian lets presets force a specific mode
    const useGuardian = overrideGuardian !== undefined ? overrideGuardian : guardianEnabled

    try {
      const res = await fetch('/api/fetch', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ url: target, guardianEnabled: useGuardian }),
      })

      const rawText = await res.text()
      let data
      try { data = JSON.parse(rawText) }
      catch (e) {
        data = { ok: false, error: 'Parse error: ' + rawText.slice(0, 200), guardianEnabled: useGuardian }
      }

      setResult(data)
      // Auto-select in feed + switch to AI explainer if blocked
      if (data.blocked) {
        setSelectedAttack({ ...data, url: target })
        setRightTab(0)
      }
    } catch (err) {
      setResult({ error: err.message })
    } finally { setLoading(false) }
  }, [url, guardianEnabled])

  // Called when a preset button is clicked
  // Sets the URL and auto-configures Guardian based on preset mode
  function handlePreset(preset) {
    setUrl(preset.url)
    setResult(null)
    if (preset.mode === 'vuln') {
      // Turn Guardian OFF so the attack succeeds and data leaks
      setGuardianEnabled(false)
    } else {
      // Turn Guardian ON so the attack is blocked and explained
      setGuardianEnabled(true)
    }
    // Small delay so state updates before fetch runs
    setTimeout(() => {
      doFetch(preset.url, preset.mode !== 'vuln')
    }, 50)
  }

  return (
    <div style={{ minHeight:'100vh', background:'var(--bg)' }}>

      {/* ── Top nav ── */}
      <div style={{ borderBottom:'1px solid var(--border)', padding:'0 20px',
        display:'flex', alignItems:'center', gap:12, height:50,
        background:'var(--surface)' }}>
        <div style={{ display:'flex', alignItems:'center', gap:8 }}>
          <div style={{ width:8, height:8, borderRadius:'50%', background:'var(--red)',
            boxShadow:'0 0 6px var(--red)' }} />
          <span style={{ fontSize:15, fontWeight:700 }}>SSRF Guardian</span>
        </div>
        <span style={{ fontSize:11, color:'var(--text3)' }}>
          7-stage pipeline · AI-powered · drop-in proxy
        </span>

        {/* Guardian ON/OFF toggle */}
        <div style={{ marginLeft:'auto', display:'flex', alignItems:'center', gap:8 }}>
          <span style={{ fontSize:12, color:'var(--text2)' }}>Guardian</span>
          <div onClick={() => setGuardianEnabled(g => !g)} style={{
            width:44, height:24, borderRadius:12, cursor:'pointer', position:'relative',
            background: guardianEnabled ? 'var(--green)' : 'var(--surface2)',
            border:`1px solid ${guardianEnabled ? 'var(--green-border)' : 'var(--border)'}`,
            transition:'all 0.2s' }}>
            <div style={{ width:18, height:18, borderRadius:'50%', position:'absolute',
              top:2, left: guardianEnabled ? 22 : 2, transition:'left 0.2s',
              background: guardianEnabled ? '#000' : 'var(--text3)' }} />
          </div>
          <span style={{ fontSize:12, fontWeight:700,
            color: guardianEnabled ? 'var(--green)' : 'var(--red)' }}>
            {guardianEnabled ? 'ON' : 'OFF'}
          </span>
        </div>
      </div>

      {/* ── Main 3-column layout ── */}
      <div style={{ display:'grid', gridTemplateColumns:'320px 1fr 340px',
        gap:14, padding:14, maxWidth:1400, margin:'0 auto' }}>

        {/* ── LEFT: URL input + presets ── */}
        <div>
          <Card title="URL input">
            <input value={url} onChange={e => setUrl(e.target.value)}
              onKeyDown={e => e.key === 'Enter' && doFetch()}
              placeholder="Enter URL to fetch..."
              style={{ width:'100%', background:'var(--surface2)',
                border:'1px solid var(--border)', borderRadius:8,
                padding:'9px 12px', color:'var(--text)', fontSize:13,
                outline:'none', marginBottom:10, fontFamily:'monospace' }} />

            {/* Live 7-stage predictor — updates as you type */}
            <PreflightBar url={url} />

            {/* Fetch button — red when vulnerable, green when protected */}
            <button onClick={() => doFetch()} disabled={loading || !url.trim()}
              style={{ width:'100%', padding:'10px 0',
                background: loading ? 'var(--surface2)' : guardianEnabled ? 'var(--green)' : 'var(--red)',
                border:'none', borderRadius:8,
                color: loading ? 'var(--text3)' : '#000',
                fontSize:14, fontWeight:700,
                cursor: loading ? 'not-allowed' : 'pointer',
                transition:'all 0.15s', marginBottom:12 }}>
              {loading ? 'Fetching...' : guardianEnabled ? 'Fetch (Protected)' : 'Fetch (VULNERABLE)'}
            </button>

            {/* Result display — shows leak, block, or allow */}
            <ResultPanel result={result} guardianEnabled={guardianEnabled} />
          </Card>

          <Card title="Preset attacks">
            {/* Hint text */}
            <div style={{ fontSize:10, color:'var(--text3)', marginBottom:8, lineHeight:1.5 }}>
              Red presets = Guardian auto-OFF (shows leak)<br/>
              Grey presets = Guardian auto-ON (shows block)
            </div>
            <div style={{ display:'flex', flexDirection:'column', gap:4 }}>
              {PRESETS.map((a, i) => (
                <button key={i} onClick={() => handlePreset(a)}
                  style={{
                    background: a.mode === 'vuln' ? 'var(--red-bg)' : 'var(--surface2)',
                    border:`1px solid ${a.mode === 'vuln' ? 'var(--red-border)' : a.mode === 'allow' ? 'var(--green-border)' : 'var(--border)'}`,
                    borderRadius:6, padding:'7px 10px',
                    color: a.mode === 'vuln' ? 'var(--red)' : a.mode === 'allow' ? 'var(--green)' : 'var(--text2)',
                    fontSize:11, cursor:'pointer', textAlign:'left',
                    display:'flex', justifyContent:'space-between', alignItems:'center',
                    transition:'opacity 0.12s' }}
                  onMouseEnter={e => e.currentTarget.style.opacity = '0.8'}
                  onMouseLeave={e => e.currentTarget.style.opacity = '1'}>
                  <span>{a.label}</span>
                  <span style={{ fontSize:9, color:'inherit', opacity:0.7 }}>
                    {a.mode === 'vuln' ? 'OFF →' : a.mode === 'allow' ? 'ALLOW →' : 'ON →'}
                  </span>
                </button>
              ))}
            </div>
          </Card>
        </div>

        {/* ── CENTER: Live feed ── */}
        <div>
          <div style={{ border:'1px solid var(--border)', borderRadius:10,
            padding:'10px 14px', marginBottom:12, background:'var(--surface)',
            display:'flex', alignItems:'center', gap:10 }}>
            <div style={{ width:8, height:8, borderRadius:'50%', background:'var(--text3)' }} />
            <div>
              <div style={{ fontSize:12, fontWeight:600, color:'var(--text2)' }}>
                F8 — Drop-in proxy
              </div>
              <div className="mono" style={{ fontSize:10, color:'var(--text3)', marginTop:2 }}>
                Activate: $env:GUARDIAN_PROXY="true" then restart
              </div>
            </div>
          </div>

          <Card title="Live attack feed" style={{ flex:1 }}>
            <AttackFeed
              onSelect={(ev) => { setSelectedAttack(ev); setRightTab(0) }}
              selectedUrl={selectedAttack?.url}
            />
          </Card>
        </div>

        {/* ── RIGHT: AI panels ── */}
        <div>
          <div style={{ display:'flex', gap:4, marginBottom:8 }}>
            {RIGHT_TABS.map((tab, i) => (
              <button key={i} onClick={() => setRightTab(i)} style={{
                flex:1, padding:'7px 2px',
                background: rightTab===i ? 'var(--surface)' : 'var(--surface2)',
                border:`1px solid ${rightTab===i ? 'var(--border)' : 'transparent'}`,
                borderRadius:8, color: rightTab===i ? 'var(--text)' : 'var(--text3)',
                fontSize:10, fontWeight: rightTab===i ? 600 : 400,
                cursor:'pointer', transition:'all 0.12s' }}>
                {tab}
              </button>
            ))}
          </div>

          <Card style={{ minHeight:400 }}>
            {rightTab === 0 && <AiExplainer attack={selectedAttack} />}
            {rightTab === 1 && <ChatAnalyst />}
            {rightTab === 2 && <MutationGrid seedUrl={url} />}
            {rightTab === 3 && <DomainFuzzer />}
          </Card>
        </div>
      </div>

      <style>{`
        @keyframes flashRed {
          0%  { box-shadow: 0 0 0 0 rgba(255,71,87,0.5); }
          50% { box-shadow: 0 0 20px 4px rgba(255,71,87,0.4); }
          100%{ box-shadow: none; }
        }
        input:focus { border-color: var(--blue) !important; }
        button:active { transform: scale(0.98); }
      `}</style>
    </div>
  )
}