import { useState, useEffect, useRef } from 'react'

export default function AiExplainer({ attack }) {
  const [text, setText] = useState('')
  const [loading, setLoading] = useState(false)
  const [lastUrl, setLastUrl] = useState(null)
  const abortRef = useRef(null)

  useEffect(() => {
    if (!attack || attack.url === lastUrl) return
    explain(attack)
  }, [attack])

  async function explain(atk) {
    if (abortRef.current) abortRef.current.abort()
    abortRef.current = new AbortController()
    setLoading(true); setText(''); setLastUrl(atk.url)

    try {
      const res = await fetch('/api/explain', {
        method:'POST',
        headers:{ 'Content-Type':'application/json' },
        body: JSON.stringify({ url:atk.url, attackType:atk.attackType,
          reason:atk.reason, pipelineTrace:atk.pipelineTrace||[], redirectChain:atk.redirectChain||[] }),
        signal: abortRef.current.signal,
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
          const d = line.slice(6)
          if (d === '[DONE]') { setLoading(false); return }
          try { const p = JSON.parse(d); if (p.text) setText(prev => prev + p.text) } catch {}
        }
      }
    } catch (err) {
      if (err.name !== 'AbortError') setText('Could not load explanation. Is the server running?')
    } finally { setLoading(false) }
  }

  if (!attack) return (
    <div style={{ padding:24, color:'var(--text3)', fontSize:13, textAlign:'center' }}>
      Select a blocked attack from the feed
    </div>
  )

  return (
    <div>
      <div style={{ display:'flex', alignItems:'center', gap:8, marginBottom:10 }}>
        <div style={{ width:8, height:8, borderRadius:'50%', background:'var(--red)' }} />
        <span style={{ fontSize:11, fontWeight:700, color:'var(--red)', textTransform:'uppercase', letterSpacing:'0.06em' }}>
          {attack.attackType?.replace(/_/g,' ')||'Attack'}
        </span>
        <span style={{ fontSize:11, color:'var(--text3)' }}>stage {attack.blockedAtStage}</span>
      </div>
      <div className="mono" style={{ fontSize:11, color:'var(--text2)', background:'var(--surface2)', borderRadius:6, padding:'6px 10px', marginBottom:12, wordBreak:'break-all' }}>
        {attack.url}
      </div>
      <div style={{ fontSize:13, lineHeight:1.8, color:'var(--text)', whiteSpace:'pre-wrap', minHeight:80 }}>
        {text}
        {loading && <span style={{ display:'inline-block', width:8, height:14, background:'var(--blue)', borderRadius:1, marginLeft:2, animation:'blink 1s step-end infinite' }} />}
      </div>
      <style>{`@keyframes blink{0%,100%{opacity:1}50%{opacity:0}}`}</style>
    </div>
  )
}