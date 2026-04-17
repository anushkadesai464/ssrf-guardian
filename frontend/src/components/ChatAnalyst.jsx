import { useState, useRef, useEffect } from 'react'

const SUGGESTED = [
  'Which attack was most sophisticated?',
  'What data would have been stolen?',
  'What is the CVSS score of the worst attack?',
  'How many attacks came through the proxy?',
]

export default function ChatAnalyst() {
  const [messages, setMessages] = useState([])
  const [input, setInput] = useState('')
  const [loading, setLoading] = useState(false)
  const bottomRef = useRef(null)
  const abortRef = useRef(null)

  useEffect(() => { bottomRef.current?.scrollIntoView({ behavior:'smooth' }) }, [messages])

  async function ask(q) {
    if (!q.trim() || loading) return
    setInput(''); setLoading(true)
    setMessages(prev => [...prev, { role:'user', text:q }, { role:'ai', text:'', streaming:true }])

    if (abortRef.current) abortRef.current.abort()
    abortRef.current = new AbortController()

    try {
      const res = await fetch('/api/chat', {
        method:'POST', headers:{'Content-Type':'application/json'},
        body: JSON.stringify({ question:q }), signal: abortRef.current.signal,
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
          if (d === '[DONE]') { setMessages(prev => prev.map((m,i) => i===prev.length-1?{...m,streaming:false}:m)); setLoading(false); return }
          try { const p = JSON.parse(d); if (p.text) setMessages(prev => prev.map((m,i) => i===prev.length-1?{...m,text:m.text+p.text}:m)) } catch {}
        }
      }
    } catch(err) {
      if (err.name !== 'AbortError') setMessages(prev => [...prev.slice(0,-1), { role:'ai', text:'Error: '+err.message }])
    } finally { setLoading(false) }
  }

  return (
    <div style={{ display:'flex', flexDirection:'column', minHeight:300 }}>
      <div style={{ flex:1, overflowY:'auto', padding:'8px 0', display:'flex', flexDirection:'column', gap:10 }}>
        {!messages.length && (
          <div>
            <div style={{ fontSize:12, color:'var(--text3)', textAlign:'center', marginBottom:10 }}>Ask anything about the session</div>
            {SUGGESTED.map((s,i) => (
              <button key={i} onClick={() => ask(s)} style={{
                display:'block', width:'100%', marginBottom:6,
                background:'var(--surface2)', border:'1px solid var(--border)',
                borderRadius:8, padding:'8px 12px', color:'var(--text2)',
                fontSize:12, cursor:'pointer', textAlign:'left',
              }}>{s}</button>
            ))}
          </div>
        )}
        {messages.map((m, i) => (
          <div key={i} style={{ display:'flex', gap:8 }}>
            <div style={{ width:22, height:22, borderRadius:'50%', flexShrink:0,
              background: m.role==='user' ? 'var(--blue-bg)' : 'var(--purple-bg)',
              border: `1px solid ${m.role==='user' ? 'var(--blue-border)' : 'var(--purple-border)'}`,
              display:'flex', alignItems:'center', justifyContent:'center',
              fontSize:8, fontWeight:700, color: m.role==='user' ? 'var(--blue)' : 'var(--purple)' }}>
              {m.role==='user'?'YOU':'AI'}
            </div>
            <div style={{ flex:1, fontSize:13, lineHeight:1.7, color:'var(--text)', whiteSpace:'pre-wrap' }}>
              {m.text}
              {m.streaming && <span style={{ display:'inline-block', width:7, height:13, background:'var(--purple)', borderRadius:1, marginLeft:2, animation:'blink 1s step-end infinite' }} />}
            </div>
          </div>
        ))}
        <div ref={bottomRef} />
      </div>
      <div style={{ display:'flex', gap:8, paddingTop:10, borderTop:'1px solid var(--border)' }}>
        <input value={input} onChange={e=>setInput(e.target.value)}
          onKeyDown={e=>e.key==='Enter'&&ask(input)}
          placeholder="Ask about the attacks..."
          disabled={loading}
          style={{ flex:1, background:'var(--surface2)', border:'1px solid var(--border)',
            borderRadius:8, padding:'8px 12px', color:'var(--text)', fontSize:13, outline:'none' }} />
        <button onClick={()=>ask(input)} disabled={loading||!input.trim()}
          style={{ background:'var(--blue)', border:'none', borderRadius:8,
            padding:'8px 16px', color:'#000', fontSize:13, fontWeight:700, cursor:'pointer' }}>
          Ask
        </button>
      </div>
      <style>{`@keyframes blink{0%,100%{opacity:1}50%{opacity:0}}`}</style>
    </div>
  )
}