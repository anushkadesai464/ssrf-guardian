import express from 'express'
import cors from 'cors'
import session from 'express-session'
import path from 'path'
import fs from 'fs'
import { fileURLToPath } from 'url'
import { protect } from '../guardian-platform/sdk/index.js'

const __dirname = path.dirname(fileURLToPath(import.meta.url))
const DB_PATH = path.join(__dirname, 'db.json')
const GUARDIAN_URL = process.env.GUARDIAN_URL || 'http://localhost:3000'

// ── helpers — must be defined before app.use(guardian) ───────────────────────
function readDB() {
  return JSON.parse(fs.readFileSync(DB_PATH, 'utf8'))
}
function writeDB(data) {
  fs.writeFileSync(DB_PATH, JSON.stringify(data, null, 2))
}

const app = express()
const PORT = 4000

app.use(protect('grd_live_tiger_epelsmfu'))
app.use(cors({ origin: true, credentials: true }))
app.use(express.json())
app.use(express.urlencoded({ extended: true }))
app.use(session({
  secret: 'technotcorp-secret-2024',
  resave: false,
  saveUninitialized: false,
  cookie: { maxAge: 24 * 60 * 60 * 1000 }
}))
app.use(express.static(path.join(__dirname, 'public')))

function requireAuth(req, res, next) {
  if (req.session?.employee) return next()
  res.status(401).json({ error: 'Not authenticated' })
}
function requireAdmin(req, res, next) {
  if (req.session?.employee?.role === 'admin') return next()
  res.status(403).json({ error: 'Admin only' })
}

// ── AUTH ──────────────────────────────────────────────────────────────────────
app.post('/api/login', (req, res) => {
  const { email, password } = req.body
  const db = readDB()
  const emp = db.employees.find(e => e.email === email && e.password === password)
  if (!emp) return res.status(401).json({ error: 'Invalid credentials' })
  req.session.employee = emp
  res.json({ ok: true, employee: { ...emp, password: undefined }, role: emp.role })
})

app.post('/api/logout', (req, res) => {
  req.session.destroy()
  res.json({ ok: true })
})

app.get('/api/me', (req, res) => {
  if (!req.session?.employee) return res.status(401).json({ error: 'Not logged in' })
  const emp = { ...req.session.employee, password: undefined }
  res.json(emp)
})

// ── EMPLOYEES ─────────────────────────────────────────────────────────────────
app.get('/api/employees', requireAuth, (req, res) => {
  const db = readDB()
  const list = db.employees.map(e => ({ ...e, password: undefined }))
  res.json(list)
})

app.post('/api/employees', requireAdmin, (req, res) => {
  const db = readDB()
  const newEmp = {
    id: 'EMP' + String(db.employees.length + 1).padStart(3, '0'),
    name: req.body.name,
    email: req.body.email,
    password: req.body.password || 'pass123',
    role: req.body.role || 'employee',
    department: req.body.department,
    salary: parseInt(req.body.salary) || 50000,
    joined: new Date().toISOString().split('T')[0],
    phone: req.body.phone || '',
  }
  db.employees.push(newEmp)
  writeDB(db)
  res.json({ ok: true, employee: { ...newEmp, password: undefined } })
})

app.put('/api/employees/:id', requireAdmin, (req, res) => {
  const db = readDB()
  const idx = db.employees.findIndex(e => e.id === req.params.id)
  if (idx === -1) return res.status(404).json({ error: 'Not found' })
  db.employees[idx] = { ...db.employees[idx], ...req.body, id: req.params.id }
  writeDB(db)
  res.json({ ok: true })
})

app.delete('/api/employees/:id', requireAdmin, (req, res) => {
  const db = readDB()
  db.employees = db.employees.filter(e => e.id !== req.params.id)
  writeDB(db)
  res.json({ ok: true })
})

// ── COMPANY ───────────────────────────────────────────────────────────────────
app.get('/api/company', requireAuth, (req, res) => {
  const db = readDB()
  res.json(db.company)
})

// ── DOCUMENTS ─────────────────────────────────────────────────────────────────
app.get('/api/documents', requireAuth, (req, res) => {
  const db = readDB()
  res.json(db.documents)
})

app.post('/api/documents', requireAdmin, (req, res) => {
  const db = readDB()
  const doc = {
    id: 'DOC' + String(db.documents.length + 1).padStart(3, '0'),
    name: req.body.name,
    size: req.body.size || '1 MB',
    uploadedBy: req.session.employee.id,
    date: new Date().toISOString().split('T')[0],
    url: req.body.url || '#',
  }
  db.documents.push(doc)
  writeDB(db)
  res.json({ ok: true, document: doc })
})

app.delete('/api/documents/:id', requireAdmin, (req, res) => {
  const db = readDB()
  db.documents = db.documents.filter(d => d.id !== req.params.id)
  writeDB(db)
  res.json({ ok: true })
})

// ── VULNERABLE ENDPOINT ───────────────────────────────────────────────────────
app.post('/api/fetch-url', requireAuth, async (req, res) => {
  const { url } = req.body
  if (!url) return res.status(400).json({ error: 'url required' })

  const db = readDB()
  const guardianOn = db.company.guardianEnabled === true

  // PROTECTED MODE
  if (guardianOn) {
    try {
      const check = await fetch(`${GUARDIAN_URL}/api/preflight`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ url }),
      })
      const result = await check.json()

      if (result.prediction === 'BLOCKED') {
        const attackerIP =
          req.headers['x-forwarded-for']?.split(',')[0]?.trim() ||
          req.headers['x-real-ip'] ||
          req.socket.remoteAddress ||
          'unknown'

        // Get geolocation
        let location = 'Local network'
        try {
          if (!attackerIP.includes('127.') && !attackerIP.includes('::') && attackerIP !== 'unknown') {
            const geo = await fetch(`http://ip-api.com/json/${attackerIP}?fields=city,regionName,country`)
            const gd = await geo.json()
            if (gd.city) location = `${gd.city}, ${gd.regionName}, ${gd.country}`
          }
        } catch {}

        // Report to Guardian
        await fetch(`${GUARDIAN_URL}/api/report-attack`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            url,
            attackType: result.attackType,
            blockedAtStage: result.blockedAtStage,
            attackerIP,
            location,
            source: 'technotcorp',
            stages: result.stages,
          }),
        }).catch(() => {})

        // Save to local db
        const attack = {
          id: Date.now(),
          url,
          attackType: result.attackType,
          blockedAtStage: result.blockedAtStage,
          attackerIP,
          location,
          timestamp: new Date().toISOString(),
        }
        db.attacks = db.attacks || []
        db.attacks.unshift(attack)
        db.attacks = db.attacks.slice(0, 50)
        writeDB(db)

        return res.json({
          blocked: true,
          attackType: result.attackType,
          blockedAtStage: result.blockedAtStage,
          reason: result.stages?.find(s => s.pass === false)?.detail || 'SSRF attack blocked',
          attackerIP,
          location,
        })
      }
    } catch (err) {
      console.error('Guardian check failed:', err.message)
    }
  }

  // VULNERABLE — raw fetch
  try {
    let currentUrl = url
    let hops = 0
    let finalResponse

    while (hops < 10) {
      const response = await fetch(currentUrl, {
        signal: AbortSignal.timeout(5000),
        redirect: 'manual',
        headers: { 'User-Agent': 'TechNotCorp-Server/1.0' },
      })
      if (response.status >= 300 && response.status < 400) {
        const location = response.headers.get('location')
        if (!location) break
        currentUrl = location
        hops++
        continue
      }
      finalResponse = response
      break
    }

    if (!finalResponse) return res.json({ error: 'Too many redirects' })
    const text = await finalResponse.text()
    return res.json({ ok: true, status: finalResponse.status, body: text, finalUrl: currentUrl })
  } catch (err) {
    return res.json({ ok: false, error: err.message })
  }
})

// Toggle Guardian
app.post('/api/guardian/toggle', requireAdmin, (req, res) => {
  const db = readDB()
  db.company.guardianEnabled = !db.company.guardianEnabled
  writeDB(db)
  res.json({ enabled: db.company.guardianEnabled })
})

app.get('/api/guardian/status', (req, res) => {
  const db = readDB()
  res.json({ enabled: !!db.company.guardianEnabled })
})

app.get('/api/attacks', requireAdmin, (req, res) => {
  const db = readDB()
  res.json(db.attacks || [])
})

app.listen(PORT, () => {
  console.log(`\n TechNot Corp running on http://localhost:${PORT}`)
  console.log(` Admin: rajesh@technotcorp.com / pass123`)
  console.log(` Employee: priya@technotcorp.com / pass123\n`)
})
app.post('/api/report-attack', async (req, res) => {
  const { url, attackType, blockedAtStage, attackerIP, location, source, stages } = req.body
  const entry = sessionLog.append({
    ok: false, blocked: true, url, attackType, blockedAtStage,
    reason: `Blocked at stage ${blockedAtStage}`,
    attackerIP: attackerIP || 'unknown',
    location: location || '',
    source: source || 'technotcorp',
    pipelineTrace: stages || [],
    redirectChain: [], resolvedIPs: [],
  })
  emit('attack', entry)
  res.json({ logged: true })
})
app.post('/api/fetch-url', requireAuth, async (req, res) => {
  const { url } = req.body
  if (!url) return res.status(400).json({ error: 'url required' })

  try {
    let currentUrl = url
    let hops = 0
    let finalResponse

    while (hops < 10) {
      const response = await fetch(currentUrl, {
        signal: AbortSignal.timeout(5000),
        redirect: 'manual',
        headers: { 'User-Agent': 'TechNotCorp-Server/1.0' },
      })
      if (response.status >= 300 && response.status < 400) {
        const location = response.headers.get('location')
        if (!location) break
        currentUrl = location
        hops++
        continue
      }
      finalResponse = response
      break
    }

    if (!finalResponse) return res.json({ error: 'Too many redirects' })
    const text = await finalResponse.text()
    return res.json({ ok: true, status: finalResponse.status, body: text, finalUrl: currentUrl })

  } catch (err) {
    // Guardian blocked this request
    if (err.guardianBlocked) {
      return res.json({
        blocked: true,
        attackType: err.attackType,
        blockedAtStage: err.blockedAtStage,
        reason: `Guardian blocked: ${err.attackType} at stage ${err.blockedAtStage}`,
        attackerIP: err.attackerIP,
        location: err.location,
      })
    }
    return res.json({ ok: false, error: err.message })
  }
})
