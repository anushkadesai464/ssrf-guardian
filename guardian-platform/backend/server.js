import express from 'express'
import cors from 'cors'
import session from 'express-session'
import fs from 'fs'
import path from 'path'
import { fileURLToPath } from 'url'
import { v4 as uuid } from 'uuid'

const __dirname = path.dirname(fileURLToPath(import.meta.url))
const app = express()
const PORT = 6060
const DB_PATH = path.join(__dirname, 'db.json')

function readDB() {
  return JSON.parse(fs.readFileSync(DB_PATH, 'utf8'))
}
function writeDB(data) {
  fs.writeFileSync(DB_PATH, JSON.stringify(data, null, 2))
}
function generateAPIKey(companyName) {
  const slug = companyName.toLowerCase().replace(/\s+/g, '_').replace(/[^a-z0-9_]/g, '').slice(0, 20)
  const random = Math.random().toString(36).slice(2, 10)
  return `grd_live_${slug}_${random}`
}

app.use(cors({ origin: true, credentials: true }))
app.use(express.json())
app.use((req, res, next) => {
  res.header('Access-Control-Allow-Origin', req.headers.origin || '*')
  res.header('Access-Control-Allow-Credentials', 'true')
  res.header('Access-Control-Allow-Methods', 'GET,POST,PUT,DELETE,OPTIONS')
  res.header('Access-Control-Allow-Headers', 'Content-Type,Authorization,x-api-key')
  if (req.method === 'OPTIONS') return res.sendStatus(200)
  next()
})
app.use(session({
  secret: 'guardian-platform-secret',
  resave: false,
  saveUninitialized: false,
  cookie: { maxAge: 7 * 24 * 60 * 60 * 1000 }
}))

// ── AUTH ──────────────────────────────────────────────────────────────────────
app.post('/api/register', (req, res) => {
  const { name, email, password, website } = req.body
  if (!name || !email || !password) return res.status(400).json({ error: 'Name, email and password required' })
  const db = readDB()
  if (db.companies.find(c => c.email === email)) return res.status(409).json({ error: 'Email already registered' })
  const company = {
    id: 'comp_' + uuid().slice(0, 8),
    name, email, password,
    website: website || '',
    apiKey: generateAPIKey(name),
    plan: 'pro',
    registeredAt: new Date().toISOString(),
    connected: false,
    lastSeen: null,
    attackCount: 0,
    blockedIPs: [],
  }
  db.companies.push(company)
  writeDB(db)
  req.session.companyId = company.id
  res.json({ ok: true, company: { ...company, password: undefined } })
})

app.post('/api/login', (req, res) => {
  const { email, password } = req.body
  const db = readDB()
  const company = db.companies.find(c => c.email === email && c.password === password)
  if (!company) return res.status(401).json({ error: 'Invalid credentials' })
  req.session.companyId = company.id
  res.json({ ok: true, company: { ...company, password: undefined } })
})

app.post('/api/logout', (req, res) => {
  req.session.destroy()
  res.json({ ok: true })
})

app.get('/api/me', (req, res) => {
  if (!req.session.companyId) return res.status(401).json({ error: 'Not authenticated' })
  const db = readDB()
  const company = db.companies.find(c => c.id === req.session.companyId)
  if (!company) return res.status(404).json({ error: 'Not found' })
  res.json({ ...company, password: undefined })
})

// ── SDK ───────────────────────────────────────────────────────────────────────
app.post('/api/sdk/heartbeat', (req, res) => {
  const apiKey = req.headers['x-api-key']
  if (!apiKey) return res.status(401).json({ error: 'API key required' })
  const db = readDB()
  const company = db.companies.find(c => c.apiKey === apiKey)
  if (!company) return res.status(401).json({ error: 'Invalid API key' })
  company.connected = true
  company.lastSeen = new Date().toISOString()
  writeDB(db)
  res.json({ ok: true })
})

app.post('/api/sdk/attack', (req, res) => {
  const apiKey = req.headers['x-api-key']
  if (!apiKey) return res.status(401).json({ error: 'API key required' })
  const db = readDB()
  const company = db.companies.find(c => c.apiKey === apiKey)
  if (!company) return res.status(401).json({ error: 'Invalid API key' })
  const attack = {
    id: uuid(),
    companyId: company.id,
    companyName: company.name,
    url: req.body.url || '',
    attackType: req.body.attackType || 'unknown',
    blockedAtStage: req.body.blockedAtStage || null,
    reason: req.body.reason || '',
    attackerIP: req.body.attackerIP || 'unknown',
    location: req.body.location || '',
    source: req.body.source || 'sdk',
    stages: req.body.stages || [],
    timestamp: new Date().toISOString(),
  }
  db.attacks.unshift(attack)
  db.attacks = db.attacks.slice(0, 500)
  company.attackCount = (company.attackCount || 0) + 1
  company.lastSeen = new Date().toISOString()
  if (!company.blockedIPs) company.blockedIPs = []
  writeDB(db)
  res.json({ ok: true, attackId: attack.id })
})

// Check if IP is blocked — called by company server
app.get('/api/sdk/check-ip', (req, res) => {
  const apiKey = req.headers['x-api-key']
  const ip = req.query.ip
  if (!apiKey) return res.status(401).json({ error: 'API key required' })
  const db = readDB()
  const company = db.companies.find(c => c.apiKey === apiKey)
  if (!company) return res.status(401).json({ error: 'Invalid API key' })
  const blocked = (company.blockedIPs || []).includes(ip)
  res.json({ blocked })
})

// ── DASHBOARD ─────────────────────────────────────────────────────────────────
app.get('/api/dashboard/status', (req, res) => {
  const db = readDB()
  const companyId = req.session.companyId || req.query.companyId
  if (!companyId) return res.status(401).json({ error: 'Not authenticated' })
  const company = db.companies.find(c => c.id === companyId)
  if (!company) return res.status(404).json({ error: 'Not found' })
  const lastSeen = company.lastSeen ? new Date(company.lastSeen) : null
  const isConnected = lastSeen && (Date.now() - lastSeen.getTime()) < 60000
  if (!isConnected && company.connected) { company.connected = false; writeDB(db) }
  const attacks = db.attacks.filter(a => a.companyId === company.id)
  const today = new Date().toDateString()
  const todayAttacks = attacks.filter(a => new Date(a.timestamp).toDateString() === today)
  const byType = {}
  attacks.forEach(a => { byType[a.attackType] = (byType[a.attackType] || 0) + 1 })

  // IP frequency analysis
  const ipCount = {}
  attacks.forEach(a => { if (a.attackerIP && a.attackerIP !== 'unknown') ipCount[a.attackerIP] = (ipCount[a.attackerIP] || 0) + 1 })
  const suspiciousIPs = Object.entries(ipCount).filter(([ip, count]) => count >= 3).map(([ip, count]) => ({ ip, count, blocked: (company.blockedIPs || []).includes(ip) })).sort((a, b) => b.count - a.count)

  res.json({
    company: { ...company, password: undefined },
    connected: isConnected,
    stats: {
      totalAttacks: attacks.length,
      todayAttacks: todayAttacks.length,
      topAttackType: Object.entries(byType).sort((a, b) => b[1] - a[1])[0]?.[0] || 'none',
      lastAttack: attacks[0]?.timestamp || null,
    },
    suspiciousIPs,
  })
})

app.get('/api/dashboard/attacks', (req, res) => {
  const db = readDB()
  const companyId = req.session.companyId || req.query.companyId
  if (!companyId) return res.status(401).json({ error: 'Not authenticated' })
  const attacks = db.attacks.filter(a => a.companyId === companyId)
  res.json(attacks)
})

// Block/unblock IP
app.post('/api/dashboard/block-ip', (req, res) => {
  const db = readDB()
  const { ip, action, companyId: bodyCompanyId, apiKey } = req.body
  // Support session, body companyId, or apiKey
  let companyId = req.session.companyId || bodyCompanyId
  if (!companyId && apiKey) {
    const co = db.companies.find(c => c.apiKey === apiKey)
    if (co) companyId = co.id
  }
  if (!companyId) return res.status(401).json({ error: 'Not authenticated' })
  const company = db.companies.find(c => c.id === companyId)
  if (!company) return res.status(404).json({ error: 'Not found' })
  if (!company.blockedIPs) company.blockedIPs = []
  if (action === 'block' && !company.blockedIPs.includes(ip)) {
    company.blockedIPs.push(ip)
  } else if (action === 'unblock') {
    company.blockedIPs = company.blockedIPs.filter(i => i !== ip)
  }
  writeDB(db)
  res.json({ ok: true, blockedIPs: company.blockedIPs })
})

app.get('/api/health', (req, res) => {
  const db = readDB()
  res.json({ ok: true, companies: db.companies.length, attacks: db.attacks.length, port: PORT })
})


app.listen(PORT, () => console.log(`Guardian Platform on http://localhost:${PORT}`))