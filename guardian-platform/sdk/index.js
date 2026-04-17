/**
 * Guardian SDK v1.0
 * Drop-in SSRF protection for any Express app
 *
 * Usage:
 *   import { protect } from './guardian-sdk/index.js'
 *   app.use(protect('grd_live_your_api_key'))
 */

import { preflightAnalyze } from '../../backend/guardian.js'

const PLATFORM_URL = process.env.GUARDIAN_PLATFORM_URL || 'http://localhost:6060'
const HEARTBEAT_INTERVAL = 25000 // 25 seconds

// ── IP canonicalization helpers ────────────────────────────────────────────────
const PRIVATE_RANGES = [
  [0x7f000000, 0x7fffffff], // 127.0.0.0/8
  [0x0a000000, 0x0affffff], // 10.0.0.0/8
  [0xac100000, 0xac1fffff], // 172.16.0.0/12
  [0xc0a80000, 0xc0a8ffff], // 192.168.0.0/16
  [0xa9fe0000, 0xa9feffff], // 169.254.0.0/16
]

// ── SDK class ──────────────────────────────────────────────────────────────────
class GuardianSDK {
  constructor(apiKey) {
    if (!apiKey || !apiKey.startsWith('grd_live_')) {
      throw new Error('Invalid Guardian API key. Must start with grd_live_')
    }
    this.apiKey = apiKey
    this.connected = false
    this.startHeartbeat()
    console.log(`\n[Guardian SDK] Initialized with key: ${apiKey.slice(0, 20)}...`)
    console.log(`[Guardian SDK] Platform: ${PLATFORM_URL}`)
    console.log(`[Guardian SDK] SSRF protection: ACTIVE\n`)
  }

  // Send heartbeat to platform every 25 seconds
  startHeartbeat() {
    const ping = async () => {
      try {
        const res = await fetch(`${PLATFORM_URL}/api/sdk/heartbeat`, {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
            'x-api-key': this.apiKey,
          },
        })
        if (res.ok) {
          if (!this.connected) {
            console.log('[Guardian SDK] ✓ Connected to Guardian Platform')
            this.connected = true
          }
        }
      } catch {
        if (this.connected) {
          console.log('[Guardian SDK] ⚠ Platform unreachable — protection still active')
          this.connected = false
        }
      }
    }
    ping()
    setInterval(ping, HEARTBEAT_INTERVAL)
  }

  // Report blocked attack to platform
  async reportAttack(attackData) {
    try {
      await fetch(`${PLATFORM_URL}/api/sdk/attack`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'x-api-key': this.apiKey,
        },
        body: JSON.stringify(attackData),
      })
    } catch {
      // Silent fail — protection works even if platform is unreachable
    }
  }

  // Express middleware
  middleware() {
  const sdk = this

  return async function guardianMiddleware(req, res, next) {
    // ── Monitor INCOMING requests for malicious patterns ──────────────────
    const incomingUrl = req.protocol + '://' + (req.headers.host || '') + req.originalUrl
    const suspiciousHeaders = [
      req.headers['x-forwarded-for'],
      req.headers['x-forwarded-host'],
      req.headers['x-real-ip'],
      req.headers['host'],
    ].filter(Boolean)

    // Check if host header contains IP obfuscation tricks
    const host = req.headers.host || ''
    const suspiciousHost =
      /^0x[0-9a-f]+/i.test(host) ||        // hex IP
      /^\d{8,10}(:\d+)?$/.test(host) ||     // decimal integer IP
      /^0\d+\.\d/.test(host) ||             // octal IP
      /\[.*\]/.test(host) ||                // IPv6 bracket
      /(%2e|%00|%0a)/i.test(host)           // encoded chars

    if (suspiciousHost) {
      const attackerIP =
        req.headers['x-forwarded-for']?.split(',')[0]?.trim() ||
        req.socket?.remoteAddress || 'unknown'

      let location = 'Local network'
      try {
        const cleanIP = attackerIP.replace(/^::ffff:/, '')
        if (!cleanIP.startsWith('127.') && !cleanIP.startsWith('::') && cleanIP !== 'unknown') {
          const geo = await fetch(`http://ip-api.com/json/${cleanIP}?fields=city,regionName,country`)
          const gd = await geo.json()
          if (gd.city) location = `${gd.city}, ${gd.regionName}, ${gd.country}`
        }
      } catch {}

      sdk.reportAttack({
        url: incomingUrl,
        attackType: 'host_header_injection',
        blockedAtStage: 1,
        reason: `Suspicious host header: ${host}`,
        attackerIP,
        location,
        source: 'incoming-request',
      })

      console.log(`[Guardian SDK] BLOCKED incoming: host_header_injection — ${host}`)
      return res.status(400).json({ error: 'Request blocked by Guardian Security' })
    }

    // ── Check URL parameters for SSRF injection ───────────────────────────
    const checkParams = ['url', 'src', 'redirect', 'target', 'next', 'callback', 'fetch', 'load', 'href', 'uri']
    for (const param of checkParams) {
      const val = req.query[param] || req.body?.[param]
      if (val && typeof val === 'string' && (val.startsWith('http://') || val.startsWith('https://'))) {
        const result = preflightAnalyze(val)
        if (result.prediction === 'BLOCKED') {
          const attackerIP =
            req.headers['x-forwarded-for']?.split(',')[0]?.trim() ||
            req.socket?.remoteAddress || 'unknown'

          let location = 'Local network'
          try {
            const cleanIP = attackerIP.replace(/^::ffff:/, '')
            if (!cleanIP.startsWith('127.') && !cleanIP.startsWith('::') && cleanIP !== 'unknown') {
              const geo = await fetch(`http://ip-api.com/json/${cleanIP}?fields=city,regionName,country`)
              const gd = await geo.json()
              if (gd.city) location = `${gd.city}, ${gd.regionName}, ${gd.country}`
            }
          } catch {}

          sdk.reportAttack({
            url: val,
            attackType: result.attackType,
            blockedAtStage: result.blockedAtStage,
            reason: result.stages?.find(s => s.pass === false)?.detail || '',
            attackerIP,
            location,
            source: 'url-parameter',
          })

          console.log(`[Guardian SDK] BLOCKED param injection: ${param}=${val}`)
          return res.status(400).json({ error: 'Malicious URL parameter blocked by Guardian' })
        }
      }
    }

    // ── Patch outgoing fetch ──────────────────────────────────────────────
    const originalFetch = global.fetch

    global.fetch = async (url, options = {}) => {
      if (typeof url === 'string' && url.includes(PLATFORM_URL)) {
        return originalFetch(url, options)
      }

      if (typeof url === 'string' && (url.startsWith('http://') || url.startsWith('https://'))) {
        const result = preflightAnalyze(url)

        if (result.prediction === 'BLOCKED') {
          const attackerIP =
            req.headers['x-forwarded-for']?.split(',')[0]?.trim() ||
            req.socket?.remoteAddress || 'unknown'

          let location = 'Local network'
          try {
            const cleanIP = attackerIP.replace(/^::ffff:/, '')
            if (!cleanIP.startsWith('127.') && !cleanIP.startsWith('::') && cleanIP !== 'unknown') {
              const geo = await originalFetch(`http://ip-api.com/json/${cleanIP}?fields=city,regionName,country`)
              const gd = await geo.json()
              if (gd.city) location = `${gd.city}, ${gd.regionName}, ${gd.country}`
            }
          } catch {}

          sdk.reportAttack({
            url,
            attackType: result.attackType,
            blockedAtStage: result.blockedAtStage,
            reason: result.stages?.find(s => s.pass === false)?.detail || '',
            attackerIP,
            location,
            source: 'guardian-sdk',
            stages: result.stages,
          })

          console.log(`[Guardian SDK] BLOCKED outgoing: ${result.attackType} — ${url.slice(0, 60)}`)

          const err = new Error(`[Guardian SDK] SSRF blocked: ${result.attackType}`)
          err.guardianBlocked = true
          err.attackType = result.attackType
          err.blockedAtStage = result.blockedAtStage
          err.attackerIP = attackerIP
          err.location = location
          throw err
        }
      }

      return originalFetch(url, options)
    }

    res.on('finish', () => { global.fetch = originalFetch })
    res.on('close', () => { global.fetch = originalFetch })

    next()
  }
}
}

// ── Main export ────────────────────────────────────────────────────────────────
let instance = null

export function protect(apiKey) {
  if (!instance) instance = new GuardianSDK(apiKey)
  return instance.middleware()
}

export default { protect }
