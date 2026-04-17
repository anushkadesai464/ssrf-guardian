/**
 * guardian-protect.js
 * Drop-in SSRF protection middleware for any Express app
 * 
 * Installation:
 *   import guardian from './guardian-protect.js'
 *   app.use(guardian)
 */

import { preflightAnalyze } from '../backend/guardian.js'

const GUARDIAN_DASHBOARD = process.env.GUARDIAN_URL || 'http://localhost:3000'

function guardianMiddleware(req, res, next) {
  const originalFetch = global.fetch

  global.fetch = async (url, options = {}) => {
    // Skip Guardian API calls to avoid infinite loop
    if (typeof url === 'string' && url.includes(GUARDIAN_DASHBOARD)) {
      return originalFetch(url, options)
    }

    if (typeof url === 'string' && (url.startsWith('http://') || url.startsWith('https://'))) {
      const result = preflightAnalyze(url)

      if (result.prediction === 'BLOCKED') {
        const attackerIP =
          req.headers['x-forwarded-for']?.split(',')[0]?.trim() ||
          req.headers['x-real-ip'] ||
          req.socket?.remoteAddress ||
          'unknown'

        // Get geolocation
        let location = 'Local network'
        try {
          if (!attackerIP.includes('127.') && !attackerIP.includes('::') && attackerIP !== 'unknown') {
            const geo = await originalFetch(`http://ip-api.com/json/${attackerIP}?fields=city,regionName,country`)
            const gd = await geo.json()
            if (gd.city) location = `${gd.city}, ${gd.regionName}, ${gd.country}`
          }
        } catch {}

        // Report to Guardian dashboard
        originalFetch(`${GUARDIAN_DASHBOARD}/api/report-attack`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            url,
            attackType: result.attackType,
            blockedAtStage: result.blockedAtStage,
            attackerIP,
            location,
            source: 'guardian-protect',
            stages: result.stages,
          }),
        }).catch(() => {})

        const err = new Error(`SSRF Guardian blocked: ${result.attackType} at stage ${result.blockedAtStage}`)
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

export default guardianMiddleware