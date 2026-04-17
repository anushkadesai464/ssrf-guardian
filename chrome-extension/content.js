// content.js
const GUARDIAN_API = 'http://localhost:3000/api/preflight'

const TYPE_LABEL = {
  invalid_url:         'Invalid URL',
  protocol_switch:     'Protocol switch',
  octal_octet:         'Octal IP notation',
  decimal_integer:     'Decimal integer IP',
  hex_octet:           'Hex IP notation',
  ipv4_mapped_ipv6:    'IPv4-mapped IPv6',
  loopback_alias:      'Loopback address',
  private_ip:          'Private IP range',
  allowlist_violation: 'Not in allowlist',
}

async function analyzeCurrentPage() {
  const url = window.location.href
  if (!url.startsWith('http://') && !url.startsWith('https://')) return

  const enabled = await new Promise(resolve => {
    chrome.storage.local.get(['guardianEnabled'], result => {
      resolve(result.guardianEnabled !== false)
    })
  })
  if (!enabled) return

  createPanel(url, null)

  try {
    const res = await fetch(GUARDIAN_API, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ url, allowlist: [] }),
    })
    const data = await res.json()
    updatePanel(url, data)
  } catch {
    updatePanel(url, null)
  }
}

function createPanel(url, data) {
  const existing = document.getElementById('ssrf-guardian-panel')
  if (existing) existing.remove()

  const panel = document.createElement('div')
  panel.id = 'ssrf-guardian-panel'
  panel.style.cssText = `
    position: fixed;
    bottom: 20px;
    right: 20px;
    width: 320px;
    background: #0f1117;
    border: 1px solid #2e3347;
    border-radius: 12px;
    padding: 14px;
    z-index: 2147483647;
    font-family: 'Inter', system-ui, sans-serif;
    font-size: 13px;
    color: #e2e8f0;
    box-shadow: 0 8px 32px rgba(0,0,0,0.5);
    animation: ssrfSlideIn 0.3s ease;
  `

  renderPanel(panel, url, data)
  document.body.appendChild(panel)

  // Auto-hide after 8 seconds if safe
  setTimeout(() => {
    const p = document.getElementById('ssrf-guardian-panel')
    if (p && !p.dataset.blocked) {
      p.style.opacity = '0'
      p.style.transform = 'translateX(120%)'
      p.style.transition = 'all 0.3s ease'
      setTimeout(() => p?.remove(), 300)
    }
  }, 8000)
}

function updatePanel(url, data) {
  const panel = document.getElementById('ssrf-guardian-panel')
  if (!panel) return
  renderPanel(panel, url, data)
  if (data?.prediction === 'BLOCKED') {
    panel.dataset.blocked = 'true'
    panel.style.borderColor = 'rgba(255,71,87,0.5)'
  }
}

function renderPanel(panel, url, data) {
  // Clear panel
  panel.innerHTML = ''

  // ── Header row ──
  const header = document.createElement('div')
  header.style.cssText = 'display:flex;align-items:center;gap:8px;margin-bottom:10px'

  const dot = document.createElement('div')
  const isLoading = !data
  const isBlocked = data?.prediction === 'BLOCKED'
  const color = isLoading ? '#3d9bff' : isBlocked ? '#ff4757' : '#2ed573'
  const labelText = isLoading ? 'Analyzing...' : isBlocked ? 'BLOCKED' : 'SAFE'

  dot.style.cssText = `width:8px;height:8px;border-radius:50%;background:${color};box-shadow:0 0 6px ${color};flex-shrink:0`

  const title = document.createElement('span')
  title.style.cssText = `font-size:12px;font-weight:700;color:${color}`
  title.textContent = `SSRF Guardian — ${labelText}`

  // Close button — addEventListener instead of onclick
  const closeBtn = document.createElement('button')
  closeBtn.textContent = '×'
  closeBtn.style.cssText = 'margin-left:auto;background:none;border:none;color:#4a5568;cursor:pointer;font-size:18px;line-height:1;padding:0'
  closeBtn.addEventListener('click', () => {
    document.getElementById('ssrf-guardian-panel')?.remove()
  })

  header.appendChild(dot)
  header.appendChild(title)
  header.appendChild(closeBtn)
  panel.appendChild(header)

  // ── URL display ──
  const urlDiv = document.createElement('div')
  urlDiv.style.cssText = 'font-size:10px;color:#4a5568;font-family:monospace;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;margin-bottom:8px'
  urlDiv.title = url
  urlDiv.textContent = url
  panel.appendChild(urlDiv)

  if (!data) return // loading state — stop here

  // ── Stage grid label ──
  const stageLabel = document.createElement('div')
  stageLabel.style.cssText = 'font-size:10px;color:#8892a4;margin-bottom:4px;text-transform:uppercase;letter-spacing:0.06em'
  stageLabel.textContent = '7-stage pipeline'
  panel.appendChild(stageLabel)

  // ── Stage grid ──
  const grid = document.createElement('div')
  grid.className = 'stage-grid'
  ;(data.stages || []).forEach(s => {
    const cell = document.createElement('div')
    const cls = s.pass === true ? 'stage-pass' : s.pass === false ? 'stage-fail' : 'stage-unknown'
    cell.className = `stage-cell ${cls}`

    const icon = document.createElement('div')
    icon.textContent = s.pass === true ? '✓' : s.pass === false ? '✗' : '?'

    const name = document.createElement('span')
    name.style.fontSize = '8px'
    name.textContent = (s.name || `S${s.stage}`).split(' ')[0]

    cell.appendChild(icon)
    cell.appendChild(name)
    grid.appendChild(cell)
  })
  panel.appendChild(grid)

  // ── Attack detail if blocked ──
  if (isBlocked) {
    const detail = document.createElement('div')
    detail.style.cssText = 'margin-top:8px;padding:6px 10px;background:rgba(255,71,87,0.08);border-radius:6px;border:1px solid rgba(255,71,87,0.2)'

    const attackTitle = document.createElement('div')
    attackTitle.style.cssText = 'font-size:11px;color:#ff4757;font-weight:600;margin-bottom:2px'
    attackTitle.textContent = `${TYPE_LABEL[data.attackType] || data.attackType || 'Attack'} at stage ${data.blockedAtStage}`

    const attackDesc = document.createElement('div')
    attackDesc.style.cssText = 'font-size:10px;color:#8892a4'
    attackDesc.textContent = 'This URL contains a known SSRF bypass technique and was flagged before connecting.'

    detail.appendChild(attackTitle)
    detail.appendChild(attackDesc)
    panel.appendChild(detail)
  }

  // ── Footer ──
  const footer = document.createElement('div')
  footer.style.cssText = 'margin-top:10px;display:flex;justify-content:space-between;align-items:center'

  const footerLeft = document.createElement('span')
  footerLeft.style.cssText = 'font-size:9px;color:#4a5568'
  footerLeft.textContent = 'SSRF Guardian v1.0'

  footer.appendChild(footerLeft)

  if (!isBlocked) {
    const footerRight = document.createElement('span')
    footerRight.style.cssText = 'font-size:9px;color:#2ed573'
    footerRight.textContent = 'All stages passed ✓'
    footer.appendChild(footerRight)
  }

  panel.appendChild(footer)
}

analyzeCurrentPage()