const GUARDIAN_API = 'http://localhost:3000/api/preflight'
const ENABLED_KEY = 'guardianEnabled'
const BLOCKED_KEY = 'blockedHistory'

const TYPE_LABEL = {
  invalid_url: 'Invalid URL',
  protocol_switch: 'Protocol switch',
  octal_octet: 'Octal IP',
  decimal_integer: 'Decimal IP',
  hex_octet: 'Hex IP',
  ipv4_mapped_ipv6: 'IPv6 mapped',
  loopback_alias: 'Loopback',
  private_ip: 'Private IP',
  allowlist_violation: 'Not allowlisted',
}

// Load toggle state
chrome.storage.local.get([ENABLED_KEY], result => {
  const enabled = result[ENABLED_KEY] !== false
  setToggleUI(enabled)
})

// Toggle click
document.getElementById('toggle').addEventListener('click', () => {
  const toggle = document.getElementById('toggle')
  const isOn = toggle.classList.contains('on')
  const newState = !isOn
  chrome.storage.local.set({ [ENABLED_KEY]: newState })
  setToggleUI(newState)
})

function setToggleUI(enabled) {
  const toggle = document.getElementById('toggle')
  const statusText = document.getElementById('status-text')
  toggle.className = 'toggle ' + (enabled ? 'on' : 'off')
  statusText.textContent = enabled ? 'ON' : 'OFF'
  statusText.className = 'status-text ' + (enabled ? 'on' : 'off')
}

// URL checker
document.getElementById('check-btn').addEventListener('click', checkURL)
document.getElementById('url-input').addEventListener('keydown', e => {
  if (e.key === 'Enter') checkURL()
})

async function checkURL() {
  const url = document.getElementById('url-input').value.trim()
  if (!url) return

  const resultDiv = document.getElementById('result')
  resultDiv.innerHTML = `<div class="result checking">Analyzing...</div>`

  try {
    const res = await fetch(GUARDIAN_API, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ url, allowlist: [] }),
    })
    const data = await res.json()
    showResult(data, url)
  } catch {
    resultDiv.innerHTML = `<div class="result blocked">Backend offline — start server on localhost:3000</div>`
  }
}

function showResult(data, url) {
  const resultDiv = document.getElementById('result')
  const isBlocked = data.prediction === 'BLOCKED'

  // Save to history if blocked
  if (isBlocked) {
    saveToHistory({ url, attackType: data.attackType, blockedAtStage: data.blockedAtStage })
  }

  // Stage mini-grid
  const stagesHTML = (data.stages || []).map(s => {
    const cls = s.pass === true ? 'pass' : s.pass === false ? 'fail' : 'unknown'
    return `<div class="stage-cell ${cls}">S${s.stage}<br>${s.pass === true ? '✓' : s.pass === false ? '✗' : '?'}</div>`
  }).join('')

  resultDiv.innerHTML = `
    <div class="result ${isBlocked ? 'blocked' : 'safe'}">
      <strong>${isBlocked ? '✗ BLOCKED' : '✓ SAFE'}</strong>
      ${isBlocked ? ` — ${TYPE_LABEL[data.attackType] || data.attackType} at stage ${data.blockedAtStage}` : ' — Passed all 7 stages'}
    </div>
    <div class="stages">${stagesHTML}</div>
  `

  loadHistory()
}

function saveToHistory(entry) {
  chrome.storage.local.get([BLOCKED_KEY], result => {
    const history = result[BLOCKED_KEY] || []
    history.unshift({ ...entry, timestamp: new Date().toISOString() })
    chrome.storage.local.set({ [BLOCKED_KEY]: history.slice(0, 5) })
    loadHistory()
  })
}

function loadHistory() {
  chrome.storage.local.get([BLOCKED_KEY], result => {
    const history = result[BLOCKED_KEY] || []
    const list = document.getElementById('recent-list')

    if (!history.length) {
      list.innerHTML = '<div style="font-size:11px;color:#4a5568">No blocks yet</div>'
      return
    }

    list.innerHTML = history.map(h => {
      let domain = h.url
      try { domain = new URL(h.url).hostname } catch {}
      return `
        <div class="recent-item">
          <div class="dot-small" style="background:#ff4757"></div>
          <div style="flex:1;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;color:#8892a4">${domain}</div>
          <div style="color:#ff4757;font-size:9px">${TYPE_LABEL[h.attackType] || h.attackType || 'blocked'}</div>
        </div>
      `
    }).join('')
  })
}

loadHistory()