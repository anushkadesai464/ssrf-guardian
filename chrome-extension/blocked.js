const TYPE_LABEL = {
  invalid_url:         'Invalid URL format',
  protocol_switch:     'Protocol switch attack (file://, gopher://)',
  octal_octet:         'Octal IP notation bypass',
  decimal_integer:     'Decimal integer IP bypass',
  hex_octet:           'Hex IP notation bypass',
  ipv4_mapped_ipv6:    'IPv4-mapped IPv6 bypass',
  loopback_alias:      'Loopback address (127.0.0.1)',
  private_ip:          'Private/internal IP range',
  allowlist_violation: 'Domain not in allowlist',
  dns_rebinding:       'DNS rebinding attack',
}

const STAGE_NAMES = ['Scheme','DNS','IP check','Allowlist','Redirects','Socket','Response']

const REASONS = {
  private_ip:       'This URL resolves to a private or reserved IP address. Accessing it could expose internal network services, cloud metadata credentials (like AWS keys), or backend APIs that should never be publicly accessible.',
  octal_octet:      'This URL uses octal notation to disguise a private IP (e.g. 0177.0.0.1 = 127.0.0.1). This is a known SSRF bypass technique used to evade basic IP blocklists.',
  decimal_integer:  'This URL uses a decimal integer to represent an IP address (e.g. 2130706433 = 127.0.0.1). This bypasses blocklists that only check dotted-decimal notation.',
  hex_octet:        'This URL uses hexadecimal notation to represent an IP address (e.g. 0x7f.0x0.0x0.0x1 = 127.0.0.1). This is a classic SSRF obfuscation technique.',
  ipv4_mapped_ipv6: 'This URL uses an IPv4-mapped IPv6 address (::ffff:127.0.0.1) to bypass IPv4 blocklists while still resolving to a private address.',
  protocol_switch:  'This URL uses a non-HTTP scheme (file://, gopher://, dict://) that could access local files or internal services.',
  loopback_alias:   'This URL points to the loopback interface (localhost or ::1) which accesses services running locally on this machine.',
}

const params       = new URLSearchParams(window.location.search)
const blockedUrl   = params.get('url') || 'Unknown URL'
const attackType   = params.get('attackType') || ''
const blockedStage = params.get('blockedAtStage') || '?'
let   stages       = []

try { stages = JSON.parse(params.get('stages') || '[]') } catch {}

document.getElementById('blocked-url').textContent = blockedUrl

document.getElementById('attack-type').textContent =
  TYPE_LABEL[attackType] || attackType || 'Unknown attack type'

document.getElementById('stage-num').textContent =
  `Blocked at stage ${blockedStage} of 7`

document.getElementById('reason-text').textContent =
  REASONS[attackType] || 'This URL was flagged as potentially dangerous by the SSRF Guardian pipeline.'

const grid = document.getElementById('stage-grid')
if (stages.length > 0) {
  grid.innerHTML = stages.map(s => {
    const cls  = s.pass === true ? 'stage-pass' : s.pass === false ? 'stage-fail' : 'stage-unknown'
    const icon = s.pass === true ? '✓' : s.pass === false ? '✗' : '?'
    const name = s.name || STAGE_NAMES[s.stage - 1] || `S${s.stage}`
    return `<div class="stage-cell ${cls}">${icon}<br><span style="font-size:8px">${name.split(' ')[0]}</span></div>`
  }).join('')
} else {
  grid.innerHTML = STAGE_NAMES.map((name, i) => {
    const stageNum = i + 1
    const passed   = stageNum < parseInt(blockedStage)
    const failed   = stageNum === parseInt(blockedStage)
    const cls      = passed ? 'stage-pass' : failed ? 'stage-fail' : 'stage-unknown'
    const icon     = passed ? '✓' : failed ? '✗' : '?'
    return `<div class="stage-cell ${cls}">${icon}<br><span style="font-size:8px">${name.split(' ')[0]}</span></div>`
  }).join('')
}

document.getElementById('proceed-btn').addEventListener('click', (e) => {
  e.preventDefault()
  if (!blockedUrl || blockedUrl === 'Unknown URL') return
  
  // Store a one-time bypass flag then navigate
  chrome.storage.local.set({ bypassOnce: blockedUrl }, () => {
    window.location.href = blockedUrl
  })
})
document.getElementById('back-btn').addEventListener('click', (e) => {
  e.preventDefault()
  history.back()
})