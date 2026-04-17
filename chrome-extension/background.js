const GUARDIAN_API = 'http://localhost:3000/api/preflight'
const ENABLED_KEY = 'guardianEnabled'

async function isEnabled() {
  return new Promise(resolve => {
    chrome.storage.local.get([ENABLED_KEY], result => {
      resolve(result.guardianEnabled !== false)
    })
  })
}

async function checkURL(url) {
  try {
    const res = await fetch(GUARDIAN_API, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ url, allowlist: [] }),
    })
    return await res.json()
  } catch {
    return null
  }
}

chrome.webNavigation.onBeforeNavigate.addListener(async (details) => {
  if (details.frameId !== 0) return

  const enabled = await isEnabled()
  if (!enabled) return

  const url = details.url
  if (!url.startsWith('http://') && !url.startsWith('https://')) return
  if (url.includes('chrome-extension://')) return

  // Check one-time bypass — user clicked "proceed anyway"
  const bypass = await new Promise(resolve => {
    chrome.storage.local.get(['bypassOnce'], result => {
      resolve(result.bypassOnce)
    })
  })

  if (bypass === url) {
    // Clear the bypass flag and allow through
    chrome.storage.local.remove('bypassOnce')
    console.log('[guardian] Bypass allowed for:', url)
    return
  }

  const result = await checkURL(url)
  if (!result) return

  if (result.prediction === 'BLOCKED') {
    const params = new URLSearchParams({
      url: url,
      attackType: result.attackType || '',
      blockedAtStage: result.blockedAtStage || '',
      stages: JSON.stringify(result.stages || []),
    })

    chrome.tabs.update(details.tabId, {
      url: chrome.runtime.getURL('blocked.html') + '?' + params.toString()
    })
  }
})