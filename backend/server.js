import express from 'express';
import cors from 'cors';
import { safeFetch, preflightAnalyze } from './guardian.js';
import { sessionLog } from './sessionLog.js';
import { addSSEClient, emit } from './sseEmitter.js';
import { startTrap } from './redirectTrap.js';

// Conditionally import AI routes if API key is available
let aiRouter = null;
if (process.env.GROQ_API_KEY) {
  try {
    aiRouter = (await import('./aiRoutes.js')).default;
  } catch (err) {
    console.warn('[server] AI routes disabled: GROQ_API_KEY not set or invalid');
  }
}

const app = express();
const PORT = 3000;

app.use(cors());
app.use(express.json());

// Start mock metadata + redirect server on :3001
startTrap(3001);

// ── Live event stream ─────────────────────────────────────────────────────────
app.get('/api/events', (req, res) => addSSEClient(res));

// ── AI routes (F4 / F6 / F7) ─────────────────────────────────────────────────
if (aiRouter) {
  app.use('/api', aiRouter);
} else {
  console.log('[server] AI features disabled - set GROQ_API_KEY to enable');
}

// ── F5: preflight analysis ────────────────────────────────────────────────────
app.post('/api/preflight', (req, res) => {
  const { url, allowlist = [] } = req.body;
  res.json(preflightAnalyze(url, allowlist));
});

// ── Core: URL fetch ───────────────────────────────────────────────────────────
app.post('/api/fetch', async (req, res) => {
  const { url, guardianEnabled = false, allowlist = [] } = req.body;
  if (!url) return res.status(400).json({ error: 'url required' });

  console.log(`[server] fetch | guardian=${guardianEnabled} | ${url}`);

  // VULNERABLE MODE — raw fetch, no validation
  // VULNERABLE MODE — raw fetch, no validation, manually follow redirects
if (!guardianEnabled) {
  try {
    // Manually follow redirects so we can show the full chain
    let currentUrl = url;
    let finalResponse;
    let hops = 0;

    while (hops < 10) {
      const response = await fetch(currentUrl, {
        signal: AbortSignal.timeout(5000),
        redirect: 'manual',
        headers: { 'User-Agent': 'VulnerableApp/1.0' },
      });

      // If redirect, follow it
      if (response.status >= 300 && response.status < 400) {
        const location = response.headers.get('location');
        if (!location) break;
        currentUrl = location;
        hops++;
        continue;
      }

      finalResponse = response;
      break;
    }

    if (!finalResponse) throw new Error('Too many redirects');

    const text = await finalResponse.text();

    const entry = sessionLog.append({
      ok: true, blocked: false, url,
      source: 'manual_unprotected',
      pipelineTrace: [], redirectChain: [], resolvedIPs: [],
    });
    emit('request', entry);

    return res.json({
      ok: true, guardianEnabled: false,
      status: finalResponse.status,
      body: text,
      finalUrl: currentUrl,
      warning: 'UNPROTECTED — No SSRF validation performed',
    });
  } catch (err) {
    return res.json({ ok: false, error: err.message, guardianEnabled: false });
  }
}

  // PROTECTED MODE — full 7-stage pipeline
  const result = await safeFetch(url, { allowlist });
  const entry = sessionLog.append({ ...result, url });
  emit('attack', entry);

  return res.json({
    ok: result.ok,
    guardianEnabled: true,
    blocked: result.blocked || false,
    attackType: result.attackType || null,
    reason: result.reason || null,
    blockedAtStage: result.blockedAtStage || null,
    body: result.body || null,
    pipelineTrace: result.pipelineTrace || [],
    redirectChain: result.redirectChain || [],
    resolvedIPs: result.resolvedIPs || [],
  });
});

// ── Session log ───────────────────────────────────────────────────────────────
app.get('/api/session', (req, res) => {
  res.json({ log: sessionLog.getAll(), summary: sessionLog.getSummary() });
});

app.delete('/api/session', (req, res) => {
  sessionLog.clear();
  res.json({ cleared: true });
});

// ── Health ────────────────────────────────────────────────────────────────────
app.get('/api/health', (req, res) => {
  res.json({
    status: 'ok',
    proxy: !!process.env.GUARDIAN_PROXY,
    session: sessionLog.getSummary(),
  });
});
// ── Custom SSRF AI Model — rule-based generation ──────────────────────────────
app.post('/api/pentest', async (req, res) => {
  const { targetUrl } = req.body
  if (!targetUrl) return res.status(400).json({ error: 'targetUrl required' })

  res.setHeader('Content-Type', 'text/event-stream')
  res.setHeader('Cache-Control', 'no-cache')
  res.setHeader('Access-Control-Allow-Origin', '*')

  const send = (data) => res.write(`data: ${JSON.stringify(data)}\n\n`)

  // ── Custom AI Model — knows every SSRF bypass technique ────────────────────
  function generateVariants(baseUrl) {
    const variants = []

    // Parse base URL
    let parsed
    try { parsed = new URL(baseUrl) } catch { parsed = null }

    const path = parsed?.pathname || '/admin'
    const port = parsed?.port || ''

    // ── Technique 1: Loopback IP variants ─────────────────────────────────────
    const loopbacks = [
      { ip: '127.0.0.1',           label: 'Loopback direct' },
      { ip: '127.0.0.2',           label: 'Loopback alt' },
      { ip: '127.1',               label: 'Short form' },
      { ip: '127.0.1',             label: 'Short form 2' },
      { ip: '0177.0.0.1',          label: 'Octal octet' },
      { ip: '0177.0.0.01',         label: 'Octal padded' },
      { ip: '00177.0.0.1',         label: 'Octal double pad' },
      { ip: '2130706433',          label: 'Decimal integer' },
      { ip: '0x7f.0x0.0x0.0x1',   label: 'Hex octets' },
      { ip: '0x7f000001',          label: 'Hex integer' },
      { ip: '[::1]',               label: 'IPv6 loopback' },
      { ip: '[::ffff:127.0.0.1]',  label: 'IPv4-mapped IPv6' },
      { ip: '[::ffff:7f00:1]',     label: 'IPv6 hex mapped' },
      { ip: '127.000.000.001',     label: 'Zero padded' },
      { ip: '127%2e0%2e0%2e1',     label: 'URL encoded dots' },
      { ip: '127.0.0.1%00',        label: 'Null byte suffix' },
    ]

    loopbacks.forEach(({ ip, label }) => {
      const portPart = port ? `:${port}` : ''
      variants.push({
        url: `http://${ip}${portPart}${path}`,
        technique: label,
        category: 'Loopback bypass',
      })
    })

    // ── Technique 2: Cloud metadata endpoint variants ──────────────────────────
    const metadataIPs = [
      { ip: '169.254.169.254',       label: 'AWS metadata direct' },
      { ip: '0xa9.0xfe.0xa9.0xfe',   label: 'AWS metadata hex' },
      { ip: '2852039166',            label: 'AWS metadata decimal' },
      { ip: '0251.0376.0251.0376',   label: 'AWS metadata octal' },
      { ip: '[::ffff:169.254.169.254]', label: 'AWS metadata IPv6' },
      { ip: '169.254.169.254',       label: 'GCP metadata' },
      { ip: '100.100.100.200',       label: 'Alibaba metadata' },
    ]

    const metaPaths = [
      '/latest/meta-data/',
      '/latest/meta-data/iam/security-credentials/',
      '/computeMetadata/v1/',
      '/metadata/v1/',
    ]

    metadataIPs.forEach(({ ip, label }, i) => {
      variants.push({
        url: `http://${ip}${metaPaths[i % metaPaths.length]}`,
        technique: label,
        category: 'Cloud metadata',
      })
    })

    // ── Technique 3: Private network ranges ────────────────────────────────────
    const privateIPs = [
      { ip: '10.0.0.1',      label: 'Private class A' },
      { ip: '10.255.255.255', label: 'Private class A edge' },
      { ip: '172.16.0.1',    label: 'Private class B' },
      { ip: '172.31.255.255', label: 'Private class B edge' },
      { ip: '192.168.1.1',   label: 'Private class C' },
      { ip: '192.168.0.1',   label: 'Private class C alt' },
    ]

    privateIPs.forEach(({ ip, label }) => {
      variants.push({
        url: `http://${ip}${path}`,
        technique: label,
        category: 'Private network',
      })
    })

    // ── Technique 4: Protocol switch ───────────────────────────────────────────
    const protocols = [
      { url: `file:///etc/passwd`,           label: 'File read /etc/passwd' },
      { url: `file:///etc/shadow`,           label: 'File read /etc/shadow' },
      { url: `file:///proc/self/environ`,    label: 'Process environment' },
      { url: `gopher://127.0.0.1:80/_GET ${path}`, label: 'Gopher HTTP' },
      { url: `dict://127.0.0.1:11/info`,    label: 'Dict protocol' },
      { url: `ftp://127.0.0.1/etc/passwd`,  label: 'FTP protocol' },
    ]
    protocols.forEach(({ url, label }) => {
      variants.push({ url, technique: label, category: 'Protocol switch' })
    })

    // ── Technique 5: Open redirect chains ──────────────────────────────────────
    const redirectors = [
      `http://127.0.0.1:3001/redirect?to=`,
      `https://httpbin.org/redirect-to?url=`,
    ]
    const redirectTargets = [
      'http://169.254.169.254/latest/meta-data/',
      'http://127.0.0.1/admin',
      'http://10.0.0.1/internal',
    ]
    redirectors.forEach(r => {
      redirectTargets.forEach(t => {
        variants.push({
          url: r + encodeURIComponent(t),
          technique: 'Open redirect chain',
          category: 'Redirect bypass',
        })
      })
    })

    // ── Technique 6: URL parameter injection ───────────────────────────────────
    const baseHost = parsed?.hostname || 'target.com'
    const params = ['url', 'src', 'redirect', 'target', 'next', 'callback', 'fetch', 'load']
    const injTargets = ['http://169.254.169.254/', 'http://127.0.0.1/admin']
    params.forEach((p, i) => {
      variants.push({
        url: `https://${baseHost}/?${p}=${encodeURIComponent(injTargets[i % 2])}`,
        technique: `Parameter injection (?${p}=)`,
        category: 'Parameter injection',
      })
    })

    // ── Technique 7: DNS rebinding simulation ──────────────────────────────────
    variants.push(
      { url: 'http://localtest.me/', technique: 'DNS alias loopback', category: 'DNS bypass' },
      { url: 'http://127.0.0.1.nip.io/', technique: 'NIP.io loopback', category: 'DNS bypass' },
      { url: 'http://0.0.0.0/', technique: 'Unspecified address', category: 'DNS bypass' },
    )

    return variants.slice(0, 60)
  }

  // ── Run the model ───────────────────────────────────────────────────────────
  try {
    send({ type: 'status', message: '🤖 AI model analyzing target URL...' })
    await new Promise(r => setTimeout(r, 400))

    const variants = generateVariants(targetUrl)
    send({ type: 'status', message: `✓ Model generated ${variants.length} attack variants across 7 technique categories` })
    send({ type: 'total', total: variants.length })
    await new Promise(r => setTimeout(r, 300))
    send({ type: 'status', message: '⚡ Testing each variant through Guardian 7-stage pipeline...' })

    let blocked = 0, passed = 0

    for (let i = 0; i < variants.length; i++) {
      const v = variants[i]
      let result

      try {
        const r = await safeFetch(v.url, { dryRun: true })
        const isBlocked = !r.ok || r.blocked
        if (isBlocked) { blocked++; sessionLog.append({ ...r, url: v.url, source: 'pentest' }) }
        else passed++

        result = {
          type: 'result',
          index: i,
          total: variants.length,
          url: v.url,
          technique: v.technique,
          category: v.category,
          blocked: isBlocked,
          attackType: r.attackType || null,
          blockedAtStage: r.blockedAtStage || null,
          reason: r.reason || null,
        }
      } catch (err) {
        blocked++
        result = {
          type: 'result',
          index: i,
          total: variants.length,
          url: v.url,
          technique: v.technique,
          category: v.category,
          blocked: true,
          attackType: 'error',
          reason: err.message,
        }
      }

      send(result)
    }

    send({
      type: 'complete',
      total: variants.length,
      blocked,
      passed,
      message: passed === 0
        ? `✅ All ${variants.length} variants blocked — server is fully protected`
        : `⚠️ ${passed} variant(s) passed — review needed`,
    })

    res.end()
  } catch (err) {
    send({ type: 'error', message: err.message })
    res.end()
  }
})
// ── IP BLOCKING (managed by Guardian, not company server) ─────────────────────
app.post('/api/block-ip', async (req, res) => {
  const { ip, apiKey, action } = req.body
  if (!ip || !apiKey) return res.status(400).json({ error: 'ip and apiKey required' })

  try {
    // Forward to platform
    const r = await fetch('http://localhost:6060/api/dashboard/block-ip', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ ip, action, apiKey }),
    })
    const data = await r.json()
    res.json(data)
  } catch(e) {
    res.status(500).json({ error: e.message })
  }
})

// Check if IP is blocked — Guardian intercepts before request reaches company
app.get('/api/check-ip', async (req, res) => {
  const { ip, apiKey } = req.query
  try {
    const r = await fetch(`http://localhost:6060/api/sdk/check-ip?ip=${ip}`, {
      headers: { 'x-api-key': apiKey }
    })
    const data = await r.json()
    res.json(data)
  } catch {
    res.json({ blocked: false })
  }
})
app.listen(PORT, () => {
  console.log(`\n SSRF Guardian running on http://localhost:${PORT}`);
  console.log(` Events:   http://localhost:${PORT}/api/events`);
  console.log(` Health:   http://localhost:${PORT}/api/health\n`);
});
// F8: start proxy if enabled
if (process.env.GUARDIAN_PROXY === 'true') {
  const { startProxy } = await import('./proxy.js');
  startProxy();
}