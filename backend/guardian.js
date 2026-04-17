import dns from 'dns';
import http from 'http';
import https from 'https';
import { canonicalizeIP, detectObfuscationType } from './canonicalize.js';
import { isPrivateIP, getRangeLabel } from './ipRanges.js';

const ALLOWED_SCHEMES = ['http:', 'https:'];
const MAX_REDIRECTS = 5;
const MAX_BYTES = 1024 * 1024; // 1MB
const TIMEOUT_MS = 8000;

// ── helpers ───────────────────────────────────────────────────────────────────

function blocked(trace, attackType, reason, extra = {}) {
  return { ok: false, blocked: true, attackType, reason,
           blockedAtStage: trace.length + 1, pipelineTrace: trace, ...extra };
}

function pass(trace, stage, detail = '') {
  trace.push({ stage, pass: true, detail });
}

function fail(trace, stage, detail = '') {
  trace.push({ stage, pass: false, detail });
}

async function resolveDNS(hostname) {
  // Windows often fails to resolve 'localhost' via dns.resolve4
  // Map it directly — it's loopback either way
  if (hostname === 'localhost') return ['127.0.0.1'];

  return new Promise((resolve, reject) => {
    dns.resolve4(hostname, (err, addrs) => {
      if (err) {
        dns.resolve6(hostname, (e6, a6) => {
          if (e6) reject(new Error(`DNS failed for ${hostname}: ${err.message}`));
          else resolve(a6 || []);
        });
      } else resolve(addrs || []);
    });
  });
}

// ── main safeFetch ────────────────────────────────────────────────────────────

export async function safeFetch(url, opts = {}) {
  const trace = [];
  const redirectChain = [];
  const resolvedIPs = [];
  const allowlist = opts.allowlist ?? [];
  return _validate(url, trace, redirectChain, resolvedIPs, allowlist, opts.dryRun ?? false, 0);
}

async function _validate(url, trace, redirectChain, resolvedIPs, allowlist, dryRun, hop) {

  if (hop > MAX_REDIRECTS)
    return blocked(trace, 'too_many_redirects', `Exceeded ${MAX_REDIRECTS} redirect hops`,
                   { redirectChain, resolvedIPs, url });

  // ── STAGE 1: scheme ───────────────────────────────────────────────────────
  let parsed;
  try { parsed = new URL(url); }
  catch {
    fail(trace, 1, 'Invalid URL');
    return blocked(trace, 'invalid_url', 'URL could not be parsed',
                   { redirectChain, resolvedIPs, url });
  }

  if (!ALLOWED_SCHEMES.includes(parsed.protocol)) {
    fail(trace, 1, `Scheme "${parsed.protocol}" not allowed`);
    return blocked(trace, 'protocol_switch',
                   `Scheme "${parsed.protocol}" blocked — only http/https allowed`,
                   { redirectChain, resolvedIPs, url });
  }
  pass(trace, 1, `${parsed.protocol} allowed`);

  // ── STAGE 2: DNS resolution + pin ─────────────────────────────────────────
  const hostname = parsed.hostname.replace(/^\[|\]$/g, '');
  let ips;

  if (/^[\d.:a-fA-F]+$/.test(hostname)) {
    ips = [hostname]; // already an IP literal — skip DNS
    pass(trace, 2, `IP literal ${hostname} — DNS skipped`);
  } else {
    try {
      ips = await resolveDNS(hostname);
      pass(trace, 2, `${hostname} → [${ips.join(', ')}] pinned`);
    } catch (err) {
      fail(trace, 2, err.message);
      return blocked(trace, 'dns_failure', `DNS failed: ${err.message}`,
                     { redirectChain, resolvedIPs, url });
    }
  }

  if (!ips.length) {
    fail(trace, 2, 'No IPs returned');
    return blocked(trace, 'dns_failure', 'DNS returned no addresses',
                   { redirectChain, resolvedIPs, url });
  }
  resolvedIPs.push(...ips);

  // ── STAGE 3: IP canonicalize + blocklist ──────────────────────────────────
  // Use raw hostname for obfuscation detection BEFORE browser normalization
  const rawHost = url.replace(/^https?:\/\//i,'').split('/')[0].split('?')[0].split('#')[0];
  const obfType = detectObfuscationType(rawHost);
  const canonical = canonicalizeIP(rawHost) || canonicalizeIP(ips[0]);

  if (obfType) {
    fail(trace, 3, `Obfuscated IP: "${rawHost}" (${obfType}) → ${canonical}`);
    return blocked(trace, obfType,
                   `IP obfuscation detected: "${rawHost}" (${obfType}) → "${canonical}"`,
                   { redirectChain, resolvedIPs, url, canonicalIP: canonical });
  }

  for (const ip of ips) {
    const c = canonicalizeIP(ip);
    if (isPrivateIP(c)) {
      const label = getRangeLabel(c);
      fail(trace, 3, `${c} is in ${label || 'private range'}`);
      return blocked(trace, 'private_ip',
                     `${c} is blocked — ${label || 'private/reserved range'}`,
                     { redirectChain, resolvedIPs, url, canonicalIP: c });
    }
  }
  pass(trace, 3, `All IPs public: [${ips.join(', ')}]`);

  // ── STAGE 4: allowlist ────────────────────────────────────────────────────
  if (allowlist.length > 0) {
    const ok = allowlist.some(p =>
      p.startsWith('*.') ? hostname.endsWith(p.slice(1)) : hostname === p
    );
    if (!ok) {
      fail(trace, 4, `"${hostname}" not in allowlist`);
      return blocked(trace, 'allowlist_violation',
                     `"${hostname}" is not in the permitted allowlist`,
                     { redirectChain, resolvedIPs, url });
    }
    pass(trace, 4, `"${hostname}" matches allowlist`);
  } else {
    pass(trace, 4, 'No allowlist — open mode');
  }

  redirectChain.push({ hop, url, resolvedIPs: [...ips], status: 'pending' });

  if (dryRun) {
    pass(trace, 5, 'Dry run — skipping fetch');
    pass(trace, 6, 'Dry run — skipping socket check');
    pass(trace, 7, 'Dry run — skipping response check');
    redirectChain[redirectChain.length - 1].status = 'validated';
    return { ok: true, blocked: false, pipelineTrace: trace, redirectChain, resolvedIPs, url };
  }

  // ── STAGE 5: fetch with manual redirect handling ──────────────────────────
  let fetchResult;
  try {
    fetchResult = await _fetchWithSocketCheck(url, ips[0], trace);
  } catch (err) {
    fail(trace, 5, err.message);
    return blocked(trace, 'fetch_error', err.message, { redirectChain, resolvedIPs, url });
  }

  if (!fetchResult.ok) return { ...fetchResult, redirectChain, resolvedIPs, url };

  const { statusCode, headers, body } = fetchResult;
  redirectChain[redirectChain.length - 1].status = statusCode;

  // Redirect detected — re-run ENTIRE pipeline on the new URL (kills open-redirect chains)
  if (statusCode >= 300 && statusCode < 400 && headers.location) {
    pass(trace, 5, `${statusCode} → "${headers.location}" — re-validating hop ${hop + 1}`);
    return _validate(headers.location, trace, redirectChain, resolvedIPs,
                     allowlist, dryRun, hop + 1);
  }
  pass(trace, 5, `${statusCode} — no redirect`);

  // ── STAGE 7: response size cap ────────────────────────────────────────────
  if (body && body.length > MAX_BYTES) {
    fail(trace, 7, `Response ${body.length} bytes > ${MAX_BYTES} cap`);
    return blocked(trace, 'response_too_large', 'Response exceeds 1MB cap',
                   { redirectChain, resolvedIPs, url });
  }
  pass(trace, 7, `Response ${body?.length ?? 0} bytes — OK`);

  return { ok: true, blocked: false, statusCode, body,
           pipelineTrace: trace, redirectChain, resolvedIPs, url };
}

function _fetchWithSocketCheck(url, pinnedIP, trace) {
  return new Promise((resolve, reject) => {
    const parsed = new URL(url);
    const lib = parsed.protocol === 'https:' ? https : http;
    const port = parseInt(parsed.port) || (parsed.protocol === 'https:' ? 443 : 80);

    const req = lib.request({
      hostname: parsed.hostname, port,
      path: parsed.pathname + parsed.search,
      method: 'GET',
      timeout: TIMEOUT_MS,
      headers: { 'User-Agent': 'SSRF-Guardian/1.0' },
    }, (res) => {

      // ── STAGE 6: post-connect socket IP verify (DNS rebind defense) ────────
      const socketIP = res.socket?.remoteAddress?.replace(/^::ffff:/, '');
      const canonSocket = socketIP ? canonicalizeIP(socketIP) : null;
      const canonPinned = canonicalizeIP(pinnedIP);

      if (canonSocket && canonSocket !== canonPinned) {
        fail(trace, 6, `Rebind! Pinned:${canonPinned} Socket:${canonSocket}`);
        req.destroy();
        resolve({ ok: false, attackType: 'dns_rebinding',
          reason: `DNS rebind detected. Pinned ${canonPinned} ≠ socket ${canonSocket}`,
          blockedAtStage: 6, pipelineTrace: trace });
        return;
      }
      pass(trace, 6, `Socket IP ${canonSocket} matches pinned ${canonPinned}`);

      let body = '';
      let size = 0;
      res.on('data', chunk => { size += chunk.length; if (size <= MAX_BYTES) body += chunk; });
      res.on('end', () => resolve({ ok: true, statusCode: res.statusCode, headers: res.headers, body }));
    });

    req.on('timeout', () => { req.destroy(); reject(new Error(`Timeout after ${TIMEOUT_MS}ms`)); });
    req.on('error', err => {
      if (err.code === 'ECONNREFUSED') resolve({ ok: true, statusCode: 0, headers: {}, body: '' });
      else reject(err);
    });
    req.end();
  });
}

// ── preflightAnalyze — runs stages 1-4 client-side, no network ───────────────

export function preflightAnalyze(url, allowlist = []) {
  const stages = [
    { stage:1, name:'Scheme check',       pass:null, detail:'' },
    { stage:2, name:'DNS format',         pass:null, detail:'' },
    { stage:3, name:'IP canonicalize',    pass:null, detail:'' },
    { stage:4, name:'Allowlist',          pass:null, detail:'' },
    { stage:5, name:'Redirect intercept', pass:null, detail:'runtime only' },
    { stage:6, name:'Post-connect verify',pass:null, detail:'runtime only' },
    { stage:7, name:'Response cap',       pass:null, detail:'runtime only' },
  ];

  if (!url) return { stages, prediction: null };

  let parsed;
  try { parsed = new URL(url); }
  catch {
    stages[0].pass = false; stages[0].detail = 'Invalid URL';
    return { stages, prediction:'BLOCKED', attackType:'invalid_url', blockedAtStage:1 };
  }

  // Stage 1
  if (!ALLOWED_SCHEMES.includes(parsed.protocol)) {
    stages[0].pass = false; stages[0].detail = `"${parsed.protocol}" not allowed`;
    return { stages, prediction:'BLOCKED', attackType:'protocol_switch', blockedAtStage:1 };
  }
  stages[0].pass = true; stages[0].detail = `${parsed.protocol} ✓`;

  // Stage 2
  const hostname = parsed.hostname.replace(/^\[|\]$/g, '');
  stages[1].pass = true; stages[1].detail = hostname;

  // Stage 3 — detect on RAW input before browser normalizes it
  const rawHost = url.replace(/^https?:\/\//i,'').split('/')[0].split('?')[0];
  const obfType = detectObfuscationType(rawHost);
  const canonical = canonicalizeIP(rawHost) || canonicalizeIP(hostname);

  if (obfType) {
    stages[2].pass = false; stages[2].detail = `${obfType}: "${rawHost}" → ${canonical}`;
    return { stages, prediction:'BLOCKED', attackType:obfType, blockedAtStage:3 };
  }
  if (isPrivateIP(canonical)) {
    stages[2].pass = false; stages[2].detail = `${canonical} is private`;
    return { stages, prediction:'BLOCKED', attackType:'private_ip', blockedAtStage:3 };
  }
  stages[2].pass = true; stages[2].detail = `${rawHost} → public ✓`;

  // Stage 4
  if (allowlist.length > 0) {
    const ok = allowlist.some(p =>
      p.startsWith('*.') ? hostname.endsWith(p.slice(1)) : hostname === p
    );
    stages[3].pass = ok;
    stages[3].detail = ok ? 'Matches allowlist ✓' : `"${hostname}" not in allowlist`;
    if (!ok) return { stages, prediction:'BLOCKED', attackType:'allowlist_violation', blockedAtStage:4 };
  } else {
    stages[3].pass = true; stages[3].detail = 'Open mode ✓';
  }
  // Stage 3b — scan URL parameters for embedded SSRF targets
  // e.g. https://vvce.ac.in/fetch?url=http://169.254.169.254/
  const suspiciousParams = ['url','to','src','target','redirect',
    'link','callback','next','return','feed','proxy','image',
    'page','file','export','import','webhook','load','fetch']

  for (const [key, value] of parsed.searchParams.entries()) {
    if (!suspiciousParams.includes(key.toLowerCase())) continue
    if (!value.startsWith('http://') && !value.startsWith('https://')) continue

    // Run the same checks on the embedded URL value
    const embeddedRaw = value.replace(/^https?:\/\//i,'').split('/')[0].split('?')[0]
    const embeddedObf = detectObfuscationType(embeddedRaw)
    const embeddedCanonical = canonicalizeIP(embeddedRaw) || embeddedRaw

    if (embeddedObf) {
      stages[2].pass = false
      stages[2].detail = `Param "${key}" contains obfuscated IP: ${embeddedRaw}`
      return { stages, prediction:'BLOCKED', attackType: embeddedObf,
               blockedAtStage:3, embeddedParam: key, embeddedValue: value }
    }
    if (isPrivateIP(embeddedCanonical)) {
      stages[2].pass = false
      stages[2].detail = `Param "${key}" contains private IP: ${embeddedCanonical}`
      return { stages, prediction:'BLOCKED', attackType:'ssrf_parameter',
               blockedAtStage:3, embeddedParam: key, embeddedValue: value }
    }
  }
  return { stages, prediction:'LIKELY_SAFE', attackType:null, blockedAtStage:null };
}