export function buildExplainPrompt(url, attackType, reason, trace, chain) {
  return `You are a senior security engineer explaining an SSRF attack to a developer.

A URL was blocked. Here are the details:
URL: ${url}
Attack type: ${attackType}
Reason: ${reason}
Pipeline trace: ${JSON.stringify(trace)}
Redirect chain: ${JSON.stringify(chain)}

Write exactly 3 short paragraphs:
1. What the attacker was trying to do (be specific about the technique)
2. What internal data would have been exposed if it succeeded
3. The exact Node.js fix using safeFetch() — show before/after code

Be specific. Reference the actual URL and technique. Keep each paragraph to 2-3 sentences.`;
}

export function buildChatPrompt(sessionLog, question) {
  // Only send last 10 entries to stay within token limits
  const recentLog = sessionLog.slice(-10);
  const summary = {
    total: sessionLog.length,
    blocked: sessionLog.filter(e => e.blocked).length,
    types: [...new Set(sessionLog.filter(e => e.attackType).map(e => e.attackType))],
  };
  return `You are a security analyst. Answer questions about this attack session.

SESSION SUMMARY: ${JSON.stringify(summary)}
RECENT ATTACKS (last ${recentLog.length}): ${JSON.stringify(recentLog.map(e => ({
    url: e.url,
    blocked: e.blocked,
    attackType: e.attackType,
    reason: e.reason,
    blockedAtStage: e.blockedAtStage,
    source: e.source,
  })))}

QUESTION: ${question}

Answer in 2-3 sentences. Be specific — reference attack types and URLs from the log above.`;
}

export function buildMutatePrompt(seedUrl) {
  return `You are a security researcher. Generate exactly 50 SSRF bypass variants of this URL: ${seedUrl}

Include these techniques:
- Decimal integer IP (e.g. http://2130706433/)
- Octal octets (e.g. http://0177.0.0.1/)
- Hex octets (e.g. http://0x7f.0x0.0x0.0x1/)
- IPv6 loopback (http://[::1]/)
- IPv4-mapped IPv6 (http://[::ffff:127.0.0.1]/)
- Short-form IP (http://127.1/)
- gopher:// scheme
- file:// scheme
- URL-encoded dots (127%2e0%2e0%2e1)
- user@host confusion (http://attacker.com@169.254.169.254/)
- Open redirect prefixes using http://127.0.0.1:3001/redirect?to=
- Cloud metadata variants (169.254.169.254 paths)

Return ONLY a valid JSON array of URL strings. No explanation. No markdown. Just the raw JSON array.`;
}

export function buildDomainFuzzPrompt(domain) {
  return `You are a security researcher doing authorized SSRF testing on ${domain}.

Generate 40 URLs that test for SSRF vulnerabilities on this domain. Include:

1. Common SSRF-vulnerable parameters with internal targets:
   - ${domain}/fetch?url=http://169.254.169.254/
   - ${domain}/proxy?target=http://127.0.0.1/
   - ${domain}/load?src=http://10.0.0.1/
   - ${domain}/import?link=http://192.168.1.1/
   - ${domain}/preview?page=http://169.254.169.254/
   - ${domain}/redirect?to=http://127.0.0.1/
   - ${domain}/image?src=http://169.254.169.254/
   - ${domain}/webhook?callback=http://10.0.0.1/
   - ${domain}/rss?feed=http://127.0.0.1/
   - ${domain}/export?file=http://169.254.169.254/

2. Common admin/internal paths to probe:
   - ${domain}/admin
   - ${domain}/internal
   - ${domain}/api/internal
   - ${domain}/dashboard
   - ${domain}/.env
   - ${domain}/config
   - ${domain}/actuator
   - ${domain}/api/v1/admin

3. Subdomain variants that might have vulnerable services:
   - http://api.${domain.replace('https://','').replace('http://','').replace(/\/.*/,'')}
   - http://admin.${domain.replace('https://','').replace('http://','').replace(/\/.*/,'')}
   - http://internal.${domain.replace('https://','').replace('http://','').replace(/\/.*/,'')}
   - http://dev.${domain.replace('https://','').replace('http://','').replace(/\/.*/,'')}
   - http://staging.${domain.replace('https://','').replace('http://','').replace(/\/.*/,'')}

4. Open redirect tests:
   - ${domain}/?redirect=http://169.254.169.254/
   - ${domain}/?next=http://127.0.0.1/
   - ${domain}/?return=http://10.0.0.1/
   - ${domain}/?url=http://169.254.169.254/
   - ${domain}/?continue=http://127.0.0.1/

Return ONLY a valid JSON array of URL strings. No explanation. No markdown. Just the raw JSON array.`;
}