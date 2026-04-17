import express from 'express';
import Groq from 'groq-sdk';
import { sessionLog } from './sessionLog.js';
import { safeFetch } from './guardian.js';
import { buildExplainPrompt, buildChatPrompt, buildMutatePrompt, buildDomainFuzzPrompt } from './prompts.js';

const router = express.Router();
const groq = new Groq({ apiKey: process.env.GROQ_API_KEY });

// ── helper: stream Groq response as SSE ───────────────────────────────────────
async function streamToSSE(res, prompt) {
  res.setHeader('Content-Type', 'text/event-stream');
  res.setHeader('Cache-Control', 'no-cache');
  res.setHeader('Access-Control-Allow-Origin', '*');

  try {
    const stream = await groq.chat.completions.create({
      model: 'llama-3.3-70b-versatile',
      messages: [{ role: 'user', content: prompt }],
      stream: true,
      max_tokens: 300,
    });

    for await (const chunk of stream) {
      const text = chunk.choices[0]?.delta?.content || '';
      if (text) res.write(`data: ${JSON.stringify({ text })}\n\n`);
    }

    res.write('data: [DONE]\n\n');
    res.end();
  } catch (err) {
    console.error('[ai] error:', err.message);
    res.write(`data: ${JSON.stringify({ text: `Error: ${err.message}` })}\n\n`);
    res.write('data: [DONE]\n\n');
    res.end();
  }
}

// ── F4: AI Explainer ──────────────────────────────────────────────────────────
router.post('/explain', async (req, res) => {
  const { url, attackType, reason, pipelineTrace, redirectChain } = req.body;
  if (!url) return res.status(400).json({ error: 'url required' });

  const prompt = buildExplainPrompt(
    url, attackType, reason,
    pipelineTrace || [], redirectChain || []
  );
  await streamToSSE(res, prompt);
});

// ── F6: Chat Analyst ──────────────────────────────────────────────────────────
router.post('/chat', async (req, res) => {
  const { question } = req.body;
  if (!question) return res.status(400).json({ error: 'question required' });

  const log = sessionLog.getAll();
  const prompt = buildChatPrompt(log, question);
  await streamToSSE(res, prompt);
});

// ── F7: Mutation Engine ───────────────────────────────────────────────────────
router.post('/mutate', async (req, res) => {
  const { seedUrl, allowlist = [] } = req.body;
  if (!seedUrl) return res.status(400).json({ error: 'seedUrl required' });

  res.setHeader('Content-Type', 'text/event-stream');
  res.setHeader('Cache-Control', 'no-cache');
  res.setHeader('Access-Control-Allow-Origin', '*');

  const send = (data) => res.write(`data: ${JSON.stringify(data)}\n\n`);

  try {
    send({ type: 'status', message: 'Asking Groq to generate bypass variants...' });

    // Use non-streaming for mutation — we need the full JSON array at once
    const completion = await groq.chat.completions.create({
      model: 'llama-3.3-70b-versatile',
      messages: [{ role: 'user', content: buildMutatePrompt(seedUrl) }],
      stream: false,
      max_tokens: 2000,
    });

    const raw = completion.choices[0]?.message?.content?.trim()
      .replace(/^```json\s*/i, '').replace(/^```\s*/i, '').replace(/\s*```$/, '');

    let variants;
    try {
      variants = JSON.parse(raw);
    } catch {
      send({ type: 'error', message: 'Failed to parse variants — Groq returned invalid JSON' });
      return res.end();
    }

    send({ type: 'status', message: `Generated ${variants.length} variants — testing each...` });

    let blocked = 0, passed = 0;

    for (let i = 0; i < variants.length; i++) {
      const variantUrl = variants[i];
      let r;
      try {
        r = await safeFetch(variantUrl, { allowlist, dryRun: true });
      } catch (err) {
        r = { ok: false, blocked: true, attackType: 'error', reason: err.message };
      }

      const isBlocked = !r.ok || r.blocked;
      isBlocked ? blocked++ : passed++;

      sessionLog.append({ ...r, url: variantUrl, source: 'mutation' });

      send({
        type: 'result',
        index: i,
        total: variants.length,
        url: variantUrl,
        blocked: isBlocked,
        attackType: r.attackType || null,
        reason: r.reason || null,
        blockedAtStage: r.blockedAtStage || null,
      });
    }

    send({
      type: 'complete',
      total: variants.length,
      blocked,
      passed,
      message: `${blocked}/${variants.length} blocked · ${passed} passed`,
    });

    res.end();
  } catch (err) {
    console.error('[mutate]', err.message);
    send({ type: 'error', message: err.message });
    res.end();
  }
});
// ── Domain SSRF Fuzzer — tests real domains for SSRF parameters ───────────────
router.post('/fuzz', async (req, res) => {
  const { domain, allowlist = [] } = req.body;
  if (!domain) return res.status(400).json({ error: 'domain required' });

  res.setHeader('Content-Type', 'text/event-stream');
  res.setHeader('Cache-Control', 'no-cache');
  res.setHeader('Access-Control-Allow-Origin', '*');

  const send = (data) => res.write(`data: ${JSON.stringify(data)}\n\n`);

  try {
    send({ type: 'status', message: `Generating SSRF test URLs for ${domain}...` });

    const completion = await groq.chat.completions.create({
      model: 'llama-3.3-70b-versatile',
      messages: [{ role: 'user', content: buildDomainFuzzPrompt(domain) }],
      stream: false,
      max_tokens: 2000,
    });

    const raw = completion.choices[0]?.message?.content?.trim()
      .replace(/^```json\s*/i, '').replace(/^```\s*/i, '').replace(/\s*```$/, '');

    let urls;
    try {
      urls = JSON.parse(raw);
    } catch {
      send({ type: 'error', message: 'Failed to parse URLs from AI' });
      return res.end();
    }

    send({ type: 'status', message: `Generated ${urls.length} test URLs — probing ${domain}...` });

    let vulnerable = 0;
    let safe = 0;
    let errors = 0;

    for (let i = 0; i < urls.length; i++) {
      const testUrl = urls[i];
      let result;

      try {
        // Try to actually fetch the URL (with a short timeout)
        const response = await fetch(testUrl, {
          signal: AbortSignal.timeout(3000),
          redirect: 'manual',
          headers: { 'User-Agent': 'SecurityScanner/1.0 (Authorized Testing)' },
        });

        const isRedirect = response.status >= 300 && response.status < 400;
        const location = response.headers.get('location') || '';
        const isSSRFRedirect = isRedirect && (
          location.includes('169.254') ||
          location.includes('127.0.0') ||
          location.includes('10.0.0') ||
          location.includes('192.168')
        );

        if (isSSRFRedirect) {
          vulnerable++;
          result = {
            type: 'result', index: i, total: urls.length,
            url: testUrl, status: response.status,
            vulnerable: true,
            reason: `SSRF redirect detected → ${location}`,
            severity: 'CRITICAL',
          };
        } else {
          safe++;
          result = {
            type: 'result', index: i, total: urls.length,
            url: testUrl, status: response.status,
            vulnerable: false,
            reason: `${response.status} — no SSRF redirect`,
          };
        }
      } catch (err) {
        errors++;
        result = {
          type: 'result', index: i, total: urls.length,
          url: testUrl, status: 0,
          vulnerable: false,
          reason: err.name === 'TimeoutError' ? 'Timeout' : `Error: ${err.message}`,
          error: true,
        };
      }

      send(result);
    }

    send({
      type: 'complete',
      total: urls.length,
      vulnerable,
      safe,
      errors,
      message: vulnerable > 0
        ? `CRITICAL: ${vulnerable} potential SSRF vulnerabilities found on ${domain}`
        : `${safe} endpoints tested — no SSRF redirects detected on ${domain}`,
    });

    res.end();
  } catch (err) {
    console.error('[fuzz]', err.message);
    send({ type: 'error', message: err.message });
    res.end();
  }
});
export default router;