import http from 'http';
import net from 'net';
import { safeFetch } from './guardian.js';
import { sessionLog } from './sessionLog.js';
import { emit } from './sseEmitter.js';

const PROXY_PORT = 8080;

const server = http.createServer(async (req, res) => {
  const targetUrl = req.url;

  if (!targetUrl || !targetUrl.startsWith('http')) {
    res.writeHead(400);
    return res.end('Guardian Proxy: absolute URLs only');
  }

  console.log(`[proxy] Intercepted: ${req.method} ${targetUrl}`);

  const validation = await safeFetch(targetUrl, {
    allowlist: process.env.GUARDIAN_ALLOWLIST?.split(',').map(s => s.trim()) ?? [],
    dryRun: true,
  });

  if (!validation.ok || validation.blocked) {
    const entry = sessionLog.append({ ...validation, url: targetUrl, source: 'proxy' });
    emit('attack', { ...entry, source: 'proxy' });

    console.log(`[proxy] BLOCKED: ${targetUrl} — ${validation.reason}`);

    res.writeHead(403, { 'Content-Type': 'application/json' });
    return res.end(JSON.stringify({
      blocked: true,
      attackType: validation.attackType,
      reason: validation.reason,
      blockedAtStage: validation.blockedAtStage,
    }, null, 2));
  }

  // Safe — forward to actual target
  console.log(`[proxy] ALLOWED: ${targetUrl}`);
  const parsed = new URL(targetUrl);

  const proxyReq = http.request({
    hostname: parsed.hostname,
    port: parsed.port || 80,
    path: parsed.pathname + parsed.search,
    method: req.method,
    headers: { ...req.headers, host: parsed.host },
  }, (proxyRes) => {
    res.writeHead(proxyRes.statusCode, proxyRes.headers);
    proxyRes.pipe(res);
  });

  proxyReq.on('error', (err) => {
    res.writeHead(502);
    res.end(`Proxy error: ${err.message}`);
  });

  req.pipe(proxyReq);
});

// Handle HTTPS CONNECT tunneling
server.on('connect', async (req, clientSocket, head) => {
  const [hostname, port] = req.url.split(':');
  const targetUrl = `https://${hostname}:${port || 443}/`;

  const validation = await safeFetch(targetUrl, {
    allowlist: process.env.GUARDIAN_ALLOWLIST?.split(',').map(s => s.trim()) ?? [],
    dryRun: true,
  });

  if (!validation.ok || validation.blocked) {
    const entry = sessionLog.append({ ...validation, url: targetUrl, source: 'proxy' });
    emit('attack', { ...entry, source: 'proxy' });
    console.log(`[proxy] BLOCKED CONNECT: ${targetUrl}`);
    clientSocket.write('HTTP/1.1 403 Forbidden\r\n\r\n');
    clientSocket.destroy();
    return;
  }

  const serverSocket = net.connect(port || 443, hostname, () => {
    clientSocket.write('HTTP/1.1 200 Connection Established\r\n\r\n');
    serverSocket.write(head);
    serverSocket.pipe(clientSocket);
    clientSocket.pipe(serverSocket);
  });

  serverSocket.on('error', () => {
    clientSocket.write('HTTP/1.1 502 Bad Gateway\r\n\r\n');
    clientSocket.destroy();
  });
});

export function startProxy() {
  server.listen(PROXY_PORT, () => {
    console.log(`[proxy] Guardian proxy on port ${PROXY_PORT}`);
    console.log(`[proxy] Activate any app: set HTTP_PROXY=http://localhost:${PROXY_PORT}`);
  });
}

export default server;