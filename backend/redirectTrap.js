import http from 'http';

const FAKE_CREDS = JSON.stringify({
  Code: 'Success',
  Type: 'AWS-HMAC',
  AccessKeyId: 'AKIAIOSFODNN7EXAMPLE',
  SecretAccessKey: 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY',
  Token: 'AQoDYXdzEJr//////////wEaoAK1wvxJY12r2IQA++EXAMPLETOKEN++',
  Expiration: new Date(Date.now() + 6 * 3600 * 1000).toISOString(),
  RoleArn: 'arn:aws:iam::123456789012:role/prod-ec2-admin-role',
  _warning: 'SIMULATED CREDENTIALS — DEMO ONLY'
}, null, 2);

const METADATA = {
  '/latest/meta-data/':
    'ami-id\nhostname\niam\ninstance-id\nlocal-ipv4\npublic-ipv4\n',
  '/latest/meta-data/iam/':
    'info\nsecurity-credentials/\n',
  '/latest/meta-data/iam/security-credentials/':
    'prod-ec2-admin-role\n',
  '/latest/meta-data/iam/security-credentials/prod-ec2-admin-role':
    FAKE_CREDS,
  '/latest/meta-data/instance-id': 'i-0a1b2c3d4e5f67890',
  '/latest/meta-data/local-ipv4':  '10.0.1.42',
  '/latest/user-data':
    '#!/bin/bash\nexport DB_PASSWORD=supersecret_prod_2024\nexport GITHUB_TOKEN=ghp_DEMO_TOKEN_ONLY',
};

const server = http.createServer((req, res) => {
  const url = new URL(req.url, 'http://localhost:3001');
  console.log(`[trap] ${req.method} ${req.url}`);

  // Open redirect — simulates a vulnerable partner domain
  if (url.pathname === '/redirect') {
    const target = url.searchParams.get('to')
                || url.searchParams.get('url')
                || url.searchParams.get('next');
    if (target) {
      console.log(`[trap] 302 → ${target}`);
      res.writeHead(302, { Location: target });
      return res.end();
    }
  }

  // Fake metadata responses
  if (METADATA[url.pathname]) {
    const isJson = url.pathname.includes('prod-ec2-admin-role');
    res.writeHead(200, {
      'Content-Type': isJson ? 'application/json' : 'text/plain',
      'X-Demo': 'SIMULATED',
    });
    return res.end(METADATA[url.pathname]);
  }

  res.writeHead(404);
  res.end('Not found');
});

export function startTrap(port = 3001) {
  server.listen(port, () => {
    console.log(`[trap] Mock server on http://localhost:${port}`);
    console.log(`[trap] Open redirect: http://localhost:${port}/redirect?to=<URL>`);
    console.log(`[trap] Fake creds:    http://localhost:${port}/latest/meta-data/iam/security-credentials/prod-ec2-admin-role`);
  });
}

export default server;