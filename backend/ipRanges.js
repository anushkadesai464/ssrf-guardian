const BLOCKED = [
  ['127.0.0.0',   '127.255.255.255'], // loopback
  ['10.0.0.0',    '10.255.255.255'],  // private A
  ['172.16.0.0',  '172.31.255.255'],  // private B
  ['192.168.0.0', '192.168.255.255'], // private C
  ['169.254.0.0', '169.254.255.255'], // link-local / cloud metadata
  ['0.0.0.0',     '0.255.255.255'],   // unspecified
  ['224.0.0.0',   '239.255.255.255'], // multicast
  ['240.0.0.0',   '255.255.255.255'], // reserved
];

function toInt(ip) {
  return ip.split('.').reduce((acc, o) => (acc << 8) + parseInt(o, 10), 0) >>> 0;
}

export function isPrivateIP(ip) {
  if (!ip) return false;
  if (ip === '::1') return true;
  if (!/^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(ip)) return false;
  const n = toInt(ip);
  return BLOCKED.some(([s, e]) => n >= toInt(s) && n <= toInt(e));
}

export function getRangeLabel(ip) {
  if (!ip) return null;
  const n = toInt(ip);
  const labels = [
    ['127.0.0.0','127.255.255.255','loopback'],
    ['10.0.0.0','10.255.255.255','private class A'],
    ['172.16.0.0','172.31.255.255','private class B'],
    ['192.168.0.0','192.168.255.255','private class C'],
    ['169.254.0.0','169.254.255.255','link-local / cloud metadata'],
  ];
  const match = labels.find(([s,e]) => n >= toInt(s) && n <= toInt(e));
  return match ? match[2] : null;
}