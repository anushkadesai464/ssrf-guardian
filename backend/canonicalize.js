export function canonicalizeIP(raw) {
  if (!raw || typeof raw !== 'string') return raw;
  const trimmed = raw.trim().toLowerCase().replace(/^\[|\]$/g, '');

  // IPv4-mapped IPv6: ::ffff:x.x.x.x
  const ipv4mapped = trimmed.match(/^::ffff:(\d+\.\d+\.\d+\.\d+)$/i);
  if (ipv4mapped) return ipv4mapped[1];

  // IPv6 loopback
  if (trimmed === '::1' || trimmed === 'localhost') return '127.0.0.1';

  // Pure decimal integer: 2130706433 → 127.0.0.1
  if (/^\d+$/.test(trimmed)) {
    const num = parseInt(trimmed, 10);
    if (num >= 0 && num <= 4294967295) {
      return [(num>>>24)&255,(num>>>16)&255,(num>>>8)&255,num&255].join('.');
    }
  }

  // Dotted notation — octal, hex, or decimal octets
  const parts = trimmed.split('.');
  if (parts.length >= 2 && parts.length <= 4) {
    const converted = parts.map(p => {
      if (p.startsWith('0x')) return parseInt(p, 16);
      if (p.startsWith('0') && p.length > 1) return parseInt(p, 8);
      return parseInt(p, 10);
    });
    if (converted.every(n => !isNaN(n) && n >= 0 && n <= 255)) {
      while (converted.length < 4) converted.splice(converted.length - 1, 0, 0);
      return converted.join('.');
    }
  }

  return raw;
}

export function detectObfuscationType(raw) {
  const t = (raw || '').trim().toLowerCase().replace(/^\[|\]$/g, '');
  if (/^\d+$/.test(t) && parseInt(t) > 255) return 'decimal_integer';
  if (/^::ffff:/i.test(t)) return 'ipv4_mapped_ipv6';
  if (t === '::1' || t === 'localhost') return 'loopback_alias';
  if (t.includes('.') && /(?:^|\.)0[0-7]+/.test(t)) return 'octal_octet';
  if (/0x[0-9a-f]/i.test(t)) return 'hex_octet';
  if (/^\d+\.\d+$/.test(t)) return 'short_form_ip';
  return null;
}