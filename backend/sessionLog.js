const log = [];

export const sessionLog = {
  append(result) {
    const entry = {
      id: log.length + 1,
      timestamp: new Date().toISOString(),
      url: result.url,
      blocked: !result.ok,
      attackType: result.attackType || null,
      blockedAtStage: result.blockedAtStage || null,
      reason: result.reason || null,
      redirectChain: result.redirectChain || [],
      resolvedIPs: result.resolvedIPs || [],
      source: result.source || 'manual',
    };
    log.push(entry);
    return entry;
  },
  getAll()     { return [...log]; },
  getBlocked() { return log.filter(e => e.blocked); },
  getSummary() {
    const blocked = log.filter(e => e.blocked);
    const byType = {};
    blocked.forEach(e => { byType[e.attackType] = (byType[e.attackType] || 0) + 1; });
    return { total: log.length, blocked: blocked.length,
             allowed: log.length - blocked.length, byAttackType: byType };
  },
  clear() { log.length = 0; },
};