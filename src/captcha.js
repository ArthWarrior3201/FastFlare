import crypto from 'node:crypto';
import { coarseIp, httpError } from './util.js';

const CHALLENGE_TTL = 120_000;
const TOKEN_TTL = 120_000;
const MAX_BITS = 23;
const STEPUP_BITS = 3;
const PASS_SCORE = 0.5;
const STEPUP_PASS_SCORE = 0.2;

function safeEqual(a, b) {
  const x = Buffer.from(String(a));
  const y = Buffer.from(String(b));
  return x.length === y.length && crypto.timingSafeEqual(x, y);
}

export function leadingZeroBits(digest) {
  let n = 0;
  for (const byte of digest) {
    if (byte === 0) {
      n += 8;
      continue;
    }
    n += Math.clz32(byte) - 24;
    break;
  }
  return n;
}

const num = (v, max = 1e6) => {
  v = Number(v);
  return Number.isFinite(v) ? Math.max(0, Math.min(max, v)) : 0;
};

// Scores browser-reported signals from 0 (bot) to 1 (human). Signals are client-supplied and
// can be forged, so they only ever *add friction* (harder proof-of-work, step-up, rejection of
// lazy automation). They are not a security boundary on their own.
export function scoreSignals(raw, ua = '') {
  const s = raw && typeof raw === 'object' ? raw : {};
  let score = 0.8;
  const reasons = [];
  const penalise = (amount, why) => {
    score -= amount;
    reasons.push(why);
  };

  if (s.wd) penalise(0.6, 'webdriver');
  if (/HeadlessChrome|PhantomJS|Selenium|puppeteer|playwright|slimerjs|electron/i.test(ua)) penalise(0.6, 'headless-ua');
  if (!ua || ua.length < 20) penalise(0.3, 'short-ua');
  if (!num(s.lg, 50)) penalise(0.15, 'no-languages');
  if (!num(s.sw) || !num(s.sh)) penalise(0.3, 'no-screen');

  const pm = num(s.pm);
  const interacted = pm >= 3 || num(s.kd) >= 1 || num(s.tc) >= 1 || num(s.sc) >= 1;
  if (interacted) score += 0.1;
  else penalise(0.25, 'no-interaction');
  if (pm >= 8 && num(s.pv, 1e5) < 0.5) penalise(0.25, 'linear-pointer');
  if (num(s.dt, 1e9) < 250) penalise(0.1, 'too-fast');

  score = Math.max(0, Math.min(1, score));
  return { score: Math.round(score * 100) / 100, reasons };
}

export function createCaptcha({ secret, sites, trustProxy = false, baseBits = 16, now = Date.now }) {
  const hmac = (s) => crypto.createHmac('sha256', secret).update(s).digest('base64url');
  const ipTag = (ip) => crypto.createHash('sha256').update(secret + coarseIp(ip)).digest('hex').slice(0, 16);

  const usedChallenges = new Map(); // id -> expiry
  const usedTokens = new Map();
  const rate = new Map(); // ipTag -> {n, reset}

  const sweep = setInterval(() => {
    const t = now();
    for (const m of [usedChallenges, usedTokens]) for (const [k, exp] of m) if (exp < t) m.delete(k);
    for (const [k, v] of rate) if (v.reset < t) rate.delete(k);
  }, 30_000);
  sweep.unref();

  function siteFor(sitekey) {
    return Object.prototype.hasOwnProperty.call(sites, sitekey) ? sites[sitekey] : null;
  }

  function siteBySecret(sec) {
    let found = null;
    for (const [key, site] of Object.entries(sites)) {
      if (safeEqual(site.secret || '', sec || '') && site.secret) found = key; // no early exit: constant-ish time
    }
    return found;
  }

  function checkOrigin(site, origin) {
    if (!site.origins || site.origins.length === 0) return;
    if (!origin || !site.origins.includes(origin)) throw httpError(403, 'origin_not_allowed');
  }

  function difficultyFor(tag) {
    const t = now();
    let r = rate.get(tag);
    if (!r || r.reset < t) r = { n: 0, reset: t + 60_000 };
    r.n++;
    rate.set(tag, r);
    if (r.n > 120) throw httpError(429, 'rate_limited');
    // +1 bit for every doubling of requests above 5 per minute.
    const extra = r.n > 5 ? Math.floor(Math.log2(r.n / 5)) + 1 : 0;
    return Math.min(MAX_BITS, baseBits + extra);
  }

  function makeChallenge({ sitekey, tag, bits, attempt }) {
    const id = crypto.randomBytes(12).toString('hex');
    const salt = crypto.randomBytes(8).toString('hex');
    const exp = now() + CHALLENGE_TTL;
    const sig = hmac(`c|${id}|${salt}|${bits}|${exp}|${sitekey}|${tag}|${attempt}`);
    return { id, salt, difficulty: bits, exp, attempt, sig };
  }

  function issue({ sitekey, ip, origin }) {
    const site = siteFor(sitekey);
    if (!site) throw httpError(400, 'invalid_sitekey');
    checkOrigin(site, origin);
    const tag = ipTag(ip);
    return { challenge: makeChallenge({ sitekey, tag, bits: difficultyFor(tag), attempt: 0 }) };
  }

  function verify({ sitekey, challenge: c, nonce, signals, hp, ip, ua, origin }) {
    const site = siteFor(sitekey);
    if (!site) throw httpError(400, 'invalid_sitekey');
    checkOrigin(site, origin);
    if (!c || typeof c !== 'object') throw httpError(400, 'missing_challenge');
    const tag = ipTag(ip);

    const expected = hmac(`c|${c.id}|${c.salt}|${c.difficulty}|${c.exp}|${sitekey}|${tag}|${c.attempt}`);
    if (!safeEqual(expected, c.sig)) throw httpError(400, 'bad_challenge');
    if (now() > c.exp) throw httpError(400, 'challenge_expired');
    if (usedChallenges.has(c.id)) throw httpError(400, 'challenge_used');

    const n = String(nonce ?? '');
    if (!/^\d{1,12}$/.test(n)) throw httpError(400, 'bad_nonce');
    const digest = crypto.createHash('sha256').update(`${c.id}.${c.salt}.${n}`).digest();
    if (leadingZeroBits(digest) < c.difficulty) throw httpError(400, 'bad_proof');

    usedChallenges.set(c.id, c.exp + 1000);

    if (hp) throw httpError(403, 'failed'); // honeypot field filled in: only bots do that

    // The browser reports how long it has been on the page. The server saw the challenge being
    // issued, so a client claiming a much longer dwell than the server observed is making it up.
    const observed = now() - (c.exp - CHALLENGE_TTL);
    const claimed = Number(signals && signals.dt);
    if (Number.isFinite(claimed) && claimed > observed + 4000) {
      const e = httpError(403, 'failed');
      e.reasons = ['inconsistent-timing'];
      throw e;
    }
    const { score, reasons } = scoreSignals(signals, ua);
    const needed = c.attempt >= 1 ? STEPUP_PASS_SCORE : PASS_SCORE;

    if (score >= needed) {
      const t = now();
      const payload = Buffer.from(JSON.stringify({ k: sitekey, i: c.id, t, e: t + TOKEN_TTL, s: score, h: tag })).toString('base64url');
      return { ok: true, token: `${payload}.${hmac('t|' + payload)}`, expires: t + TOKEN_TTL, score };
    }
    if (c.attempt === 0 && score >= STEPUP_PASS_SCORE) {
      const bits = Math.min(MAX_BITS, c.difficulty + STEPUP_BITS);
      return { ok: false, retry: true, challenge: makeChallenge({ sitekey, tag, bits, attempt: 1 }) };
    }
    const err = httpError(403, 'failed');
    err.reasons = reasons;
    throw err;
  }

  // Called by the integrator's backend (never from a browser).
  function siteverify({ secret: sec, token, remoteip }) {
    const fail = (code) => ({ success: false, 'error-codes': [code] });
    const sitekey = siteBySecret(sec);
    if (!sitekey) return fail('invalid-input-secret');
    if (typeof token !== 'string' || !token.includes('.')) return fail('invalid-input-response');
    const [payload, sig] = token.split('.');
    if (!safeEqual(hmac('t|' + payload), sig || '')) return fail('invalid-input-response');
    let p;
    try {
      p = JSON.parse(Buffer.from(payload, 'base64url').toString('utf8'));
    } catch {
      return fail('invalid-input-response');
    }
    if (p.k !== sitekey) return fail('invalid-input-response');
    if (now() > p.e) return fail('timeout-or-duplicate');
    if (usedTokens.has(p.i)) return fail('timeout-or-duplicate');
    if (remoteip && ipTag(String(remoteip)) !== p.h) return fail('remoteip-mismatch');
    usedTokens.set(p.i, p.e + 1000);
    return { success: true, challenge_ts: new Date(p.t).toISOString(), score: p.s };
  }

  return { issue, verify, siteverify, close: () => clearInterval(sweep) };
}
