import crypto from 'node:crypto';
import { coarseIp, httpError } from './util.js';
import { makePuzzle } from './puzzle.js';

const CHALLENGE_TTL = 120_000;
const TOKEN_TTL = 120_000;
const PUZZLE_TTL = 120_000;
const WINDOW_MS = 10 * 60_000;
const MAX_BITS = 23;
const PASS_SCORE = 0.5;
const TOLERANCE = 5; // pixels: easy to hit by eye, about a 4% chance for a blind guess
const PUZZLE_TRIES = 2; // puzzles per verification before giving up
const MAX_FAILS = 3; // failed puzzles per network per window before it is locked out

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

// Per-network key for quotas: full IPv4 address, or the /64 for IPv6.
const netKey = (ip) => (ip.includes(':') ? ip.split(':').slice(0, 4).join(':') : ip);

/**
 * Browser-reported environment. `hard` reasons are automation tells that block outright; the rest
 * lower the score. Client-supplied, so only ever used to add friction.
 */
export function scoreSignals(raw, ua = '') {
  const s = raw && typeof raw === 'object' ? raw : {};
  let score = 0.8;
  const hard = [];
  const soft = [];
  const penalise = (amount, why) => {
    score -= amount;
    soft.push(why);
  };

  if (s.wd) hard.push('webdriver');
  if (/HeadlessChrome|PhantomJS|Selenium|puppeteer|playwright|slimerjs|electron/i.test(ua)) hard.push('headless-ua');
  if (!ua || ua.length < 20) hard.push('not-a-browser');
  if (!num(s.sw) || !num(s.sh)) hard.push('no-screen');
  if (num(s.dt, 1e9) < 250) hard.push('too-fast');

  if (!num(s.lg, 50)) penalise(0.2, 'no-languages');
  const pm = num(s.pm);
  const interacted = pm >= 3 || num(s.kd) >= 1 || num(s.tc) >= 1 || num(s.sc) >= 1;
  if (interacted) score += 0.1;
  else penalise(0.25, 'no-interaction');
  if (pm >= 8 && num(s.pv, 1e5) < 0.5) penalise(0.3, 'linear-pointer');

  score = Math.max(0, Math.min(1, score));
  return { score: Math.round(score * 100) / 100, hard, reasons: [...hard, ...soft] };
}

function cleanTrace(trace, max = 400) {
  if (!Array.isArray(trace)) return [];
  const out = [];
  for (const p of trace.slice(0, max)) {
    if (!Array.isArray(p) || p.length < 3) continue;
    const a = [Number(p[0]), Number(p[1]), Number(p[2])];
    if (a.every(Number.isFinite)) out.push(a);
  }
  return out;
}

const mean = (a) => a.reduce((x, y) => x + y, 0) / (a.length || 1);
const std = (a) => {
  const m = mean(a);
  return Math.sqrt(mean(a.map((v) => (v - m) ** 2)));
};

/**
 * Looks at the actual pointer path ([x, y, t] samples). People accelerate and brake, wobble, and
 * produce irregular event timing; simple scripts move in straight lines at constant speed on a fixed
 * timer. This catches cheap fakes; a carefully synthesised path can still pass, which is why it only
 * ever lets a visitor skip the puzzle and is limited per network.
 */
export function analyzeTrace(trace, opts = {}) {
  const { minPoints = 12, minDuration = 200, minLength = 60, minSpeedCV = 0.2, maxStraightness = 0.995, minTurnStd = 0.05 } = opts;
  const p = cleanTrace(trace);
  const fail = (why, extra = {}) => ({ ok: false, why, points: p.length, ...extra });
  if (p.length < minPoints) return fail(p.length ? 'too-few-points' : 'no-trace');
  const duration = p[p.length - 1][2] - p[0][2];
  if (duration < minDuration) return fail('too-short', { duration });

  const speeds = [];
  const angles = [];
  const dts = [];
  let L = 0;
  for (let i = 1; i < p.length; i++) {
    const dx = p[i][0] - p[i - 1][0];
    const dy = p[i][1] - p[i - 1][1];
    const dt = p[i][2] - p[i - 1][2];
    if (dt < 0) return fail('time-backwards');
    if (dt === 0) continue;
    const d = Math.hypot(dx, dy);
    L += d;
    dts.push(dt);
    speeds.push(d / dt);
    if (d > 0) angles.push(Math.atan2(dy, dx));
  }
  if (L < minLength) return fail('too-little-movement', { duration });

  const turns = [];
  for (let i = 1; i < angles.length; i++) {
    let a = angles[i] - angles[i - 1];
    while (a > Math.PI) a -= 2 * Math.PI;
    while (a < -Math.PI) a += 2 * Math.PI;
    turns.push(a);
  }
  const D = Math.hypot(p[p.length - 1][0] - p[0][0], p[p.length - 1][1] - p[0][1]);
  const features = {
    duration: Math.round(duration),
    length: Math.round(L),
    speedCV: +(std(speeds) / (mean(speeds) || 1)).toFixed(3),
    straightness: +(D / L).toFixed(4),
    turnStd: +(turns.length ? std(turns) : 0).toFixed(3),
    distinctDt: new Set(dts.map((d) => Math.round(d))).size,
  };
  if (features.speedCV < minSpeedCV) return fail('constant-speed', features);
  if (features.straightness > maxStraightness) return fail('perfectly-straight', features);
  if (features.turnStd < minTurnStd) return fail('too-smooth', features);
  if (features.distinctDt < 2) return fail('machine-timing', features);
  return { ok: true, points: p.length, ...features };
}

export const analyzeDrag = (trace) =>
  analyzeTrace(trace, { minPoints: 6, minDuration: 250, minLength: 15, minSpeedCV: 0.15, maxStraightness: 1.01, minTurnStd: 0.02 });

function keyboardOk(keys) {
  if (!Array.isArray(keys) || keys.length < 2) return false;
  const t = keys.map(Number).filter(Number.isFinite);
  if (t.length < 2 || t[t.length - 1] - t[0] < 300) return false;
  if (t.length < 3) return true;
  const gaps = t.slice(1).map((v, i) => Math.round(v - t[i]));
  return new Set(gaps).size >= 2; // a script pressing keys on a fixed timer is not a person
}

export function createCaptcha({ secret, sites, baseBits = 16, quotaSoft = 1, quotaHard = 8, puzzleMinMs = 800, now = Date.now }) {
  const hmac = (s) => crypto.createHmac('sha256', secret).update(s).digest('base64url');
  const ipTag = (ip) => crypto.createHash('sha256').update(secret + coarseIp(ip)).digest('hex').slice(0, 16);

  const usedChallenges = new Map();
  const usedTokens = new Map();
  const rate = new Map();
  const passLog = new Map(); // network -> times tokens were issued
  const failLog = new Map(); // network -> times puzzles were failed
  const puzzles = new Map(); // id -> { tx, sitekey, tag, tries, issued, exp }

  const count = (log, key) => {
    const t = now();
    const list = (log.get(key) || []).filter((x) => t - x < WINDOW_MS);
    if (list.length) log.set(key, list);
    else log.delete(key);
    return list.length;
  };
  const add = (log, key) => {
    count(log, key);
    log.set(key, [...(log.get(key) || []), now()]);
  };

  const sweep = setInterval(() => {
    const t = now();
    for (const m of [usedChallenges, usedTokens]) for (const [k, exp] of m) if (exp < t) m.delete(k);
    for (const [k, v] of rate) if (v.reset < t) rate.delete(k);
    for (const [k, v] of puzzles) if (v.exp < t) puzzles.delete(k);
    for (const k of [...passLog.keys()]) count(passLog, k);
    for (const k of [...failLog.keys()]) count(failLog, k);
  }, 30_000);
  sweep.unref();

  function siteFor(sitekey) {
    return Object.prototype.hasOwnProperty.call(sites, sitekey) ? sites[sitekey] : null;
  }
  function siteBySecret(sec) {
    let found = null;
    for (const [key, site] of Object.entries(sites)) if (site.secret && safeEqual(site.secret, sec || '')) found = key;
    return found;
  }
  function checkSite(sitekey, origin) {
    const site = siteFor(sitekey);
    if (!site) throw httpError(400, 'invalid_sitekey');
    if (site.origins && site.origins.length && (!origin || !site.origins.includes(origin))) throw httpError(403, 'origin_not_allowed');
  }
  function guardNetwork(net) {
    if (count(failLog, net) >= MAX_FAILS) throw httpError(429, 'too_many_failures');
    if (count(passLog, net) >= quotaHard) throw httpError(429, 'too_many_tokens');
  }
  function reject(reasons) {
    const e = httpError(403, 'failed');
    e.reasons = reasons;
    throw e;
  }

  function difficultyFor(tag) {
    const t = now();
    let r = rate.get(tag);
    if (!r || r.reset < t) r = { n: 0, reset: t + 60_000 };
    r.n++;
    rate.set(tag, r);
    if (r.n > 120) throw httpError(429, 'rate_limited');
    const extra = r.n > 5 ? Math.floor(Math.log2(r.n / 5)) + 1 : 0;
    return Math.min(MAX_BITS, baseBits + extra);
  }

  function makeChallenge({ sitekey, tag, bits }) {
    const id = crypto.randomBytes(12).toString('hex');
    const salt = crypto.randomBytes(8).toString('hex');
    const exp = now() + CHALLENGE_TTL;
    const attempt = 0;
    const sig = hmac(`c|${id}|${salt}|${bits}|${exp}|${sitekey}|${tag}|${attempt}`);
    return { id, salt, difficulty: bits, exp, attempt, sig };
  }

  function issueToken({ sitekey, id, tag, net, score, method }) {
    add(passLog, net);
    const t = now();
    const payload = Buffer.from(JSON.stringify({ k: sitekey, i: id, t, e: t + TOKEN_TTL, s: score, h: tag, m: method })).toString('base64url');
    return { ok: true, token: `${payload}.${hmac('t|' + payload)}`, expires: t + TOKEN_TTL, score, method };
  }

  function newPuzzle({ sitekey, tag, tries }) {
    const pz = makePuzzle();
    const id = crypto.randomBytes(12).toString('hex');
    const t = now();
    puzzles.set(id, { tx: pz.x, sitekey, tag, tries, issued: t, exp: t + PUZZLE_TTL });
    return {
      id,
      image: 'data:image/png;base64,' + pz.png.toString('base64'),
      width: pz.width,
      height: pz.height,
      size: pz.size,
      y: pz.y,
      shape: pz.shape,
    };
  }

  function issue({ sitekey, ip, origin }) {
    checkSite(sitekey, origin);
    guardNetwork(netKey(ip));
    const tag = ipTag(ip);
    return { challenge: makeChallenge({ sitekey, tag, bits: difficultyFor(tag) }) };
  }

  function verify({ sitekey, challenge: c, nonce, signals, trace, hp, ip, ua, origin }) {
    checkSite(sitekey, origin);
    if (!c || typeof c !== 'object') throw httpError(400, 'missing_challenge');
    const tag = ipTag(ip);
    const net = netKey(ip);

    const expected = hmac(`c|${c.id}|${c.salt}|${c.difficulty}|${c.exp}|${sitekey}|${tag}|${c.attempt}`);
    if (!safeEqual(expected, c.sig)) throw httpError(400, 'bad_challenge');
    if (now() > c.exp) throw httpError(400, 'challenge_expired');
    if (usedChallenges.has(c.id)) throw httpError(400, 'challenge_used');
    const n = String(nonce ?? '');
    if (!/^\d{1,12}$/.test(n)) throw httpError(400, 'bad_nonce');
    const digest = crypto.createHash('sha256').update(`${c.id}.${c.salt}.${n}`).digest();
    if (leadingZeroBits(digest) < c.difficulty) throw httpError(400, 'bad_proof');
    usedChallenges.set(c.id, c.exp + 1000);

    if (hp) reject(['honeypot']);

    // The server saw when the challenge was issued: a client claiming more time on the page, or a
    // longer mouse recording, than that is making it up.
    const observed = now() - (c.exp - CHALLENGE_TTL);
    const claimed = Number(signals && signals.dt);
    const tr = cleanTrace(trace);
    const traceSpan = tr.length > 1 ? tr[tr.length - 1][2] - tr[0][2] : 0;
    if ((Number.isFinite(claimed) && claimed > observed + 4000) || traceSpan > observed + 4000) reject(['inconsistent-timing']);

    const sig = scoreSignals(signals, ua);
    if (sig.hard.length) reject(sig.reasons);
    guardNetwork(net);

    const path = analyzeTrace(trace);
    if (path.ok && sig.score >= PASS_SCORE && count(passLog, net) < quotaSoft) {
      return issueToken({ sitekey, id: c.id, tag, net, score: sig.score, method: 'invisible' });
    }
    // Not confident: ask for something a person finds easy and a script cannot do blind.
    const reason = !path.ok ? `pointer:${path.why}` : sig.score < PASS_SCORE ? 'low-score' : 'network-quota';
    return { ok: false, puzzle: newPuzzle({ sitekey, tag, tries: 0 }), reason };
  }

  function solvePuzzle({ sitekey, id, x, trace, keys, ip, origin }) {
    checkSite(sitekey, origin);
    const tag = ipTag(ip);
    const net = netKey(ip);
    const pz = puzzles.get(String(id));
    if (!pz) throw httpError(400, 'puzzle_expired');
    puzzles.delete(String(id));
    if (pz.tag !== tag || pz.sitekey !== sitekey) throw httpError(400, 'bad_puzzle');
    if (now() > pz.exp) throw httpError(400, 'puzzle_expired');
    guardNetwork(net);

    const placed = Math.abs(Number(x) - pz.tx) <= TOLERANCE;
    const tooFast = now() - pz.issued < puzzleMinMs;
    const human = analyzeDrag(trace).ok || keyboardOk(keys);
    if (placed && !tooFast && human) return issueToken({ sitekey, id: String(id), tag, net, score: 0.7, method: 'puzzle' });

    add(failLog, net);
    const reason = !placed ? 'wrong-position' : tooFast ? 'too-fast' : 'robotic-drag';
    if (count(failLog, net) < MAX_FAILS && pz.tries + 1 < PUZZLE_TRIES) {
      return { ok: false, puzzle: newPuzzle({ sitekey, tag, tries: pz.tries + 1 }), reason };
    }
    reject([reason]);
  }

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
    return { success: true, challenge_ts: new Date(p.t).toISOString(), score: p.s, method: p.m || 'invisible' };
  }

  return {
    issue,
    verify,
    solvePuzzle,
    siteverify,
    close: () => clearInterval(sweep),
    _puzzleAnswer: (id) => puzzles.get(String(id))?.tx, // tests only; never exposed over HTTP
  };
}
