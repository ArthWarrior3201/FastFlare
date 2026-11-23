import test from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import fs from 'node:fs';
import vm from 'node:vm';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { createApp } from '../src/server.js';
import { consensus, EnvTime, formatTime } from '../src/envtime.js';
import { queryNtp, startNtpServer } from '../src/ntp.js';
import { localMs } from '../src/clock.js';
import { leadingZeroBits, analyzeTrace } from '../src/captcha.js';
import { makePuzzle } from '../src/puzzle.js';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');

function loadWidgetCore() {
  const ctx = vm.createContext({});
  vm.runInContext(fs.readFileSync(path.join(root, 'docs/fastflare.js'), 'utf8'), ctx);
  return ctx.FastFlare._pow();
}

const UA = 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0 Safari/537.36';
const HUMAN = { wd: false, lg: 2, sw: 1920, sh: 1080, pm: 30, kd: 2, tc: 0, sc: 1, fc: 1, pv: 12, dt: 3000 };

// A wandering, accelerating, wobbling path sampled at roughly display rate.
function humanTrace(n = 60, seed = 7) {
  const r = () => ((seed = (seed * 16807) % 2147483647) / 2147483647);
  const pts = [];
  let x = 300, y = 300, t = 0, ang = 0.4, speed = 0.4;
  for (let i = 0; i < n; i++) {
    ang += (r() - 0.5) * 0.7;
    speed = Math.max(0.05, Math.min(1.5, speed + (r() - 0.5) * 0.35));
    const dt = 16 + r() * 2;
    x += Math.cos(ang) * speed * dt;
    y += Math.sin(ang) * speed * dt;
    t += dt;
    pts.push([Math.round(x), Math.round(y), Math.round(t * 10) / 10]);
  }
  return pts;
}
// What a cheap script produces: a straight line at constant speed on a fixed timer.
const robotTrace = (n = 40) => Array.from({ length: n }, (_, i) => [100 + i * 8, 200 + i * 3, i * 16]);
function humanDrag(toX, seed = 3) {
  const r = () => ((seed = (seed * 16807) % 2147483647) / 2147483647);
  const pts = [];
  let t = 0;
  for (let i = 0; i <= 30; i++) {
    const s = i / 30;
    const e = s < 0.5 ? 2 * s * s : 1 - (-2 * s + 2) ** 2 / 2;
    t += 15 + r() * 6;
    pts.push([Math.round(500 + e * toX + (r() - 0.5) * 2), Math.round(400 + (r() - 0.5) * 4), Math.round(t)]);
  }
  return pts;
}

// ---------------------------------------------------------------------------------------------
test('browser proof-of-work hash matches Node SHA-256', () => {
  const core = loadWidgetCore();
  for (const s of ['abc', '', 'a'.repeat(55), 'abcdef0123456789abcdef01.0123456789abcdef.123456789012']) {
    assert.equal(core.digestHex(s), crypto.createHash('sha256').update(s).digest('hex'), JSON.stringify(s));
  }
  const prefix = 'aaaaaaaaaaaaaaaaaaaaaaaa.bbbbbbbbbbbbbbbb.';
  const nonce = core.solve(prefix, 12, 0, 1e6);
  assert.ok(nonce >= 0);
  const d = crypto.createHash('sha256').update(prefix + nonce).digest();
  assert.ok(leadingZeroBits(d) >= 12);
});

// ---------------------------------------------------------------------------------------------
test('consensus kicks the provider that disagrees with the majority', () => {
  const r = consensus(
    [
      { host: 'a', offsetMs: 2, rttMs: 20 },
      { host: 'b', offsetMs: 4, rttMs: 30 },
      { host: 'c', offsetMs: 3, rttMs: 25 },
      { host: 'liar', offsetMs: 900, rttMs: 20 },
    ],
    { toleranceMs: 50 },
  );
  assert.deepEqual(r.kicked.map((s) => s.host), ['liar']);
  assert.equal(r.agree.length, 3);
  assert.ok(Math.abs(r.offsetMs - 3) < 1.5);
});

test('consensus refuses to decide without a majority', () => {
  const split = consensus(
    [
      { host: 'a', offsetMs: 0, rttMs: 10 },
      { host: 'b', offsetMs: 500, rttMs: 10 },
      { host: 'c', offsetMs: 1000, rttMs: 10 },
    ],
    { toleranceMs: 50 },
  );
  assert.equal(split, null);
  assert.equal(consensus([{ host: 'solo', offsetMs: 1, rttMs: 5 }]), null);
});

test('EnvTime round leaves a slow provider once enough have answered', async () => {
  const offsets = { g: 10, a: 12, w: 11, liar: 700 };
  const query = (host, { signal }) =>
    host === 'slow'
      ? new Promise((_, rej) => signal.addEventListener('abort', () => rej(new Error('aborted'))))
      : Promise.resolve({ offsetMs: offsets[host], rttMs: 15 });
  const et = new EnvTime({
    providers: ['g', 'a', 'w', 'liar', 'slow'].map((host) => ({ host })),
    query,
    graceMs: 20,
    hardTimeoutMs: 5000,
  });
  const t0 = Date.now();
  const s = await et.round();
  assert.ok(Date.now() - t0 < 1000, 'must not wait for the slow provider');
  assert.deepEqual(s.skippedSlow, ['slow']);
  assert.deepEqual(s.kicked.map((x) => x.host), ['liar']);
  assert.equal(s.used.length, 3);
  assert.ok(et.synced);
  assert.ok(Math.abs(et.offset - 11) < 2);
  const a = et.now();
  const b = et.now();
  assert.ok(b >= a, 'time never runs backwards');
});

test('EnvTime ignores a round that has no majority and keeps the old time', async () => {
  let mode = 'good';
  const query = (host) => Promise.resolve({ offsetMs: mode === 'good' ? 5 : { a: 0, b: 400, c: 800 }[host], rttMs: 10 });
  const et = new EnvTime({ providers: ['a', 'b', 'c'].map((host) => ({ host })), query, graceMs: 5 });
  await et.round();
  const before = et.offset;
  mode = 'bad';
  const s = await et.round();
  assert.equal(s.accepted, false);
  assert.equal(et.offset, before);
});

test('formatTime renders other time zones correctly', () => {
  const ms = Date.UTC(2026, 10, 22, 9, 32, 0, 123);
  const k = formatTime(ms, 'Asia/Kolkata');
  assert.equal(k.offsetMinutes, 330);
  assert.equal(k.local, '2026-11-22T15:02:00.123+05:30');
  assert.equal(formatTime(ms, 'America/New_York').offsetMinutes, -300);
  assert.equal(formatTime(ms).local, '2026-11-22T09:32:00.123+00:00');
  assert.throws(() => formatTime(ms, 'Not/AZone'), RangeError);
});

// ---------------------------------------------------------------------------------------------
test('NTP server and client round trip compensates for the clock offset', async () => {
  const skew = 5000;
  const srv = await startNtpServer({
    port: 0,
    host: '127.0.0.1',
    clock: () => ({ ms: localMs() + skew, synced: true, rootDelayMs: 1, dispersionMs: 1, refMs: localMs() + skew }),
  });
  try {
    const r = await queryNtp('127.0.0.1', { port: srv.port, timeoutMs: 1000 });
    assert.ok(Math.abs(r.offsetMs - skew) < 25, `offset ${r.offsetMs}`);
    assert.ok(r.rttMs < 25);
  } finally {
    srv.close();
  }
});

test('an unsynchronized NTP server is rejected by clients', async () => {
  const srv = await startNtpServer({ port: 0, host: '127.0.0.1', clock: () => ({ ms: localMs(), synced: false }) });
  try {
    await assert.rejects(queryNtp('127.0.0.1', { port: srv.port, timeoutMs: 1000 }), /unsynchronized/);
  } finally {
    srv.close();
  }
});

// ---------------------------------------------------------------------------------------------
async function withApp(fn) {
  const offsets = { 'time.a': 1000, 'time.b': 1002, 'time.c': 1001, 'time.liar': 99999 };
  const app = await createApp({
    quiet: true,
    port: 0,
    host: '127.0.0.1',
    captchaBaseBits: 10,
    puzzleMinMs: 0,
    ntp: { enabled: false },
    envtime: { providers: Object.keys(offsets).map((host) => ({ host })), graceMs: 10, pollMs: 60000 },
    timeQuery: (host) => Promise.resolve({ offsetMs: offsets[host], rttMs: 8 }),
  });
  const { port } = await app.start();
  try {
    await fn(`http://127.0.0.1:${port}`, app);
  } finally {
    await app.stop();
  }
}

const j = (base, p, body, headers = {}) =>
  fetch(base + p, { method: 'POST', headers: { 'Content-Type': 'application/json', 'User-Agent': UA, ...headers }, body: JSON.stringify(body) });

async function challengeAndProof(base) {
  const core = loadWidgetCore();
  const r = await j(base, '/captcha/challenge', { sitekey: 'ff_demo_site' });
  if (r.status !== 200) return { status: r.status, error: (await r.json()).error };
  const { challenge } = await r.json();
  return { challenge, nonce: String(core.solve(`${challenge.id}.${challenge.salt}.`, challenge.difficulty, 0, 1e8)) };
}
const verifyWith = (base, c, extra) =>
  j(base, '/captcha/verify', { sitekey: 'ff_demo_site', challenge: c.challenge, nonce: c.nonce, signals: HUMAN, hp: '', ...extra });

test('pointer path analysis tells a wandering hand from a straight scripted line', () => {
  assert.equal(analyzeTrace(humanTrace()).ok, true, JSON.stringify(analyzeTrace(humanTrace())));
  assert.equal(analyzeTrace(robotTrace()).ok, false);
  assert.equal(analyzeTrace([]).why, 'no-trace');
});

test('puzzle image is a valid PNG and the answer is not in the JSON', () => {
  const pz = makePuzzle();
  assert.deepEqual([...pz.png.subarray(0, 8)], [0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]);
  assert.ok(pz.png.length < 200_000, `png is ${pz.png.length} bytes`);
  assert.ok(pz.x >= pz.size && pz.x <= pz.width - pz.size);
});

test('CAPTCHA: human path passes invisibly, token verifies once, replay rejected', async () => {
  await withApp(async (base) => {
    const c = await challengeAndProof(base);
    const out = await (await verifyWith(base, c, { trace: humanTrace() })).json();
    assert.equal(out.ok, true, JSON.stringify(out));
    assert.equal(out.method, 'invisible');

    const check = (token, secret = 'ff_demo_secret') => j(base, '/captcha/siteverify', { secret, response: token }).then((r) => r.json());
    assert.equal((await check(out.token, 'wrong-secret'))['error-codes'][0], 'invalid-input-secret');
    const ok = await check(out.token);
    assert.equal(ok.success, true);
    assert.equal(ok.method, 'invisible');
    assert.equal((await check(out.token)).success, false, 'tokens are single use');
    assert.equal((await verifyWith(base, c, { trace: humanTrace() })).status, 400, 'challenge cannot be reused');
  });
});

test('CAPTCHA: wrong proof, forged challenge, honeypot, automation and faked timing are rejected', async () => {
  await withApp(async (base) => {
    let c = await challengeAndProof(base);
    assert.equal((await (await verifyWith(base, { ...c, nonce: '1' }, {})).json()).error, 'bad_proof');
    c = await challengeAndProof(base);
    assert.equal((await (await verifyWith(base, { ...c, challenge: { ...c.challenge, difficulty: 1 } }, {})).json()).error, 'bad_challenge');
    c = await challengeAndProof(base);
    assert.equal((await verifyWith(base, c, { hp: 'http://spam', trace: humanTrace() })).status, 403);
    c = await challengeAndProof(base);
    assert.equal((await verifyWith(base, c, { signals: { ...HUMAN, wd: true }, trace: humanTrace() })).status, 403);
    c = await challengeAndProof(base);
    assert.equal((await verifyWith(base, c, { signals: { ...HUMAN, dt: 60000 }, trace: humanTrace() })).status, 403);
    c = await challengeAndProof(base);
    const curl = await j(base, '/captcha/verify', { sitekey: 'ff_demo_site', challenge: c.challenge, nonce: c.nonce, signals: HUMAN, trace: humanTrace() }, { 'User-Agent': 'curl/8.0' });
    assert.equal(curl.status, 403, 'non-browser clients are rejected');
    assert.equal((await j(base, '/captcha/challenge', { sitekey: 'nope' })).status, 400);
  });
});

test('CAPTCHA: a scripted pointer gets a puzzle; guessing fails and locks the network', async () => {
  await withApp(async (base) => {
    const results = [];
    for (let i = 0; i < 3; i++) {
      const c = await challengeAndProof(base);
      if (c.status) { results.push(c.error); continue; }
      let v = await (await verifyWith(base, c, { trace: robotTrace() })).json();
      assert.ok(v.puzzle, 'robotic path must be challenged');
      assert.match(v.puzzle.image, /^data:image\/png;base64,/);
      assert.equal(v.puzzle.x, undefined, 'answer must not be sent');
      const r = await j(base, '/captcha/puzzle', { sitekey: 'ff_demo_site', id: v.puzzle.id, x: 0, trace: humanDrag(10) });
      v = await r.json();
      results.push(v.puzzle ? 'retry' : v.error);
      if (v.puzzle) {
        const r2 = await j(base, '/captcha/puzzle', { sitekey: 'ff_demo_site', id: v.puzzle.id, x: 1, trace: humanDrag(10) });
        results.push((await r2.json()).error);
      }
    }
    // 1st puzzle: wrong -> second puzzle; wrong -> failed. 3rd failure locks the network.
    assert.deepEqual(results.slice(0, 2), ['retry', 'failed']);
    assert.ok(results.includes('too_many_failures') || results.at(-1) === 'failed', JSON.stringify(results));
    const after = await j(base, '/captcha/challenge', { sitekey: 'ff_demo_site' });
    assert.equal(after.status, 429);
    assert.equal((await after.json()).error, 'too_many_failures');
  });
});

test('CAPTCHA: solving the puzzle correctly with a human drag passes; a robotic drag does not', async () => {
  await withApp(async (base, app) => {
    const c = await challengeAndProof(base);
    const v = await (await verifyWith(base, c, {})).json();
    assert.ok(v.puzzle);
    const x = app.captcha._puzzleAnswer(v.puzzle.id);
    const robot = await (await j(base, '/captcha/puzzle', { sitekey: 'ff_demo_site', id: v.puzzle.id, x, trace: robotTrace(10) })).json();
    assert.ok(robot.puzzle, 'robotic drag is not accepted even at the right spot');
    const x2 = app.captcha._puzzleAnswer(robot.puzzle.id);
    const ok = await (await j(base, '/captcha/puzzle', { sitekey: 'ff_demo_site', id: robot.puzzle.id, x: x2 + 4, trace: humanDrag(x2) })).json();
    assert.equal(ok.ok, true, JSON.stringify(ok));
    assert.equal(ok.method, 'puzzle');
  });
});

test('CAPTCHA: one network gets 1 invisible token, then puzzles, then nothing', async () => {
  await withApp(async (base, app) => {
    const seen = [];
    for (let i = 0; i < 10; i++) {
      const c = await challengeAndProof(base);
      if (c.status) { seen.push(c.error); continue; }
      const v = await (await verifyWith(base, c, { trace: humanTrace(60, i + 2) })).json();
      if (v.ok) { seen.push('invisible'); continue; }
      const x = app.captcha._puzzleAnswer(v.puzzle.id);
      const r = await (await j(base, '/captcha/puzzle', { sitekey: 'ff_demo_site', id: v.puzzle.id, x, trace: humanDrag(x, i + 5) })).json();
      seen.push(r.ok ? 'puzzle' : r.error);
    }
    assert.deepEqual(seen, ['invisible', ...Array(7).fill('puzzle'), 'too_many_tokens', 'too_many_tokens']);
  });
});

test('EnvTime HTTP: majority time in the requested zone, outlier kicked', async () => {
  await withApp(async (base) => {
    const before = Date.now();
    const t = await (await fetch(base + '/time?tz=Asia/Kolkata')).json();
    assert.equal(t.synced, true);
    assert.equal(t.offsetMinutes, 330);
    assert.deepEqual(t.sources.kicked, ['time.liar']);
    // The fake providers say true time is ~1001 ms ahead of the local clock.
    assert.ok(Math.abs(t.unixMs - (before + 1001)) < 250, `unixMs off by ${t.unixMs - before - 1001}`);
    assert.match(t.local, /\+05:30$/);
    assert.equal((await fetch(base + '/time?tz=Bad/Zone')).status, 400);

    const status = await (await fetch(base + '/time/status')).json();
    assert.equal(status.lastRound.kicked[0].host, 'time.liar');
  });
});

test('static docs are served and path traversal is blocked', async () => {
  await withApp(async (base) => {
    const home = await fetch(base + '/');
    assert.equal(home.status, 200);
    assert.match(await home.text(), /FastFlare/);
    assert.equal((await fetch(base + '/fastflare.js')).status, 200);
    const evil = await fetch(base + '/%2e%2e/%2e%2e/package.json');
    assert.ok([403, 404].includes(evil.status));
  });
});

test('site signup: creates a working key bound to its origins, saved across restarts', async () => {
  const dir = fs.mkdtempSync(path.join(process.env.TMPDIR || '/tmp', 'ff-sites-'));
  const boot = () => createApp({ quiet: true, port: 0, host: '127.0.0.1', captchaBaseBits: 10, ntp: { enabled: false }, dataDir: dir, envtime: { providers: [{ host: 'a' }, { host: 'b' }, { host: 'c' }], pollMs: 60000 }, timeQuery: () => Promise.resolve({ offsetMs: 0, rttMs: 5 }) });
  let app = await boot();
  let { port } = await app.start();
  let base = `http://127.0.0.1:${port}`;
  try {
    assert.equal((await j(base, '/sites/register', { name: 'x', origins: ['javascript:alert(1)'] })).status, 400);
    assert.equal((await j(base, '/sites/register', { name: 'x', origins: ['http://example.com'] })).status, 400, 'plain http only for localhost');
    assert.equal((await j(base, '/sites/register', { name: '', origins: ['example.com'] })).status, 400);
    const r = await (await j(base, '/sites/register', { name: 'My Shop', origins: 'shop.example.com\nhttp://localhost:3000/' })).json();
    assert.match(r.sitekey, /^ff_site_/);
    assert.match(r.secret, /^ff_secret_/);
    assert.deepEqual(r.origins, ['https://shop.example.com', 'http://localhost:3000']);
    assert.equal((await j(base, '/captcha/challenge', { sitekey: r.sitekey }, { Origin: 'https://evil.example' })).status, 403);
    assert.equal((await j(base, '/captcha/challenge', { sitekey: r.sitekey }, { Origin: 'http://localhost:3000' })).status, 200);
    for (let i = 0; i < 4; i++) await j(base, '/sites/register', { name: 'n' + i, origins: ['a.example.com'] });
    assert.equal((await j(base, '/sites/register', { name: 'over', origins: ['a.example.com'] })).status, 429, 'five signups per network per day');
    await app.stop();

    app = await boot();
    ({ port } = await app.start());
    base = `http://127.0.0.1:${port}`;
    assert.equal((await j(base, '/captcha/challenge', { sitekey: r.sitekey }, { Origin: 'http://localhost:3000' })).status, 200, 'key survives a restart');
    const sv = await (await j(base, '/captcha/siteverify', { secret: r.secret, response: 'x.y' })).json();
    assert.equal(sv['error-codes'][0], 'invalid-input-response', 'secret is recognised');
  } finally {
    await app.stop();
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test('gate: a passed token sets a pass cookie and redirects; bad or reused tokens do not', async () => {
  const { createGate } = await import('../docs/kit/fastflare-gate.mjs');
  await withApp(async (base) => {
    const gate = createGate({ sitekey: 'ff_demo_site', secret: 'ff_demo_secret', api: base, redirect: '/welcome' });
    const { port } = await gate.listen(0, '127.0.0.1');
    const g = `http://127.0.0.1:${port}`;
    try {
      const home = await (await fetch(g + '/')).text();
      assert.match(home, /data-verify="\/fastflare\/verify"/);
      assert.match(home, /data-redirect="\/welcome"/);
      assert.equal((await fetch(g + '/welcome', { redirect: 'manual' })).status, 302, 'welcome needs a pass');

      const bad = await j(g, '/fastflare/verify', { token: 'forged.token' });
      assert.equal(bad.status, 403);
      assert.equal((await bad.json()).success, false);

      const c = await challengeAndProof(base);
      const { token } = await (await verifyWith(base, c, { trace: humanTrace() })).json();
      const ok = await j(g, '/fastflare/verify', { token, redirect: '//evil.example' });
      const body = await ok.json();
      assert.equal(body.success, true);
      assert.equal(body.redirect, '/welcome', 'off-site redirects are replaced');
      const cookie = ok.headers.get('set-cookie').split(';')[0];
      assert.equal((await fetch(g + '/welcome', { headers: { cookie } })).status, 200);
      assert.equal((await j(g, '/fastflare/verify', { token })).status, 403, 'token is single use');
      assert.equal((await fetch(g + '/welcome', { headers: { cookie: 'ff_pass=9999999999999.forged' }, redirect: 'manual' })).status, 302);
    } finally {
      await gate.close();
    }
  });
});
