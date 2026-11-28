import test from 'node:test';
import http from 'node:http';
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

// ---------------------------------------------------------------------------------------------
// CDN: mock GitHub (Git Data API + raw) so the GitHub tier is exercised.
function mockCloud() {
  const blobs = new Map();
  const trees = new Map(); // tree sha -> Map(path -> blob sha)
  const commits = new Map(); // commit sha -> { tree }
  const sha = () => crypto.randomBytes(20).toString('hex');
  const t0 = sha();
  trees.set(t0, new Map());
  const c0 = sha();
  commits.set(c0, { tree: t0 });
  let head = c0;
  const calls = { rawGet: 0 };
  const server = http.createServer(async (req, res) => {
    const chunks = [];
    for await (const c of req) chunks.push(c);
    const body = Buffer.concat(chunks);
    const u = new URL(req.url, 'http://x');
    const p = decodeURIComponent(u.pathname);
    const json = (s, o) => { res.writeHead(s, { 'Content-Type': 'application/json' }); res.end(JSON.stringify(o)); };
    if (p.startsWith('/repos/me/repo/')) {
      if (req.headers.authorization !== 'Bearer gh-token') return json(401, {});
      const r = p.slice('/repos/me/repo'.length);
      const b = body.length ? JSON.parse(body) : null;
      if (req.method === 'GET' && r === '/git/ref/heads/cdn') return json(200, { object: { sha: head } });
      if (req.method === 'GET' && r.startsWith('/git/commits/')) return json(200, { tree: { sha: commits.get(r.split('/').pop()).tree } });
      if (req.method === 'POST' && r === '/git/blobs') { const s = sha(); blobs.set(s, Buffer.from(b.content, 'base64')); return json(201, { sha: s }); }
      if (req.method === 'POST' && r === '/git/trees') {
        const t = new Map(trees.get(b.base_tree));
        for (const e of b.tree) e.sha === null ? t.delete(e.path) : t.set(e.path, e.sha);
        const s = sha(); trees.set(s, t); return json(201, { sha: s });
      }
      if (req.method === 'POST' && r === '/git/commits') { const s = sha(); commits.set(s, { tree: b.tree }); return json(201, { sha: s }); }
      if (req.method === 'PATCH' && r === '/git/refs/heads/cdn') { head = b.sha; return json(200, {}); }
    }
    let m;
    if ((m = p.match(/^\/raw\/me\/repo\/([0-9a-f]{40})\/(.+)$/))) {
      calls.rawGet++;
      const t = trees.get(commits.get(m[1])?.tree);
      const s = t && t.get(m[2]);
      if (!s) { res.writeHead(404); return res.end(); }
      res.writeHead(200);
      return res.end(blobs.get(s));
    }
    json(404, { error: 'mock: ' + req.method + ' ' + p });
  });
  return {
    server, blobs, calls,
    ghFiles: () => [...trees.get(commits.get(head).tree).keys()],
    tamperGithub(prefix) {
      for (const [p, s] of trees.get(commits.get(head).tree)) if (p.startsWith(prefix)) { const c = Buffer.from(blobs.get(s)); c[5] ^= 1; blobs.set(s, c); }
    },
  };
}

async function withCdn(fn, extra = {}) {
  const cloud = mockCloud();
  await new Promise((r) => cloud.server.listen(0, '127.0.0.1', r));
  const mock = `http://127.0.0.1:${cloud.server.address().port}`;
  const dir = fs.mkdtempSync(path.join(process.env.TMPDIR || '/tmp', 'ff-cdn-'));
  const boot = async () => {
    const app = await createApp({
      quiet: true, port: 0, host: '127.0.0.1', ntp: { enabled: false }, dataDir: dir,
      envtime: { providers: [{ host: 'a' }, { host: 'b' }, { host: 'c' }], pollMs: 60000 },
      timeQuery: () => Promise.resolve({ offsetMs: 0, rttMs: 5 }),
      cdn: {
        token: 'owner-token',
        github: { repo: 'me/repo', branch: 'cdn', token: 'gh-token', api: mock, raw: mock + '/raw' },
        ...extra,
      },
    });
    const { port } = await app.start();
    return { app, base: `http://127.0.0.1:${port}` };
  };
  let cur = await boot();
  try {
    await fn({ get base() { return cur.base; }, cloud, restart: async () => { await cur.app.stop(); cur = await boot(); } });
  } finally {
    await cur.app.stop();
    cloud.server.close();
    fs.rmSync(dir, { recursive: true, force: true });
  }
}

function readZip(buf) {
  const out = {};
  let o = 0;
  while (buf.readUInt32LE(o) === 0x04034b50) {
    const crc = buf.readUInt32LE(o + 14);
    let size = buf.readUInt32LE(o + 18);
    const n = buf.readUInt16LE(o + 26);
    const x = buf.readUInt16LE(o + 28);
    const name = buf.subarray(o + 30, o + 30 + n).toString('utf8');
    o += 30 + n + x;
    out[name] = { data: buf.subarray(o, o + size), crc };
    o += size;
  }
  assert.equal(buf.readUInt32LE(o), 0x02014b50, 'central directory follows the entries');
  return out;
}

test('CDN: upload to the server and GitHub, download with the key, ranges, zip, wrong key, tamper, delete, restart', { timeout: 120000 }, async () => {
  await withCdn(async (env) => {
    const put = (name, data, { bundle, key, tier, token = 'owner-token' } = {}) =>
      fetch(`${env.base}/cdn/upload?name=${encodeURIComponent(name)}${bundle ? '&bundle=' + bundle : ''}${tier ? '&tier=' + tier : ''}`, {
        method: 'PUT', headers: { Authorization: 'Bearer ' + token, ...(key ? { 'X-FF-Key': key } : {}) }, body: data,
      });

    assert.equal((await put('x.txt', 'hi', { token: 'nope' })).status, 401);

    const logo = crypto.randomBytes(30_000);
    const r1 = await put('logo.png', logo);
    assert.equal(r1.status, 201);
    const a = await r1.json();
    assert.equal(a.key, undefined, 'the key is not given until the batch is finished');
    const fin = await (await fetch(`${env.base}/cdn/finish`, { method: 'POST', headers: { 'X-FF-Ticket': a.ticket } })).json();
    a.key = fin.key;
    assert.match(a.key, /^ffk_/);
    assert.equal(a.file.tier, 'vm', 'small files stay on the server');
    const { bundle, key } = a;

    const mid = crypto.randomBytes(6 * 1024 * 1024 + 123);
    assert.equal((await put('app/setup.bin', mid, { bundle, key: 'ffk_' + 'A'.repeat(43) })).status, 403, 'adding needs the bundle key');
    const b = await (await put('app/setup.bin', mid, { bundle, key })).json();
    assert.equal(b.file.tier, 'github', 'medium and large files go to GitHub');
    assert.equal(b.key, undefined, 'the key is only shown at the end');

    const big = crypto.randomBytes(50 * 1024 * 1024 + 9);
    const c = await (await put('main.iso', big, { bundle, key, tier: 'vm' })).json();
    assert.equal(c.file.tier, 'vm');
    assert.equal(c.file.parts, 2);
    assert.ok(env.cloud.ghFiles().every((f) => f.endsWith('.ffencrypted')), 'only encrypted parts on GitHub');
    for (const v of env.cloud.blobs.values()) assert.equal(v.indexOf(mid.subarray(0, 64)), -1, 'GitHub never sees plaintext');

    const get = (p, headers = {}) => fetch(env.base + p, { headers });
    assert.equal((await get(`/cdn/${bundle}/logo.png`)).status, 403, 'no key, no file');
    assert.equal((await get(`/cdn/${bundle}/logo.png?key=ffk_${'B'.repeat(43)}`)).status, 403, 'wrong key');
    assert.equal((await get(`/cdn/AAAAAAAAAAAAAAAA?key=${key}`)).status, 404);

    let res = await get(`/cdn/${bundle}/logo.png?key=${key}`);
    assert.equal(res.status, 200);
    assert.equal(res.headers.get('content-type'), 'image/png');
    assert.ok(Buffer.from(await res.arrayBuffer()).equals(logo));
    res = await get(`/cdn/${bundle}/app/setup.bin`, { 'X-FF-Key': key });
    assert.ok(Buffer.from(await res.arrayBuffer()).equals(mid), 'key in a header works too');
    res = await get(`/cdn/${bundle}/main.iso?key=${key}`, { Range: 'bytes=46137300-46137400' });
    assert.equal(res.status, 206);
    assert.ok(Buffer.from(await res.arrayBuffer()).equals(big.subarray(46137300, 46137401)), 'range across a part boundary');

    const list = await (await get(`/cdn/${bundle}?key=${key}&list=1`)).json();
    assert.deepEqual(list.files.map((f) => f.name).sort(), ['app/setup.bin', 'logo.png', 'main.iso']);

    res = await get(`/cdn/${bundle}?key=${key}&files=logo.png,app/setup.bin`);
    assert.equal(res.headers.get('content-type'), 'application/zip');
    const zbuf = Buffer.from(await res.arrayBuffer());
    assert.equal(Number(res.headers.get('content-length')), zbuf.length);
    const z = readZip(zbuf);
    assert.ok(z['logo.png'].data.equals(logo) && z['app/setup.bin'].data.equals(mid));
    const all = readZip(Buffer.from(await (await get(`/cdn/${bundle}?key=${key}`)).arrayBuffer()));
    assert.ok(all['main.iso'].data.equals(big), 'no selection = every file');

    const gets = env.cloud.calls.rawGet;
    await (await get(`/cdn/${bundle}/app/setup.bin?key=${key}`)).arrayBuffer();
    assert.equal(env.cloud.calls.rawGet, gets, 'repeat downloads come from the VM cache');

    const d = await (await fetch(`${env.base}/cdn/upload?name=fresh.txt&done=1&tier=github`, { method: 'PUT', headers: { Authorization: 'Bearer owner-token' }, body: 'tamper me' })).json();
    env.cloud.tamperGithub(d.bundle + '/');
    assert.equal((await get(`/cdn/${d.bundle}/fresh.txt?key=${d.key}`)).status, 502, 'altered storage is detected');

    await env.restart();
    res = await get(`/cdn/${bundle}/app/setup.bin?key=${key}`);
    assert.ok(Buffer.from(await res.arrayBuffer()).equals(mid), 'survives a restart');
    const st = await (await get('/cdn/status', { Authorization: 'Bearer owner-token' })).json();
    assert.ok(st.tiers.github.usedBytes > mid.length && st.tiers.vm.usedBytes > big.length);

    const del = await fetch(`${env.base}/cdn/${bundle}/app/setup.bin`, { method: 'DELETE', headers: { Authorization: 'Bearer owner-token' } });
    assert.equal(del.status, 200);
    assert.equal(env.cloud.ghFiles().filter((f) => f.startsWith(bundle)).length, 0, 'GitHub parts removed from the branch');
    assert.equal((await get(`/cdn/${bundle}/app/setup.bin?key=${key}`)).status, 404);
    await fetch(`${env.base}/cdn/${bundle}`, { method: 'DELETE', headers: { Authorization: 'Bearer owner-token' } });
    assert.equal((await get(`/cdn/${bundle}?key=${key}&list=1`)).status, 404);
    assert.ok(!env.cloud.ghFiles().some((k) => k.startsWith(bundle)), 'GitHub parts removed');
  });
});

test('CDN edge function: decrypts at the edge from direct GitHub links, ranges, zip, wrong key, large-file handoff', { timeout: 120000 }, async () => {
  const { default: edge } = await import('../vercel/api/cdn.js');
  await withCdn(async (env) => {
    process.env.FF_ORIGIN = env.base;
    const put = (name, data, q = '', h = {}) =>
      fetch(`${env.base}/cdn/upload?name=${encodeURIComponent(name)}${q}`, { method: 'PUT', headers: { Authorization: 'Bearer owner-token', ...h }, body: data }).then((r) => r.json());
    const logo = crypto.randomBytes(40_000);
    const mid = crypto.randomBytes(7 * 1024 * 1024 + 5);
    const big = crypto.randomBytes(46 * 1024 * 1024);
    const a = await put('logo.png', logo, '&done=1');
    await put('dl/setup.bin', mid, `&bundle=${a.bundle}`, { 'X-FF-Key': a.key });
    await put('main.iso', big, `&bundle=${a.bundle}&tier=vm`, { 'X-FF-Key': a.key });
    const call = (p, headers = {}) => edge(new Request('https://edge.example' + p, { headers }));

    let r = await call(`/cdn/${a.bundle}/logo.png?key=${a.key}`);
    assert.equal(r.status, 200);
    assert.equal(r.headers.get('x-fastflare-edge'), '1');
    assert.match(r.headers.get('cache-control'), /s-maxage/, 'small files are cached at the edge');
    assert.ok(Buffer.from(await r.arrayBuffer()).equals(logo));

    const raws = env.cloud.calls.rawGet;
    r = await call(`/cdn/${a.bundle}/dl/setup.bin`, { 'X-FF-Key': a.key, Range: 'bytes=1048570-1048590' });
    assert.equal(r.status, 206);
    assert.ok(Buffer.from(await r.arrayBuffer()).equals(mid.subarray(1048570, 1048591)));
    assert.ok(env.cloud.calls.rawGet > raws, 'the edge read GitHub directly');

    r = await call(`/cdn/${a.bundle}/main.iso?key=${a.key}`, { Range: 'bytes=46137300-46137400' });
    assert.ok(Buffer.from(await r.arrayBuffer()).equals(big.subarray(46137300, 46137401)), 'server-stored parts via signed links');

    r = await call(`/cdn/${a.bundle}?key=${a.key}&files=logo.png,dl/setup.bin`);
    const z = readZip(Buffer.from(await r.arrayBuffer()));
    assert.ok(z['logo.png'].data.equals(logo) && z['dl/setup.bin'].data.equals(mid));

    const list = await (await call(`/cdn/${a.bundle}?key=${a.key}&list=1`)).json();
    assert.equal(list.files.length, 3);
    assert.equal((await call(`/cdn/${a.bundle}/logo.png?key=ffk_${'C'.repeat(43)}`)).status, 403);
    assert.equal((await call(`/cdn/${a.bundle}/logo.png`)).status, 403);
    assert.equal((await call(`/cdn/${a.bundle}/nope.png?key=${a.key}`)).status, 404);

    r = await call(`/cdn/${a.bundle}/main.iso?key=${a.key}`);
    assert.equal(r.status, 307, 'normal-size files are sent to the server');
    assert.equal(r.headers.get('location'), `${env.base}/cdn/${a.bundle}/main.iso?key=${a.key}&route=native`);

    const t = await put('t.txt', 'tamper', '&done=1&tier=github');
    env.cloud.tamperGithub(t.bundle + '/');
    assert.equal((await call(`/cdn/${t.bundle}/t.txt?key=${t.key}`)).status, 502, 'altered parts are refused at the edge');
    assert.equal((await fetch(`${env.base}/cdn/part/${a.bundle}/x/0?exp=${Date.now() + 1e5}&sig=bad`)).status, 403, 'part links must be signed');
    delete process.env.FF_ORIGIN;
  });
});

test('CDN smart routing: small to the edge, normal from the server, extra-large to the chunked downloader', { timeout: 60000 }, async () => {
  const { default: edge } = await import('../vercel/api/cdn.js');
  await withCdn(async (env) => {
    process.env.FF_ORIGIN = env.base;
    process.env.FF_ROUTE_SMALL_MB = '1';
    process.env.FF_ROUTE_XL_MB = '5';
    try {
      const put = (name, data, q = '', h = {}) =>
        fetch(`${env.base}/cdn/upload?name=${encodeURIComponent(name)}${q}`, { method: 'PUT', headers: { Authorization: 'Bearer owner-token', ...h }, body: data }).then((r) => r.json());
      const logo = crypto.randomBytes(40_000);
      const mid = crypto.randomBytes(3 * 1024 * 1024);
      const big = crypto.randomBytes(7 * 1024 * 1024);
      const a = await put('logo.png', logo, '&done=1');
      await put('mid.bin', mid, `&bundle=${a.bundle}`, { 'X-FF-Key': a.key });
      await put('big.bin', big, `&bundle=${a.bundle}`, { 'X-FF-Key': a.key });
      const HTML = { Accept: 'text/html,application/xhtml+xml' };
      const vm = (p, h = {}) => fetch(env.base + p, { headers: h, redirect: 'manual' });

      // Server side
      let r = await vm(`/cdn/${a.bundle}/logo.png?key=${a.key}`);
      assert.equal(r.status, 307);
      assert.equal(r.headers.get('location'), `https://edge.example/cdn/${a.bundle}/logo.png?key=${a.key}&route=edge`);
      r = await vm(`/cdn/${a.bundle}/mid.bin?key=${a.key}`, HTML);
      assert.equal(r.status, 200, 'normal files stream from the server');
      assert.ok(Buffer.from(await r.arrayBuffer()).equals(mid));
      r = await vm(`/cdn/${a.bundle}/big.bin?key=${a.key}`, HTML);
      assert.equal(r.status, 307);
      const loc = new URL(r.headers.get('location'));
      assert.equal(loc.origin + loc.pathname, 'https://edge.example/get.html');
      const hp = new URLSearchParams(loc.hash.slice(1));
      assert.equal(hp.get('f'), 'big.bin');
      assert.equal(Number(hp.get('s')), big.length);
      assert.equal(hp.get('src'), 'https://edge.example');
      assert.match(hp.get('native'), /route=native&download=1$/);
      r = await vm(`/cdn/${a.bundle}/big.bin?key=${a.key}`);
      assert.equal(r.status, 200, 'tools that are not browsers get the file directly');
      await r.arrayBuffer();
      r = await vm(`/cdn/${a.bundle}/big.bin?key=${a.key}`, { Range: 'bytes=10-99', ...HTML });
      assert.equal(r.status, 206, 'a chunk is served where it is asked');
      assert.ok(Buffer.from(await r.arrayBuffer()).equals(big.subarray(10, 100)));
      r = await vm(`/cdn/${a.bundle}/logo.png?key=${a.key}&route=native`);
      assert.equal(r.status, 200, 'route=native is honoured (no redirect loop)');
      assert.ok(Buffer.from(await r.arrayBuffer()).equals(logo));

      // Edge side
      const call = (p, headers = {}) => edge(new Request('https://edge.example' + p, { headers }));
      r = await call(`/cdn/${a.bundle}/logo.png?key=${a.key}&route=edge`);
      assert.equal(r.status, 200);
      assert.ok(Buffer.from(await r.arrayBuffer()).equals(logo));
      r = await call(`/cdn/${a.bundle}/mid.bin?key=${a.key}`, HTML);
      assert.equal(r.status, 307);
      assert.equal(r.headers.get('location'), `${env.base}/cdn/${a.bundle}/mid.bin?key=${a.key}&route=native`);
      r = await call(`/cdn/${a.bundle}/big.bin?key=${a.key}`, HTML);
      assert.equal(r.status, 307);
      assert.match(r.headers.get('location'), /^https:\/\/edge\.example\/get\.html#/);
      // What the chunked downloader does: parallel Range requests with the key in a header.
      const parts = await Promise.all([0, 1, 2, 3, 4, 5, 6].map(async (i) => {
        const x = await call(`/cdn/${a.bundle}/big.bin`, { 'X-FF-Key': a.key, Range: `bytes=${i * 1048576}-${(i + 1) * 1048576 - 1}` });
        assert.equal(x.status, 206);
        return Buffer.from(await x.arrayBuffer());
      }));
      assert.ok(Buffer.concat(parts).equals(big), 'chunks reassemble into the file');
    } finally {
      delete process.env.FF_ORIGIN;
      delete process.env.FF_ROUTE_SMALL_MB;
      delete process.env.FF_ROUTE_XL_MB;
    }
  }, { edgeUrl: 'https://edge.example', routeSmallBytes: 1024 * 1024, routeXlBytes: 5 * 1024 * 1024 });
});

test('the chunked downloader page is identical on the server and on Vercel', () => {
  assert.equal(fs.readFileSync(path.join(root, 'docs/get.html'), 'utf8'), fs.readFileSync(path.join(root, 'vercel/get.html'), 'utf8'));
});

test('CDN public uploads: human check instead of a token, key only at the end, limits per network', { timeout: 60000 }, async () => {
  await withCdn(async (env) => {
    const human = async () => {
      const core = loadWidgetCore();
      const { challenge } = await (await j(env.base, '/captcha/challenge', { sitekey: 'ff_site_cdn' })).json();
      const nonce = String(core.solve(`${challenge.id}.${challenge.salt}.`, challenge.difficulty, 0, 1e9));
      const out = await (await j(env.base, '/captcha/verify', { sitekey: 'ff_site_cdn', challenge, nonce, signals: HUMAN, trace: humanTrace(), hp: '' })).json();
      assert.ok(out.token, JSON.stringify(out));
      return out.token;
    };
    const up = (name, body, h = {}, q = '') => fetch(`${env.base}/cdn/upload?name=${name}${q}`, { method: 'PUT', headers: h, body });

    let r = await up('a.txt', 'x');
    assert.equal(r.status, 403);
    assert.equal((await r.json()).error, 'human_check_required', 'no token and no human check: refused');

    const tok = await human();
    r = await up('a.txt', 'first file', { 'X-FF-Captcha': tok });
    assert.equal(r.status, 201);
    const first = await r.json();
    assert.equal(first.key, undefined);
    assert.match(first.ticket, /^fft_/);
    assert.equal((await up('b.txt', 'x', { 'X-FF-Captcha': tok })).status, 403, 'a human check works once');
    assert.equal((await up('b.txt', 'second file', { 'X-FF-Ticket': first.ticket })).status, 201, 'the rest of the batch uses the ticket');
    assert.equal((await up('c.txt', 'x', { 'X-FF-Ticket': first.ticket }, '&tier=vm')).status, 403, 'choosing a store is for the owner');
    assert.equal((await up('c.txt', 'x', { 'X-FF-Ticket': 'fft_' + 'A'.repeat(80) })).status, 403, 'forged tickets are refused');
    assert.equal((await up('big.bin', crypto.randomBytes(3000), { 'X-FF-Ticket': first.ticket })).status, 413, 'public file size limit');

    const fin = await (await fetch(`${env.base}/cdn/finish`, { method: 'POST', headers: { 'X-FF-Ticket': first.ticket } })).json();
    assert.match(fin.key, /^ffk_/);
    assert.deepEqual(fin.files.map((f) => f.name).sort(), ['a.txt', 'b.txt']);
    const got = await fetch(`${env.base}/cdn/${fin.bundle}/b.txt?key=${fin.key}`);
    assert.equal(await got.text(), 'second file');

    assert.equal((await up('d.txt', 'x', { 'X-FF-Ticket': first.ticket })).status, 429, 'daily file limit per network');
    assert.equal((await up('d.txt', 'owner is not limited', { Authorization: 'Bearer owner-token' })).status, 201);
  }, { publicFileMaxBytes: 2000, publicDayFiles: 2 });
});
