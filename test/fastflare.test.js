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
import { leadingZeroBits } from '../src/captcha.js';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');

function loadWidgetCore() {
  const ctx = vm.createContext({});
  vm.runInContext(fs.readFileSync(path.join(root, 'docs/fastflare.js'), 'utf8'), ctx);
  return ctx.FastFlare._pow();
}

const UA = 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0 Safari/537.36';
const HUMAN = { wd: false, lg: 2, sw: 1920, sh: 1080, pm: 30, kd: 2, tc: 0, sc: 1, fc: 1, pv: 12, dt: 3000 };

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

test('CAPTCHA: solve, verify, siteverify once, reject replay', async () => {
  await withApp(async (base) => {
    const core = loadWidgetCore();
    const { challenge } = await (await j(base, '/captcha/challenge', { sitekey: 'ff_demo_site' })).json();
    const nonce = core.solve(`${challenge.id}.${challenge.salt}.`, challenge.difficulty, 0, 1e7);
    const res = await j(base, '/captcha/verify', { sitekey: 'ff_demo_site', challenge, nonce: String(nonce), signals: HUMAN, hp: '' });
    const out = await res.json();
    assert.equal(out.ok, true);

    const check = (token, secret = 'ff_demo_secret') => j(base, '/captcha/siteverify', { secret, response: token }).then((r) => r.json());
    assert.equal((await check(out.token, 'wrong-secret'))['error-codes'][0], 'invalid-input-secret');
    assert.equal((await check(out.token)).success, true);
    assert.equal((await check(out.token)).success, false, 'tokens are single use');

    // Same challenge cannot be redeemed twice.
    const again = await j(base, '/captcha/verify', { sitekey: 'ff_demo_site', challenge, nonce: String(nonce), signals: HUMAN, hp: '' });
    assert.equal(again.status, 400);
  });
});

test('CAPTCHA: wrong proof, forged challenge, honeypot and automation are rejected', async () => {
  await withApp(async (base) => {
    const core = loadWidgetCore();
    const get = async () => (await (await j(base, '/captcha/challenge', { sitekey: 'ff_demo_site' })).json()).challenge;
    const solve = (c) => String(core.solve(`${c.id}.${c.salt}.`, c.difficulty, 0, 1e7));

    let c = await get();
    let r = await j(base, '/captcha/verify', { sitekey: 'ff_demo_site', challenge: c, nonce: '1', signals: HUMAN });
    assert.equal((await r.json()).error, 'bad_proof');

    c = await get();
    r = await j(base, '/captcha/verify', { sitekey: 'ff_demo_site', challenge: { ...c, difficulty: 1 }, nonce: '1', signals: HUMAN });
    assert.equal((await r.json()).error, 'bad_challenge');

    c = await get();
    r = await j(base, '/captcha/verify', { sitekey: 'ff_demo_site', challenge: c, nonce: solve(c), signals: HUMAN, hp: 'http://spam' });
    assert.equal(r.status, 403);

    c = await get();
    const bot = { wd: true, lg: 0, sw: 0, sh: 0, pm: 0, kd: 0, tc: 0, sc: 0, dt: 10 };
    r = await j(base, '/captcha/verify', { sitekey: 'ff_demo_site', challenge: c, nonce: solve(c), signals: bot });
    assert.equal(r.status, 403);

    r = await j(base, '/captcha/challenge', { sitekey: 'nope' });
    assert.equal(r.status, 400);
  });
});

test('CAPTCHA: signals claiming more time on page than the server observed are rejected', async () => {
  await withApp(async (base) => {
    const core = loadWidgetCore();
    const { challenge } = await (await j(base, '/captcha/challenge', { sitekey: 'ff_demo_site' })).json();
    const nonce = String(core.solve(`${challenge.id}.${challenge.salt}.`, challenge.difficulty, 0, 1e7));
    const r = await j(base, '/captcha/verify', { sitekey: 'ff_demo_site', challenge, nonce, signals: { ...HUMAN, dt: 60000 } });
    assert.equal(r.status, 403);
  });
});

test('CAPTCHA: borderline traffic gets a harder second challenge', async () => {
  await withApp(async (base) => {
    const core = loadWidgetCore();
    const { challenge } = await (await j(base, '/captcha/challenge', { sitekey: 'ff_demo_site' })).json();
    // Looks like a browser but reports no languages and no interaction: score lands in the step-up band.
    const shady = { wd: false, lg: 0, sw: 1920, sh: 1080, pm: 0, kd: 0, tc: 0, sc: 0, dt: 3000 };
    const nonce = String(core.solve(`${challenge.id}.${challenge.salt}.`, challenge.difficulty, 0, 1e7));
    const r1 = await (await j(base, '/captcha/verify', { sitekey: 'ff_demo_site', challenge, nonce, signals: shady })).json();
    assert.equal(r1.retry, true);
    assert.equal(r1.challenge.difficulty, challenge.difficulty + 3);
    assert.equal(r1.challenge.attempt, 1);
  });
});

test('Speed test: registry, ping, download size and upload accounting', async () => {
  await withApp(async (base) => {
    const list = await (await fetch(base + '/speed/servers')).json();
    assert.equal(list.servers[0].provider, 'Local');

    assert.equal((await fetch(base + '/speed/ping')).status, 200);

    const d = await fetch(base + '/speed/down?bytes=300000');
    assert.equal((await d.arrayBuffer()).byteLength, 300000);
    assert.equal((await fetch(base + '/speed/down?bytes=-1')).status, 400);

    const up = await (await fetch(base + '/speed/up', { method: 'POST', headers: { 'Content-Type': 'application/octet-stream' }, body: new Uint8Array(200000) })).json();
    assert.equal(up.bytes, 200000);

    const pre = await fetch(base + '/speed/up', { method: 'OPTIONS' });
    assert.equal(pre.status, 204);
    assert.equal(pre.headers.get('access-control-allow-origin'), '*');
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
