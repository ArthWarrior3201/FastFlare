import crypto from 'node:crypto';
import { CORS, httpError, send, clientIp } from './util.js';

// Pre-generated random block, streamed repeatedly: cheap on CPU and not compressible by
// accident even if a proxy tries to gzip it.
const BLOCK = crypto.randomBytes(64 * 1024);

// Upload is measured where it lands: the server records how many bytes it received in each 100 ms
// slot, per test session, so data sitting in buffers on the way never counts as "sent".
const SLOT_MS = 100;
const SESSION_TTL = 120_000;

export function createSpeedtest({ node, servers, maxBytes, trustProxy }) {
  const sessions = new Map(); // sid -> { start, slots: Map(slot -> bytes), touched }
  const sweep = setInterval(() => {
    const t = Date.now();
    for (const [k, v] of sessions) if (t - v.touched > SESSION_TTL) sessions.delete(k);
  }, 30_000);
  sweep.unref();
  const validSid = (sid) => typeof sid === 'string' && /^[a-z0-9]{6,32}$/.test(sid);

  function registry() {
    const self = {
      id: node.id,
      provider: node.provider,
      city: node.city,
      country: node.country,
      url: node.publicUrl || '',
    };
    const all = [self, ...servers.filter((s) => s && s.provider && s.city && s.url)];
    return all.map((s, i) => ({
      id: s.id || `${s.provider}-${s.city}`.toLowerCase().replace(/[^a-z0-9]+/g, '-') + (i ? '' : ''),
      provider: s.provider,
      city: s.city,
      country: s.country || '',
      url: s.url,
    }));
  }

  function ping(req, res) {
    res.writeHead(200, { 'Content-Length': 0, 'Cache-Control': 'no-store', ...CORS });
    res.end();
  }

  function down(req, res, url) {
    const requested = parseInt(url.searchParams.get('bytes') || '', 10);
    if (!Number.isFinite(requested) || requested < 0) throw httpError(400, 'bad_bytes');
    const bytes = Math.min(requested, maxBytes);
    res.writeHead(200, {
      'Content-Type': 'application/octet-stream',
      'Content-Length': bytes,
      'Content-Encoding': 'identity',
      'Cache-Control': 'no-store',
      ...CORS,
    });
    let left = bytes;
    const pump = () => {
      while (left > 0 && !res.destroyed) {
        const n = Math.min(left, BLOCK.length);
        const ok = res.write(n === BLOCK.length ? BLOCK : BLOCK.subarray(0, n));
        left -= n;
        if (!ok) {
          res.once('drain', pump);
          return;
        }
      }
      if (!res.destroyed) res.end();
    };
    pump();
  }

  function up(req, res, url) {
    const started = process.hrtime.bigint();
    let received = 0;
    let aborted = false;
    const sid = url && url.searchParams.get('sid');
    let session = null;
    if (validSid(sid)) {
      session = sessions.get(sid);
      if (!session && sessions.size < 2000) sessions.set(sid, (session = { start: Date.now(), slots: new Map(), touched: Date.now() }));
    }
    req.on('data', (c) => {
      received += c.length;
      if (session) {
        const t = Date.now();
        const slot = Math.floor((t - session.start) / SLOT_MS);
        session.slots.set(slot, (session.slots.get(slot) || 0) + c.length);
        session.touched = t;
      }
      if (received > maxBytes && !aborted) {
        aborted = true;
        send(res, 413, { error: 'payload_too_large' }, CORS);
        req.destroy();
      }
    });
    req.on('end', () => {
      if (aborted) return;
      const ms = Number(process.hrtime.bigint() - started) / 1e6;
      send(res, 200, { bytes: received, ms }, { ...CORS, 'Server-Timing': `ff;dur=${ms.toFixed(2)}` });
    });
    req.on('error', () => {});
  }

  function upstats(req, res, url) {
    const sid = url.searchParams.get('sid');
    const session = validSid(sid) ? sessions.get(sid) : null;
    if (!session) throw httpError(404, 'unknown_session');
    sessions.delete(sid);
    const slots = [...session.slots.entries()].sort((a, b) => a[0] - b[0]);
    send(res, 200, { slotMs: SLOT_MS, slots }, CORS);
  }

  function info(req, res) {
    send(res, 200, { node: registry()[0], ip: clientIp(req, trustProxy), maxBytes }, CORS);
  }

  function list(req, res) {
    send(res, 200, { servers: registry() }, CORS);
  }

  return { ping, down, up, upstats, info, list, registry, close: () => clearInterval(sweep) };
}
