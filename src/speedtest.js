import crypto from 'node:crypto';
import { CORS, httpError, send, clientIp } from './util.js';

// Pre-generated random block, streamed repeatedly: cheap on CPU and not compressible by
// accident even if a proxy tries to gzip it.
const BLOCK = crypto.randomBytes(64 * 1024);

export function createSpeedtest({ node, servers, maxBytes, trustProxy }) {
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

  function up(req, res) {
    const started = process.hrtime.bigint();
    let received = 0;
    let aborted = false;
    req.on('data', (c) => {
      received += c.length;
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

  function info(req, res) {
    send(res, 200, { node: registry()[0], ip: clientIp(req, trustProxy), maxBytes }, CORS);
  }

  function list(req, res) {
    send(res, 200, { servers: registry() }, CORS);
  }

  return { ping, down, up, info, list, registry };
}
