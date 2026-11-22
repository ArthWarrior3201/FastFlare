import http from 'node:http';
import fs from 'node:fs';
import path from 'node:path';
import { pathToFileURL } from 'node:url';
import { loadConfig } from './config.js';
import { CORS, send, readBody, clientIp, httpError } from './util.js';
import { createCaptcha } from './captcha.js';
import { createSpeedtest } from './speedtest.js';
import { EnvTime, formatTime } from './envtime.js';
import { startNtpServer } from './ntp.js';

const MIME = {
  '.html': 'text/html; charset=utf-8',
  '.js': 'text/javascript; charset=utf-8',
  '.css': 'text/css; charset=utf-8',
  '.json': 'application/json; charset=utf-8',
  '.svg': 'image/svg+xml',
  '.png': 'image/png',
  '.ico': 'image/x-icon',
  '.txt': 'text/plain; charset=utf-8',
};

export async function createApp(overrides = {}) {
  const config = loadConfig(overrides);
  const log = overrides.quiet ? () => {} : (...a) => console.log('[fastflare]', ...a);

  const captcha = createCaptcha({
    secret: config.secret,
    sites: config.sites,
    trustProxy: config.trustProxy,
    baseBits: config.captchaBaseBits,
    quotaSoft: config.quotaSoft,
    quotaHard: config.quotaHard,
    puzzleMinMs: config.puzzleMinMs,
  });
  const speed = createSpeedtest({
    node: config.node,
    servers: config.servers,
    maxBytes: config.speed.maxBytes,
    trustProxy: config.trustProxy,
  });
  const envtime = new EnvTime({ ...config.envtime, query: overrides.timeQuery, log });

  function serveStatic(req, res, pathname) {
    let rel = decodeURIComponent(pathname);
    if (rel.endsWith('/')) rel += 'index.html';
    const file = path.resolve(config.docsDir, '.' + rel);
    if (file !== config.docsDir && !file.startsWith(config.docsDir + path.sep)) throw httpError(403, 'forbidden');
    let target = file;
    try {
      if (fs.statSync(target).isDirectory()) target = path.join(target, 'index.html');
    } catch {
      if (!path.extname(target)) target += '.html';
    }
    if (!fs.existsSync(target)) throw httpError(404, 'not_found');
    const type = MIME[path.extname(target)] || 'application/octet-stream';
    res.writeHead(200, { 'Content-Type': type, 'Cache-Control': 'public, max-age=300', ...CORS });
    fs.createReadStream(target).pipe(res);
  }

  async function timeHandler(req, res, url) {
    const tz = url.searchParams.get('tz') || 'UTC';
    // Validate before doing any work.
    let probe;
    try {
      probe = formatTime(0, tz);
    } catch {
      throw httpError(400, 'unknown_timezone');
    }
    void probe;
    if (!envtime.synced) await envtime.ready(1500);
    else if (url.searchParams.get('fresh') === '1') await envtime.refreshIfAllowed();
    else if (envtime.status().lastSyncAgeMs > envtime.staleMs) envtime.round().catch(() => {});

    const ms = envtime.now(); // taken last, so processing above is not part of the answer's age
    const fmt = formatTime(ms, tz);
    const body = {
      unixMs: Math.floor(ms),
      unix: Math.floor(ms / 1000),
      utc: new Date(Math.floor(ms)).toISOString(),
      ...fmt,
      synced: envtime.synced,
      uncertaintyMs: envtime.uncertaintyMs(),
      sources: envtime.lastRound ? { used: envtime.lastRound.used.map((s) => s.host), kicked: envtime.lastRound.kicked.map((s) => s.host) } : null,
    };
    send(res, 200, body, { ...CORS, 'X-FastFlare-Time': String(body.unixMs) });
  }

  const server = http.createServer(async (req, res) => {
    try {
      const url = new URL(req.url, 'http://x');
      const p = url.pathname;
      if (req.method === 'OPTIONS') {
        res.writeHead(204, CORS);
        return res.end();
      }
      const ip = clientIp(req, config.trustProxy);

      if (req.method === 'GET' && p === '/health') return send(res, 200, { ok: true }, CORS);

      // --- Service 1: bot protection -------------------------------------------------------
      if (p === '/captcha/challenge' && req.method === 'POST') {
        const b = await readBody(req);
        return send(res, 200, captcha.issue({ sitekey: b.sitekey, ip, origin: req.headers.origin }), CORS);
      }
      if (p === '/captcha/verify' && req.method === 'POST') {
        const b = await readBody(req, 64 * 1024);
        const r = captcha.verify({
          sitekey: b.sitekey,
          challenge: b.challenge,
          nonce: b.nonce,
          signals: b.signals,
          trace: b.trace,
          hp: b.hp,
          ip,
          ua: String(req.headers['user-agent'] || ''),
          origin: req.headers.origin,
        });
        return send(res, 200, r, CORS);
      }
      if (p === '/captcha/puzzle' && req.method === 'POST') {
        const b = await readBody(req, 64 * 1024);
        const r = captcha.solvePuzzle({ sitekey: b.sitekey, id: b.id, x: b.x, trace: b.trace, keys: b.keys, ip, origin: req.headers.origin });
        return send(res, 200, r, CORS);
      }
      // Server-to-server only: deliberately no CORS headers (it takes your secret key).
      if (p === '/captcha/siteverify' && req.method === 'POST') {
        const b = await readBody(req);
        return send(res, 200, captcha.siteverify({ secret: b.secret, token: b.response ?? b.token, remoteip: b.remoteip }));
      }

      // --- Service 2: speed test -----------------------------------------------------------
      if (p === '/speed/ping') return speed.ping(req, res);
      if (p === '/speed/down' && req.method === 'GET') return speed.down(req, res, url);
      if (p === '/speed/up' && req.method === 'POST') return speed.up(req, res);
      if (p === '/speed/servers') return speed.list(req, res);
      if (p === '/speed/info') return speed.info(req, res);

      // --- Service 3: EnvTime ---------------------------------------------------------------
      if (p === '/time' && req.method === 'GET') return await timeHandler(req, res, url);
      if (p === '/time/status') return send(res, 200, envtime.status(), CORS);

      if (req.method === 'GET' || req.method === 'HEAD') return serveStatic(req, res, p);
      throw httpError(404, 'not_found');
    } catch (e) {
      if (res.headersSent) return res.destroy();
      const status = e.status || 500;
      if (status === 500) console.error(e);
      send(res, status, { error: e.code || 'internal_error', ...(e.reasons && config.debug ? { reasons: e.reasons } : {}) }, CORS);
    }
  });

  let ntp = null;
  async function start() {
    await new Promise((resolve, reject) => {
      server.once('error', reject);
      server.listen(config.port, config.host, resolve);
    });
    const port = server.address().port;
    envtime.start();
    if (config.ntp.enabled) {
      try {
        ntp = await startNtpServer({
          port: config.ntp.port,
          clock: () => ({
            ms: envtime.now(),
            synced: envtime.synced,
            rootDelayMs: envtime.lastRound?.bestRttMs ?? 0,
            dispersionMs: envtime.uncertaintyMs() ?? 1000,
            refMs: envtime.synced ? envtime.now() - (envtime.status().lastSyncAgeMs || 0) : 0,
          }),
          log,
        });
        log(`NTP server listening on udp/${ntp.port}`);
      } catch (e) {
        log(`NTP server NOT started (${e.code || e.message}). UDP port ${config.ntp.port} needs privileges; set NTP_PORT or FF_NTP=0.`);
      }
    }
    return { port, ntpPort: ntp?.port ?? null };
  }

  async function stop() {
    envtime.stop();
    captcha.close();
    ntp?.close();
    await new Promise((r) => server.close(r));
    server.closeAllConnections?.();
  }

  return { server, config, captcha, speed, envtime, start, stop, log };
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  const app = await createApp();
  for (const w of app.config.warnings) app.log('WARNING:', w);
  const { port } = await app.start();
  app.log(`listening on http://${app.config.host}:${port}  (docs, widget and demos are served at /)`);
  for (const sig of ['SIGINT', 'SIGTERM']) process.on(sig, () => app.stop().then(() => process.exit(0)));
}
