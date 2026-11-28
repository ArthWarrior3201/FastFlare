#!/usr/bin/env node
/*!
 * FastFlare Gate: the small backend that sits between your visitors and your site.
 *
 *   1. It shows the FastFlare "I'm not a robot" check.
 *   2. When the visitor clicks, the FastFlare network decides: let through, challenge with a
 *      puzzle, or block.
 *   3. On a pass, the widget sends the token here; the gate confirms it with FastFlare using your
 *      secret, gives the visitor a pass cookie, and sends them to redirect_to_if_pass.
 *      On a fail, the widget asks the visitor to try again.
 *
 * Needs only Node.js 18 or newer. No packages to install.
 *
 *   node fastflare-gate.mjs --sitekey=ff_site_xxx --secret=ff_secret_xxx
 *   node fastflare-gate.mjs --sitekey=... --secret=... --redirect=/dashboard --upstream=http://localhost:8080
 *
 * Every option can also be an environment variable (FF_SITEKEY, FF_SECRET, FF_API, PORT,
 * REDIRECT_TO_IF_PASS, FF_UPSTREAM, FF_PASS_MINUTES, FF_TITLE, FF_CHECK_IP, TRUST_PROXY).
 *
 * Docs: https://arthwarrior3201.github.io/FastFlare/quickstart.html
 */
import http from 'node:http';
import https from 'node:https';
import crypto from 'node:crypto';
import { pathToFileURL } from 'node:url';

export const DEFAULT_API = 'https://129-225-87-247.sslip.io';
const COOKIE = 'ff_pass';

// ---- Token check: usable on its own from any Node backend --------------------------------------
// Returns { success: true, method, score } or { success: false, error }.
export async function verifyToken(token, { secret, api = DEFAULT_API, remoteip, timeoutMs = 8000 } = {}) {
  if (!secret) throw new Error('verifyToken: secret is required');
  if (typeof token !== 'string' || !token) return { success: false, error: 'missing-input-response' };
  let res;
  try {
    res = await fetch(api.replace(/\/$/, '') + '/captcha/siteverify', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ secret, response: token, ...(remoteip ? { remoteip } : {}) }),
      signal: AbortSignal.timeout(timeoutMs),
    });
  } catch {
    return { success: false, error: 'fastflare-unreachable' };
  }
  const j = await res.json().catch(() => ({}));
  if (j.success) return { success: true, method: j.method || 'invisible', score: j.score, challenge_ts: j.challenge_ts };
  return { success: false, error: (j['error-codes'] && j['error-codes'][0]) || j.error || 'rejected' };
}

// ---- The gate -----------------------------------------------------------------------------------
export function createGate(options = {}) {
  const o = {
    sitekey: options.sitekey,
    secret: options.secret,
    api: (options.api || DEFAULT_API).replace(/\/$/, ''),
    redirect: options.redirect || '/welcome',
    upstream: options.upstream ? new URL(options.upstream) : null,
    passMinutes: Number(options.passMinutes) || 30,
    title: options.title || 'Checking your browser',
    checkIp: !!options.checkIp,
    trustProxy: !!options.trustProxy,
  };
  if (!o.sitekey || !o.secret) throw new Error('FastFlare Gate needs a site key and a secret (--sitekey and --secret).');
  const builtInWelcome = !o.upstream && o.redirect === '/welcome';

  const sign = (exp) => crypto.createHmac('sha256', o.secret).update('ff-pass|' + exp).digest('base64url');
  function makePass() {
    const exp = Date.now() + o.passMinutes * 60_000;
    return `${exp}.${sign(exp)}`;
  }
  function hasPass(req) {
    const m = String(req.headers.cookie || '').match(/(?:^|;\s*)ff_pass=([^;]+)/);
    if (!m) return false;
    const [exp, sig] = m[1].split('.');
    if (!exp || !sig || Number(exp) < Date.now()) return false;
    const want = Buffer.from(sign(exp));
    const got = Buffer.from(sig);
    return want.length === got.length && crypto.timingSafeEqual(want, got);
  }
  function visitorIp(req) {
    if (o.trustProxy) {
      const f = req.headers['cf-connecting-ip'] || String(req.headers['x-forwarded-for'] || '').split(',')[0].trim();
      if (f) return String(f);
    }
    return String(req.socket.remoteAddress || '').replace(/^::ffff:/, '');
  }
  const isHttps = (req) => req.socket.encrypted || (o.trustProxy && req.headers['x-forwarded-proto'] === 'https');

  // Only same-site paths may be chosen by the page; anything else uses the configured target.
  function pickRedirect(asked) {
    if (typeof asked === 'string' && /^\/(?![/\\])/.test(asked) && asked.length < 2000) return asked;
    return o.redirect;
  }

  function json(res, status, obj, headers = {}) {
    const body = JSON.stringify(obj);
    res.writeHead(status, { 'Content-Type': 'application/json; charset=utf-8', 'Cache-Control': 'no-store', ...headers });
    res.end(body);
  }
  function html(res, status, body) {
    res.writeHead(status, { 'Content-Type': 'text/html; charset=utf-8', 'Cache-Control': 'no-store', 'X-Frame-Options': 'DENY' });
    res.end(body);
  }
  async function readJson(req) {
    let size = 0;
    const chunks = [];
    for await (const c of req) {
      size += c.length;
      if (size > 16 * 1024) throw new Error('too large');
      chunks.push(c);
    }
    try {
      return JSON.parse(Buffer.concat(chunks).toString('utf8') || '{}');
    } catch {
      return {};
    }
  }

  async function onVerify(req, res) {
    const b = await readJson(req).catch(() => ({}));
    const r = await verifyToken(b.token, { secret: o.secret, api: o.api, remoteip: o.checkIp ? visitorIp(req) : undefined });
    if (!r.success) return json(res, r.error === 'fastflare-unreachable' ? 502 : 403, { success: false, error: r.error });
    const cookie = `${COOKIE}=${makePass()}; Path=/; HttpOnly; SameSite=Lax; Max-Age=${o.passMinutes * 60}${isHttps(req) ? '; Secure' : ''}`;
    json(res, 200, { success: true, method: r.method, redirect: pickRedirect(b.redirect) }, { 'Set-Cookie': cookie });
  }

  function proxy(req, res) {
    const u = o.upstream;
    const lib = u.protocol === 'https:' ? https : http;
    const up = lib.request(
      {
        protocol: u.protocol,
        hostname: u.hostname,
        port: u.port || (u.protocol === 'https:' ? 443 : 80),
        method: req.method,
        path: req.url,
        headers: { ...req.headers, host: u.host, 'x-forwarded-for': visitorIp(req), 'x-fastflare-pass': '1' },
      },
      (ur) => {
        res.writeHead(ur.statusCode || 502, ur.headers);
        ur.pipe(res);
      },
    );
    up.on('error', () => {
      if (!res.headersSent) html(res, 502, page('Site unavailable', '<p>The site behind FastFlare Gate is not answering right now.</p>'));
      else res.destroy();
    });
    req.pipe(up);
  }

  function gatePage(redirectTo) {
    const esc = (s) => String(s).replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' })[c]);
    return page(
      o.title,
      `<p class="lead">Complete the check to continue.</p>
  <div class="ff-captcha" data-sitekey="${esc(o.sitekey)}" data-api="${esc(o.api)}" data-verify="/fastflare/verify" data-redirect="${esc(redirectTo)}"></div>
  <noscript><p class="warn">Please turn on JavaScript to continue.</p></noscript>
  <script src="${esc(o.api)}/fastflare.js" async defer></script>`,
    );
  }

  async function handler(req, res) {
    try {
      const url = new URL(req.url, 'http://gate');
      if (url.pathname === '/fastflare/verify' && req.method === 'POST') return await onVerify(req, res);
      if (url.pathname === '/fastflare/health') return json(res, 200, { ok: true });
      const passed = hasPass(req);

      if (o.upstream) {
        if (passed) return proxy(req, res);
        if (req.method === 'GET' || req.method === 'HEAD') return html(res, 403, gatePage(req.url));
        return json(res, 403, { error: 'fastflare_check_required' });
      }

      if (builtInWelcome && url.pathname === '/welcome') {
        if (!passed) {
          res.writeHead(302, { Location: '/', 'Cache-Control': 'no-store' });
          return res.end();
        }
        return html(res, 200, page('Verified', '<p class="lead">Verification complete. This page is only shown to visitors who passed the check.</p><p class="ok">&#10003; Verified</p>'));
      }
      if (url.pathname === '/' && (req.method === 'GET' || req.method === 'HEAD')) return html(res, 200, gatePage(o.redirect));
      return json(res, 404, { error: 'not_found' });
    } catch (e) {
      console.error('[fastflare-gate]', e);
      if (!res.headersSent) json(res, 500, { error: 'internal_error' });
    }
  }

  const server = http.createServer(handler);
  return {
    handler,
    server,
    hasPass,
    options: o,
    listen: (port = 3000, host) => new Promise((resolve) => server.listen(port, host, () => resolve(server.address()))),
    close: () => new Promise((resolve) => server.close(resolve)),
  };
}

function page(title, inner) {
  return `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="robots" content="noindex">
<title>${title}</title>
<style>
  :root { color-scheme: light dark; }
  body { margin: 0; min-height: 100vh; display: grid; place-items: center; font: 16px/1.5 system-ui, -apple-system, "Segoe UI", Roboto, sans-serif; background: #0b0e1f; color: #e8ebf7; }
  main { width: min(420px, 92vw); text-align: center; padding: 40px 28px; border-radius: 20px; background: #12162a; border: 1px solid #2c3350; box-shadow: 0 20px 60px rgba(0,0,0,.45); }
  h1 { font-size: 22px; margin: 0 0 6px; }
  .lead { color: #8b93b5; margin: 0 0 24px; }
  .ff-captcha { display: flex; justify-content: center; }
  .ok { color: #22b573; font-weight: 700; font-size: 20px; }
  .warn { color: #f5b942; }
  footer { margin-top: 26px; font-size: 12px; color: #6b7280; }
</style>
</head>
<body>
<main>
  <h1>${title}</h1>
  ${inner}
  <footer>Protected by FastFlare</footer>
</main>
</body>
</html>`;
}

// ---- Command line -----------------------------------------------------------------------------
function args(argv) {
  const out = {};
  for (const a of argv) {
    const m = a.match(/^--([a-z-]+)(?:=(.*))?$/i);
    if (m) out[m[1].toLowerCase()] = m[2] === undefined ? '1' : m[2];
  }
  return out;
}

async function main() {
  const a = args(process.argv.slice(2));
  const env = process.env;
  const opts = {
    sitekey: a.sitekey || env.FF_SITEKEY,
    secret: a.secret || env.FF_SECRET,
    api: a.api || env.FF_API || DEFAULT_API,
    redirect: a.redirect || env.REDIRECT_TO_IF_PASS,
    upstream: a.upstream || env.FF_UPSTREAM,
    passMinutes: a['pass-minutes'] || env.FF_PASS_MINUTES,
    title: a.title || env.FF_TITLE,
    checkIp: (a['check-ip'] || env.FF_CHECK_IP) === '1',
    trustProxy: (a['trust-proxy'] || env.TRUST_PROXY) === '1',
  };
  const port = Number(a.port || env.PORT) || 3000;
  let gate;
  try {
    gate = createGate(opts);
  } catch (e) {
    console.error(e.message + '\nGet keys at https://arthwarrior3201.github.io/FastFlare/quickstart.html');
    process.exit(1);
  }

  // Check the keys before taking traffic: a dummy token tells a bad secret from a bad token.
  const probe = await verifyToken('check.only', { secret: opts.secret, api: gate.options.api });
  if (probe.error === 'invalid-input-secret') {
    console.error('FastFlare rejected this secret. Check --secret (it must belong to --sitekey).');
    process.exit(1);
  }
  if (probe.error === 'fastflare-unreachable') console.warn(`Warning: could not reach ${gate.options.api} right now. Visitors will see "try again" until it is back.`);

  await gate.listen(port);
  const local = `http://localhost:${port}`;
  console.log(`FastFlare Gate is running at ${local}`);
  console.log(gate.options.upstream ? `Visitors who pass go through to ${gate.options.upstream.origin}` : `Visitors who pass go to ${gate.options.redirect}`);
  console.log(`Make sure ${local} (and your real site address) is listed for this site key, or the check will refuse it.`);
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) main();
