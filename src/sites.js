// Self-serve site keys. A developer submits a name and the website addresses that will show the
// widget; the server creates a site key and a secret, saves them, and the key works right away.
import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';
import { httpError } from './util.js';

const DAY = 24 * 60 * 60 * 1000;
const MAX_ORIGINS = 10;

const LOCAL_HOSTS = new Set(['localhost', '127.0.0.1', '[::1]']);

// Turns "example.com", "https://example.com/page" or "http://localhost:3000" into an origin.
export function normalizeOrigin(input) {
  let s = String(input || '').trim();
  if (!s) return null;
  if (!/^[a-z]+:\/\//i.test(s)) s = (/^(localhost|127\.0\.0\.1)(:|$)/i.test(s) ? 'http://' : 'https://') + s;
  let u;
  try {
    u = new URL(s);
  } catch {
    return null;
  }
  if (u.protocol !== 'https:' && u.protocol !== 'http:') return null;
  if (u.username || u.password) return null;
  const host = u.hostname.toLowerCase();
  if (u.protocol === 'http:' && !LOCAL_HOSTS.has(host) && !host.endsWith('.localhost')) return null; // http only for local testing
  if (!host.includes('.') && !LOCAL_HOSTS.has(host) && !host.endsWith('localhost')) return null;
  return u.origin;
}

export function createSiteRegistry({ sites, dataDir, open = true, perIpPerDay = 5, maxSites = 5000, now = Date.now, log = () => {} }) {
  const file = dataDir ? path.join(dataDir, 'registered-sites.json') : null;
  const recent = new Map(); // ip -> [timestamps]
  let registered = {};

  if (file) {
    try {
      registered = JSON.parse(fs.readFileSync(file, 'utf8')) || {};
    } catch (e) {
      if (e.code !== 'ENOENT') log(`could not read ${file}: ${e.message}`);
    }
    for (const [key, site] of Object.entries(registered)) if (!Object.prototype.hasOwnProperty.call(sites, key)) sites[key] = site;
  }

  function save() {
    if (!file) return;
    fs.mkdirSync(dataDir, { recursive: true, mode: 0o700 });
    const tmp = file + '.tmp';
    fs.writeFileSync(tmp, JSON.stringify(registered, null, 2), { mode: 0o600 });
    fs.renameSync(tmp, file);
  }

  function register({ name, origins, ip }) {
    if (!open) throw httpError(403, 'signup_closed');
    const label = String(name || '').trim().slice(0, 80);
    if (!label) throw httpError(400, 'name_required');
    const list = (Array.isArray(origins) ? origins : String(origins || '').split(/[\s,]+/)).filter(Boolean);
    if (!list.length) throw httpError(400, 'origins_required');
    if (list.length > MAX_ORIGINS) throw httpError(400, 'too_many_origins');
    const clean = [];
    for (const o of list) {
      const n = normalizeOrigin(o);
      if (!n) {
        const e = httpError(400, 'invalid_origin');
        e.detail = String(o).slice(0, 200);
        throw e;
      }
      if (!clean.includes(n)) clean.push(n);
    }

    const t = now();
    const mine = (recent.get(ip) || []).filter((x) => t - x < DAY);
    if (mine.length >= perIpPerDay) throw httpError(429, 'too_many_signups');
    if (Object.keys(registered).length >= maxSites) throw httpError(503, 'signup_full');

    let sitekey;
    do sitekey = 'ff_site_' + crypto.randomBytes(9).toString('base64url');
    while (Object.prototype.hasOwnProperty.call(sites, sitekey));
    const secret = 'ff_secret_' + crypto.randomBytes(24).toString('base64url');
    const site = { secret, origins: clean, name: label, created: new Date(t).toISOString() };

    registered[sitekey] = site;
    try {
      save();
    } catch (e) {
      delete registered[sitekey];
      log(`could not save site keys: ${e.message}`);
      throw httpError(500, 'storage_unavailable');
    }
    sites[sitekey] = site;
    mine.push(t);
    recent.set(ip, mine);
    log(`registered ${sitekey} (${label}) for ${clean.join(', ')}`);
    return { sitekey, secret, origins: clean, name: label };
  }

  return { register, count: () => Object.keys(registered).length, file };
}
