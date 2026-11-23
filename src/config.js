import fs from 'node:fs';
import crypto from 'node:crypto';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');

function int(v, d) {
  const n = parseInt(v, 10);
  return Number.isFinite(n) ? n : d;
}

function readJson(file) {
  try {
    return JSON.parse(fs.readFileSync(file, 'utf8'));
  } catch {
    return null;
  }
}

function parseProviders(list) {
  return list
    .split(',')
    .map((s) => s.trim())
    .filter(Boolean)
    .map((s) => {
      const [host, port] = s.split(':');
      return { host, port: port ? int(port, 123) : 123 };
    });
}

export const DEFAULT_TIME_PROVIDERS = [
  { host: 'time.google.com', port: 123 },
  { host: 'time.apple.com', port: 123 },
  { host: 'time.windows.com', port: 123 },
  { host: 'time.cloudflare.com', port: 123 },
  { host: 'time.nist.gov', port: 123 },
  { host: 'pool.ntp.org', port: 123 },
];

export function loadConfig(overrides = {}) {
  const env = process.env;
  const warnings = [];

  let secret = env.FF_SECRET;
  if (!secret) {
    secret = crypto.randomBytes(32).toString('hex');
    warnings.push('FF_SECRET is not set: using a random secret. CAPTCHA tokens will not survive restarts or work across instances.');
  }

  let sites =
    (env.FF_SITES && JSON.parse(env.FF_SITES)) ||
    readJson(env.FF_SITES_FILE || path.join(root, 'config', 'sites.json'));
  if (!sites) {
    sites = { ff_demo_site: { secret: 'ff_demo_secret', origins: [] } };
    warnings.push('No config/sites.json found: only the public demo site key "ff_demo_site" is enabled. Do not use it in production.');
  }


  const cfg = {
    root,
    docsDir: path.join(root, 'docs'),
    port: int(env.PORT, 8787),
    host: env.HOST || '0.0.0.0',
    trustProxy: env.TRUST_PROXY === '1',
    secret,
    sites,
    captchaBaseBits: int(env.FF_CAPTCHA_BITS, 16),
    quotaSoft: int(env.FF_QUOTA_SOFT, 1),
    puzzleMinMs: int(env.FF_PUZZLE_MIN_MS, 800),
    quotaHard: int(env.FF_QUOTA_HARD, 8),
    ntp: {
      enabled: env.FF_NTP !== '0',
      port: int(env.NTP_PORT, 123),
    },
    envtime: {
      providers: env.FF_TIME_PROVIDERS ? parseProviders(env.FF_TIME_PROVIDERS) : DEFAULT_TIME_PROVIDERS,
      minVotes: int(env.FF_TIME_MIN_VOTES, 3),
      graceMs: int(env.FF_TIME_GRACE_MS, 60),
      hardTimeoutMs: int(env.FF_TIME_TIMEOUT_MS, 1200),
      toleranceMs: int(env.FF_TIME_TOLERANCE_MS, 50),
      pollMs: int(env.FF_TIME_POLL_MS, 32000),
    },
    warnings,
  };
  return deepMerge(cfg, overrides);
}

function deepMerge(a, b) {
  for (const [k, v] of Object.entries(b)) {
    if (v && typeof v === 'object' && !Array.isArray(v) && a[k] && typeof a[k] === 'object') deepMerge(a[k], v);
    else a[k] = v;
  }
  return a;
}
