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
    publicUrl: (env.FF_PUBLIC_URL || '').replace(/\/$/, ''),
    dataDir: env.FF_DATA_DIR || path.join(root, 'data'),
    openSignup: env.FF_OPEN_SIGNUP !== '0',
    signupsPerIpPerDay: int(env.FF_SIGNUPS_PER_DAY, 5),
    cdn: {
      token: env.FF_CDN_TOKEN || '',
      edgeUrl: (env.FF_CDN_EDGE_URL || '').replace(/\/$/, ''),
      routeSmallBytes: int(env.FF_ROUTE_SMALL_MB, 25) * 1048576,
      routeXlBytes: int(env.FF_ROUTE_XL_MB, 500) * 1048576,
      maxBytes: int(env.FF_CDN_MAX_MB, 4096) * 1048576,
      smallMaxBytes: int(env.FF_CDN_SMALL_MB, 5) * 1048576,
      githubMaxBytes: int(env.FF_CDN_GITHUB_MAX_MB, 1024) * 1048576,
      vmCapBytes: int(env.FF_CDN_VM_MB, 20480) * 1048576,
      supabaseCapBytes: int(env.FF_CDN_SUPABASE_MB, 950) * 1048576,
      githubCapBytes: int(env.FF_CDN_GITHUB_MB, 4500) * 1048576,
      cacheBytes: int(env.FF_CDN_CACHE_MB, 2048) * 1048576,
      supabase: { url: env.FF_SUPABASE_URL || '', key: env.FF_SUPABASE_KEY || '', bucket: env.FF_SUPABASE_BUCKET || 'ffcdn' },
      github: {
        repo: env.FF_CDN_GITHUB_REPO || 'ArthWarrior3201/FastFlare',
        branch: env.FF_CDN_GITHUB_BRANCH || 'cdn',
        token: env.FF_CDN_GITHUB_TOKEN || '',
        public: env.FF_CDN_GITHUB_PUBLIC !== '0',
        api: env.FF_CDN_GITHUB_API || 'https://api.github.com',
        raw: env.FF_CDN_GITHUB_RAW || 'https://raw.githubusercontent.com',
      },
    },
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
