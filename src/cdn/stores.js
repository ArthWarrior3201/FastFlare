// Where encrypted parts live. Every store keeps opaque objects named
// "<bundle>/<file>.<part>.ffencrypted"; none of them ever sees a key or a file name.
import fs from 'node:fs';
import fsp from 'node:fs/promises';
import path from 'node:path';
import crypto from 'node:crypto';

const UA = 'FastFlare-CDN';

async function check(res, what) {
  if (res.ok) return res;
  const body = await res.text().catch(() => '');
  const e = new Error(`${what} failed: HTTP ${res.status} ${body.slice(0, 300)}`);
  e.status = res.status;
  throw e;
}

// ---- The VM's own disk --------------------------------------------------------------------------
export function localStore(dir) {
  const full = (p) => {
    const f = path.resolve(dir, p);
    if (!f.startsWith(path.resolve(dir) + path.sep)) throw new Error('bad path');
    return f;
  };
  return {
    name: 'vm',
    ready: true,
    async putFiles(items) {
      for (const it of items) {
        const dest = full(it.path);
        await fsp.mkdir(path.dirname(dest), { recursive: true });
        await fsp.rename(it.file, dest).catch(async () => {
          await fsp.copyFile(it.file, dest);
          await fsp.unlink(it.file);
        });
      }
      return {};
    },
    localPath: (p) => full(p),
    async remove(paths) {
      for (const p of paths) await fsp.unlink(full(p)).catch(() => {});
      const dirs = new Set(paths.map((p) => path.dirname(full(p))));
      for (const d of dirs) await fsp.rmdir(d).catch(() => {});
    },
  };
}

// ---- Supabase Storage (free plan: 1 GB, 50 MB per object) -------------------------------------------
export function supabaseStore({ url, key, bucket = 'ffcdn', fetchImpl = fetch }) {
  const base = String(url || '').replace(/\/$/, '');
  const ready = !!(base && key);
  const headers = { Authorization: `Bearer ${key}`, apikey: key, 'User-Agent': UA };
  const objUrl = (p) => `${base}/storage/v1/object/${encodeURIComponent(bucket)}/${p.split('/').map(encodeURIComponent).join('/')}`;
  return {
    name: 'supabase',
    ready,
    async putFiles(items) {
      for (const it of items) {
        const body = await fsp.readFile(it.file);
        await check(
          await fetchImpl(objUrl(it.path), {
            method: 'POST',
            headers: { ...headers, 'Content-Type': 'application/octet-stream', 'x-upsert': 'true', 'Cache-Control': 'max-age=31536000' },
            body,
          }),
          'Supabase upload',
        );
        await fsp.unlink(it.file).catch(() => {});
      }
      return {};
    },
    // Time-limited links the edge function can read directly.
    async signUrls(paths, seconds) {
      const res = await check(
        await fetchImpl(`${base}/storage/v1/object/sign/${encodeURIComponent(bucket)}`, {
          method: 'POST',
          headers: { ...headers, 'Content-Type': 'application/json' },
          body: JSON.stringify({ expiresIn: Math.floor(seconds), paths }),
        }),
        'Supabase sign',
      );
      const list = await res.json();
      return paths.map((p) => {
        const hit = list.find((x) => x.path === p);
        if (!hit || hit.error || !hit.signedURL) throw new Error('Supabase sign: no link for ' + p);
        return `${base}/storage/v1${hit.signedURL.startsWith('/') ? '' : '/'}${hit.signedURL}`;
      });
    },
    async download(p, _ref, dest) {
      const res = await check(
        await fetchImpl(`${base}/storage/v1/object/authenticated/${encodeURIComponent(bucket)}/${p.split('/').map(encodeURIComponent).join('/')}`, { headers }),
        'Supabase download',
      );
      await fsp.writeFile(dest, Buffer.from(await res.arrayBuffer()));
    },
    async remove(paths) {
      if (!paths.length) return;
      await check(
        await fetchImpl(`${base}/storage/v1/object/${encodeURIComponent(bucket)}`, {
          method: 'DELETE',
          headers: { ...headers, 'Content-Type': 'application/json' },
          body: JSON.stringify({ prefixes: paths }),
        }),
        'Supabase delete',
      );
    },
  };
}

// ---- GitHub: a branch of a repository, written through the Git Data API ----------------------------
// Each upload becomes one commit on top of the branch; nothing is cloned to the VM. Parts are read
// back from raw.githubusercontent.com by commit, so a later commit can never change them.
export function githubStore({ repo, branch = 'cdn', token, api = 'https://api.github.com', raw = 'https://raw.githubusercontent.com', fetchImpl = fetch }) {
  const ready = !!(repo && token);
  const H = { Authorization: `Bearer ${token}`, Accept: 'application/vnd.github+json', 'X-GitHub-Api-Version': '2022-11-28', 'User-Agent': UA };
  const call = async (method, p, body) => {
    const res = await fetchImpl(`${api}/repos/${repo}${p}`, {
      method,
      headers: body ? { ...H, 'Content-Type': 'application/json' } : H,
      body: body ? (typeof body === 'string' ? body : JSON.stringify(body)) : undefined,
    });
    await check(res, `GitHub ${method} ${p}`);
    return res.json();
  };
  let lock = Promise.resolve();
  const serial = (fn) => {
    const run = lock.then(fn, fn);
    lock = run.catch(() => {});
    return run;
  };

  async function commit(entries, message) {
    for (let attempt = 0; ; attempt++) {
      const head = (await call('GET', `/git/ref/heads/${encodeURIComponent(branch)}`)).object.sha;
      const baseTree = (await call('GET', `/git/commits/${head}`)).tree.sha;
      const tree = await call('POST', '/git/trees', { base_tree: baseTree, tree: entries });
      const c = await call('POST', '/git/commits', { message, tree: tree.sha, parents: [head] });
      try {
        await call('PATCH', `/git/refs/heads/${encodeURIComponent(branch)}`, { sha: c.sha, force: false });
        return c.sha;
      } catch (e) {
        if (attempt >= 3 || (e.status !== 422 && e.status !== 409)) throw e; // someone else moved the branch
      }
    }
  }

  return {
    name: 'github',
    ready,
    putFiles: (items, label = 'upload') =>
      serial(async () => {
        const entries = [];
        for (const it of items) {
          // One part at a time (about 44 MB, 60 MB as base64), so memory stays bounded.
          const body = await fsp.readFile(it.file);
          const blob = await call('POST', '/git/blobs', JSON.stringify({ encoding: 'base64', content: body.toString('base64') }));
          entries.push({ path: it.path, mode: '100644', type: 'blob', sha: blob.sha });
        }
        const sha = await commit(entries, `cdn: ${label}`);
        for (const it of items) await fsp.unlink(it.file).catch(() => {});
        return { commit: sha };
      }),
    rawUrl: (p, ref) => `${raw}/${repo}/${ref.commit}/${p}`,
    async download(p, ref, dest) {
      const res = await check(
        await fetchImpl(`${raw}/${repo}/${ref.commit}/${p}`, { headers: { Authorization: `token ${token}`, 'User-Agent': UA } }),
        'GitHub download',
      );
      await fsp.writeFile(dest, Buffer.from(await res.arrayBuffer()));
    },
    remove: (paths) =>
      serial(async () => {
        if (!paths.length) return;
        await commit(paths.map((p) => ({ path: p, mode: '100644', type: 'blob', sha: null })), 'cdn: delete');
      }),
  };
}

// ---- Cache on the VM for parts fetched from Supabase or GitHub -------------------------------------
// Popular small files are then read from Supabase or GitHub once instead of on every download, which
// keeps Supabase's monthly egress allowance for new files.
export function partCache(dir, maxBytes) {
  const inflight = new Map();
  let used = null;

  async function scan() {
    const out = [];
    const walk = async (d) => {
      for (const e of await fsp.readdir(d, { withFileTypes: true }).catch(() => [])) {
        const f = path.join(d, e.name);
        if (e.isDirectory()) await walk(f);
        else if (!e.name.endsWith('.tmp')) {
          const s = await fsp.stat(f).catch(() => null);
          if (s) out.push({ f, size: s.size, at: s.mtimeMs });
        }
      }
    };
    await walk(dir);
    return out;
  }
  async function trim() {
    const all = await scan();
    used = all.reduce((a, x) => a + x.size, 0);
    if (used <= maxBytes) return;
    all.sort((a, b) => a.at - b.at);
    for (const x of all) {
      if (used <= maxBytes * 0.8) break;
      await fsp.unlink(x.f).catch(() => {});
      used -= x.size;
    }
  }

  return {
    // Returns a local file path for the part, fetching it with `fetchTo(dest)` if needed.
    async get(key, fetchTo) {
      const f = path.join(dir, key);
      try {
        const now = new Date();
        await fsp.utimes(f, now, now);
        return f;
      } catch {
        /* not cached */
      }
      if (inflight.has(f)) return inflight.get(f);
      const p = (async () => {
        await fsp.mkdir(path.dirname(f), { recursive: true });
        const tmp = `${f}.${crypto.randomBytes(4).toString('hex')}.tmp`;
        try {
          await fetchTo(tmp);
          await fsp.rename(tmp, f);
        } catch (e) {
          await fsp.unlink(tmp).catch(() => {});
          throw e;
        }
        const s = await fsp.stat(f);
        used = (used ?? 0) + s.size;
        if (used > maxBytes) trim().catch(() => {});
        return f;
      })();
      inflight.set(f, p);
      try {
        return await p;
      } finally {
        inflight.delete(f);
      }
    },
    async drop(keys) {
      for (const k of keys) await fsp.unlink(path.join(dir, k)).catch(() => {});
    },
  };
}

export const exists = (f) => fs.existsSync(f);
