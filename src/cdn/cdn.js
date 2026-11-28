// FastFlare CDN: encrypted file bundles spread over the VM, Supabase and a GitHub branch.
//
//   PUT    /cdn/upload?name=logo.png[&bundle=ID][&tier=auto|vm|supabase|github]
//          Authorization: Bearer FF_CDN_TOKEN   (+ X-FF-Key when adding to an existing bundle)
//   GET    /cdn/ID?key=KEY                      every file (one file as itself, several as a .zip)
//   GET    /cdn/ID?key=KEY&files=a.png,b.css    just those files
//   GET    /cdn/ID/logo.png?key=KEY             one file (supports Range for resuming)
//   GET    /cdn/ID?key=KEY&list=1               file list as JSON
//   DELETE /cdn/ID[/name]                       Authorization: Bearer FF_CDN_TOKEN
//   GET    /cdn/status, /cdn/bundles            Authorization: Bearer FF_CDN_TOKEN
//
// The key can also be sent as an X-FF-Key header instead of ?key=.
import fs from 'node:fs';
import fsp from 'node:fs/promises';
import path from 'node:path';
import crypto from 'node:crypto';
import { Readable, pipeline } from 'node:stream';
import { httpError, send, CORS } from '../util.js';
import * as F from './format.js';
import { localStore, supabaseStore, githubStore, partCache } from './stores.js';

const MB = 1024 * 1024;
const ID_RE = /^[A-Za-z0-9_-]{16}$/;

const TYPES = {
  '.png': 'image/png', '.jpg': 'image/jpeg', '.jpeg': 'image/jpeg', '.gif': 'image/gif', '.webp': 'image/webp',
  '.avif': 'image/avif', '.svg': 'image/svg+xml', '.ico': 'image/x-icon', '.css': 'text/css; charset=utf-8',
  '.js': 'text/javascript; charset=utf-8', '.mjs': 'text/javascript; charset=utf-8', '.json': 'application/json',
  '.html': 'text/html; charset=utf-8', '.txt': 'text/plain; charset=utf-8', '.md': 'text/markdown; charset=utf-8',
  '.pdf': 'application/pdf', '.zip': 'application/zip', '.mp4': 'video/mp4', '.webm': 'video/webm', '.mp3': 'audio/mpeg',
  '.wav': 'audio/wav', '.woff': 'font/woff', '.woff2': 'font/woff2', '.ttf': 'font/ttf', '.exe': 'application/vnd.microsoft.portable-executable',
  '.msi': 'application/x-msi', '.jar': 'application/java-archive', '.apk': 'application/vnd.android.package-archive',
  '.iso': 'application/x-iso9660-image', '.7z': 'application/x-7z-compressed', '.gz': 'application/gzip',
};
// Never render these inline from the CDN's origin: they could run script there.
const NEVER_INLINE = /^(text\/html|image\/svg\+xml|text\/javascript|application\/xhtml)/;

export function cleanName(input) {
  let n = String(input || '').replace(/\\/g, '/').replace(/^\/+/, '').trim();
  if (!n || n.length > 255 || /[\u0000-\u001f]/.test(n)) return null;
  const parts = n.split('/');
  if (parts.some((p) => !p || p === '.' || p === '..')) return null;
  return parts.join('/');
}

export function createCdn({ config, log = () => {}, fetchImpl = fetch }) {
  const c = config.cdn;
  const root = c.dir;
  const dirs = { bundles: path.join(root, 'bundles'), store: path.join(root, 'store'), cache: path.join(root, 'cache'), tmp: path.join(root, 'tmp') };
  for (const d of Object.values(dirs)) fs.mkdirSync(d, { recursive: true, mode: 0o700 });
  // Leftovers from an upload that was cut off by a restart.
  for (const e of fs.readdirSync(dirs.tmp)) fs.rmSync(path.join(dirs.tmp, e), { recursive: true, force: true });

  const stores = {
    vm: localStore(dirs.store),
    supabase: supabaseStore({ ...c.supabase, fetchImpl }),
    github: githubStore({ ...c.github, fetchImpl }),
  };
  const caps = { vm: c.vmCapBytes, supabase: c.supabaseCapBytes, github: c.githubCapBytes };
  const cache = partCache(dirs.cache, c.cacheBytes);

  // ---- Manifests (on the VM only; they hold names and sizes, never keys) -------------------------
  const used = { vm: 0, supabase: 0, github: 0 };
  const manifestPath = (id) => path.join(dirs.bundles, id + '.json');
  for (const f of fs.readdirSync(dirs.bundles)) {
    if (!f.endsWith('.json')) continue;
    try {
      for (const file of JSON.parse(fs.readFileSync(path.join(dirs.bundles, f), 'utf8')).files) used[file.tier] += F.encryptedSize(file.size);
    } catch (e) {
      log(`cdn: unreadable manifest ${f}: ${e.message}`);
    }
  }
  async function loadBundle(id) {
    if (!ID_RE.test(id || '')) return null;
    try {
      return JSON.parse(await fsp.readFile(manifestPath(id), 'utf8'));
    } catch {
      return null;
    }
  }
  async function saveBundle(b) {
    const tmp = manifestPath(b.id) + '.tmp';
    await fsp.writeFile(tmp, JSON.stringify(b), { mode: 0o600 });
    await fsp.rename(tmp, manifestPath(b.id));
  }
  const locks = new Map();
  function withLock(id, fn) {
    const prev = locks.get(id) || Promise.resolve();
    const run = prev.then(fn, fn);
    const tail = run.catch(() => {});
    locks.set(id, tail);
    tail.then(() => locks.get(id) === tail && locks.delete(id));
    return run;
  }

  const objectPath = (bundle, file, p) => `${bundle}/${file.id}.${p}.ffencrypted`;

  function authorized(req) {
    const h = String(req.headers.authorization || '');
    const m = h.match(/^Bearer\s+(.+)$/i);
    if (!c.token || !m) return false;
    const a = crypto.createHash('sha256').update(m[1].trim()).digest();
    const b = crypto.createHash('sha256').update(c.token).digest();
    return crypto.timingSafeEqual(a, b);
  }
  function requireOwner(req) {
    if (!c.token) throw httpError(503, 'cdn_upload_disabled');
    if (!authorized(req)) throw httpError(401, 'unauthorized');
  }

  function chooseTier(asked, size) {
    const fits = (t) => stores[t].ready && used[t] + F.encryptedSize(size) <= caps[t];
    if (asked && asked !== 'auto') {
      if (!stores[asked]) throw httpError(400, 'unknown_tier');
      if (!stores[asked].ready) throw httpError(400, 'tier_not_configured');
      if (!fits(asked)) throw httpError(507, 'tier_full');
      return asked;
    }
    if (size <= c.smallMaxBytes && fits('supabase')) return 'supabase';
    if (size > c.smallMaxBytes && size <= c.githubMaxBytes && fits('github')) return 'github';
    if (fits('vm')) return 'vm';
    if (fits('github')) return 'github';
    if (fits('supabase')) return 'supabase';
    throw httpError(507, 'storage_full');
  }

  // ---- Upload -----------------------------------------------------------------------------------
  async function upload(req, res, url) {
    requireOwner(req);
    const q = url.searchParams;
    const name = cleanName(q.get('name') || decodeURIComponent(String(req.headers['x-ff-name'] || '')));
    if (!name) throw httpError(400, 'name_required');
    const declared = Number(req.headers['content-length'] || q.get('size') || 0);
    if (declared > c.maxBytes) throw httpError(413, 'too_large');

    let bundleId = q.get('bundle') || req.headers['x-ff-bundle'];
    let keyRaw;
    let keyText = null;
    if (bundleId) {
      const b = await loadBundle(String(bundleId));
      if (!b) throw httpError(404, 'bundle_not_found');
      keyRaw = F.parseKey(String(req.headers['x-ff-key'] || q.get('key') || ''));
      if (!F.keyMatches(keyRaw, b.keyCheck)) throw httpError(403, 'invalid_key');
    } else {
      const k = F.newKey();
      keyRaw = k.raw;
      keyText = k.text;
      bundleId = crypto.randomBytes(12).toString('base64url');
    }

    let tier = chooseTier(q.get('tier') || req.headers['x-ff-tier'], declared);
    const file = { id: crypto.randomBytes(8).toString('hex'), name, tier };
    const fk = F.fileKey(keyRaw, bundleId, file.id);
    const work = path.join(dirs.tmp, file.id);
    await fsp.mkdir(work, { recursive: true });
    const items = [];
    let out = null;
    let inPart = 0;
    const openPart = () => {
      const f = path.join(work, `${items.length}.part`);
      out = fs.createWriteStream(f);
      items.push({ file: f, p: items.length });
    };
    const write = (buf) =>
      new Promise((resolve, reject) => {
        out.once('error', reject);
        if (out.write(buf)) {
          out.off('error', reject);
          resolve();
        } else
          out.once('drain', () => {
            out.off('error', reject);
            resolve();
          });
      });
    const closePart = () => new Promise((resolve, reject) => out.end((e) => (e ? reject(e) : resolve())));

    try {
      const r = await F.encryptStream(
        req,
        fk,
        file.id,
        async (seg) => {
          if (!out || inPart === F.SEG_PER_PART) {
            if (out) await closePart();
            openPart();
            inPart = 0;
          }
          await write(seg);
          inPart++;
        },
        { maxBytes: c.maxBytes },
      );
      await closePart();
      file.size = r.size;
      file.crc32 = r.crc32;
      file.parts = items.length;
      file.type = TYPES[path.extname(name).toLowerCase()] || 'application/octet-stream';
      file.created = new Date().toISOString();

      // The real size may differ from what was announced: re-check the tier now.
      if (!declared || declared !== r.size) {
        try {
          tier = chooseTier(q.get('tier') || req.headers['x-ff-tier'], r.size);
        } catch (e) {
          throw e;
        }
        file.tier = tier;
      }
      used[tier] += F.encryptedSize(r.size); // reserve before the slow part
      try {
        const ref = await stores[tier].putFiles(
          items.map((it) => ({ file: it.file, path: objectPath(bundleId, file, it.p) })),
          `${bundleId}/${file.id}`,
        );
        if (ref && ref.commit) file.ref = { commit: ref.commit };
      } catch (e) {
        used[tier] -= F.encryptedSize(r.size);
        log(`cdn: ${tier} upload failed: ${e.message}`);
        throw httpError(502, `${tier}_upload_failed`);
      }

      const replaced = await withLock(bundleId, async () => {
        const b = (await loadBundle(bundleId)) || { id: bundleId, keyCheck: F.keyCheck(keyRaw), created: file.created, files: [] };
        const old = b.files.filter((x) => x.name === name);
        b.files = b.files.filter((x) => x.name !== name).concat(file);
        await saveBundle(b);
        return old;
      });
      for (const o of replaced) removeFile(bundleId, o).catch((e) => log(`cdn: cleanup failed: ${e.message}`));

      const base = c.edgeUrl || c.publicUrl || '';
      log(`cdn: stored ${bundleId}/${name} (${r.size} bytes) on ${tier}`);
      send(
        res,
        201,
        {
          bundle: bundleId,
          ...(keyText ? { key: keyText } : {}),
          file: { name, size: r.size, tier, parts: file.parts },
          url: `${base}/cdn/${bundleId}/${name.split('/').map(encodeURIComponent).join('/')}`,
          bundleUrl: `${base}/cdn/${bundleId}`,
        },
        CORS,
      );
    } catch (e) {
      if (e.code === 'too_large') throw httpError(413, 'too_large');
      throw e;
    } finally {
      if (out && !out.closed) out.destroy();
      await fsp.rm(work, { recursive: true, force: true });
    }
  }

  async function removeFile(bundleId, file) {
    const paths = Array.from({ length: file.parts }, (_, p) => objectPath(bundleId, file, p));
    if (stores[file.tier].ready || file.tier === 'vm') await stores[file.tier].remove(paths);
    await cache.drop(paths);
    used[file.tier] = Math.max(0, used[file.tier] - F.encryptedSize(file.size));
  }

  // ---- Download ---------------------------------------------------------------------------------
  function partReader(bundleId, file) {
    return async function* (p, from, to) {
      const obj = objectPath(bundleId, file, p);
      let local;
      if (file.tier === 'vm') local = stores.vm.localPath(obj);
      else {
        const store = stores[file.tier];
        if (!store.ready) throw httpError(503, `${file.tier}_not_configured`);
        local = await cache.get(obj, (dest) => store.download(obj, file.ref, dest));
      }
      yield* fs.createReadStream(local, { start: from, end: to, highWaterMark: 256 * 1024 });
    };
  }

  function plaintext(bundleId, file, keyRaw, start, end) {
    return F.decryptRange({ key: F.fileKey(keyRaw, bundleId, file.id), fileId: file.id, size: file.size, start, end, readPart: partReader(bundleId, file) });
  }

  // Pulls the first chunk before sending headers, so a damaged or missing part becomes a clean error.
  async function stream(res, status, headers, iter, head) {
    const it = iter[Symbol.asyncIterator]();
    let first;
    try {
      first = await it.next();
    } catch (e) {
      throw e.status ? e : httpError(502, e.code === 'ENOENT' ? 'file_missing' : 'file_damaged');
    }
    res.writeHead(status, headers);
    if (head) {
      it.return?.();
      return res.end();
    }
    const rest = Readable.from(
      (async function* () {
        if (!first.done) yield first.value;
        for (;;) {
          const n = await it.next();
          if (n.done) return;
          yield n.value;
        }
      })(),
    );
    pipeline(rest, res, (err) => {
      if (err && err.code !== 'ERR_STREAM_PREMATURE_CLOSE') log(`cdn: download stopped: ${err.message}`);
    });
  }

  async function download(req, res, url, bundleId, name) {
    const b = await loadBundle(bundleId);
    if (!b) throw httpError(404, 'not_found');
    const keyRaw = F.parseKey(String(req.headers['x-ff-key'] || url.searchParams.get('key') || ''));
    if (!F.keyMatches(keyRaw, b.keyCheck)) throw httpError(403, 'invalid_key');
    const q = url.searchParams;
    const head = req.method === 'HEAD';
    const base = { ...CORS, 'Cache-Control': 'private, max-age=86400', 'X-Content-Type-Options': 'nosniff' };

    if (q.get('list') === '1') {
      return send(res, 200, {
        bundle: b.id,
        created: b.created,
        files: b.files.map((f) => ({ name: f.name, size: f.size, type: f.type, tier: f.tier, created: f.created })),
      }, CORS);
    }

    let selected;
    if (name) {
      const f = b.files.find((x) => x.name === name);
      if (!f) throw httpError(404, 'file_not_found');
      selected = [f];
    } else if (q.get('files')) {
      const want = q.get('files').split(',').map((s) => cleanName(s)).filter(Boolean);
      selected = want.map((w) => b.files.find((x) => x.name === w)).filter(Boolean);
      if (selected.length !== want.length) throw httpError(404, 'file_not_found');
    } else selected = b.files;
    if (!selected.length) throw httpError(404, 'empty_bundle');

    // One file: send it as itself, with Range support for resuming and video seeking.
    if (selected.length === 1 && q.get('zip') !== '1') {
      const f = selected[0];
      let start = 0;
      let end = f.size - 1;
      let status = 200;
      const h = { ...base, 'Accept-Ranges': 'bytes', ETag: `"${b.id}-${f.id}"` };
      const range = String(req.headers.range || '');
      const m = range.match(/^bytes=(\d*)-(\d*)$/);
      if (m && f.size > 0 && (m[1] || m[2])) {
        if (m[1]) {
          start = Number(m[1]);
          end = m[2] ? Math.min(Number(m[2]), f.size - 1) : f.size - 1;
        } else {
          start = Math.max(0, f.size - Number(m[2]));
        }
        if (start >= f.size || start > end) {
          res.writeHead(416, { ...h, 'Content-Range': `bytes */${f.size}` });
          return res.end();
        }
        status = 206;
        h['Content-Range'] = `bytes ${start}-${end}/${f.size}`;
      }
      const inline = q.get('download') !== '1' && !NEVER_INLINE.test(f.type);
      const fname = path.basename(f.name);
      h['Content-Type'] = f.type;
      h['Content-Length'] = f.size === 0 ? 0 : end - start + 1;
      h['Content-Disposition'] = `${inline ? 'inline' : 'attachment'}; filename="${fname.replace(/[^\x20-\x7e]|"/g, '_')}"; filename*=UTF-8''${encodeURIComponent(fname)}`;
      return stream(res, status, h, plaintext(b.id, f, keyRaw, start, end), head);
    }

    // Several files: one .zip, length known in advance.
    const plan = F.zipPlan(selected.map((f) => ({ name: f.name, size: f.size, crc32: f.crc32, data: () => plaintext(b.id, f, keyRaw, 0, f.size - 1) })));
    return stream(
      res,
      200,
      { ...base, 'Content-Type': 'application/zip', 'Content-Length': plan.length, 'Content-Disposition': `attachment; filename="${b.id}.zip"` },
      plan.stream(),
      head,
    );
  }

  async function remove(req, res, bundleId, name) {
    requireOwner(req);
    const left = await withLock(bundleId, async () => {
      const b = await loadBundle(bundleId);
      if (!b) throw httpError(404, 'not_found');
      const gone = name ? b.files.filter((f) => f.name === name) : b.files;
      if (name && !gone.length) throw httpError(404, 'file_not_found');
      for (const f of gone) await removeFile(b.id, f);
      b.files = b.files.filter((f) => !gone.includes(f));
      if (b.files.length) await saveBundle(b);
      else await fsp.unlink(manifestPath(b.id)).catch(() => {});
      return b.files.length;
    });
    send(res, 200, { ok: true, filesLeft: left }, CORS);
  }

  // ---- Edge delivery (Vercel) -------------------------------------------------------------------
  // The edge function sends the visitor's key here. If it matches, it gets the file list and a
  // short-lived link to every encrypted part, then fetches and decrypts the parts itself, close to
  // the visitor. Parts on Supabase and GitHub never pass through this server.
  const EDGE_TTL = 6 * 60 * 60 * 1000;
  const partSig = (bundle, fileId, p, exp) => crypto.createHmac('sha256', config.secret).update(`ffcdn-part|${bundle}|${fileId}|${p}|${exp}`).digest('base64url');

  async function edgeMeta(req, res, bundleId) {
    const b = await loadBundle(bundleId);
    if (!b) throw httpError(404, 'not_found');
    const keyRaw = F.parseKey(String(req.headers['x-ff-key'] || ''));
    if (!F.keyMatches(keyRaw, b.keyCheck)) throw httpError(403, 'invalid_key');
    const origin = c.publicUrl || `http://${req.headers.host}`;
    const exp = Date.now() + EDGE_TTL;
    const vmUrl = (f, p) => `${origin}/cdn/part/${b.id}/${f.id}/${p}?exp=${exp}&sig=${partSig(b.id, f.id, p, exp)}`;
    const files = [];
    for (const f of b.files) {
      const paths = Array.from({ length: f.parts }, (_, p) => objectPath(b.id, f, p));
      let src = null;
      try {
        if (f.tier === 'supabase' && stores.supabase.ready) src = await stores.supabase.signUrls(paths, EDGE_TTL / 1000);
        else if (f.tier === 'github' && stores.github.ready && c.github.public !== false) src = paths.map((p) => stores.github.rawUrl(p, f.ref));
      } catch (e) {
        log(`cdn: direct links failed, using the server: ${e.message}`);
      }
      files.push({ id: f.id, name: f.name, size: f.size, crc32: f.crc32, type: f.type, parts: f.parts, src: src || paths.map((_, p) => vmUrl(f, p)) });
    }
    send(res, 200, { bundle: b.id, files }, { 'Cache-Control': 'no-store' });
  }

  // Encrypted bytes of one part, for the edge function. Useless without the key.
  async function signedPart(req, res, url, bundleId, fileId, p) {
    const exp = Number(url.searchParams.get('exp'));
    const sig = String(url.searchParams.get('sig') || '');
    const want = partSig(bundleId, fileId, p, exp);
    if (!exp || exp < Date.now() || sig.length !== want.length || !crypto.timingSafeEqual(Buffer.from(sig), Buffer.from(want))) throw httpError(403, 'link_expired');
    const b = await loadBundle(bundleId);
    const f = b && b.files.find((x) => x.id === fileId);
    const n = Number(p);
    if (!f || !Number.isInteger(n) || n < 0 || n >= f.parts) throw httpError(404, 'not_found');
    const total = F.partSize(f.size, n);
    let start = 0;
    let end = total - 1;
    let status = 200;
    const h = { 'Content-Type': 'application/octet-stream', 'Accept-Ranges': 'bytes', 'Cache-Control': 'private, no-store' };
    const m = String(req.headers.range || '').match(/^bytes=(\d+)-(\d*)$/);
    if (m) {
      start = Number(m[1]);
      end = m[2] ? Math.min(Number(m[2]), total - 1) : total - 1;
      if (start > end) throw httpError(416, 'bad_range');
      status = 206;
      h['Content-Range'] = `bytes ${start}-${end}/${total}`;
    }
    h['Content-Length'] = end - start + 1;
    const read = partReader(bundleId, f);
    return stream(res, status, h, read(n, start, end), req.method === 'HEAD');
  }

  async function bundles(req, res) {
    requireOwner(req);
    const out = [];
    for (const f of await fsp.readdir(dirs.bundles)) {
      if (!f.endsWith('.json')) continue;
      const b = await loadBundle(f.slice(0, -5));
      if (b) out.push({ bundle: b.id, created: b.created, files: b.files.map((x) => ({ name: x.name, size: x.size, tier: x.tier })) });
    }
    out.sort((a, b) => String(b.created).localeCompare(String(a.created)));
    send(res, 200, { bundles: out }, CORS);
  }

  function status(req, res) {
    requireOwner(req);
    const tiers = {};
    for (const t of Object.keys(stores)) tiers[t] = { ready: stores[t].ready, usedBytes: used[t], capBytes: caps[t] };
    send(res, 200, { tiers, maxUploadBytes: c.maxBytes, smallMaxBytes: c.smallMaxBytes, githubMaxBytes: c.githubMaxBytes }, CORS);
  }

  // Router for everything under /cdn/
  async function handle(req, res, url) {
    const segs = url.pathname.split('/').slice(2).map((s) => {
      try {
        return decodeURIComponent(s);
      } catch {
        return '\u0000';
      }
    });
    const [first] = segs;
    if (first === 'upload' && (req.method === 'PUT' || req.method === 'POST')) return upload(req, res, url);
    if (first === 'status' && req.method === 'GET') return status(req, res);
    if (first === 'bundles' && req.method === 'GET') return bundles(req, res);
    if (first === 'edge' && req.method === 'GET' && ID_RE.test(segs[1] || '')) return edgeMeta(req, res, segs[1]);
    if (first === 'part' && (req.method === 'GET' || req.method === 'HEAD') && segs.length === 4) return signedPart(req, res, url, segs[1], segs[2], segs[3]);
    if (!ID_RE.test(first || '')) throw httpError(404, 'not_found');
    const name = segs.length > 1 ? cleanName(segs.slice(1).join('/')) : null;
    if (segs.length > 1 && !name) throw httpError(404, 'file_not_found');
    if (req.method === 'GET' || req.method === 'HEAD') return download(req, res, url, first, name);
    if (req.method === 'DELETE') return remove(req, res, first, name);
    throw httpError(405, 'method_not_allowed');
  }

  return { handle, used, stores };
}

export { MB };
