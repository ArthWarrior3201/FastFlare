// FastFlare CDN at the edge (Vercel Edge Functions).
//
// A download request lands on the Vercel edge node nearest the visitor. The function asks the
// FastFlare server whether the key is right; if it is, the server answers with short-lived links to
// the encrypted parts on Supabase, GitHub or the server. The function fetches them, decrypts and
// verifies every segment here, and streams the file. The key is never stored anywhere.
//
// Same URLs as the server:  /cdn/BUNDLE?key=KEY   /cdn/BUNDLE/file.png?key=KEY   ?files=a,b   ?list=1
export const config = { runtime: 'edge' };

const env = (k, d) => globalThis.process?.env?.[k] || d;
const origin = () => env('FF_ORIGIN', 'https://129-225-87-247.sslip.io').replace(/\/$/, '');
const edgeMax = () => Number(env('FF_EDGE_MAX_MB', 2048)) * 1048576; // larger downloads go straight to the server
const EDGE_CACHE_MAX = 10 * 1048576; // small files are cached on Vercel's CDN when the key is in the URL

const SEGMENT = 1048576;
const TAG = 16;
const SEG_PER_PART = 44;
const enc = new TextEncoder();
const ID_RE = /^[A-Za-z0-9_-]{16}$/;
const NEVER_INLINE = /^(text\/html|image\/svg\+xml|text\/javascript|application\/xhtml)/;

const CORS = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Methods': 'GET, HEAD, OPTIONS',
  'Access-Control-Allow-Headers': 'Range, X-FF-Key',
  'Access-Control-Expose-Headers': 'Content-Range, Content-Disposition, Content-Length, Accept-Ranges',
};
const json = (status, obj, extra = {}) =>
  new Response(JSON.stringify(obj), { status, headers: { 'Content-Type': 'application/json; charset=utf-8', 'Cache-Control': 'no-store', ...CORS, ...extra } });

function b64url(s) {
  const b = atob(s.replace(/-/g, '+').replace(/_/g, '/') + '==='.slice((s.length + 3) % 4));
  return Uint8Array.from(b, (c) => c.charCodeAt(0));
}
function parseKey(text) {
  if (typeof text !== 'string' || !text.startsWith('ffk_')) return null;
  try {
    const raw = b64url(text.slice(4));
    return raw.length === 32 ? raw : null;
  } catch {
    return null;
  }
}
async function fileKey(raw, bundle, fileId) {
  const base = await crypto.subtle.importKey('raw', raw, 'HKDF', false, ['deriveKey']);
  return crypto.subtle.deriveKey(
    { name: 'HKDF', hash: 'SHA-256', salt: enc.encode(bundle), info: enc.encode('ffcdn-file|' + fileId) },
    base,
    { name: 'AES-GCM', length: 256 },
    false,
    ['decrypt'],
  );
}
function nonce(i) {
  const n = new Uint8Array(12);
  new DataView(n.buffer).setBigUint64(0, BigInt(i));
  return n;
}
const segCount = (size) => Math.max(1, Math.ceil(size / SEGMENT));
const plainLen = (size, i) => Math.max(0, Math.min(SEGMENT, size - i * SEGMENT));
function concat(a, b) {
  if (!a.length) return b;
  const o = new Uint8Array(a.length + b.length);
  o.set(a);
  o.set(b, a.length);
  return o;
}

// Yields the stored bytes [from, to] of one part, whether or not the source honours Range.
async function* fetchPart(url, from, to) {
  const res = await fetch(url, { headers: { Range: `bytes=${from}-${to}` } });
  if (!res.ok) {
    const e = new Error(`part ${res.status}`);
    e.status = res.status === 404 ? 404 : 502;
    throw e;
  }
  let skip = res.status === 206 ? 0 : from;
  let left = to - from + 1;
  const reader = res.body.getReader();
  try {
    while (left > 0) {
      const { value, done } = await reader.read();
      if (done) break;
      let v = value;
      if (skip) {
        if (v.length <= skip) {
          skip -= v.length;
          continue;
        }
        v = v.subarray(skip);
        skip = 0;
      }
      if (v.length > left) v = v.subarray(0, left);
      left -= v.length;
      yield v;
    }
  } finally {
    reader.cancel().catch(() => {});
  }
}

async function* decryptRange(key, file, start, end) {
  const { id, size, src } = file;
  const segs = segCount(size);
  const open = async (i, sealed) => {
    const plain = await crypto.subtle.decrypt(
      { name: 'AES-GCM', iv: nonce(i), additionalData: enc.encode(`ffcdn|v1|${id}|${i}|${i === segs - 1 ? 1 : 0}`), tagLength: 128 },
      key,
      sealed,
    );
    return new Uint8Array(plain);
  };
  if (size === 0) {
    let buf = new Uint8Array(0);
    for await (const c of fetchPart(src[0], 0, TAG - 1)) buf = concat(buf, c);
    await open(0, buf);
    return;
  }
  const first = Math.floor(start / SEGMENT);
  const last = Math.floor(end / SEGMENT);
  for (let p = Math.floor(first / SEG_PER_PART); p <= Math.floor(last / SEG_PER_PART); p++) {
    const s0 = Math.max(first, p * SEG_PER_PART);
    const s1 = Math.min(last, p * SEG_PER_PART + SEG_PER_PART - 1);
    const from = (s0 - p * SEG_PER_PART) * (SEGMENT + TAG);
    const to = (s1 - p * SEG_PER_PART) * (SEGMENT + TAG) + plainLen(size, s1) + TAG - 1;
    let buf = new Uint8Array(0);
    let s = s0;
    for await (const chunk of fetchPart(src[p], from, to)) {
      buf = concat(buf, chunk);
      for (;;) {
        const need = plainLen(size, s) + TAG;
        if (s > s1 || buf.length < need) break;
        const plain = await open(s, buf.subarray(0, need));
        buf = buf.slice(need);
        const a = Math.max(0, start - s * SEGMENT);
        const b = Math.min(plain.length, end - s * SEGMENT + 1);
        if (b > a) yield plain.subarray(a, b);
        s++;
      }
    }
    if (s <= s1) throw Object.assign(new Error('truncated'), { status: 502 });
  }
}

// ---- ZIP (stored), same layout as the server's ------------------------------------------------
const U32 = 0xffffffff;
function bytes(n, fill) {
  const b = new Uint8Array(n);
  fill(new DataView(b.buffer));
  return b;
}
function zipPlan(entries) {
  let offset = 0;
  const plan = entries.map((e) => {
    const name = enc.encode(e.name);
    const z64 = e.size >= U32;
    const extra = z64 ? bytes(20, (d) => { d.setUint16(0, 1, true); d.setUint16(2, 16, true); d.setBigUint64(4, BigInt(e.size), true); d.setBigUint64(12, BigInt(e.size), true); }) : new Uint8Array(0);
    const h = bytes(30, (d) => {
      d.setUint32(0, 0x04034b50, true); d.setUint16(4, z64 ? 45 : 20, true); d.setUint16(6, 0x0800, true);
      d.setUint32(10, 0x00210000, true); d.setUint32(14, e.crc32 >>> 0, true);
      d.setUint32(18, z64 ? U32 : e.size, true); d.setUint32(22, z64 ? U32 : e.size, true);
      d.setUint16(26, name.length, true); d.setUint16(28, extra.length, true);
    });
    const header = concat(concat(h, name), extra);
    const at = offset;
    offset += header.length + e.size;
    return { ...e, name, header, offset: at };
  });
  let central = new Uint8Array(0);
  for (const e of plan) {
    const bigSize = e.size >= U32;
    const bigOff = e.offset >= U32;
    const fields = [...(bigSize ? [e.size, e.size] : []), ...(bigOff ? [e.offset] : [])];
    const extra = fields.length ? bytes(4 + fields.length * 8, (d) => { d.setUint16(0, 1, true); d.setUint16(2, fields.length * 8, true); fields.forEach((v, k) => d.setBigUint64(4 + k * 8, BigInt(v), true)); }) : new Uint8Array(0);
    const h = bytes(46, (d) => {
      d.setUint32(0, 0x02014b50, true); d.setUint16(4, 45 | (3 << 8), true); d.setUint16(6, fields.length ? 45 : 20, true);
      d.setUint16(8, 0x0800, true); d.setUint32(12, 0x00210000, true); d.setUint32(16, e.crc32 >>> 0, true);
      d.setUint32(20, bigSize ? U32 : e.size, true); d.setUint32(24, bigSize ? U32 : e.size, true);
      d.setUint16(28, e.name.length, true); d.setUint16(30, extra.length, true);
      d.setUint32(38, (0o100644 << 16) >>> 0, true); d.setUint32(42, bigOff ? U32 : e.offset, true);
    });
    central = concat(central, concat(concat(h, e.name), extra));
  }
  const cd = offset;
  const need64 = cd >= U32 || plan.length >= 0xffff;
  let tail = new Uint8Array(0);
  if (need64) {
    tail = concat(
      bytes(56, (d) => { d.setUint32(0, 0x06064b50, true); d.setBigUint64(4, 44n, true); d.setUint16(12, 45, true); d.setUint16(14, 45, true); d.setBigUint64(24, BigInt(plan.length), true); d.setBigUint64(32, BigInt(plan.length), true); d.setBigUint64(40, BigInt(central.length), true); d.setBigUint64(48, BigInt(cd), true); }),
      bytes(20, (d) => { d.setUint32(0, 0x07064b50, true); d.setBigUint64(8, BigInt(cd + central.length), true); d.setUint32(16, 1, true); }),
    );
  }
  const end = bytes(22, (d) => { d.setUint32(0, 0x06054b50, true); d.setUint16(8, Math.min(plan.length, 0xffff), true); d.setUint16(10, Math.min(plan.length, 0xffff), true); d.setUint32(12, central.length, true); d.setUint32(16, need64 ? U32 : cd, true); });
  const trailer = concat(concat(central, tail), end);
  return {
    length: cd + trailer.length,
    async *stream() {
      for (const e of plan) {
        yield e.header;
        yield* e.data();
      }
      yield trailer;
    },
  };
}

// Waits for the first verified bytes before answering, so a bad part becomes a clean error.
async function respond(status, headers, iter, head) {
  const it = iter[Symbol.asyncIterator]();
  let first;
  try {
    first = await it.next();
  } catch (e) {
    return json(e.status === 404 ? 404 : 502, { error: e.status === 404 ? 'file_missing' : 'file_damaged' });
  }
  if (head) {
    it.return?.();
    return new Response(null, { status, headers });
  }
  let pending = first;
  const body = new ReadableStream({
    async pull(ctrl) {
      try {
        const n = pending || (await it.next());
        pending = null;
        if (n.done) ctrl.close();
        else ctrl.enqueue(n.value);
      } catch (e) {
        ctrl.error(e);
      }
    },
    cancel() {
      it.return?.();
    },
  });
  return new Response(body, { status, headers });
}

export default async function handler(req) {
  if (req.method === 'OPTIONS') return new Response(null, { status: 204, headers: CORS });
  if (req.method !== 'GET' && req.method !== 'HEAD') return json(405, { error: 'method_not_allowed' });
  const url = new URL(req.url);
  const q = url.searchParams;
  const rest = (q.get('p') ?? url.pathname.replace(/^\/(api\/)?cdn\/?/, '')).split('/').filter(Boolean).map((s) => {
    try {
      return decodeURIComponent(s);
    } catch {
      return '';
    }
  });
  const [bundle, ...nameParts] = rest;
  if (!ID_RE.test(bundle || '')) return json(404, { error: 'not_found' });
  const name = nameParts.join('/') || null;
  const keyText = req.headers.get('x-ff-key') || q.get('key') || '';
  const raw = parseKey(keyText);
  if (!raw) return json(403, { error: 'invalid_key' });

  const ORIGIN = origin();
  const meta = await fetch(`${ORIGIN}/cdn/edge/${bundle}`, { headers: { 'X-FF-Key': keyText } });
  if (!meta.ok) {
    const j = await meta.json().catch(() => ({}));
    return json(meta.status === 403 || meta.status === 404 ? meta.status : 502, { error: j.error || 'origin_error' });
  }
  const m = await meta.json();
  if (q.get('list') === '1') return json(200, { bundle: m.bundle, files: m.files.map((f) => ({ name: f.name, size: f.size, type: f.type })) });

  let selected;
  if (name) selected = m.files.filter((f) => f.name === name);
  else if (q.get('files')) {
    const want = q.get('files').split(',').filter(Boolean);
    selected = want.map((w) => m.files.find((f) => f.name === w)).filter(Boolean);
    if (selected.length !== want.length) selected = [];
  } else selected = m.files;
  if (!selected.length) return json(404, { error: 'file_not_found' });

  // Too big to finish within Vercel's 300-second streaming limit: hand over to the server.
  const total = selected.reduce((a, f) => a + f.size, 0);
  if (total > edgeMax()) {
    const qs = new URLSearchParams(q);
    qs.delete('p');
    const to = `${ORIGIN}/cdn/${[bundle, ...nameParts].map(encodeURIComponent).join('/')}${[...qs].length ? '?' + qs : ''}`;
    return new Response(null, { status: 307, headers: { ...CORS, Location: to } });
  }

  const keyInUrl = !req.headers.get('x-ff-key');
  const base = { ...CORS, 'X-Content-Type-Options': 'nosniff', 'X-FastFlare-Edge': '1' };
  const head = req.method === 'HEAD';

  if (selected.length === 1 && q.get('zip') !== '1') {
    const f = selected[0];
    let start = 0;
    let end = f.size - 1;
    let status = 200;
    const h = { ...base, 'Accept-Ranges': 'bytes', ETag: `"${bundle}-${f.id}"` };
    const r = (req.headers.get('range') || '').match(/^bytes=(\d*)-(\d*)$/);
    if (r && f.size > 0 && (r[1] || r[2])) {
      if (r[1]) {
        start = Number(r[1]);
        end = r[2] ? Math.min(Number(r[2]), f.size - 1) : f.size - 1;
      } else start = Math.max(0, f.size - Number(r[2]));
      if (start >= f.size || start > end) return new Response(null, { status: 416, headers: { ...h, 'Content-Range': `bytes */${f.size}` } });
      status = 206;
      h['Content-Range'] = `bytes ${start}-${end}/${f.size}`;
    }
    const inline = q.get('download') !== '1' && !NEVER_INLINE.test(f.type);
    const fname = f.name.split('/').pop();
    h['Content-Type'] = f.type;
    h['Content-Length'] = String(f.size === 0 ? 0 : end - start + 1);
    h['Content-Disposition'] = `${inline ? 'inline' : 'attachment'}; filename="${fname.replace(/[^\x20-\x7e]|"/g, '_')}"; filename*=UTF-8''${encodeURIComponent(fname)}`;
    h['Cache-Control'] = keyInUrl && status === 200 && f.size <= EDGE_CACHE_MAX ? 'public, max-age=3600, s-maxage=86400' : 'private, max-age=3600';
    const key = await fileKey(raw, bundle, f.id);
    return respond(status, h, decryptRange(key, f, start, end), head);
  }

  const keys = await Promise.all(selected.map((f) => fileKey(raw, bundle, f.id)));
  const plan = zipPlan(selected.map((f, k) => ({ name: f.name, size: f.size, crc32: f.crc32, data: () => decryptRange(keys[k], f, 0, f.size - 1) })));
  return respond(
    200,
    { ...base, 'Content-Type': 'application/zip', 'Content-Length': String(plan.length), 'Content-Disposition': `attachment; filename="${bundle}.zip"`, 'Cache-Control': 'private, max-age=3600' },
    plan.stream(),
    head,
  );
}
