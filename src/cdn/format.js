// The .ffencrypted format.
//
// Every bundle has one random 256-bit key, given to the uploader and never stored on the server
// (only a hash of it is kept, to check requests). Each file gets its own key derived from it
// (HKDF-SHA256). The file is encrypted in 1 MiB segments with AES-256-GCM; every segment carries
// its own authentication tag, its position, and whether it is the last one, so a segment cannot be
// altered, reordered, swapped between files or cut off without the download failing. Segments are
// grouped 44 to a part (about 44 MB), which keeps every stored object under the 50 MB limits of
// GitHub's 50 MB large-file warning and 100 MB limit.
import crypto from 'node:crypto';
import zlib from 'node:zlib';

export const SEGMENT = 1024 * 1024;
export const TAG = 16;
export const SEG_PER_PART = 44;
export const PART_BYTES = SEG_PER_PART * (SEGMENT + TAG);

const KEY_PREFIX = 'ffk_';

export function newKey() {
  const raw = crypto.randomBytes(32);
  return { raw, text: KEY_PREFIX + raw.toString('base64url') };
}

export function parseKey(text) {
  if (typeof text !== 'string' || !text.startsWith(KEY_PREFIX)) return null;
  const raw = Buffer.from(text.slice(KEY_PREFIX.length), 'base64url');
  return raw.length === 32 ? raw : null;
}

// What the server stores instead of the key.
export function keyCheck(raw) {
  return crypto.createHash('sha256').update('ffcdn-check|').update(raw).digest('hex');
}

export function keyMatches(raw, check) {
  if (!raw || typeof check !== 'string') return false;
  const a = Buffer.from(keyCheck(raw), 'hex');
  const b = Buffer.from(check, 'hex');
  return a.length === b.length && crypto.timingSafeEqual(a, b);
}

export function fileKey(raw, bundle, fileId) {
  return Buffer.from(crypto.hkdfSync('sha256', raw, Buffer.from(bundle), Buffer.from('ffcdn-file|' + fileId), 32));
}

export const segmentCount = (size) => Math.max(1, Math.ceil(size / SEGMENT));
export const partCount = (size) => Math.ceil(segmentCount(size) / SEG_PER_PART);
export const encryptedSize = (size) => size + segmentCount(size) * TAG;
export function partSize(size, p) {
  const segs = segmentCount(size);
  const first = p * SEG_PER_PART;
  const last = Math.min(segs, first + SEG_PER_PART) - 1;
  let bytes = 0;
  for (let i = first; i <= last; i++) bytes += plainLen(size, i) + TAG;
  return bytes;
}
const plainLen = (size, i) => Math.max(0, Math.min(SEGMENT, size - i * SEGMENT));

function nonce(i) {
  const n = Buffer.alloc(12);
  n.writeBigUInt64BE(BigInt(i), 0);
  return n;
}
const aad = (fileId, i, last) => Buffer.from(`ffcdn|v1|${fileId}|${i}|${last ? 1 : 0}`);

function sealSegment(key, fileId, i, last, plain) {
  const c = crypto.createCipheriv('aes-256-gcm', key, nonce(i));
  c.setAAD(aad(fileId, i, last));
  const body = Buffer.concat([c.update(plain), c.final()]);
  return Buffer.concat([body, c.getAuthTag()]);
}

function openSegment(key, fileId, i, last, sealed) {
  const d = crypto.createDecipheriv('aes-256-gcm', key, nonce(i));
  d.setAAD(aad(fileId, i, last));
  d.setAuthTag(sealed.subarray(sealed.length - TAG));
  return Buffer.concat([d.update(sealed.subarray(0, sealed.length - TAG)), d.final()]);
}

const crcOf = zlib.crc32
  ? (buf, prev) => zlib.crc32(buf, prev)
  : (() => {
      const t = new Int32Array(256);
      for (let n = 0; n < 256; n++) {
        let c = n;
        for (let k = 0; k < 8; k++) c = c & 1 ? 0xedb88320 ^ (c >>> 1) : c >>> 1;
        t[n] = c;
      }
      return (buf, prev = 0) => {
        let c = ~prev;
        for (let i = 0; i < buf.length; i++) c = t[(c ^ buf[i]) & 0xff] ^ (c >>> 8);
        return ~c >>> 0;
      };
    })();

// Encrypts an async iterable of plaintext chunks. Calls onSegment(sealedBuffer, index) for each
// segment in order (awaited, so slow storage slows the upload instead of filling memory).
// Resolves to { size, crc32 }.
export async function encryptStream(source, key, fileId, onSegment, { maxBytes = Infinity } = {}) {
  let held = Buffer.alloc(0);
  let i = 0;
  let size = 0;
  let crc = 0;
  for await (const chunk of source) {
    size += chunk.length;
    if (size > maxBytes) {
      const e = new Error('too_large');
      e.code = 'too_large';
      throw e;
    }
    crc = crcOf(chunk, crc);
    held = held.length ? Buffer.concat([held, chunk]) : chunk;
    // Keep at least one full segment back: only at the end do we know which segment is last.
    while (held.length > SEGMENT) {
      await onSegment(sealSegment(key, fileId, i, false, held.subarray(0, SEGMENT)), i);
      held = held.subarray(SEGMENT);
      i++;
    }
  }
  await onSegment(sealSegment(key, fileId, i, true, held), i);
  return { size, crc32: crc >>> 0 };
}

// Decrypts plaintext bytes [start, end] (inclusive) of a file. readPart(p, from, to) must yield the
// stored bytes of part p from byte `from` to byte `to` (inclusive). Yields verified plaintext only.
export async function* decryptRange({ key, fileId, size, start = 0, end = size - 1, readPart }) {
  if (size === 0) {
    // Still check the single empty segment so a wrong key or a damaged file is noticed.
    let buf = Buffer.alloc(0);
    for await (const c of readPart(0, 0, TAG - 1)) buf = Buffer.concat([buf, c]);
    openSegment(key, fileId, 0, true, buf);
    return;
  }
  if (end < start) return;
  const segs = segmentCount(size);
  const firstSeg = Math.floor(start / SEGMENT);
  const lastSeg = Math.floor(end / SEGMENT);
  for (let p = Math.floor(firstSeg / SEG_PER_PART); p <= Math.floor(lastSeg / SEG_PER_PART); p++) {
    const s0 = Math.max(firstSeg, p * SEG_PER_PART);
    const s1 = Math.min(lastSeg, p * SEG_PER_PART + SEG_PER_PART - 1);
    const from = (s0 - p * SEG_PER_PART) * (SEGMENT + TAG);
    const to = (s1 - p * SEG_PER_PART) * (SEGMENT + TAG) + plainLen(size, s1) + TAG - 1;
    let buf = Buffer.alloc(0);
    let s = s0;
    for await (const chunk of readPart(p, from, to)) {
      buf = buf.length ? Buffer.concat([buf, chunk]) : chunk;
      for (;;) {
        const need = plainLen(size, s) + TAG;
        if (s > s1 || buf.length < need) break;
        const plain = openSegment(key, fileId, s, s === segs - 1, buf.subarray(0, need));
        buf = buf.subarray(need);
        const segStart = s * SEGMENT;
        const a = Math.max(0, start - segStart);
        const b = Math.min(plain.length, end - segStart + 1);
        if (b > a) yield plain.subarray(a, b);
        s++;
      }
    }
    if (s <= s1) {
      const e = new Error('truncated');
      e.code = 'damaged';
      throw e;
    }
  }
}

// ---- ZIP (stored, no compression) with exact length known up front -----------------------------
// Sizes and CRC-32 values come from the manifest, so the archive's total size is known before a
// byte is sent: downloads show real progress. ZIP64 records are added only when needed.
const U32 = 0xffffffff;

function localHeader(name, size, crc, zip64) {
  const n = Buffer.from(name, 'utf8');
  const extra = zip64 ? Buffer.alloc(20) : Buffer.alloc(0);
  if (zip64) {
    extra.writeUInt16LE(0x0001, 0);
    extra.writeUInt16LE(16, 2);
    extra.writeBigUInt64LE(BigInt(size), 4);
    extra.writeBigUInt64LE(BigInt(size), 12);
  }
  const h = Buffer.alloc(30);
  h.writeUInt32LE(0x04034b50, 0);
  h.writeUInt16LE(zip64 ? 45 : 20, 4);
  h.writeUInt16LE(0x0800, 6); // UTF-8 names
  h.writeUInt16LE(0, 8); // stored
  h.writeUInt32LE(0x00210000, 10); // 1980-01-01 00:00
  h.writeUInt32LE(crc >>> 0, 14);
  h.writeUInt32LE(zip64 ? U32 : size, 18);
  h.writeUInt32LE(zip64 ? U32 : size, 22);
  h.writeUInt16LE(n.length, 26);
  h.writeUInt16LE(extra.length, 28);
  return Buffer.concat([h, n, extra]);
}

function centralEntry(name, size, crc, offset) {
  const n = Buffer.from(name, 'utf8');
  const bigSize = size >= U32;
  const bigOff = offset >= U32;
  const fields = [];
  if (bigSize) fields.push(size, size);
  if (bigOff) fields.push(offset);
  let extra = Buffer.alloc(0);
  if (fields.length) {
    extra = Buffer.alloc(4 + fields.length * 8);
    extra.writeUInt16LE(0x0001, 0);
    extra.writeUInt16LE(fields.length * 8, 2);
    fields.forEach((v, k) => extra.writeBigUInt64LE(BigInt(v), 4 + k * 8));
  }
  const h = Buffer.alloc(46);
  h.writeUInt32LE(0x02014b50, 0);
  h.writeUInt16LE(45 | (3 << 8), 4);
  h.writeUInt16LE(fields.length ? 45 : 20, 6);
  h.writeUInt16LE(0x0800, 8);
  h.writeUInt16LE(0, 10);
  h.writeUInt32LE(0x00210000, 12);
  h.writeUInt32LE(crc >>> 0, 16);
  h.writeUInt32LE(bigSize ? U32 : size, 20);
  h.writeUInt32LE(bigSize ? U32 : size, 24);
  h.writeUInt16LE(n.length, 28);
  h.writeUInt16LE(extra.length, 30);
  h.writeUInt32LE((0o100644 << 16) >>> 0, 38);
  h.writeUInt32LE(bigOff ? U32 : offset, 42);
  return Buffer.concat([h, n, extra]);
}

// entries: [{ name, size, crc32, data: () => AsyncIterable<Buffer> }]
export function zipPlan(entries) {
  let offset = 0;
  const plan = entries.map((e) => {
    const zip64 = e.size >= U32;
    const header = localHeader(e.name, e.size, e.crc32, zip64);
    const at = offset;
    offset += header.length + e.size;
    return { ...e, header, offset: at };
  });
  const central = Buffer.concat(plan.map((e) => centralEntry(e.name, e.size, e.crc32, e.offset)));
  const cdStart = offset;
  const need64 = cdStart >= U32 || central.length >= U32 || plan.length >= 0xffff;
  const tail = [];
  if (need64) {
    const z = Buffer.alloc(56);
    z.writeUInt32LE(0x06064b50, 0);
    z.writeBigUInt64LE(44n, 4);
    z.writeUInt16LE(45, 12);
    z.writeUInt16LE(45, 14);
    z.writeBigUInt64LE(BigInt(plan.length), 24);
    z.writeBigUInt64LE(BigInt(plan.length), 32);
    z.writeBigUInt64LE(BigInt(central.length), 40);
    z.writeBigUInt64LE(BigInt(cdStart), 48);
    const loc = Buffer.alloc(20);
    loc.writeUInt32LE(0x07064b50, 0);
    loc.writeBigUInt64LE(BigInt(cdStart + central.length), 8);
    loc.writeUInt32LE(1, 16);
    tail.push(z, loc);
  }
  const end = Buffer.alloc(22);
  end.writeUInt32LE(0x06054b50, 0);
  end.writeUInt16LE(Math.min(plan.length, 0xffff), 8);
  end.writeUInt16LE(Math.min(plan.length, 0xffff), 10);
  end.writeUInt32LE(Math.min(central.length, U32), 12);
  end.writeUInt32LE(need64 ? U32 : cdStart, 16);
  tail.push(end);
  const trailer = Buffer.concat([central, ...tail]);
  return {
    length: cdStart + trailer.length,
    async *stream() {
      for (const e of plan) {
        yield e.header;
        yield* e.data();
      }
      yield trailer;
    },
  };
}
