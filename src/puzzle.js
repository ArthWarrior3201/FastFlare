import zlib from 'node:zlib';
import crypto from 'node:crypto';

// Interactive challenge: a picture with several shaped holes. The visitor drags a piece of one
// shape into the hole of the same shape. The hole's position exists only in the pixels, never in
// the JSON, so a script that calls the API cannot answer without reading and understanding the image.

export const WIDTH = 300;
export const HEIGHT = 150;
export const SIZE = 44;
export const SHAPES = ['circle', 'square', 'triangle', 'diamond', 'cross'];

export function insideShape(shape, u, v) {
  const au = Math.abs(u);
  const av = Math.abs(v);
  switch (shape) {
    case 'circle': return u * u + v * v <= 1;
    case 'square': return au <= 0.8 && av <= 0.8;
    case 'triangle': return v <= 0.85 && v >= -0.95 && au <= (v + 0.95) / 1.8;
    case 'diamond': return au + av <= 1;
    case 'cross': return (au <= 0.34 && av <= 0.95) || (av <= 0.34 && au <= 0.95);
    default: return false;
  }
}

const CRC = new Uint32Array(256).map((_, n) => {
  let c = n;
  for (let k = 0; k < 8; k++) c = c & 1 ? 0xedb88320 ^ (c >>> 1) : c >>> 1;
  return c >>> 0;
});
function crc32(buf) {
  let c = 0xffffffff;
  for (const b of buf) c = CRC[(c ^ b) & 255] ^ (c >>> 8);
  return (c ^ 0xffffffff) >>> 0;
}
function chunk(type, data) {
  const len = Buffer.alloc(4);
  len.writeUInt32BE(data.length);
  const td = Buffer.concat([Buffer.from(type, 'ascii'), data]);
  const crc = Buffer.alloc(4);
  crc.writeUInt32BE(crc32(td));
  return Buffer.concat([len, td, crc]);
}
export function encodePng(w, h, rgb) {
  const stride = w * 3 + 1;
  const raw = Buffer.alloc(stride * h);
  for (let y = 0; y < h; y++) rgb.copy(raw, y * stride + 1, y * w * 3, (y + 1) * w * 3);
  const ihdr = Buffer.alloc(13);
  ihdr.writeUInt32BE(w, 0);
  ihdr.writeUInt32BE(h, 4);
  ihdr[8] = 8; // bit depth
  ihdr[9] = 2; // RGB
  return Buffer.concat([
    Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]),
    chunk('IHDR', ihdr),
    chunk('IDAT', zlib.deflateSync(raw, { level: 9 })),
    chunk('IEND', Buffer.alloc(0)),
  ]);
}

const rnd = () => crypto.randomInt(0, 1 << 30) / (1 << 30);
const PALETTES = [
  [[22, 16, 60], [120, 40, 120]],
  [[10, 28, 66], [40, 118, 140]],
  [[38, 14, 40], [176, 80, 60]],
  [[16, 22, 46], [92, 88, 170]],
];

export function makePuzzle() {
  const W = WIDTH;
  const H = HEIGHT;
  const S = SIZE;
  const shapes = [...SHAPES];
  for (let i = shapes.length - 1; i > 0; i--) {
    const j = crypto.randomInt(i + 1);
    [shapes[i], shapes[j]] = [shapes[j], shapes[i]];
  }
  const [target, ...decoyShapes] = shapes;
  const y = crypto.randomInt(8, H - S - 8);

  // Three non-overlapping slots: the real hole and two decoys of other shapes, all on the same row
  // so the row the piece sits on gives nothing away.
  const lo = S + 14;
  const hi = W - S - 4;
  let xs;
  do {
    xs = [0, 1, 2].map(() => crypto.randomInt(lo, hi + 1));
  } while (Math.min(Math.abs(xs[0] - xs[1]), Math.abs(xs[0] - xs[2]), Math.abs(xs[1] - xs[2])) < S + 6);

  const [c1, c2] = PALETTES[crypto.randomInt(PALETTES.length)];
  const GX = 11;
  const GY = 6;
  const grid = Array.from({ length: GX * GY }, rnd);
  const BN = 3;
  const bcols = Math.ceil(W / BN);
  const blocks = Array.from({ length: bcols * Math.ceil(H / BN) }, () => (rnd() - 0.5) * 22);
  const rgb = Buffer.alloc(W * H * 3);

  for (let py = 0; py < H; py++) {
    for (let px = 0; px < W; px++) {
      const t = (px / W) * 0.7 + (py / H) * 0.3;
      const gx = (px / W) * (GX - 1);
      const gy = (py / H) * (GY - 1);
      const ix = Math.min(GX - 2, Math.floor(gx));
      const iy = Math.min(GY - 2, Math.floor(gy));
      const fx = gx - ix;
      const fy = gy - iy;
      const g = (a, b) => grid[(iy + b) * GX + ix + a];
      const n = (g(0, 0) * (1 - fx) + g(1, 0) * fx) * (1 - fy) + (g(0, 1) * (1 - fx) + g(1, 1) * fx) * fy;
      const shade = (n - 0.5) * 80 + blocks[Math.floor(py / BN) * bcols + Math.floor(px / BN)];
      const o = (py * W + px) * 3;
      for (let k = 0; k < 3; k++) rgb[o + k] = Math.max(0, Math.min(255, Math.round(c1[k] + (c2[k] - c1[k]) * t + shade)));
    }
  }
  for (let i = 0; i < 45; i++) {
    const o = (crypto.randomInt(H) * W + crypto.randomInt(W)) * 3;
    const b = 170 + crypto.randomInt(80);
    rgb[o] = rgb[o + 1] = rgb[o + 2] = b;
  }

  const draw = (shape, x0) => {
    const h = S / 2;
    for (let py = y; py < y + S; py++) {
      for (let px = x0; px < x0 + S; px++) {
        const u = (px - x0 + 0.5 - h) / h;
        const v = (py - y + 0.5 - h) / h;
        if (!insideShape(shape, u, v)) continue;
        const o = (py * W + px) * 3;
        const edge = !insideShape(shape, u / 0.86, v / 0.86);
        for (let k = 0; k < 3; k++) rgb[o + k] = edge ? Math.round(rgb[o + k] + (255 - rgb[o + k]) * 0.45) : Math.round(rgb[o + k] * 0.45);
      }
    }
  };
  draw(target, xs[0]);
  draw(decoyShapes[0], xs[1]);
  draw(decoyShapes[1], xs[2]);

  return { png: encodePng(W, H, rgb), x: xs[0], y, shape: target, width: W, height: H, size: S };
}
