import dgram from 'node:dgram';
import crypto from 'node:crypto';
import { localMs } from './clock.js';

const NTP_UNIX = 2208988800; // seconds between 1900-01-01 and 1970-01-01
const TWO32 = 4294967296;

export function msToNtp(ms) {
  const sec = Math.floor(ms / 1000);
  const frac = Math.floor(((ms - sec * 1000) / 1000) * TWO32);
  return { sec: (sec + NTP_UNIX) >>> 0, frac: frac >>> 0 };
}

export function ntpToMs(sec, frac) {
  let s = sec;
  if (s < 0x80000000) s += TWO32; // NTP era 1 (after 7 Feb 2036)
  return (s - NTP_UNIX) * 1000 + (frac / TWO32) * 1000;
}

function writeTs(buf, off, ms) {
  const { sec, frac } = msToNtp(ms);
  buf.writeUInt32BE(sec, off);
  buf.writeUInt32BE(frac, off + 4);
}

function readTs(buf, off) {
  const sec = buf.readUInt32BE(off);
  const frac = buf.readUInt32BE(off + 4);
  return { sec, frac, ms: sec === 0 && frac === 0 ? NaN : ntpToMs(sec, frac) };
}

/**
 * One NTP exchange. Resolves with the offset of the server clock relative to our local clock
 * (offset = ((T2-T1)+(T3-T4))/2), the round-trip delay, and server metadata. The round-trip
 * compensation is what makes network latency not matter to accuracy.
 */
export function queryNtp(host, { port = 123, timeoutMs = 1500, signal } = {}) {
  return new Promise((resolve, reject) => {
    const sock = dgram.createSocket('udp4');
    const pkt = Buffer.alloc(48);
    pkt[0] = (0 << 6) | (4 << 3) | 3; // LI 0, VN 4, mode 3 (client)
    let timer;
    let settled = false;
    const finish = (fn, v) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      signal?.removeEventListener('abort', onAbort);
      try {
        sock.close();
      } catch {}
      fn(v);
    };
    const onAbort = () => finish(reject, new Error('aborted'));
    if (signal?.aborted) return onAbort();
    signal?.addEventListener('abort', onAbort, { once: true });

    // Random low bits in the transmit timestamp let us reject spoofed replies (origin must echo it).
    const t1ms = localMs();
    writeTs(pkt, 40, t1ms);
    crypto.randomFillSync(pkt, 46, 2); // lowest 16 bits of the fraction (about 15 microseconds)
    const origin = Buffer.from(pkt.subarray(40, 48));

    sock.on('error', (e) => finish(reject, e));
    sock.on('message', (msg) => {
      const t4 = localMs();
      if (msg.length < 48) return;
      const mode = msg[0] & 7;
      const li = msg[0] >> 6;
      const stratum = msg[1];
      if (mode !== 4) return;
      if (!msg.subarray(24, 32).equals(origin)) return; // not a reply to our request
      if (li === 3 || stratum < 1 || stratum > 15) return finish(reject, new Error(`unsynchronized server (stratum ${stratum})`));
      const t1 = readTs(origin, 0).ms;
      const t2 = readTs(msg, 32).ms;
      const t3 = readTs(msg, 40).ms;
      if (!Number.isFinite(t2) || !Number.isFinite(t3)) return finish(reject, new Error('empty timestamps'));
      const offsetMs = (t2 - t1 + (t3 - t4)) / 2;
      const rttMs = t4 - t1 - (t3 - t2);
      if (rttMs < -5) return finish(reject, new Error('negative delay'));
      finish(resolve, { offsetMs, rttMs: Math.max(rttMs, 0), stratum, t4 });
    });
    timer = setTimeout(() => finish(reject, new Error('timeout')), timeoutMs);
    sock.send(pkt, port, host, (err) => err && finish(reject, err));
  });
}

/**
 * Serves NTP over UDP using the consensus clock, so Windows (w32tm), chrony, ntpd etc. can use
 * FastFlare as a time server. `clock()` must return { ms, synced, rootDelayMs, dispersionMs, refMs }.
 */
export function startNtpServer({ port = 123, host = '0.0.0.0', clock, log = () => {} }) {
  const sock = dgram.createSocket('udp4');
  const toFixed1616 = (seconds) => Math.max(0, Math.min(0xffffffff, Math.round(seconds * 65536))) >>> 0;

  sock.on('message', (msg, rinfo) => {
    if (msg.length < 48) return;
    const c = clock();
    const rx = c.ms;
    const mode = msg[0] & 7;
    if (mode !== 3 && mode !== 1) return;
    const vn = Math.min(4, Math.max(1, (msg[0] >> 3) & 7));
    const out = Buffer.alloc(48);
    if (!c.synced) {
      out[0] = (3 << 6) | (vn << 3) | 4; // LI 3 = alarm: clients will ignore us
      out[1] = 16;
    } else {
      out[0] = (0 << 6) | (vn << 3) | 4; // server mode
      out[1] = 2;
    }
    out[2] = msg[2];
    out[3] = 0xec; // precision 2^-20 s
    out.writeUInt32BE(toFixed1616((c.rootDelayMs || 0) / 1000), 4);
    out.writeUInt32BE(toFixed1616((c.dispersionMs || 1) / 1000), 8);
    out.write('FFLR', 12, 'ascii');
    if (c.refMs) writeTs(out, 16, c.refMs);
    msg.copy(out, 24, 40, 48); // origin = client's transmit timestamp
    writeTs(out, 32, rx);
    writeTs(out, 40, clock().ms);
    sock.send(out, rinfo.port, rinfo.address);
  });

  return new Promise((resolve, reject) => {
    sock.once('error', reject);
    sock.bind(port, host, () => {
      sock.removeListener('error', reject);
      sock.on('error', (e) => log('ntp server error:', e.message));
      resolve({ port: sock.address().port, close: () => sock.close() });
    });
  });
}
