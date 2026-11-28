export const CORS = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Methods': 'GET, HEAD, POST, PUT, DELETE, OPTIONS',
  'Access-Control-Allow-Headers': 'Content-Type, Authorization, Range, X-FF-Key, X-FF-Bundle, X-FF-Tier, X-FF-Name',
  'Access-Control-Max-Age': '86400',
  'Access-Control-Expose-Headers': 'Server-Timing, X-FastFlare-Time, Content-Range, Content-Disposition, Content-Length, Accept-Ranges',
  'Timing-Allow-Origin': '*',
};

export function httpError(status, code) {
  const e = new Error(code);
  e.status = status;
  e.code = code;
  return e;
}

export function send(res, status, obj, extra = {}) {
  const body = JSON.stringify(obj);
  res.writeHead(status, {
    'Content-Type': 'application/json; charset=utf-8',
    'Content-Length': Buffer.byteLength(body),
    'Cache-Control': 'no-store',
    ...extra,
  });
  res.end(body);
}

// Reads a JSON or application/x-www-form-urlencoded body (like reCAPTCHA's siteverify).
export async function readBody(req, limit = 16 * 1024) {
  let size = 0;
  const chunks = [];
  for await (const c of req) {
    size += c.length;
    if (size > limit) throw httpError(413, 'payload_too_large');
    chunks.push(c);
  }
  const text = Buffer.concat(chunks).toString('utf8');
  if (!text) return {};
  const type = String(req.headers['content-type'] || '');
  if (type.includes('application/x-www-form-urlencoded')) {
    return Object.fromEntries(new URLSearchParams(text));
  }
  try {
    const v = JSON.parse(text);
    if (v === null || typeof v !== 'object') throw new Error('not an object');
    return v;
  } catch {
    throw httpError(400, 'invalid_json');
  }
}

export function clientIp(req, trustProxy) {
  if (trustProxy) {
    const cf = req.headers['cf-connecting-ip'];
    if (cf) return String(cf);
    const xff = req.headers['x-forwarded-for'];
    if (xff) return String(xff).split(',')[0].trim();
  }
  return String(req.socket.remoteAddress || '').replace(/^::ffff:/, '');
}

// Coarse network prefix (IPv4 /24, IPv6 first 3 groups) so mobile/NAT address churn
// inside one network does not break challenge binding.
export function coarseIp(ip) {
  if (ip.includes(':')) return ip.split(':').slice(0, 3).join(':');
  return ip.split('.').slice(0, 3).join('.');
}
