// Smart routing for CDN downloads. The same rules run on the server and on the Vercel edge.
//
//   small files (<= FF_ROUTE_SMALL_MB, default 25)     -> Vercel edge: close to the visitor, cached
//   normal files                                       -> the server, streamed directly ("native")
//   extra-large files (> FF_ROUTE_XL_MB, default 500)  -> the chunked downloader page in a browser:
//                                                         parallel Range requests through the edge
//   a Range request of up to CHUNK_MAX bytes           -> served wherever it arrived (that is how the
//                                                         chunked downloader and video seeking work)
// ?route=edge|native|chunked forces a route.
export const CHUNK_MAX = 256 * 1024 * 1024;

export function rangeSpan(header, size) {
  const m = String(header || '').match(/^bytes=(\d*)-(\d*)$/);
  if (!m || (!m[1] && !m[2])) return null;
  if (!m[1]) return Math.min(size, Number(m[2]));
  const a = Number(m[1]);
  const b = m[2] ? Math.min(Number(m[2]), size - 1) : size - 1;
  return Math.max(0, b - a + 1);
}

export function pickRoute({ asked, total, single, span, html, smallMax, xlMin, haveEdge, here }) {
  let r;
  if (asked === 'edge' || asked === 'native' || (asked === 'chunked' && single)) r = asked;
  else if (span != null && span <= CHUNK_MAX) r = here;
  else if (total <= smallMax) r = 'edge';
  else if (single && total > xlMin && html) r = 'chunked';
  else r = 'native';
  if (r === 'edge' && !haveEdge) r = 'native';
  return r;
}

// The downloader page reads everything from the fragment, which browsers never send to a server.
export function chunkedPageUrl({ pageBase, chunkBase, nativeUrl, bundle, name, size, key }) {
  const h = new URLSearchParams({ b: bundle, f: name, s: String(size), k: key, src: chunkBase, native: nativeUrl });
  return `${pageBase}/get.html#${h}`;
}
