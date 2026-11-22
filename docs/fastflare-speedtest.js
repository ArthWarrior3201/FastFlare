/*!
 * FastFlare speed test client. Pick a provider and a city, then measure latency, jitter, download,
 * upload and latency under load against that provider's server in that city.
 *
 *   const st = new FastFlareSpeedTest({ api: 'https://YOUR-FASTFLARE-HOST' });
 *   await st.loadServers();
 *   st.providers();            // ['AWS', 'Oracle', ...]
 *   st.cities('Oracle');       // [{ id, provider, city, country, url }, ...]
 *   const result = await st.run({ serverId: 'oracle-hyderabad', onProgress: (p) => console.log(p) });
 *
 * How it stays accurate:
 *  - Download and upload each run for a fixed time over several parallel connections, with chunk
 *    sizes that adapt to the line, so fast and slow connections are both measured properly.
 *  - The first seconds (TCP ramp-up) are ignored; only the steady part counts.
 *  - Upload speed is measured by the server: it counts bytes as they arrive, so data still sitting in
 *    buffers on the way is never counted as sent.
 *  - Upload data is random, so nothing along the way can compress it.
 *  - Latency uses the browser's own network timing (Resource Timing) where available, so JavaScript
 *    overhead is not counted, and the first request (connection setup) is discarded.
 *  - Latency is also sampled during the transfers ("loaded latency"), which shows bufferbloat.
 *
 * Docs: https://arthwarrior3201.github.io/FastFlare/speedtest.html
 */
(function (global) {
  'use strict';

  var now = function () { return performance.now(); };
  var rnd = function () { return Math.random().toString(36).slice(2); };
  var abortErr = function () { return new DOMException('Aborted', 'AbortError'); };

  function percentile(sorted, p) {
    if (!sorted.length) return 0;
    var i = (sorted.length - 1) * p;
    var lo = Math.floor(i), hi = Math.ceil(i);
    return sorted[lo] + (sorted[hi] - sorted[lo]) * (i - lo);
  }

  function latencyStats(samples, lost) {
    var s = samples.slice().sort(function (a, b) { return a - b; });
    var mean = samples.reduce(function (a, b) { return a + b; }, 0) / (samples.length || 1);
    var jit = 0;
    for (var i = 1; i < samples.length; i++) jit += Math.abs(samples[i] - samples[i - 1]);
    return {
      min: s[0] || 0,
      median: percentile(s, 0.5),
      mean: mean,
      p90: percentile(s, 0.9),
      max: s[s.length - 1] || 0,
      jitter: samples.length > 1 ? jit / (samples.length - 1) : 0, // mean difference between consecutive pings
      loss: samples.length + lost ? lost / (samples.length + lost) : 0,
      samples: samples,
    };
  }

  // Random, incompressible upload data, generated once.
  var RANDOM = null;
  function randomBlob(bytes) {
    if (!RANDOM) {
      RANDOM = new Uint8Array(1 << 20);
      for (var o = 0; o < RANDOM.length; o += 65536) crypto.getRandomValues(RANDOM.subarray(o, o + 65536));
    }
    var parts = [];
    for (var left = bytes; left > 0; left -= RANDOM.length) parts.push(left >= RANDOM.length ? RANDOM : RANDOM.subarray(0, left));
    return new Blob(parts);
  }

  function FastFlareSpeedTest(opts) {
    opts = opts || {};
    this.api = (opts.api || '').replace(/\/$/, '');
    this.registry = opts.registry || this.api + '/speed/servers';
    this.servers = [];
    this.pings = opts.pings || 20;
    this.duration = opts.duration || 10; // seconds per direction
    this.warmup = opts.warmup || 2; // seconds ignored at the start of each direction
    this.downloadStreams = opts.downloadStreams || 4;
    this.uploadStreams = opts.uploadStreams || 3;
    try { performance.setResourceTimingBufferSize(2000); } catch (e) {}
  }

  FastFlareSpeedTest.prototype.loadServers = function () {
    var self = this;
    return fetch(this.registry, { cache: 'no-store' })
      .then(function (r) { if (!r.ok) throw new Error('registry ' + r.status); return r.json(); })
      .then(function (j) {
        self.servers = (j.servers || []).map(function (s) {
          s.url = (s.url || self.api || new URL(self.registry).origin).replace(/\/$/, '');
          return s;
        });
        return self.servers;
      });
  };

  FastFlareSpeedTest.prototype.providers = function () {
    var seen = {};
    this.servers.forEach(function (s) { seen[s.provider] = 1; });
    return Object.keys(seen).sort();
  };

  FastFlareSpeedTest.prototype.cities = function (provider) {
    return this.servers
      .filter(function (s) { return s.provider === provider; })
      .sort(function (a, b) { return a.city.localeCompare(b.city); });
  };

  // One round trip. Prefers the browser's network timing (request sent -> first byte back).
  function pingOnce(base, signal) {
    var url = new URL(base + '/speed/ping?r=' + rnd(), location.href).href;
    var t0 = now();
    return fetch(url, { cache: 'no-store', signal: signal }).then(function (r) { return r.arrayBuffer(); }).then(function () {
      var wall = now() - t0;
      var ms = wall;
      try {
        var e = performance.getEntriesByName(url).pop();
        if (e && e.requestStart > 0 && e.responseStart > e.requestStart) ms = Math.min(wall, e.responseStart - e.requestStart);
        performance.clearResourceTimings();
      } catch (err) {}
      return ms;
    });
  }

  FastFlareSpeedTest.prototype.latency = function (server, o) {
    o = o || {};
    var self = this;
    var samples = [];
    var lost = 0;
    // The first request pays for DNS, TCP and TLS setup: discard it.
    return pingOnce(server.url, o.signal).catch(function (e) { if (e.name === 'AbortError') throw e; }).then(function () {
      var p = Promise.resolve();
      for (var i = 0; i < self.pings; i++) {
        (function (i) {
          p = p.then(function () {
            return pingOnce(server.url, o.signal).then(
              function (ms) { samples.push(ms); if (o.onSample) o.onSample(ms, i, samples); },
              function (e) { if (e && e.name === 'AbortError') throw e; lost++; },
            );
          });
        })(i);
      }
      return p.then(function () { return latencyStats(samples, lost); });
    });
  };

  // Runs one direction for a fixed time over parallel streams.
  FastFlareSpeedTest.prototype._direction = function (kind, server, o) {
    var self = this;
    var phase = kind === 'down' ? 'download' : 'upload';
    var DUR = self.duration * 1000;
    var WARM = self.warmup * 1000;
    var streams = kind === 'down' ? self.downloadStreams : self.uploadStreams;
    var maxChunk = kind === 'down' ? 50e6 : 25e6;
    var ctrl = new AbortController();
    var onOuterAbort = function () { ctrl.abort(); };
    if (o.signal) {
      if (o.signal.aborted) return Promise.reject(abortErr());
      o.signal.addEventListener('abort', onOuterAbort, { once: true });
    }

    var t0 = now();
    var tEnd = t0 + DUR;
    var chunk = kind === 'down' ? 1e6 : 512e3;
    var recent = []; // [t, bytes] for the live graph
    var flowBytes = 0; // bytes seen arriving / leaving inside the measured window
    var done = []; // [completedAt, bytes] of finished requests (upload: confirmed by the server)
    var series = [];
    var loaded = [];
    var requests = 0;
    var sid = kind === 'up' ? rnd().replace(/[^a-z0-9]/g, '').slice(0, 12) + 'x0000' : '';

    function flow(bytes) {
      var t = now();
      recent.push([t, bytes]);
      if (t >= t0 + WARM && t <= tEnd) flowBytes += bytes;
    }

    var sampler = setInterval(function () {
      var t = now();
      var cut = t - 1000;
      while (recent.length && recent[0][0] < cut) recent.shift();
      var sum = 0;
      recent.forEach(function (e) { sum += e[1]; });
      var span = Math.min(1000, t - t0) || 1;
      var pt = { t: (t - t0) / 1000, mbps: (sum * 8) / (span / 1000) / 1e6 };
      series.push(pt);
      if (o.onProgress) o.onProgress({ phase: phase, mbps: pt.mbps, t: pt.t, series: series, progress: Math.min(1, (t - t0) / DUR) });
    }, 200);

    // Latency under load, sampled while the line is busy.
    var pinging = true;
    (function pingLoop() {
      if (!pinging) return;
      setTimeout(function () {
        if (!pinging) return;
        if (now() - t0 < WARM) return pingLoop();
        pingOnce(server.url, ctrl.signal).then(function (ms) { if (pinging) loaded.push(ms); }, function () {}).then(pingLoop);
      }, 400);
    })();

    function download(bytes) {
      return fetch(server.url + '/speed/down?bytes=' + Math.round(bytes) + '&r=' + rnd(), { cache: 'no-store', signal: ctrl.signal }).then(function (r) {
        if (!r.ok) throw new Error('download HTTP ' + r.status);
        var reader = r.body.getReader();
        var got = 0;
        return (function pump() {
          return reader.read().then(function (x) {
            if (x.done) return got;
            got += x.value.byteLength;
            flow(x.value.byteLength);
            return pump();
          });
        })();
      });
    }

    function upload(bytes) {
      return new Promise(function (resolve, reject) {
        var xhr = new XMLHttpRequest();
        var sent = 0;
        xhr.open('POST', server.url + '/speed/up?sid=' + sid + '&r=' + rnd());
        xhr.upload.onprogress = function (e) { flow(e.loaded - sent); sent = e.loaded; };
        xhr.onload = function () {
          if (xhr.status !== 200) return reject(new Error('upload HTTP ' + xhr.status));
          var confirmed = bytes;
          try { confirmed = JSON.parse(xhr.responseText).bytes || bytes; } catch (e) {}
          resolve(confirmed);
        };
        xhr.onerror = function () { reject(new Error('upload failed')); };
        xhr.onabort = function () { reject(abortErr()); };
        ctrl.signal.addEventListener('abort', function () { xhr.abort(); }, { once: true });
        xhr.send(randomBlob(Math.round(bytes)));
      });
    }

    function stream() {
      if (now() >= tEnd || ctrl.signal.aborted) return Promise.resolve();
      var size = chunk;
      var t1 = now();
      requests++;
      return (kind === 'down' ? download(size) : upload(size)).then(
        function (bytes) {
          var t2 = now();
          done.push([t2, bytes]);
          // Aim for requests of about 0.75 s each at the speed this one achieved.
          var rate = bytes / Math.max((t2 - t1) / 1000, 0.02);
          chunk = Math.max(100e3, Math.min(maxChunk, rate * 0.75));
          return stream();
        },
        function (e) {
          if (ctrl.signal.aborted) return;
          throw e;
        },
      );
    }

    var stopTimer = setTimeout(function () { ctrl.abort(); }, DUR);
    var all = [];
    for (var i = 0; i < streams; i++) all.push(stream());

    function cleanup() {
      clearTimeout(stopTimer);
      clearInterval(sampler);
      pinging = false;
      if (o.signal) o.signal.removeEventListener('abort', onOuterAbort);
    }

    function finish(mbps, seconds, method) {
      loaded.sort(function (a, b) { return a - b; });
      return {
        mbps: mbps,
        seconds: seconds,
        streams: streams,
        requests: requests,
        method: method,
        series: series,
        loadedLatency: { median: percentile(loaded, 0.5), p90: percentile(loaded, 0.9), samples: loaded },
      };
    }

    return Promise.all(all).then(
      function () {
        cleanup();
        if (o.signal && o.signal.aborted) throw abortErr();
        var seconds = (Math.min(now(), tEnd) - (t0 + WARM)) / 1000;
        var clientMbps = seconds > 0 ? (flowBytes * 8) / seconds / 1e6 : 0;
        if (kind === 'down') return finish(clientMbps, seconds, 'received');
        // Upload: use the server's own count of bytes that arrived, skipping its first WARM seconds
        // and the last slot (cut off when the test stopped).
        return fetch(server.url + '/speed/upstats?sid=' + sid, { cache: 'no-store' })
          .then(function (r) { if (!r.ok) throw new Error('no stats'); return r.json(); })
          .then(function (st) {
            var slots = st.slots || [];
            if (slots.length < 5) throw new Error('too few slots');
            var firstSlot = slots[0][0];
            var lastSlot = slots[slots.length - 1][0];
            var from = firstSlot + Math.round(WARM / st.slotMs);
            var bytes = 0;
            slots.forEach(function (x) { if (x[0] >= from && x[0] < lastSlot) bytes += x[1]; });
            var secs = ((lastSlot - from) * st.slotMs) / 1000;
            if (secs <= 0.5) throw new Error('window too short');
            return finish((bytes * 8) / secs / 1e6, secs, 'server-measured');
          })
          .catch(function () { return finish(clientMbps, seconds, 'browser-estimate'); });
      },
      function (e) { cleanup(); ctrl.abort(); throw e; },
    );
  };

  FastFlareSpeedTest.prototype.download = function (server, o) { return this._direction('down', server, o || {}); };
  FastFlareSpeedTest.prototype.upload = function (server, o) { return this._direction('up', server, o || {}); };

  /**
   * Full run: latency and jitter -> download -> upload.
   * options: { serverId | server, signal, onPhase(phase), onProgress({phase, mbps, t, series, progress}), onPing(ms, i, samples) }
   */
  FastFlareSpeedTest.prototype.run = function (o) {
    var self = this;
    o = o || {};
    var server = o.server || this.servers.filter(function (s) { return s.id === o.serverId; })[0];
    if (!server) return Promise.reject(new Error('Unknown server'));
    var started = Date.now();
    var result = { server: server, startedAt: new Date(started).toISOString() };
    if (o.onPhase) o.onPhase('latency');
    return this.latency(server, { signal: o.signal, onSample: o.onPing })
      .then(function (lat) {
        result.latency = lat;
        if (o.onPhase) o.onPhase('download');
        return self.download(server, o);
      })
      .then(function (dl) {
        result.download = dl;
        if (o.onPhase) o.onPhase('upload');
        return self.upload(server, o);
      })
      .then(function (ul) {
        result.upload = ul;
        result.durationMs = Date.now() - started;
        if (o.onPhase) o.onPhase('done');
        return result;
      });
  };

  global.FastFlareSpeedTest = FastFlareSpeedTest;
})(typeof window !== 'undefined' ? window : globalThis);
