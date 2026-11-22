/*!
 * FastFlare speed test client. Pick a provider and a city, measure latency, jitter, download and
 * upload against that provider's server in that city.
 *
 *   const st = new FastFlareSpeedTest({ api: 'https://YOUR-FASTFLARE-HOST' });
 *   await st.loadServers();
 *   st.providers();            // ['AWS', 'Hetzner', ...]
 *   st.cities('AWS');          // [{ id, provider, city, country, url }, ...]
 *   const result = await st.run({ serverId: 'aws-frankfurt', onProgress: (p) => console.log(p) });
 *
 * Docs: https://arthwarrior3201.github.io/FastFlare/speedtest.html
 */
(function (global) {
  'use strict';

  var now = function () { return performance.now(); };

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
      jitter: samples.length > 1 ? jit / (samples.length - 1) : 0, // mean absolute difference of consecutive pings
      loss: samples.length + lost ? lost / (samples.length + lost) : 0,
      samples: samples,
    };
  }

  var rnd = function () { return Math.random().toString(36).slice(2); };

  function FastFlareSpeedTest(opts) {
    opts = opts || {};
    this.api = (opts.api || '').replace(/\/$/, '');
    this.registry = opts.registry || this.api + '/speed/servers';
    this.servers = [];
    this.pings = opts.pings || 20;
    this.downloadPlan = opts.downloadPlan || [
      { bytes: 100e3, count: 8, parallel: 1 },
      { bytes: 1e6, count: 6, parallel: 1 },
      { bytes: 10e6, count: 4, parallel: 2 },
      { bytes: 25e6, count: 3, parallel: 4 },
      { bytes: 50e6, count: 2, parallel: 4 },
    ];
    this.uploadPlan = opts.uploadPlan || [
      { bytes: 100e3, count: 6, parallel: 1 },
      { bytes: 1e6, count: 5, parallel: 1 },
      { bytes: 5e6, count: 4, parallel: 2 },
      { bytes: 10e6, count: 3, parallel: 3 },
    ];
    this.maxStageSeconds = opts.maxStageSeconds || 10; // skip a stage if it is predicted to take longer than this
  }

  FastFlareSpeedTest.prototype.loadServers = function () {
    var self = this;
    return fetch(this.registry, { cache: 'no-store' })
      .then(function (r) { if (!r.ok) throw new Error('registry ' + r.status); return r.json(); })
      .then(function (j) {
        self.servers = (j.servers || []).map(function (s) {
          // A server with no public URL is the registry host itself.
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

  FastFlareSpeedTest.prototype.latency = function (server, o) {
    o = o || {};
    var self = this;
    var samples = [];
    var lost = 0;
    var base = server.url;
    function one(i) {
      if (o.signal && o.signal.aborted) return Promise.reject(new DOMException('Aborted', 'AbortError'));
      var t0 = now();
      return fetch(base + '/speed/ping?r=' + rnd(), { cache: 'no-store', signal: o.signal })
        .then(function (r) { return r.arrayBuffer(); })
        .then(function () { return now() - t0; });
    }
    // The first request pays for DNS/TCP/TLS setup; discard it so we measure the path, not the handshake.
    return one(-1).catch(function () {}).then(function () {
      var p = Promise.resolve();
      for (var i = 0; i < self.pings; i++) {
        (function (i) {
          p = p.then(function () {
            return one(i).then(
              function (ms) { samples.push(ms); if (o.onSample) o.onSample(ms, i, samples); },
              function (e) { if (e && e.name === 'AbortError') throw e; lost++; },
            );
          });
        })(i);
      }
      return p.then(function () { return latencyStats(samples, lost); });
    });
  };

  // Runs one stage of a plan: `count` transfers, `parallel` at a time. Each transfer reports bytes
  // as they move so we can draw a live throughput line.
  function runStage(stage, doTransfer, tracker, latencyMs, signal) {
    var perReq = [];
    var left = stage.count;
    var t0 = now();
    var total = 0;
    function worker() {
      if (left <= 0 || (signal && signal.aborted)) return Promise.resolve();
      left--;
      return doTransfer(stage.bytes, tracker).then(function (r) {
        perReq.push(r);
        total += r.bytes;
        return worker();
      });
    }
    var ws = [];
    for (var i = 0; i < stage.parallel; i++) ws.push(worker());
    return Promise.all(ws).then(function () {
      var wall = now() - t0;
      // Subtract one round trip (request + first byte) so latency does not masquerade as slowness.
      var usable = Math.max(wall - latencyMs, wall * 0.5, 1);
      return { bytes: stage.bytes, count: stage.count, parallel: stage.parallel, totalBytes: total, ms: wall, mbps: (total * 8) / (usable / 1000) / 1e6 };
    });
  }

  function Tracker(onProgress, phase) {
    var t0 = now();
    var events = []; // [t, bytes]
    var series = [];
    var lastEmit = 0;
    return {
      series: series,
      add: function (bytes) {
        var t = now();
        events.push([t, bytes]);
        if (t - lastEmit < 100) return;
        lastEmit = t;
        // Throughput over the trailing 400 ms window.
        var cut = t - 400, sum = 0;
        while (events.length && events[0][0] < cut) events.shift();
        events.forEach(function (e) { sum += e[1]; });
        var span = Math.min(400, t - t0) || 1;
        var mbps = (sum * 8) / (span / 1000) / 1e6;
        var pt = { t: (t - t0) / 1000, mbps: mbps };
        series.push(pt);
        if (onProgress) onProgress({ phase: phase, mbps: mbps, t: pt.t, series: series });
      },
    };
  }

  FastFlareSpeedTest.prototype._transfers = function (plan, doTransfer, tracker, latencyMs, o) {
    var self = this;
    var stages = [];
    var chain = Promise.resolve();
    var lastMbps = null;
    plan.forEach(function (stage) {
      chain = chain.then(function () {
        if (o.signal && o.signal.aborted) throw new DOMException('Aborted', 'AbortError');
        if (lastMbps !== null) {
          var predicted = (stage.bytes * stage.count * 8) / (lastMbps * 1e6);
          if (predicted > self.maxStageSeconds) return; // too slow to bother: we already know the answer
        }
        return runStage(stage, doTransfer, tracker, latencyMs, o.signal).then(function (r) {
          stages.push(r);
          lastMbps = r.mbps;
        });
      });
    });
    return chain.then(function () {
      var big = stages.filter(function (s) { return s.bytes >= 1e6; });
      var pool = (big.length ? big : stages).map(function (s) { return s.mbps; }).sort(function (a, b) { return a - b; });
      return { mbps: percentile(pool, 0.9), stages: stages, series: tracker.series };
    });
  };

  FastFlareSpeedTest.prototype.download = function (server, latencyMs, o) {
    o = o || {};
    var tracker = Tracker(o.onProgress, 'download');
    function transfer(bytes, tr) {
      var t0 = now();
      return fetch(server.url + '/speed/down?bytes=' + bytes + '&r=' + rnd(), { cache: 'no-store', signal: o.signal }).then(function (r) {
        var reader = r.body.getReader();
        var got = 0;
        return (function pump() {
          return reader.read().then(function (x) {
            if (x.done) return { bytes: got, ms: now() - t0 };
            got += x.value.byteLength;
            tr.add(x.value.byteLength);
            return pump();
          });
        })();
      });
    }
    return this._transfers(this.downloadPlan, transfer, tracker, latencyMs, o);
  };

  FastFlareSpeedTest.prototype.upload = function (server, latencyMs, o) {
    o = o || {};
    var tracker = Tracker(o.onProgress, 'upload');
    var cache = {};
    function transfer(bytes, tr) {
      return new Promise(function (resolve, reject) {
        var body = cache[bytes] || (cache[bytes] = new Uint8Array(bytes));
        var xhr = new XMLHttpRequest();
        var t0 = now();
        var sent = 0;
        xhr.open('POST', server.url + '/speed/up?r=' + rnd());
        xhr.setRequestHeader('Content-Type', 'application/octet-stream');
        xhr.upload.onprogress = function (e) { tr.add(e.loaded - sent); sent = e.loaded; };
        xhr.onload = function () { if (xhr.status === 200) resolve({ bytes: bytes, ms: now() - t0 }); else reject(new Error('upload ' + xhr.status)); };
        xhr.onerror = function () { reject(new Error('upload failed')); };
        xhr.onabort = function () { reject(new DOMException('Aborted', 'AbortError')); };
        if (o.signal) o.signal.addEventListener('abort', function () { xhr.abort(); }, { once: true });
        xhr.send(body);
      });
    }
    return this._transfers(this.uploadPlan, transfer, tracker, latencyMs, o);
  };

  /**
   * Full run: latency/jitter -> download -> upload.
   * options: { serverId | server, signal, onPhase(phase), onProgress({phase, mbps, t, series}), onPing(ms, i, samples) }
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
        return self.download(server, lat.median, o);
      })
      .then(function (dl) {
        result.download = dl;
        if (o.onPhase) o.onPhase('upload');
        return self.upload(server, result.latency.median, o);
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
