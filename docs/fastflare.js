/*!
 * FastFlare bot-protection widget. No image puzzles.
 * Proof-of-work (solved in Web Workers) + browser behaviour signals, verified by your FastFlare server.
 *
 *   <script src="https://YOUR-FASTFLARE-HOST/fastflare.js" async defer></script>
 *   <div class="ff-captcha" data-sitekey="YOUR_SITE_KEY"></div>
 *
 * Docs: https://arthwarrior3201.github.io/FastFlare/captcha.html
 */
(function (global) {
  'use strict';

  // ---- Proof-of-work core -------------------------------------------------------------------
  // Self-contained (no outer references) so the same source runs in a Worker and on the main thread.
  // Hashes "<id>.<salt>.<nonce>" with SHA-256 and looks for `bits` leading zero bits. The message
  // always fits one 64-byte block, so each attempt is a single compression.
  function powCore() {
    var K = new Int32Array([
      0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
      0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
      0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
      0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
      0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
      0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
      0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
      0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
    ]);
    var W = new Int32Array(64);
    var H = new Int32Array(8);
    var buf = new Uint8Array(64);

    function compress(len) {
      var i;
      buf[len] = 0x80;
      for (i = len + 1; i < 60; i++) buf[i] = 0;
      var bitLen = len * 8;
      buf[60] = (bitLen >>> 24) & 255;
      buf[61] = (bitLen >>> 16) & 255;
      buf[62] = (bitLen >>> 8) & 255;
      buf[63] = bitLen & 255;
      for (i = 0; i < 16; i++) W[i] = (buf[i * 4] << 24) | (buf[i * 4 + 1] << 16) | (buf[i * 4 + 2] << 8) | buf[i * 4 + 3];
      for (i = 16; i < 64; i++) {
        var x = W[i - 15];
        var y = W[i - 2];
        var s0 = ((x >>> 7) | (x << 25)) ^ ((x >>> 18) | (x << 14)) ^ (x >>> 3);
        var s1 = ((y >>> 17) | (y << 15)) ^ ((y >>> 19) | (y << 13)) ^ (y >>> 10);
        W[i] = (W[i - 16] + s0 + W[i - 7] + s1) | 0;
      }
      var a = 0x6a09e667 | 0, b = 0xbb67ae85 | 0, c = 0x3c6ef372 | 0, d = 0xa54ff53a | 0;
      var e = 0x510e527f | 0, f = 0x9b05688c | 0, g = 0x1f83d9ab | 0, h = 0x5be0cd19 | 0;
      for (i = 0; i < 64; i++) {
        var S1 = ((e >>> 6) | (e << 26)) ^ ((e >>> 11) | (e << 21)) ^ ((e >>> 25) | (e << 7));
        var ch = (e & f) ^ (~e & g);
        var t1 = (h + S1 + ch + K[i] + W[i]) | 0;
        var S0 = ((a >>> 2) | (a << 30)) ^ ((a >>> 13) | (a << 19)) ^ ((a >>> 22) | (a << 10));
        var maj = (a & b) ^ (a & c) ^ (b & c);
        var t2 = (S0 + maj) | 0;
        h = g; g = f; f = e; e = (d + t1) | 0; d = c; c = b; b = a; a = (t1 + t2) | 0;
      }
      H[0] = (0x6a09e667 + a) | 0; H[1] = (0xbb67ae85 + b) | 0; H[2] = (0x3c6ef372 + c) | 0; H[3] = (0xa54ff53a + d) | 0;
      H[4] = (0x510e527f + e) | 0; H[5] = (0x9b05688c + f) | 0; H[6] = (0x1f83d9ab + g) | 0; H[7] = (0x5be0cd19 + h) | 0;
    }

    function zeroBits() {
      var n = 0;
      for (var i = 0; i < 8; i++) {
        if (H[i] === 0) { n += 32; continue; }
        return n + Math.clz32(H[i]);
      }
      return n;
    }

    function digestHex(str) {
      for (var i = 0; i < str.length; i++) buf[i] = str.charCodeAt(i);
      compress(str.length);
      var out = '';
      for (var j = 0; j < 8; j++) out += ('00000000' + (H[j] >>> 0).toString(16)).slice(-8);
      return out;
    }

    // Tries nonces start .. start+iters-1. Returns the first that works, or -1.
    function solve(prefix, bits, start, iters) {
      var p = prefix.length;
      for (var i = 0; i < p; i++) buf[i] = prefix.charCodeAt(i);
      for (var n = start; n < start + iters; n++) {
        var s = '' + n;
        var len = p;
        for (var j = 0; j < s.length; j++) buf[len++] = s.charCodeAt(j);
        compress(len);
        if (zeroBits() >= bits) return n;
      }
      return -1;
    }

    return { solve: solve, digestHex: digestHex };
  }

  function workerBody() {
    var core = powCore();
    self.onmessage = function (e) {
      var d = e.data;
      var n = d.start;
      var chunk = 20000;
      for (;;) {
        var r = core.solve(d.prefix, d.bits, n, chunk);
        if (r >= 0) { self.postMessage({ nonce: r }); return; }
        n += chunk;
      }
    };
  }

  function solvePow(challenge) {
    var prefix = challenge.id + '.' + challenge.salt + '.';
    var bits = challenge.difficulty;
    return new Promise(function (resolve, reject) {
      var workers = [];
      var done = false;
      function finish(nonce) {
        if (done) return;
        done = true;
        workers.forEach(function (w) { w.terminate(); });
        resolve(String(nonce));
      }
      var count = Math.max(1, Math.min(4, (global.navigator && navigator.hardwareConcurrency) || 2));
      try {
        var src = 'var powCore=' + powCore.toString() + ';(' + workerBody.toString() + ')()';
        var url = URL.createObjectURL(new Blob([src], { type: 'text/javascript' }));
        for (var i = 0; i < count; i++) {
          var w = new Worker(url);
          w.onmessage = function (e) { finish(e.data.nonce); };
          w.onerror = function () {
            // Workers blocked (strict CSP etc.): fall back to the main thread.
            if (done) return;
            workers.forEach(function (x) { x.terminate(); });
            workers = [];
            mainThread();
          };
          w.postMessage({ prefix: prefix, bits: bits, start: i * 1e9 });
          workers.push(w);
        }
      } catch (err) {
        mainThread();
      }
      function mainThread() {
        var core = powCore();
        var n = 0;
        (function step() {
          if (done) return;
          var r = core.solve(prefix, bits, n, 5000);
          if (r >= 0) return finish(r);
          n += 5000;
          setTimeout(step, 0);
        })();
      }
    });
  }

  // ---- Behaviour signals --------------------------------------------------------------------
  function Signals() {
    var s = { pm: 0, kd: 0, tc: 0, sc: 0, fc: 0, pv: 0 };
    var t0 = Date.now();
    var pts = [];
    function onMove(e) {
      s.pm++;
      if (pts.length < 40 && s.pm % 2 === 0) pts.push([e.clientX, e.clientY]);
    }
    var handlers = {
      pointermove: onMove,
      keydown: function () { s.kd++; },
      touchstart: function () { s.tc++; },
      scroll: function () { s.sc++; },
      focusin: function () { s.fc++; },
    };
    var opts = { passive: true, capture: true };
    Object.keys(handlers).forEach(function (k) { document.addEventListener(k, handlers[k], opts); });
    return {
      interacted: function () { return s.pm >= 3 || s.kd >= 1 || s.tc >= 1 || s.sc >= 1; },
      snapshot: function () {
        // Largest sideways deviation of the recorded pointer path from the straight line start->end.
        // Scripted mouse moves are perfectly straight; human ones are not.
        var pv = 0;
        if (pts.length >= 4) {
          var a = pts[0], b = pts[pts.length - 1];
          var dx = b[0] - a[0], dy = b[1] - a[1];
          var len = Math.sqrt(dx * dx + dy * dy) || 1;
          pts.forEach(function (p) { pv = Math.max(pv, Math.abs(dy * (p[0] - a[0]) - dx * (p[1] - a[1])) / len); });
        }
        var nav = global.navigator || {};
        return {
          wd: !!nav.webdriver,
          lg: (nav.languages && nav.languages.length) || (nav.language ? 1 : 0),
          sw: (global.screen && screen.width) || 0,
          sh: (global.screen && screen.height) || 0,
          hc: nav.hardwareConcurrency || 0,
          pm: s.pm, kd: s.kd, tc: s.tc, sc: s.sc, fc: s.fc,
          pv: Math.round(pv * 10) / 10,
          dt: Date.now() - t0,
        };
      },
      stop: function () {
        Object.keys(handlers).forEach(function (k) { document.removeEventListener(k, handlers[k], opts); });
      },
    };
  }

  // ---- Network flow -------------------------------------------------------------------------
  function post(api, path, body) {
    return fetch(api + path, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(body),
      credentials: 'omit',
    }).then(function (r) {
      return r.json().then(function (j) { if (!r.ok) { var e = new Error(j.error || 'request_failed'); e.code = j.error; throw e; } return j; });
    });
  }

  function wait(ms) { return new Promise(function (r) { setTimeout(r, ms); }); }

  // Runs the full flow and resolves { token, expires }.
  function run(opts, hooks) {
    hooks = hooks || {};
    var sig = Signals();
    var settle = opts.settle == null ? 1200 : opts.settle;
    function attempt(challenge) {
      return solvePow(challenge).then(function (nonce) {
        var waited = settle > 0 && !sig.interacted() ? wait(settle) : Promise.resolve();
        return waited.then(function () {
          return post(opts.api, '/captcha/verify', {
            sitekey: opts.sitekey, challenge: challenge, nonce: nonce, signals: sig.snapshot(), hp: opts.hp || '',
          });
        });
      });
    }
    return post(opts.api, '/captcha/challenge', { sitekey: opts.sitekey })
      .then(function (r) { return attempt(r.challenge); })
      .then(function (r) {
        if (r.ok) return r;
        if (r.retry) { if (hooks.stepup) hooks.stepup(); return attempt(r.challenge); }
        throw new Error('failed');
      })
      .then(function (r) { sig.stop(); if (!r.ok) throw new Error('failed'); return r; }, function (e) { sig.stop(); throw e; });
  }

  // ---- Widget -------------------------------------------------------------------------------
  var scriptSrc = (typeof document !== 'undefined' && document.currentScript && document.currentScript.src) || '';
  var defaultApi = scriptSrc ? new URL(scriptSrc).origin : '';
  var STYLE =
    '.ff-w{display:inline-flex;align-items:center;gap:10px;padding:10px 14px;border-radius:12px;font:14px/1.2 system-ui,-apple-system,Segoe UI,Roboto,sans-serif;' +
    'border:1px solid var(--ffb);background:var(--ffbg);color:var(--fft);min-width:220px;box-sizing:border-box}' +
    '.ff-w[data-theme=light]{--ffb:#d7dbe6;--ffbg:#fff;--fft:#1b2030;--ffm:#6b7280}' +
    '.ff-w[data-theme=dark]{--ffb:#2c3350;--ffbg:#12162a;--fft:#e8ebf7;--ffm:#8b93b5}' +
    '.ff-i{width:20px;height:20px;border-radius:50%;flex:none;display:grid;place-items:center;font-size:13px;color:#fff;background:#8b93b5}' +
    '.ff-w[data-state=solving] .ff-i{background:none;border:2px solid #ff8a3d;border-top-color:transparent;animation:ffs .8s linear infinite;box-sizing:border-box}' +
    '.ff-w[data-state=ok] .ff-i{background:#22b573}.ff-w[data-state=error] .ff-i{background:#e5484d}' +
    '.ff-b{margin-left:auto;font-size:11px;color:var(--ffm);letter-spacing:.02em}' +
    '.ff-r{background:none;border:0;color:#ff8a3d;cursor:pointer;font:inherit;text-decoration:underline;padding:0}' +
    '@keyframes ffs{to{transform:rotate(360deg)}}@media(prefers-reduced-motion:reduce){.ff-i{animation:none!important}}';

  function injectStyle() {
    if (document.getElementById('ff-style')) return;
    var st = document.createElement('style');
    st.id = 'ff-style';
    st.textContent = STYLE;
    document.head.appendChild(st);
  }

  var instances = [];

  function render(el, options) {
    if (typeof el === 'string') el = document.querySelector(el);
    if (!el) throw new Error('FastFlare: element not found');
    if (el.__ff) return el.__ff;
    injectStyle();
    var d = el.dataset || {};
    var opts = {
      sitekey: (options && options.sitekey) || d.sitekey,
      api: ((options && options.api) || d.api || defaultApi).replace(/\/$/, ''),
      theme: (options && options.theme) || d.theme || 'auto',
      callback: (options && options.callback) || (d.callback && global[d.callback]),
      expired: (options && options.expiredCallback) || (d.expiredCallback && global[d.expiredCallback]),
      error: (options && options.errorCallback) || (d.errorCallback && global[d.errorCallback]),
      field: (options && options.field) || d.field || 'ff-token',
      settle: options && options.settle != null ? options.settle : d.settle != null ? +d.settle : undefined,
    };
    if (!opts.sitekey) throw new Error('FastFlare: data-sitekey is required');

    var theme = opts.theme === 'auto' ? (global.matchMedia && matchMedia('(prefers-color-scheme: dark)').matches ? 'dark' : 'light') : opts.theme;
    var box = document.createElement('div');
    box.className = 'ff-w';
    box.setAttribute('role', 'status');
    box.setAttribute('aria-live', 'polite');
    box.dataset.theme = theme;
    box.innerHTML = '<span class="ff-i" aria-hidden="true"></span><span class="ff-t"></span><span class="ff-b">FastFlare</span>';
    var icon = box.querySelector('.ff-i');
    var text = box.querySelector('.ff-t');
    var input = document.createElement('input');
    input.type = 'hidden';
    input.name = opts.field;
    // Honeypot: invisible to people, tempting to form-filling bots.
    var hp = document.createElement('input');
    hp.type = 'text';
    hp.name = 'ff-website';
    hp.tabIndex = -1;
    hp.autocomplete = 'off';
    hp.setAttribute('aria-hidden', 'true');
    hp.style.cssText = 'position:absolute;left:-9999px;width:1px;height:1px;opacity:0';
    el.appendChild(box);
    el.appendChild(input);
    el.appendChild(hp);

    var timer = null;
    var api = {
      token: function () { return input.value || null; },
      reset: function () { clearTimeout(timer); input.value = ''; start(); },
      execute: function () { return api.token() ? Promise.resolve(api.token()) : start(); },
    };

    function setState(state, msg) {
      box.dataset.state = state;
      text.textContent = msg;
      icon.textContent = state === 'ok' ? '✓' : state === 'error' ? '!' : '';
    }

    function start() {
      setState('solving', 'Verifying you are human…');
      return run({ sitekey: opts.sitekey, api: opts.api, settle: opts.settle, hp: hp.value }, { stepup: function () { setState('solving', 'Extra check…'); } }).then(
        function (r) {
          input.value = r.token;
          setState('ok', 'Verified');
          if (opts.callback) opts.callback(r.token);
          el.dispatchEvent(new CustomEvent('ff-verified', { detail: { token: r.token }, bubbles: true }));
          // Tokens last 2 minutes: renew at 100s so slow form-fillers always submit a valid one.
          timer = setTimeout(function () {
            input.value = '';
            if (opts.expired) opts.expired();
            start().catch(function () {});
          }, 100000);
          return r.token;
        },
        function (e) {
          setState('error', 'Verification failed. ');
          var b = document.createElement('button');
          b.type = 'button';
          b.className = 'ff-r';
          b.textContent = 'Retry';
          b.onclick = function () { api.reset(); };
          text.appendChild(b);
          if (opts.error) opts.error(e);
          throw e;
        },
      );
    }

    el.__ff = api;
    instances.push(api);
    start().catch(function () {});
    return api;
  }

  // One-shot, invisible use (e.g. before a fetch() to your own API): FastFlare.execute({sitekey}).then(token => ...)
  function execute(options) {
    var api = (options.api || defaultApi).replace(/\/$/, '');
    return run({ sitekey: options.sitekey, api: api, settle: options.settle == null ? 600 : options.settle }).then(function (r) { return r.token; });
  }

  function autoRender() {
    var nodes = document.querySelectorAll('.ff-captcha:not([data-ff-rendered])');
    for (var i = 0; i < nodes.length; i++) {
      nodes[i].setAttribute('data-ff-rendered', '1');
      try { render(nodes[i]); } catch (e) { console.error(e); }
    }
  }

  global.FastFlare = { render: render, execute: execute, autoRender: autoRender, _pow: powCore };

  if (typeof document !== 'undefined' && document.addEventListener) {
    if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', autoRender);
    else autoRender();
  }
})(typeof window !== 'undefined' ? window : globalThis);
