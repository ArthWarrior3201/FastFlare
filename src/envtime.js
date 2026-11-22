import { localMs } from './clock.js';
import { queryNtp } from './ntp.js';

export function median(values) {
  const a = [...values].sort((x, y) => x - y);
  const m = a.length >> 1;
  return a.length % 2 ? a[m] : (a[m - 1] + a[m]) / 2;
}

/**
 * Pure consensus step. Takes per-provider samples ({host, offsetMs, rttMs}), finds the median
 * offset, kicks every provider that disagrees with it by more than the tolerance (plus half its
 * own round-trip, the physical limit of what one exchange can resolve), and averages the rest
 * weighted by 1/rtt. Returns null when there is no strict majority of agreeing providers.
 */
export function consensus(samples, { toleranceMs = 50, minAgree = 2 } = {}) {
  if (!samples.length) return null;
  const med = median(samples.map((s) => s.offsetMs));
  const agree = [];
  const kicked = [];
  for (const s of samples) {
    (Math.abs(s.offsetMs - med) <= toleranceMs + s.rttMs / 2 ? agree : kicked).push(s);
  }
  if (agree.length < minAgree || agree.length * 2 <= samples.length) return null;
  let w = 0;
  let acc = 0;
  for (const s of agree) {
    const k = 1 / Math.max(s.rttMs, 1);
    w += k;
    acc += k * s.offsetMs;
  }
  return {
    offsetMs: acc / w,
    medianMs: med,
    bestRttMs: Math.min(...agree.map((s) => s.rttMs)),
    agree,
    kicked,
  };
}

export function formatTime(ms, timeZone = 'UTC') {
  const whole = Math.floor(ms);
  const d = new Date(whole);
  let fmt;
  try {
    fmt = new Intl.DateTimeFormat('en-US', {
      timeZone,
      hourCycle: 'h23',
      year: 'numeric',
      month: '2-digit',
      day: '2-digit',
      hour: '2-digit',
      minute: '2-digit',
      second: '2-digit',
      timeZoneName: 'short',
    });
  } catch {
    throw new RangeError(`Unknown time zone: ${timeZone}`);
  }
  const p = Object.fromEntries(fmt.formatToParts(d).map((x) => [x.type, x.value]));
  const asUtc = Date.UTC(+p.year, +p.month - 1, +p.day, +p.hour, +p.minute, +p.second);
  const offsetMin = Math.round((asUtc - Math.floor(whole / 1000) * 1000) / 60000);
  const sign = offsetMin < 0 ? '-' : '+';
  const abs = Math.abs(offsetMin);
  const hh = String(Math.floor(abs / 60)).padStart(2, '0');
  const mm = String(abs % 60).padStart(2, '0');
  const msPart = String(((whole % 1000) + 1000) % 1000).padStart(3, '0');
  return {
    timeZone,
    abbreviation: p.timeZoneName,
    offsetMinutes: offsetMin,
    local: `${p.year}-${p.month}-${p.day}T${p.hour}:${p.minute}:${p.second}.${msPart}${sign}${hh}:${mm}`,
  };
}

export class EnvTime {
  constructor({
    providers,
    minVotes = 3,
    graceMs = 60,
    hardTimeoutMs = 1200,
    toleranceMs = 50,
    pollMs = 32000,
    staleMs = 5 * 60_000,
    query = queryNtp,
    log = () => {},
  }) {
    Object.assign(this, { providers, minVotes, graceMs, hardTimeoutMs, toleranceMs, pollMs, staleMs, query, log });
    this.offset = 0; // ms to add to localMs() to get true time
    this.drift = 0; // ms of local-clock error accumulated per ms (ppm * 1e-6)
    this.syncedAt = null; // localMs() at last good round
    this.lastRound = null;
    this.rounds = 0;
    this.lastForced = 0;
    this._last = 0;
    this._inflight = null;
    this._timer = null;
    this._stopped = false;
  }

  get synced() {
    return this.syncedAt !== null;
  }

  /** True time in ms. O(1), no I/O: the live-tracked offset is just added to the monotonic clock. */
  now() {
    const l = localMs();
    if (!this.synced) return l;
    let t = l + this.offset + this.drift * (l - this.syncedAt);
    // Never run backwards for small corrections (a step of >100ms is allowed through).
    if (t < this._last && this._last - t < 100) t = this._last;
    this._last = t;
    return t;
  }

  uncertaintyMs() {
    if (!this.synced) return null;
    const age = localMs() - this.syncedAt;
    return Math.round(((this.lastRound?.bestRttMs ?? 20) / 2 + age * 5e-5 + 0.5) * 10) / 10; // 50 ppm worst-case drift
  }

  /** One query round: ask everyone, stop early once enough answered, kick outliers, update clock. */
  round() {
    if (!this._inflight) this._inflight = this._round().finally(() => (this._inflight = null));
    return this._inflight;
  }

  async _round() {
    const ac = new AbortController();
    const samples = [];
    const failed = [];
    const total = this.providers.length;
    const started = localMs();

    await new Promise((resolve) => {
      let finished = false;
      let grace = null;
      const finish = () => {
        if (finished) return;
        finished = true;
        clearTimeout(grace);
        clearTimeout(hard);
        ac.abort(); // leave providers that are still slow
        resolve();
      };
      const hard = setTimeout(finish, this.hardTimeoutMs);
      for (const p of this.providers) {
        this.query(p.host, { port: p.port, timeoutMs: this.hardTimeoutMs, signal: ac.signal }).then(
          (r) => {
            if (finished) return;
            samples.push({ host: p.host, offsetMs: r.offsetMs, rttMs: r.rttMs });
            if (samples.length >= this.minVotes && !grace) grace = setTimeout(finish, this.graceMs);
            if (samples.length + failed.length === total) finish();
          },
          (e) => {
            if (finished) return;
            failed.push({ host: p.host, error: e.message });
            if (samples.length + failed.length === total) finish();
          },
        );
      }
    });

    const answered = new Set(samples.map((s) => s.host).concat(failed.map((f) => f.host)));
    const left = this.providers.filter((p) => !answered.has(p.host)).map((p) => p.host);
    const result = consensus(samples, { toleranceMs: this.toleranceMs });
    const summary = {
      at: new Date().toISOString(),
      tookMs: Math.round(localMs() - started),
      used: result ? result.agree.map((s) => ({ host: s.host, offsetMs: +s.offsetMs.toFixed(2), rttMs: +s.rttMs.toFixed(2) })) : [],
      kicked: result ? result.kicked.map((s) => ({ host: s.host, offsetMs: +s.offsetMs.toFixed(2), rttMs: +s.rttMs.toFixed(2) })) : [],
      failed,
      skippedSlow: left,
      accepted: !!result,
      bestRttMs: result?.bestRttMs ?? null,
    };

    if (result) this._apply(result.offsetMs, localMs());
    else this.log('envtime: round rejected (no majority)', JSON.stringify({ samples, failed }));
    this.lastRound = result ? summary : { ...summary, bestRttMs: this.lastRound?.bestRttMs ?? null };
    this.lastAttempt = summary;
    this.rounds++;
    return summary;
  }

  _apply(measured, at) {
    if (this.synced) {
      const predicted = this.offset + this.drift * (at - this.syncedAt);
      const residual = measured - predicted;
      const dt = at - this.syncedAt;
      if (Math.abs(residual) <= this.toleranceMs) {
        if (dt > 10_000) {
          const obs = (measured - this.offset) / dt;
          this.drift = Math.max(-2e-4, Math.min(2e-4, 0.8 * this.drift + 0.2 * obs)); // clamp to ±200 ppm
        }
        this.offset = predicted + 0.5 * residual; // smooth small jitter
      } else {
        this.offset = measured; // genuine step (local clock was stepped, or we were wrong)
        this.drift = 0;
        this._last = 0;
      }
    } else {
      this.offset = measured;
    }
    this.syncedAt = at;
  }

  /** Optional fresh round on demand, rate-limited so clients can't hammer upstream NTP servers. */
  async refreshIfAllowed(minGapMs = 2000) {
    const t = localMs();
    if (t - this.lastForced < minGapMs) return false;
    this.lastForced = t;
    await this.round();
    return true;
  }

  async ready(timeoutMs = 2000) {
    if (this.synced) return true;
    await Promise.race([this.round(), new Promise((r) => setTimeout(r, timeoutMs))]);
    return this.synced;
  }

  start() {
    this._stopped = false;
    const tick = async () => {
      if (this._stopped) return;
      let ok = false;
      try {
        await this.round();
        ok = this.lastAttempt?.accepted;
      } catch (e) {
        this.log('envtime: round error', e.message);
      }
      const jitter = 1 + (Math.random() - 0.5) * 0.2;
      const delay = ok ? this.pollMs * jitter : Math.min(this.pollMs, 5000);
      this._timer = setTimeout(tick, delay);
      this._timer.unref?.();
    };
    tick();
  }

  stop() {
    this._stopped = true;
    clearTimeout(this._timer);
  }

  status() {
    return {
      synced: this.synced,
      uncertaintyMs: this.uncertaintyMs(),
      offsetMs: +this.offset.toFixed(3),
      driftPpm: +(this.drift * 1e6).toFixed(2),
      lastSyncAgeMs: this.synced ? Math.round(localMs() - this.syncedAt) : null,
      rounds: this.rounds,
      lastRound: this.lastRound,
      lastAttempt: this.lastAttempt ?? null,
      providers: this.providers.map((p) => p.host),
      toleranceMs: this.toleranceMs,
    };
  }
}
