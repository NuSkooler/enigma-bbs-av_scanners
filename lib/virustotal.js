/* jslint node: true */
'use strict';

//
//  The |virustotal| file scanner: looks a file's SHA-256 up with
//  GET /api/v3/files/{sha256}. It sends the hash and nothing else. It never
//  uploads a file, and has no option to.
//
//  Entry options (beside core's scanner, sources, timeout, onError, ...):
//
//    apiKey             (required) Use @environment:VAR or @file:path in config
//    minDetections      Engines that must say "malicious" to reject (default 2)
//    countSuspicious    Count "suspicious" verdicts as detections too (false)
//    requestsPerMinute  Client-side rate limit (default 4, the free tier's)
//    maxWaitMs          Longest a lookup waits for the rate limit before it
//                       is an error (default 2000; 0: never wait). A waiting
//                       lookup holds one of core's scan slots, which every
//                       scanner shares, so this stays short
//    dailyLimit         Lookups per UTC day before every lookup is an error
//                       (default 500, the free tier's; 0: no limit). Counted
//                       per process, from when it started
//    cacheMinutes       Keep answers by SHA-256 this long (default 60; 0: off)
//    cacheMaxEntries    Most answers kept (default 1000)
//    maxQueue           Most lookups waiting for the rate limit (default 100)
//
//  Concurrent lookups of the same SHA-256 share one request.
//
//  Results: unknown hash (404) -> skipped; detections >= minDetections ->
//  infected; fewer -> clean; anything else (bad key, quota, 5xx, network,
//  timeout, bad JSON, no hash) -> error.
//
//  The API key never appears in a result, a log line or an error: every
//  message here is built from our own text, and is scrubbed of the key on the
//  way out regardless.
//

const crypto = require('crypto');
const { performance } = require('perf_hooks');
const log = require('./log.js');

const SCANNER_NAME = 'virustotal';
const PRODUCTION_BASE_URL = 'https://www.virustotal.com/api/v3';

const DEFAULTS = Object.freeze({
    minDetections: 2,
    countSuspicious: false,
    requestsPerMinute: 4,
    maxWaitMs: 2000,
    dailyLimit: 500,
    cacheMinutes: 60,
    cacheMaxEntries: 1000,
    maxQueue: 100,
});

//  Whole-number options and the least each may be.
const INT_OPTION_MINIMUMS = Object.freeze({
    minDetections: 1,
    requestsPerMinute: 1,
    maxWaitMs: 0,
    dailyLimit: 0,
    cacheMinutes: 0,
    cacheMaxEntries: 0,
    maxQueue: 0,
});

//  VirusTotal runs about 70 engines, and few files are flagged by more than
//  this many: a higher minDetections rejects next to nothing.
const MAX_SENSIBLE_MIN_DETECTIONS = 30;

//  The counts a verdict is worked out from; a report without all of them,
//  as whole numbers, is malformed.
const STAT_KEYS = ['malicious', 'suspicious', 'undetected', 'harmless'];

const DAY_MS = 24 * 60 * 60 * 1000;

//  A file report is tens of KB; this is far more than any real one.
const MAX_BODY_BYTES = 4 * 1024 * 1024;
const MAX_LABEL_LENGTH = 100;

//  How long to stop asking after a 429, when VirusTotal does not say.
const DEFAULT_QUOTA_BACKOFF_MS = 60 * 1000;
const MAX_QUOTA_BACKOFF_MS = 60 * 60 * 1000;

exports.SCANNER_NAME = SCANNER_NAME;
exports.PRODUCTION_BASE_URL = PRODUCTION_BASE_URL;
exports.DEFAULTS = DEFAULTS;
exports.createVirusTotalScanner = createVirusTotalScanner;

class LookupError extends Error {}

function isUnset(v) {
    return undefined === v || null === v || '' === v;
}

//  The option's value, or undefined when it is not a usable number. A bad
//  value falls back to the default (init() says so), never to something
//  looser.
function intValue(options, name) {
    const v = options[name];
    if ('number' !== typeof v && 'string' !== typeof v) {
        return undefined;
    }
    const n = Number(v);
    return Number.isFinite(n) && n >= INT_OPTION_MINIMUMS[name]
        ? Math.floor(n)
        : undefined;
}

function intOption(options, name) {
    const n = isUnset(options[name]) ? undefined : intValue(options, name);
    return undefined === n ? DEFAULTS[name] : n;
}

function settingsOf(options) {
    const o = options || {};
    return {
        minDetections: intOption(o, 'minDetections'),
        countSuspicious: true === o.countSuspicious,
        requestsPerMinute: intOption(o, 'requestsPerMinute'),
        maxWaitMs: intOption(o, 'maxWaitMs'),
        //  0: no daily limit (a paid key)
        dailyLimit: intOption(o, 'dailyLimit') || Infinity,
        cacheMs: intOption(o, 'cacheMinutes') * 60 * 1000,
        cacheMaxEntries: intOption(o, 'cacheMaxEntries'),
        maxQueue: intOption(o, 'maxQueue'),
    };
}

//  What is wrong with an entry's options, for init() to report.
function optionProblems(options) {
    const o = options || {};
    const problems = [];
    Object.keys(INT_OPTION_MINIMUMS).forEach(name => {
        if (!isUnset(o[name]) && undefined === intValue(o, name)) {
            problems.push(
                `"${name}" must be a number of at least ${INT_OPTION_MINIMUMS[name]}; using ${DEFAULTS[name]}`
            );
        }
    });
    const min = intValue(o, 'minDetections');
    if (min > MAX_SENSIBLE_MIN_DETECTIONS) {
        problems.push(
            `"minDetections" is ${min}: few files are flagged by that many engines, so this entry will rarely if ever reject one`
        );
    }
    if (!isUnset(o.countSuspicious) && 'boolean' !== typeof o.countSuspicious) {
        problems.push('"countSuspicious" must be true or false; using false');
    }
    return problems;
}

//  A usable key: printable ASCII with no spaces, as a header value must be.
//  One that still starts with "@" is an @environment:/@file: spec that did
//  not resolve (ENiGMA½ leaves those as they are, with a console warning).
function isUsableApiKey(key) {
    return 'string' === typeof key && /^[\x21-\x7e]{1,256}$/.test(key) && '@' !== key[0];
}

function redact(text, apiKey) {
    let s = String(text);
    if ('string' === typeof apiKey && apiKey.length >= 4) {
        s = s.split(apiKey).join('[redacted]');
    }
    return s;
}

function utcDay(ms) {
    return new Date(ms).toISOString().slice(0, 10);
}

//
//  |deps| is for tests:
//    testBaseUrl   Where to send lookups instead of VirusTotal. Must be
//                  https://, or http:// to a loopback address. Only code can
//                  set it; there is no config option for it.
//    fetch         A fetch() to use instead of the global one
//    now           The wall clock, ms: only for the UTC day and an HTTP-date
//                  Retry-After
//    monoNow       A monotonic clock, ms: the rate window, 429 back-off and
//                  cache expiry, which a clock step must not stretch or skip
//    windowMs      The rate limit's window (default 60000)
//
function createVirusTotalScanner(deps = {}) {
    const fetchImpl = deps.fetch || globalThis.fetch;
    const now = deps.now || Date.now;
    const mono = deps.monoNow || (() => performance.now());
    const windowMs = deps.windowMs > 0 ? deps.windowMs : 60 * 1000;
    const baseUrl = checkBaseUrl(deps.testBaseUrl);

    //  one limiter, quota count and cache per API key: that is what
    //  VirusTotal's quota is counted against
    const states = new Map();

    function stateFor(apiKey) {
        const id = crypto.createHash('sha256').update(apiKey).digest('hex');
        let state = states.get(id);
        if (!state) {
            state = {
                sent: [], //  times (mono) of lookups within the last window
                waiting: [],
                timer: null,
                day: utcDay(now()),
                dayStarted: mono(),
                dayCount: 0,
                blockedUntil: 0, //  mono
                cache: new Map(), //  sha256 -> { expires, answer }, oldest first
                inflight: new Map(), //  sha256 -> the lookup in progress
            };
            states.set(id, state);
        }
        return state;
    }

    // ── Rate limit and daily quota ───────────────────────────────────────

    //
    //  A new day is a UTC date later than the last one seen. If the clock
    //  is stepped back, that date is not counted again; and so the count is
    //  not stuck until the clock catches up, while the clock reads earlier
    //  than the last date seen, 24 h of real time starts a new day too.
    //
    function rollDay(state) {
        const today = utcDay(now());
        const later = today > state.day;
        const stuck = today < state.day && mono() - state.dayStarted >= DAY_MS;
        if (later || stuck) {
            if (later) {
                state.day = today;
            }
            state.dayStarted = mono();
            state.dayCount = 0;
        }
    }

    function pruneSent(state, t) {
        state.sent = state.sent.filter(at => t - at < windowMs);
    }

    function blockedError(state, t) {
        return new LookupError(
            `Quota exceeded (HTTP 429); not asking again for ${Math.ceil(
                (state.blockedUntil - t) / 1000
            )}s`
        );
    }

    function pump(state) {
        clearTimeout(state.timer);
        state.timer = null;

        const t = mono();
        pruneSent(state, t);
        rollDay(state);

        //  after a 429, nothing waiting is sent: it would be refused too
        if (t < state.blockedUntil) {
            const err = blockedError(state, t);
            state.waiting.splice(0).forEach(waiter => waiter.settle(err));
            return;
        }

        while (state.waiting.length > 0) {
            const waiter = state.waiting[0];
            const { requestsPerMinute, dailyLimit } = waiter.settings;

            if (state.dayCount >= dailyLimit) {
                state.waiting.shift();
                waiter.settle(dailyLimitError(dailyLimit));
                continue;
            }
            if (state.sent.length >= requestsPerMinute) {
                break;
            }

            state.waiting.shift();
            state.sent.push(t);
            ++state.dayCount;
            waiter.settle(null);
        }

        if (state.waiting.length > 0 && state.sent.length > 0) {
            const wait = Math.max(1, state.sent[0] + windowMs - t);
            state.timer = setTimeout(() => pump(state), wait);
            if (state.timer.unref) {
                state.timer.unref();
            }
        }
    }

    //
    //  Roughly how long until a lookup joining the queue now could be sent.
    //  Slots free up as the sends in |state.sent| leave the window, the
    //  lookups already waiting take the first of them, and each send taken
    //  frees its slot again a window later.
    //
    function slotEta(state, settings, t) {
        const sent = state.sent;
        const i = state.waiting.length + sent.length - settings.requestsPerMinute;
        if (i < 0 || 0 === sent.length) {
            return 0;
        }
        const at = sent[i % sent.length] + windowMs * (1 + Math.floor(i / sent.length));
        return Math.max(0, at - t);
    }

    function dailyLimitError(dailyLimit) {
        return new LookupError(
            `Daily lookup limit (${dailyLimit}) reached; lookups resume at 00:00 UTC`
        );
    }

    //
    //  Resolves when a lookup may be sent; rejects with a LookupError when it
    //  may not, when no slot comes free within maxWaitMs, or when |signal|
    //  aborts first.
    //
    //  The wait is short on purpose: while a lookup waits here it holds one
    //  of core's scan slots (fileBase.scanning.maxConcurrent, shared by every
    //  scanner), so long waits would throttle ClamAV and TIC as well.
    //
    function acquireSlot(state, settings, signal) {
        return new Promise((resolve, reject) => {
            if (signal && signal.aborted) {
                return reject(new LookupError('Aborted'));
            }

            const t = mono();
            if (t < state.blockedUntil) {
                return reject(blockedError(state, t));
            }

            rollDay(state);
            if (state.dayCount >= settings.dailyLimit) {
                return reject(dailyLimitError(settings.dailyLimit));
            }

            pruneSent(state, t);
            if (
                0 === state.waiting.length &&
                state.sent.length < settings.requestsPerMinute
            ) {
                state.sent.push(t);
                ++state.dayCount;
                return resolve();
            }

            //  it would have to wait
            if (0 === settings.maxWaitMs) {
                return reject(
                    new LookupError(
                        `Rate limit reached (${settings.requestsPerMinute}/min) and maxWaitMs is 0`
                    )
                );
            }
            //  when its slot will come is known well enough: the lookups
            //  already waiting take the first slots to free up, in order
            const eta = slotEta(state, settings, t);
            if (eta > settings.maxWaitMs) {
                return reject(
                    new LookupError(
                        `Rate limit reached (${settings.requestsPerMinute}/min); the next free slot is more than maxWaitMs (${settings.maxWaitMs}ms) away`
                    )
                );
            }
            if (state.waiting.length >= settings.maxQueue) {
                return reject(
                    new LookupError(
                        `Too many lookups waiting for the rate limit (${settings.maxQueue})`
                    )
                );
            }

            const unqueue = () => {
                const i = state.waiting.indexOf(waiter);
                if (-1 !== i) {
                    state.waiting.splice(i, 1);
                }
            };

            const onAbort = () => {
                unqueue();
                waiter.settle(
                    new LookupError('Aborted while waiting for the rate limit')
                );
            };

            const waiter = {
                settings,
                settled: false,
                timer: null,
                settle: err => {
                    if (waiter.settled) {
                        return;
                    }
                    waiter.settled = true;
                    clearTimeout(waiter.timer);
                    if (signal) {
                        signal.removeEventListener('abort', onAbort);
                    }
                    return err ? reject(err) : resolve();
                },
            };

            waiter.timer = setTimeout(() => {
                unqueue();
                waiter.settle(
                    new LookupError(
                        `No lookup slot came free within ${settings.maxWaitMs}ms (rate limit ${settings.requestsPerMinute}/min)`
                    )
                );
            }, settings.maxWaitMs);
            if (waiter.timer.unref) {
                waiter.timer.unref();
            }

            if (signal) {
                signal.addEventListener('abort', onAbort, { once: true });
            }
            state.waiting.push(waiter);
            pump(state);
        });
    }

    // ── Cache ────────────────────────────────────────────────────────────

    function cacheGet(state, sha256) {
        const hit = state.cache.get(sha256);
        if (!hit) {
            return null;
        }
        if (hit.expires <= mono()) {
            state.cache.delete(sha256);
            return null;
        }
        //  most recently used goes to the back
        state.cache.delete(sha256);
        state.cache.set(sha256, hit);
        return hit.answer;
    }

    function cachePut(state, settings, sha256, answer) {
        if (settings.cacheMs <= 0 || settings.cacheMaxEntries <= 0) {
            return;
        }
        state.cache.delete(sha256);
        state.cache.set(sha256, { expires: mono() + settings.cacheMs, answer });
        while (state.cache.size > settings.cacheMaxEntries) {
            state.cache.delete(state.cache.keys().next().value);
        }
    }

    // ── The lookup ───────────────────────────────────────────────────────

    async function readBody(res) {
        if (!res.body) {
            return '';
        }
        const reader = res.body.getReader();
        const chunks = [];
        let total = 0;
        for (;;) {
            const { done, value } = await reader.read();
            if (done) {
                break;
            }
            total += value.length;
            if (total > MAX_BODY_BYTES) {
                reader.cancel().catch(() => {});
                throw new LookupError('Response too large');
            }
            chunks.push(Buffer.from(value));
        }
        return Buffer.concat(chunks).toString('utf8');
    }

    function discardBody(res) {
        if (res.body) {
            res.body.cancel().catch(() => {});
        }
    }

    //  Retry-After is delay-seconds or an HTTP-date (RFC 9110 10.2.3).
    function retryAfterMs(res) {
        const raw = res.headers && res.headers.get && res.headers.get('retry-after');
        const v = 'string' === typeof raw ? raw.trim() : '';
        let ms = NaN;
        if (/^[0-9]+$/.test(v)) {
            ms = Number(v) * 1000;
        } else if (v) {
            ms = Date.parse(v) - now();
        }
        if (Number.isFinite(ms) && ms > 0) {
            return Math.min(MAX_QUOTA_BACKOFF_MS, ms);
        }
        return DEFAULT_QUOTA_BACKOFF_MS;
    }

    //  The answer worth caching: { known: false } or { known: true, stats,
    //  label }. Thresholds are applied afterwards, per entry.
    async function lookup(state, apiKey, sha256, signal) {
        let res;
        try {
            res = await fetchImpl(`${baseUrl}/files/${sha256}`, {
                method: 'GET',
                headers: { 'x-apikey': apiKey, accept: 'application/json' },
                //  never follow a redirect: it would carry the key elsewhere
                redirect: 'error',
                signal,
            });
        } catch (e) {
            throw describeFetchError(e, signal);
        }

        const status = res.status;

        if (404 === status) {
            discardBody(res);
            return { known: false };
        }

        if (200 !== status) {
            discardBody(res);
            if (401 === status || 403 === status) {
                throw new LookupError(`API key rejected (HTTP ${status})`);
            }
            if (429 === status) {
                state.blockedUntil = mono() + retryAfterMs(res);
                pump(state); //  fails whatever is waiting
                throw new LookupError('Quota exceeded (HTTP 429)');
            }
            if (status >= 500) {
                throw new LookupError(`VirusTotal is unavailable (HTTP ${status})`);
            }
            throw new LookupError(`Unexpected response (HTTP ${status})`);
        }

        let body;
        try {
            body = JSON.parse(await readBody(res));
        } catch (e) {
            if (e instanceof LookupError) {
                throw e;
            }
            if (signal && signal.aborted) {
                throw new LookupError('Aborted');
            }
            throw new LookupError('Malformed response (not JSON)');
        }

        const attributes = body && body.data && body.data.attributes;
        const stats = attributes && attributes.last_analysis_stats;
        if (!stats || 'object' !== typeof stats || Array.isArray(stats)) {
            throw new LookupError('Malformed response (no last_analysis_stats)');
        }

        //  a count that is missing or not a count is not "0 engines said so"
        const counts = {};
        STAT_KEYS.forEach(k => {
            if (!Number.isSafeInteger(stats[k]) || stats[k] < 0) {
                throw new LookupError(
                    `Malformed response (last_analysis_stats.${k} is missing or not a count)`
                );
            }
            counts[k] = stats[k];
        });

        return { known: true, stats: counts, label: threatLabel(attributes) };
    }

    //
    //  The lookup for |sha256|, shared by every scan that wants it while it
    //  is in progress: one slot, one request, one answer (or error) for all.
    //  The first scan's settings govern the wait. Each scan still stops on
    //  its own |signal|; the request itself stops once no scan is waiting.
    //
    function sharedLookup(state, apiKey, sha256, settings, signal) {
        let job = state.inflight.get(sha256);
        if (!job) {
            job = { ac: new AbortController(), users: 0, settled: false, waiting: true };
            job.promise = (async () => {
                await acquireSlot(state, settings, job.ac.signal);
                job.waiting = false;
                const answer = await lookup(state, apiKey, sha256, job.ac.signal);
                cachePut(state, settings, sha256, answer);
                return answer;
            })();
            const done = () => {
                job.settled = true;
                if (state.inflight.get(sha256) === job) {
                    state.inflight.delete(sha256);
                }
            };
            job.promise.then(done, done);
            state.inflight.set(sha256, job);
        }
        return joinLookup(job, signal);
    }

    function joinLookup(job, signal) {
        return new Promise((resolve, reject) => {
            let left = false;
            const leave = () => {
                if (left) {
                    return false;
                }
                left = true;
                --job.users;
                if (signal) {
                    signal.removeEventListener('abort', onAbort);
                }
                return true;
            };
            const onAbort = () => {
                const waiting = job.waiting;
                if (!leave()) {
                    return;
                }
                if (0 === job.users && !job.settled) {
                    job.ac.abort();
                }
                reject(
                    new LookupError(
                        waiting
                            ? 'Aborted while waiting for the rate limit'
                            : 'Aborted (timed out)'
                    )
                );
            };

            ++job.users;
            if (signal) {
                if (signal.aborted) {
                    return onAbort();
                }
                signal.addEventListener('abort', onAbort, { once: true });
            }
            job.promise.then(
                answer => leave() && resolve(answer),
                err => leave() && reject(err)
            );
        });
    }

    function describeFetchError(e, signal) {
        if ((signal && signal.aborted) || (e && 'AbortError' === e.name)) {
            return new LookupError('Aborted (timed out)');
        }
        //  undici: TypeError('fetch failed', { cause }); a refused redirect
        //  is a TypeError too. Only codes are kept: messages can carry URLs.
        const cause = e && e.cause;
        const code =
            cause && 'string' === typeof cause.code && /^[A-Z0-9_]+$/.test(cause.code)
                ? cause.code
                : null;
        if (cause && /redirect/i.test(String(cause.message))) {
            return new LookupError('Request failed (redirect refused)');
        }
        return new LookupError(code ? `Request failed (${code})` : 'Request failed');
    }

    //  The label to show: VirusTotal's own suggestion when it has one, else
    //  the name most engines that flagged it agree on.
    function threatLabel(attributes) {
        const suggested =
            attributes.popular_threat_classification &&
            attributes.popular_threat_classification.suggested_threat_label;
        if ('string' === typeof suggested && suggested.trim()) {
            return suggested.trim().slice(0, MAX_LABEL_LENGTH);
        }

        const results = attributes.last_analysis_results;
        if (!results || 'object' !== typeof results) {
            return undefined;
        }
        const counts = new Map();
        Object.values(results).forEach(r => {
            if (r && 'malicious' === r.category && 'string' === typeof r.result) {
                const name = r.result.trim();
                if (name) {
                    counts.set(name, (counts.get(name) || 0) + 1);
                }
            }
        });
        let best;
        let bestCount = 0;
        counts.forEach((count, name) => {
            if (count > bestCount) {
                best = name;
                bestCount = count;
            }
        });
        return best ? best.slice(0, MAX_LABEL_LENGTH) : undefined;
    }

    function verdict(answer, settings) {
        if (!answer.known) {
            return { result: 'skipped', detail: 'Not known to VirusTotal' };
        }

        const s = answer.stats;
        const detections = s.malicious + (settings.countSuspicious ? s.suspicious : 0);
        const engines = s.malicious + s.suspicious + s.undetected + s.harmless;
        const ratio = `${detections}/${engines}`;

        if (0 === engines) {
            return {
                result: 'skipped',
                detail: 'Known to VirusTotal but not analysed yet',
            };
        }
        if (detections >= settings.minDetections) {
            return {
                result: 'infected',
                signature: `VirusTotal: ${ratio}${answer.label ? ` (${answer.label})` : ''}`,
            };
        }
        return { result: 'clean', detail: `VirusTotal: ${ratio}` };
    }

    async function run(ctx) {
        const options = ctx.options || {};
        const apiKey = options.apiKey;

        if (!isUsableApiKey(apiKey)) {
            throw new LookupError(
                'No usable apiKey (not set, or its @environment:/@file: spec did not resolve)'
            );
        }

        const sha256 = 'string' === typeof ctx.sha256 ? ctx.sha256.toLowerCase() : '';
        if (!/^[0-9a-f]{64}$/.test(sha256)) {
            throw new LookupError('No SHA-256 for this file');
        }

        const settings = settingsOf(options);
        const state = stateFor(apiKey);

        const cached = cacheGet(state, sha256);
        if (cached) {
            return verdict(cached, settings);
        }

        //  core's abortSignal covers the wait and the request; |timeout| only
        //  matters when scan() is called without one
        let signal = ctx.abortSignal;
        let timer = null;
        if (!signal && ctx.timeout > 0) {
            const ac = new AbortController();
            timer = setTimeout(() => ac.abort(), ctx.timeout);
            signal = ac.signal;
        }

        try {
            const answer = await sharedLookup(state, apiKey, sha256, settings, signal);
            return verdict(answer, settings);
        } finally {
            clearTimeout(timer);
        }
    }

    function scan(filePath, ctx, cb) {
        const apiKey = ctx && ctx.options ? ctx.options.apiKey : undefined;
        const clean = res => {
            const out = { result: res.result };
            if (res.signature) {
                out.signature = redact(res.signature, apiKey);
            }
            if (res.detail) {
                out.detail = redact(res.detail, apiKey);
            }
            return out;
        };

        run(ctx || {}).then(
            res => process.nextTick(cb, null, clean(res)),
            err => {
                const detail =
                    err instanceof LookupError
                        ? err.message
                        : 'Lookup failed unexpectedly';
                process.nextTick(cb, null, clean({ result: 'error', detail }));
            }
        );
    }

    //  Checks each entry has a key it could use and sensible options; never
    //  calls VirusTotal (that would spend quota) and never fails startup.
    function init(entries, cb) {
        const list = Array.isArray(entries) ? entries : [];
        if (0 === list.length) {
            return cb(null); //  registered, but no entry uses it
        }
        const problems = [];
        if (list.some(e => !isUsableApiKey(e && e.apiKey))) {
            problems.push(
                'an entry has no usable apiKey (not set, or its @environment:/@file: spec did not resolve); its lookups will fail'
            );
        }
        list.forEach((e, i) => {
            optionProblems(e).forEach(p =>
                problems.push(list.length > 1 ? `entry ${i + 1}: ${p}` : p)
            );
        });
        if (problems.length > 0) {
            //  warnings, not a failure: core logs each one and keeps the scanner
            return cb(null, { warnings: problems });
        }
        log(
            'info',
            { scanner: SCANNER_NAME, entries: list.length },
            'VirusTotal hash lookup ready'
        );
        return cb(null);
    }

    return { scan, init, _states: states };
}

function checkBaseUrl(testBaseUrl) {
    if (undefined === testBaseUrl) {
        return PRODUCTION_BASE_URL;
    }
    let url;
    try {
        url = new URL(testBaseUrl);
    } catch (e) {
        throw new Error('testBaseUrl is not a URL');
    }
    const loopback = ['127.0.0.1', '[::1]', 'localhost'].includes(url.hostname);
    if ('https:' !== url.protocol && !('http:' === url.protocol && loopback)) {
        throw new Error('testBaseUrl must be https://, or http:// to a loopback address');
    }
    return String(testBaseUrl).replace(/\/+$/, '');
}
