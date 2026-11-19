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
//    dailyLimit         Lookups per UTC day before every lookup is an error
//                       (default 500, the free tier's; 0: no limit)
//    cacheMinutes       Keep answers by SHA-256 this long (default 60; 0: off)
//    cacheMaxEntries    Most answers kept (default 1000)
//    maxQueue           Most lookups waiting for the rate limit (default 100)
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
const log = require('./log.js');

const SCANNER_NAME = 'virustotal';
const PRODUCTION_BASE_URL = 'https://www.virustotal.com/api/v3';

const DEFAULTS = Object.freeze({
    minDetections: 2,
    countSuspicious: false,
    requestsPerMinute: 4,
    dailyLimit: 500,
    cacheMinutes: 60,
    cacheMaxEntries: 1000,
    maxQueue: 100,
});

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

function intOption(options, name, min) {
    const v = options[name];
    if (undefined === v || null === v || '' === v) {
        return DEFAULTS[name];
    }
    const n = Number(v);
    return Number.isFinite(n) && n >= min ? Math.floor(n) : DEFAULTS[name];
}

function settingsOf(options) {
    const o = options || {};
    return {
        minDetections: intOption(o, 'minDetections', 1),
        countSuspicious: true === o.countSuspicious,
        requestsPerMinute: intOption(o, 'requestsPerMinute', 1),
        //  0: no daily limit (a paid key)
        dailyLimit: intOption(o, 'dailyLimit', 0) || Infinity,
        cacheMs: intOption(o, 'cacheMinutes', 0) * 60 * 1000,
        cacheMaxEntries: intOption(o, 'cacheMaxEntries', 0),
        maxQueue: intOption(o, 'maxQueue', 0),
    };
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
//    now           A clock, ms
//    windowMs      The rate limit's window (default 60000)
//
function createVirusTotalScanner(deps = {}) {
    const fetchImpl = deps.fetch || globalThis.fetch;
    const now = deps.now || Date.now;
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
                sent: [], //  times of lookups within the last window
                waiting: [],
                timer: null,
                day: utcDay(now()),
                dayCount: 0,
                blockedUntil: 0,
                cache: new Map(), //  sha256 -> { expires, answer }, oldest first
            };
            states.set(id, state);
        }
        return state;
    }

    // ── Rate limit and daily quota ───────────────────────────────────────

    function rollDay(state) {
        const today = utcDay(now());
        if (today !== state.day) {
            state.day = today;
            state.dayCount = 0;
        }
    }

    function pump(state) {
        clearTimeout(state.timer);
        state.timer = null;

        const t = now();
        state.sent = state.sent.filter(at => t - at < windowMs);
        rollDay(state);

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

    function dailyLimitError(dailyLimit) {
        return new LookupError(
            `Daily lookup limit (${dailyLimit}) reached; lookups resume at 00:00 UTC`
        );
    }

    //  Resolves when a lookup may be sent; rejects with a LookupError when it
    //  may not, or when |signal| aborts first.
    function acquireSlot(state, settings, signal) {
        return new Promise((resolve, reject) => {
            if (signal && signal.aborted) {
                return reject(new LookupError('Aborted'));
            }

            const t = now();
            if (t < state.blockedUntil) {
                return reject(
                    new LookupError(
                        `Quota exceeded (HTTP 429); not asking again for ${Math.ceil(
                            (state.blockedUntil - t) / 1000
                        )}s`
                    )
                );
            }

            rollDay(state);
            if (state.dayCount >= settings.dailyLimit) {
                return reject(dailyLimitError(settings.dailyLimit));
            }
            if (state.waiting.length >= settings.maxQueue) {
                return reject(
                    new LookupError(
                        `Too many lookups waiting for the rate limit (${settings.maxQueue})`
                    )
                );
            }

            const onAbort = () => {
                const i = state.waiting.indexOf(waiter);
                if (-1 !== i) {
                    state.waiting.splice(i, 1);
                }
                waiter.settle(
                    new LookupError('Aborted while waiting for the rate limit')
                );
            };

            const waiter = {
                settings,
                settled: false,
                settle: err => {
                    if (waiter.settled) {
                        return;
                    }
                    waiter.settled = true;
                    if (signal) {
                        signal.removeEventListener('abort', onAbort);
                    }
                    return err ? reject(err) : resolve();
                },
            };

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
        if (hit.expires <= now()) {
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
        state.cache.set(sha256, { expires: now() + settings.cacheMs, answer });
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

    function retryAfterMs(res) {
        const v = Number(
            res.headers && res.headers.get && res.headers.get('retry-after')
        );
        if (Number.isFinite(v) && v > 0) {
            return Math.min(MAX_QUOTA_BACKOFF_MS, v * 1000);
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
                state.blockedUntil = now() + retryAfterMs(res);
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
        if (!stats || 'object' !== typeof stats) {
            throw new LookupError('Malformed response (no last_analysis_stats)');
        }

        const num = k => (Number.isFinite(stats[k]) && stats[k] > 0 ? stats[k] : 0);
        return {
            known: true,
            stats: {
                malicious: num('malicious'),
                suspicious: num('suspicious'),
                undetected: num('undetected'),
                harmless: num('harmless'),
            },
            label: threatLabel(attributes),
        };
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
            await acquireSlot(state, settings, signal);
            const answer = await lookup(state, apiKey, sha256, signal);
            cachePut(state, settings, sha256, answer);
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

    //  Checks each entry has a key it could use; never calls VirusTotal (that
    //  would spend quota) and never fails startup.
    function init(entries, cb) {
        const list = Array.isArray(entries) ? entries : [];
        if (0 === list.length) {
            return cb(null); //  registered, but no entry uses it
        }
        const bad = list.filter(e => !isUsableApiKey(e && e.apiKey));
        if (bad.length > 0) {
            return cb(
                new Error(
                    'virustotal: an entry has no usable apiKey (not set, or its @environment:/@file: spec did not resolve); its lookups will fail'
                )
            );
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
