/* jslint node: true */
'use strict';

const assert = require('assert');
const http = require('http');
const crypto = require('crypto');

const virustotal = require('../lib/virustotal.js');
const log = require('../lib/log.js');

const API_KEY = 'f00dfacecafebeef0123456789abcdef0123456789abcdefdeadbeefc0ffee42';

function sha(n) {
    return crypto.createHash('sha256').update(String(n)).digest('hex');
}

function report({ malicious = 0, suspicious = 0, undetected = 60, harmless = 0 }, extra) {
    return {
        data: {
            id: 'x',
            type: 'file',
            attributes: Object.assign(
                {
                    last_analysis_stats: {
                        malicious,
                        suspicious,
                        undetected,
                        harmless,
                        timeout: 0,
                        'type-unsupported': 4,
                        failure: 0,
                    },
                },
                extra
            ),
        },
    };
}

//
//  A fake VirusTotal: |routes| maps a sha256 to a handler (req, res), and
//  every request is recorded with its x-apikey header and path.
//
class FakeVirusTotal {
    constructor() {
        this.routes = new Map();
        this.requests = [];
        this.server = http.createServer((req, res) => {
            this.requests.push({
                at: Date.now(),
                url: req.url,
                apiKey: req.headers['x-apikey'],
            });
            const m = /^\/api\/v3\/files\/([0-9a-f]{64})$/.exec(req.url);
            const handler = m && this.routes.get(m[1]);
            if (!handler) {
                res.writeHead(404, { 'content-type': 'application/json' });
                return res.end(
                    JSON.stringify({
                        error: { code: 'NotFoundError', message: 'not found' },
                    })
                );
            }
            return handler(req, res);
        });
        this.server.on('connection', s => {
            this.sockets = this.sockets || new Set();
            this.sockets.add(s);
            s.on('close', () => this.sockets.delete(s));
        });
    }

    json(sha256, status, body, headers = {}) {
        this.routes.set(sha256, (req, res) => {
            res.writeHead(
                status,
                Object.assign({ 'content-type': 'application/json' }, headers)
            );
            res.end('string' === typeof body ? body : JSON.stringify(body));
        });
    }

    listen() {
        return new Promise(resolve =>
            this.server.listen(0, '127.0.0.1', () =>
                resolve(`http://127.0.0.1:${this.server.address().port}/api/v3`)
            )
        );
    }

    close() {
        (this.sockets || new Set()).forEach(s => s.destroy());
        return new Promise(resolve => this.server.close(() => resolve()));
    }
}

describe('virustotal scanner', function () {
    this.timeout(10000);

    let fake;
    let baseUrl;
    let logLines;
    let allOutput; //  every result and log line, checked for the key at the end

    const options = extra =>
        Object.assign({ scanner: 'virustotal', apiKey: API_KEY }, extra);

    function scan(scanner, sha256, opts, ctxExtra = {}) {
        return new Promise(resolve => {
            let calls = 0;
            scanner.scan(
                '/does/not/matter',
                Object.assign({ options: opts || options(), sha256 }, ctxExtra),
                (err, res) => {
                    ++calls;
                    assert.strictEqual(calls, 1);
                    assert.ifError(err);
                    allOutput.push(JSON.stringify(res));
                    resolve(res);
                }
            );
        });
    }

    before(async () => {
        fake = new FakeVirusTotal();
        baseUrl = await fake.listen();
        allOutput = [];
    });

    beforeEach(() => {
        fake.routes.clear();
        fake.requests = [];
        logLines = [];
        log.setLogger({
            info: (obj, msg) => logLines.push(JSON.stringify({ obj, msg })),
            warn: (obj, msg) => logLines.push(JSON.stringify({ obj, msg })),
            error: (obj, msg) => logLines.push(JSON.stringify({ obj, msg })),
        });
    });

    afterEach(() => {
        allOutput.push(...logLines);
        log.setLogger(null);
    });

    after(async () => {
        await fake.close();
        //  the key must never have shown up anywhere
        allOutput.forEach(line => {
            assert.ok(!line.includes(API_KEY), `API key leaked: ${line}`);
            assert.ok(!line.includes(API_KEY.slice(0, 16)), `API key leaked: ${line}`);
        });
    });

    const make = deps =>
        virustotal.createVirusTotalScanner(Object.assign({ testBaseUrl: baseUrl }, deps));

    describe('results', () => {
        it('sends the key in x-apikey, and only the hash in the URL', async () => {
            const s = make();
            const h = sha('clean');
            fake.json(h, 200, report({ malicious: 0 }));
            await scan(s, h);
            assert.strictEqual(fake.requests.length, 1);
            assert.strictEqual(fake.requests[0].apiKey, API_KEY);
            assert.strictEqual(fake.requests[0].url, `/api/v3/files/${h}`);
        });

        it('clean below the threshold', async () => {
            const h = sha('one');
            fake.json(h, 200, report({ malicious: 1, undetected: 69 }));
            assert.deepStrictEqual(await scan(make(), h), {
                result: 'clean',
                detail: 'VirusTotal: 1/70',
            });
        });

        it('infected at the threshold, with the suggested label', async () => {
            const h = sha('bad');
            fake.json(
                h,
                200,
                report(
                    { malicious: 5, undetected: 65 },
                    {
                        popular_threat_classification: {
                            suggested_threat_label: 'trojan.pklite/dropper',
                        },
                    }
                )
            );
            assert.deepStrictEqual(await scan(make(), h, options({ minDetections: 5 })), {
                result: 'infected',
                signature: 'VirusTotal: 5/70 (trojan.pklite/dropper)',
            });
        });

        it('minDetections is configurable', async () => {
            const h = sha('one-b');
            fake.json(h, 200, report({ malicious: 1, undetected: 69 }));
            const res = await scan(make(), h, options({ minDetections: 1 }));
            assert.strictEqual(res.result, 'infected');
            assert.strictEqual(res.signature, 'VirusTotal: 1/70');
        });

        it('suspicious counts only with countSuspicious', async () => {
            const h = sha('sus');
            fake.json(h, 200, report({ malicious: 1, suspicious: 1, undetected: 68 }));
            assert.strictEqual((await scan(make(), h)).result, 'clean');
            const res = await scan(make(), h, options({ countSuspicious: true }));
            assert.strictEqual(res.result, 'infected');
            assert.strictEqual(res.signature, 'VirusTotal: 2/70');
        });

        it('falls back to the most common engine label', async () => {
            const h = sha('label');
            fake.json(
                h,
                200,
                report(
                    { malicious: 3, undetected: 60 },
                    {
                        last_analysis_results: {
                            A: { category: 'malicious', result: 'Trojan.Foo' },
                            B: { category: 'malicious', result: 'Trojan.Foo' },
                            C: { category: 'malicious', result: 'Generic.Bar' },
                            D: { category: 'undetected', result: null },
                        },
                    }
                )
            );
            const res = await scan(make(), h);
            assert.strictEqual(res.signature, 'VirusTotal: 3/63 (Trojan.Foo)');
        });

        it('skipped for an unknown hash (404)', async () => {
            const res = await scan(make(), sha('unknown'));
            assert.deepStrictEqual(res, {
                result: 'skipped',
                detail: 'Not known to VirusTotal',
            });
        });

        it('skipped for a known file with no analysis yet', async () => {
            const h = sha('queued');
            fake.json(h, 200, report({ malicious: 0, undetected: 0 }));
            assert.strictEqual((await scan(make(), h)).result, 'skipped');
        });
    });

    describe('errors', () => {
        [
            [401, /API key rejected \(HTTP 401\)/],
            [403, /API key rejected \(HTTP 403\)/],
            [429, /Quota exceeded \(HTTP 429\)/],
            [500, /unavailable \(HTTP 500\)/],
            [503, /unavailable \(HTTP 503\)/],
            [418, /Unexpected response \(HTTP 418\)/],
        ].forEach(([status, re]) => {
            it(`HTTP ${status} is an error`, async () => {
                const h = sha(`status-${status}`);
                //  a body echoing the key must not leak it either
                fake.json(h, status, { error: { message: `bad key ${API_KEY}` } });
                const res = await scan(make(), h);
                assert.strictEqual(res.result, 'error');
                assert.match(res.detail, re);
            });
        });

        it('after a 429, stops asking until Retry-After has passed', async () => {
            let t = 1_000_000;
            const s = make({ monoNow: () => t });
            const h = sha('quota');
            fake.json(h, 429, {}, { 'retry-after': '30' });
            assert.strictEqual((await scan(s, h)).result, 'error');
            assert.strictEqual(fake.requests.length, 1);

            const again = await scan(s, sha('quota-2'));
            assert.strictEqual(again.result, 'error');
            assert.match(again.detail, /not asking again for 30s/);
            assert.strictEqual(fake.requests.length, 1);

            t += 31 * 1000;
            assert.strictEqual((await scan(s, sha('quota-3'))).result, 'skipped');
            assert.strictEqual(fake.requests.length, 2);
        });

        it('a 429 fails the lookups already waiting, without sending them', async () => {
            const s = make({ windowMs: 300 });
            fake.routes.clear();
            const statusFor = () => (req, res) => {
                res.writeHead(429, { 'retry-after': '3600' });
                res.end();
            };
            const hashes = [1, 2, 3, 4].map(i => sha(`q429-${i}`));
            hashes.forEach(h => fake.routes.set(h, statusFor()));
            const opts = options({ requestsPerMinute: 1, cacheMinutes: 0 });
            const results = await Promise.all(hashes.map(h => scan(s, h, opts)));
            results.forEach(r => {
                assert.strictEqual(r.result, 'error');
                assert.match(r.detail, /Quota exceeded \(HTTP 429\)/);
            });
            assert.strictEqual(fake.requests.length, 1);
            assert.strictEqual([...s._states.values()][0].waiting.length, 0);
        });

        it('reads a Retry-After HTTP-date, and caps any Retry-After at an hour', async () => {
            const wall = Date.parse('2026-11-18T12:00:00Z');
            const cases = [
                [new Date(wall + 120 * 1000).toUTCString(), /for 120s/],
                ['Wed, 18 Nov 2026 11:00:00 GMT', /for 60s/], //  in the past
                ['soon', /for 60s/],
                ['999999999', /for 3600s/],
                [new Date(wall + 10 * 3600 * 1000).toUTCString(), /for 3600s/],
            ];
            for (const [header, re] of cases) {
                const s = make({ now: () => wall });
                const h = sha(`ra-${header}`);
                fake.json(h, 429, {}, { 'retry-after': header });
                await scan(s, h);
                const again = await scan(s, sha(`ra2-${header}`));
                assert.match(again.detail, re, header);
            }
        });

        [
            ['a count as a string', { malicious: '60', undetected: 5 }],
            ['a missing count', { undetected: 70, suspicious: 0, harmless: 0 }],
            ['a fractional count', { malicious: 60.5 }],
            ['a negative count', { malicious: -1 }],
            ['a count that is null', { harmless: null }],
        ].forEach(([what, override]) => {
            it(`a report with ${what} is an error, not clean`, async () => {
                const h = sha(`stats-${what}`);
                const body = report({});
                const stats = body.data.attributes.last_analysis_stats;
                Object.assign(stats, override);
                Object.keys(override).forEach(k => {
                    if (undefined === override[k]) {
                        delete stats[k];
                    }
                });
                if (!('malicious' in override) && 'a missing count' === what) {
                    delete stats.malicious;
                }
                fake.json(h, 200, body);
                const res = await scan(make(), h);
                assert.strictEqual(res.result, 'error', JSON.stringify(res));
                assert.match(res.detail, /Malformed response/);
            });
        });

        it('last_analysis_stats that is an array is an error', async () => {
            const h = sha('stats-array');
            fake.json(h, 200, { data: { attributes: { last_analysis_stats: [] } } });
            const res = await scan(make(), h);
            assert.strictEqual(res.result, 'error');
            assert.match(res.detail, /no last_analysis_stats/);
        });

        it('malformed JSON is an error', async () => {
            const h = sha('malformed');
            fake.json(h, 200, '{"data": {');
            const res = await scan(make(), h);
            assert.strictEqual(res.result, 'error');
            assert.match(res.detail, /not JSON/);
        });

        it('JSON without last_analysis_stats is an error', async () => {
            const h = sha('nostats');
            fake.json(h, 200, { data: { attributes: {} } });
            const res = await scan(make(), h);
            assert.strictEqual(res.result, 'error');
            assert.match(res.detail, /no last_analysis_stats/);
        });

        it('a hung request stops on abortSignal', async () => {
            const h = sha('hang');
            fake.routes.set(h, () => {}); //  never answers
            const ac = new AbortController();
            setTimeout(() => ac.abort(), 100);
            const t0 = Date.now();
            const res = await scan(make(), h, options(), { abortSignal: ac.signal });
            assert.strictEqual(res.result, 'error');
            assert.match(res.detail, /Aborted/);
            assert.ok(Date.now() - t0 < 2000);
        });

        it('a hung request stops on ctx.timeout without an abortSignal', async () => {
            const h = sha('hang-2');
            fake.routes.set(h, () => {});
            const res = await scan(make(), h, options(), { timeout: 150 });
            assert.strictEqual(res.result, 'error');
            assert.match(res.detail, /Aborted/);
        });

        it('a connection failure is an error naming only the code', async () => {
            const dead = new FakeVirusTotal();
            const url = await dead.listen();
            await dead.close();
            const s = virustotal.createVirusTotalScanner({ testBaseUrl: url });
            const res = await scan(s, sha('dead'));
            assert.strictEqual(res.result, 'error');
            assert.match(res.detail, /Request failed \(ECONNREFUSED\)/);
        });

        it('refuses to follow a redirect (which would carry the key)', async () => {
            const other = new FakeVirusTotal();
            const otherUrl = await other.listen();
            const h = sha('redirect');
            other.json(h, 200, report({ malicious: 0 }));
            fake.routes.set(h, (req, res) => {
                res.writeHead(302, { location: `${otherUrl}/files/${h}` });
                res.end();
            });
            const res = await scan(make(), h);
            await other.close();
            assert.strictEqual(res.result, 'error');
            assert.match(res.detail, /redirect refused|Request failed/);
            assert.strictEqual(other.requests.length, 0);
        });

        it('a missing or malformed sha256 is an error, without a request', async () => {
            const s = make();
            assert.match((await scan(s, undefined)).detail, /No SHA-256/);
            assert.match((await scan(s, 'abc')).detail, /No SHA-256/);
            assert.strictEqual(fake.requests.length, 0);
        });

        it('a missing or unresolved apiKey is an error, without a request', async () => {
            const s = make();
            for (const apiKey of [
                undefined,
                '',
                '@environment:VT_API_KEY',
                'has space',
            ]) {
                const res = await scan(s, sha('nokey'), options({ apiKey }));
                assert.strictEqual(res.result, 'error');
                assert.match(res.detail, /No usable apiKey/);
            }
            assert.strictEqual(fake.requests.length, 0);
        });

        it('scrubs the key even from errors fetch throws', async () => {
            const s = virustotal.createVirusTotalScanner({
                fetch: async () => {
                    const e = new TypeError(`fetch failed for key ${API_KEY}`);
                    e.cause = Object.assign(new Error(`connect ${API_KEY}`), {
                        code: 'ECONNRESET',
                    });
                    throw e;
                },
            });
            const res = await scan(s, sha('throws'));
            assert.strictEqual(res.result, 'error');
            assert.strictEqual(res.detail, 'Request failed (ECONNRESET)');
        });

        it('refuses a non-loopback http testBaseUrl', () => {
            assert.throws(
                () =>
                    virustotal.createVirusTotalScanner({
                        testBaseUrl: 'http://example.com/api/v3',
                    }),
                /https/
            );
            assert.doesNotThrow(() =>
                virustotal.createVirusTotalScanner({
                    testBaseUrl: 'https://vt.example/api/v3',
                })
            );
            assert.strictEqual(
                virustotal.PRODUCTION_BASE_URL,
                'https://www.virustotal.com/api/v3'
            );
        });
    });

    describe('rate limit', () => {
        it('the 5th lookup at 4/min waits for the window to roll', async () => {
            const windowMs = 600;
            const s = make({ windowMs });
            const t0 = Date.now();
            const done = [];
            await Promise.all(
                [1, 2, 3, 4, 5].map(i =>
                    scan(s, sha(`rl-${i}`)).then(res => {
                        done.push({ i, at: Date.now() - t0, res });
                    })
                )
            );
            assert.strictEqual(fake.requests.length, 5);
            done.forEach(d => assert.strictEqual(d.res.result, 'skipped'));
            const fifth = done.find(d => 5 === d.i);
            const firstFour = done.filter(d => d.i < 5);
            firstFour.forEach(d =>
                assert.ok(d.at < windowMs / 2, `#${d.i} at ${d.at}ms`)
            );
            assert.ok(fifth.at >= windowMs - 20, `5th at ${fifth.at}ms`);
        });

        it('a lookup waiting for the rate limit stops on abort', async () => {
            const s = make({ windowMs: 5000 });
            const opts = options({ requestsPerMinute: 1, maxWaitMs: 10000 });
            await scan(s, sha('w-1'), opts);
            const ac = new AbortController();
            setTimeout(() => ac.abort(), 100);
            const res = await scan(s, sha('w-2'), opts, { abortSignal: ac.signal });
            assert.strictEqual(res.result, 'error');
            assert.match(res.detail, /Aborted while waiting/);
            assert.strictEqual(fake.requests.length, 1);
            assert.strictEqual([...s._states.values()][0].waiting.length, 0);
        });

        it('too many waiting lookups are errors at once', async () => {
            const s = make({ windowMs: 300 });
            const opts = options({ requestsPerMinute: 1, maxQueue: 1 });
            const results = await Promise.all([
                scan(s, sha('q-1'), opts),
                scan(s, sha('q-2'), opts),
                scan(s, sha('q-3'), opts),
            ]);
            assert.deepStrictEqual(
                results.map(r => r.result),
                ['skipped', 'skipped', 'error']
            );
            assert.match(results[2].detail, /Too many lookups waiting/);
        });

        it('maxQueue 0 only refuses lookups that would have to wait', async () => {
            const s = make({ windowMs: 500 });
            const opts = options({ requestsPerMinute: 1, maxQueue: 0 });
            assert.strictEqual((await scan(s, sha('mq0-1'), opts)).result, 'skipped');
            const second = await scan(s, sha('mq0-2'), opts);
            assert.strictEqual(second.result, 'error');
            assert.match(
                second.detail,
                /Too many lookups waiting for the rate limit \(0\)/
            );
            assert.strictEqual(fake.requests.length, 1);
        });

        it('waits at most maxWaitMs for a slot (default 2 s), then is an error', async () => {
            assert.strictEqual(virustotal.DEFAULTS.maxWaitMs, 2000);
            //  the window would free a slot in 1 s: within reach of 2 s, not 150 ms
            const s = make({ windowMs: 1000 });
            const opts = options({ requestsPerMinute: 1, cacheMinutes: 0 });
            await scan(s, sha('mw-1'), opts);

            let t0 = Date.now();
            const waited = await scan(s, sha('mw-2'), opts);
            assert.strictEqual(waited.result, 'skipped');
            assert.ok(Date.now() - t0 >= 900, `${Date.now() - t0}ms`);

            t0 = Date.now();
            const short = await scan(
                s,
                sha('mw-3'),
                options({ requestsPerMinute: 1, maxWaitMs: 150 })
            );
            assert.strictEqual(short.result, 'error');
            assert.match(short.detail, /more than maxWaitMs \(150ms\) away/);
            assert.ok(Date.now() - t0 < 100, 'did not fail at once');
        });

        it('a slot further off than maxWaitMs fails at once, not after waiting', async () => {
            //  a real minute: a lookup that waited would hold a core scan slot
            const s = make({ windowMs: 60 * 1000 });
            const opts = options({ requestsPerMinute: 1 });
            await scan(s, sha('far-1'), opts);
            const t0 = Date.now();
            const res = await scan(s, sha('far-2'), opts);
            assert.strictEqual(res.result, 'error');
            assert.match(res.detail, /Rate limit reached \(1\/min\)/);
            assert.ok(Date.now() - t0 < 100, `${Date.now() - t0}ms`);
            assert.strictEqual(fake.requests.length, 1);
        });

        it('queues a lookup whose slot is within maxWaitMs, refuses one beyond it', async () => {
            const s = make({ windowMs: 400 });
            const opts = options({ requestsPerMinute: 1, maxWaitMs: 300 });
            await scan(s, sha('mwb-1'), opts);
            await new Promise(r => setTimeout(r, 150)); //  slot due in ~250 ms
            const t0 = Date.now();
            const results = await Promise.all([
                scan(s, sha('mwb-2'), opts), //  ~250 ms: waits
                scan(s, sha('mwb-3'), opts), //  ~650 ms: refused at once
            ]);
            assert.strictEqual(results[0].result, 'skipped');
            assert.strictEqual(results[1].result, 'error');
            assert.ok(Date.now() - t0 < 500, `${Date.now() - t0}ms`);
        });

        it('maxWaitMs bounds the wait even when the slot does not come', async () => {
            //  a stopped monotonic clock: the window never rolls
            const s = make({ windowMs: 100, monoNow: () => 42 });
            const opts = options({ requestsPerMinute: 1, maxWaitMs: 200 });
            await scan(s, sha('stuck-1'), opts);
            const t0 = Date.now();
            const res = await scan(s, sha('stuck-2'), opts);
            assert.strictEqual(res.result, 'error');
            assert.match(res.detail, /No lookup slot came free within 200ms/);
            assert.ok(Date.now() - t0 >= 190, `${Date.now() - t0}ms`);
            assert.strictEqual([...s._states.values()][0].waiting.length, 0);
        });

        it('maxWaitMs 0 never waits', async () => {
            const s = make({ windowMs: 200 });
            const opts = options({ requestsPerMinute: 1, maxWaitMs: 0 });
            await scan(s, sha('mw0-1'), opts);
            const res = await scan(s, sha('mw0-2'), opts);
            assert.strictEqual(res.result, 'error');
            assert.match(res.detail, /maxWaitMs is 0/);
        });

        it('concurrent lookups of one hash share a request', async () => {
            const s = make();
            const h = sha('dup');
            fake.json(h, 200, report({ malicious: 3, undetected: 60 }));
            const results = await Promise.all([
                scan(s, h),
                scan(s, h, options({ minDetections: 5 })),
                scan(s, h),
            ]);
            assert.strictEqual(fake.requests.length, 1);
            //  each with its own entry's threshold
            assert.deepStrictEqual(
                results.map(r => r.result),
                ['infected', 'clean', 'infected']
            );
        });

        it('a shared lookup that fails fails every scan waiting on it', async () => {
            const s = make();
            const h = sha('dup-err');
            fake.json(h, 503, {});
            const results = await Promise.all([scan(s, h), scan(s, h), scan(s, h)]);
            assert.strictEqual(fake.requests.length, 1);
            results.forEach(r => assert.match(r.detail, /unavailable \(HTTP 503\)/));
        });

        it('one scan aborting leaves a shared lookup running for the others', async () => {
            const s = make();
            const h = sha('dup-abort');
            let release;
            fake.routes.set(h, (req, res) => {
                release = () => {
                    res.writeHead(200, { 'content-type': 'application/json' });
                    res.end(JSON.stringify(report({ malicious: 0 })));
                };
            });
            const ac = new AbortController();
            const first = scan(s, h, options(), { abortSignal: ac.signal });
            const second = scan(s, h);
            await new Promise(r => setTimeout(r, 100));
            ac.abort();
            const aborted = await first;
            assert.strictEqual(aborted.result, 'error');
            assert.match(aborted.detail, /Aborted/);
            release();
            assert.strictEqual((await second).result, 'clean');
            assert.strictEqual(fake.requests.length, 1);
        });

        it('the request stops once every scan sharing it has aborted', async () => {
            const s = make();
            const h = sha('dup-all-abort');
            let closed = false;
            fake.routes.set(h, req => req.socket.on('close', () => (closed = true)));
            const ac = new AbortController();
            const both = Promise.all([
                scan(s, h, options(), { abortSignal: ac.signal }),
                scan(s, h, options(), { abortSignal: ac.signal }),
            ]);
            await new Promise(r => setTimeout(r, 100));
            ac.abort();
            (await both).forEach(r => assert.strictEqual(r.result, 'error'));
            await new Promise(r => setTimeout(r, 100));
            assert.strictEqual(closed, true);
            assert.strictEqual([...s._states.values()][0].inflight.size, 0);
        });

        it('the rate window runs on the monotonic clock, not the wall clock', async () => {
            let wall = Date.parse('2026-11-18T12:00:00Z');
            let mono = 1000;
            const s = make({ now: () => wall, monoNow: () => mono, windowMs: 60000 });
            const opts = options({ requestsPerMinute: 1, maxWaitMs: 0, cacheMinutes: 0 });
            await scan(s, sha('mono-1'), opts);
            wall += 3600 * 1000; //  the wall clock jumps an hour ahead
            assert.strictEqual((await scan(s, sha('mono-2'), opts)).result, 'error');
            mono += 60001;
            assert.strictEqual((await scan(s, sha('mono-3'), opts)).result, 'skipped');
        });

        it('a backwards clock step neither resets the day count again nor stalls it', async () => {
            let wall = Date.parse('2026-11-19T00:00:30Z');
            let mono = 0;
            const s = make({ now: () => wall, monoNow: () => mono, windowMs: 1 });
            const opts = options({ dailyLimit: 1, cacheMinutes: 0 });
            const step = () => (mono += 10);
            assert.strictEqual((await scan(s, sha('bk-1'), opts)).result, 'skipped');
            step();
            wall = Date.parse('2026-11-18T23:59:50Z'); //  stepped back over midnight
            assert.match((await scan(s, sha('bk-2'), opts)).detail, /Daily lookup limit/);
            step();
            wall = Date.parse('2026-11-19T00:00:40Z'); //  and forward again
            assert.match((await scan(s, sha('bk-3'), opts)).detail, /Daily lookup limit/);
            //  a clock stuck far behind: a new day after 24 h of real time
            wall = Date.parse('2026-11-01T00:00:00Z');
            mono += 24 * 3600 * 1000;
            assert.strictEqual((await scan(s, sha('bk-4'), opts)).result, 'skipped');
            assert.strictEqual(fake.requests.length, 2);
        });

        it('the daily limit turns lookups into errors until 00:00 UTC', async () => {
            let t = Date.parse('2026-11-18T23:59:00Z');
            const s = make({ now: () => t, windowMs: 1 });
            const opts = options({ dailyLimit: 2, cacheMinutes: 0 });
            assert.strictEqual((await scan(s, sha('d-1'), opts)).result, 'skipped');
            assert.strictEqual((await scan(s, sha('d-2'), opts)).result, 'skipped');
            const third = await scan(s, sha('d-3'), opts);
            assert.strictEqual(third.result, 'error');
            assert.match(third.detail, /Daily lookup limit \(2\) reached/);
            assert.strictEqual(fake.requests.length, 2);

            t = Date.parse('2026-11-19T00:00:01Z');
            assert.strictEqual((await scan(s, sha('d-3'), opts)).result, 'skipped');
            assert.strictEqual(fake.requests.length, 3);
        });
    });

    describe('cache', () => {
        it('answers a repeat lookup from the cache, applying the entry threshold', async () => {
            const s = make();
            const h = sha('cached');
            fake.json(h, 200, report({ malicious: 1, undetected: 69 }));
            assert.strictEqual((await scan(s, h)).result, 'clean');
            assert.strictEqual(
                (await scan(s, h, options({ minDetections: 1 }))).result,
                'infected'
            );
            assert.strictEqual(fake.requests.length, 1);
        });

        it('caches unknown hashes too, but never errors', async () => {
            const s = make();
            await scan(s, sha('unk'));
            await scan(s, sha('unk'));
            assert.strictEqual(fake.requests.length, 1);

            const h = sha('err');
            fake.json(h, 500, {});
            await scan(s, h);
            await scan(s, h);
            assert.strictEqual(fake.requests.length, 3);
        });

        it('expires entries after cacheMinutes, and can be turned off', async () => {
            let t = 5_000_000;
            const s = make({ monoNow: () => t, windowMs: 1 });
            const h = sha('ttl');
            await scan(s, h, options({ cacheMinutes: 1 }));
            t += 30 * 1000;
            await scan(s, h, options({ cacheMinutes: 1 }));
            assert.strictEqual(fake.requests.length, 1);
            t += 31 * 1000;
            await scan(s, h, options({ cacheMinutes: 1 }));
            assert.strictEqual(fake.requests.length, 2);

            const off = make({ windowMs: 1 });
            await scan(off, h, options({ cacheMinutes: 0 }));
            await scan(off, h, options({ cacheMinutes: 0 }));
            assert.strictEqual(fake.requests.length, 4);
        });

        it('keeps at most cacheMaxEntries, dropping the least recently used', async () => {
            const s = make({ windowMs: 1 });
            const opts = options({ cacheMaxEntries: 2, requestsPerMinute: 100 });
            await scan(s, sha('c-1'), opts);
            await scan(s, sha('c-2'), opts);
            await scan(s, sha('c-1'), opts); //  c-1 now most recent
            await scan(s, sha('c-3'), opts); //  evicts c-2
            assert.strictEqual(fake.requests.length, 3);
            await scan(s, sha('c-1'), opts);
            assert.strictEqual(fake.requests.length, 3);
            await scan(s, sha('c-2'), opts);
            assert.strictEqual(fake.requests.length, 4);
        });
    });

    describe('init', () => {
        it('reports an entry with no usable key, without a request', done => {
            make().init(
                [options(), options({ apiKey: '@environment:NOPE' })],
                (err, info) => {
                    assert.ifError(err);
                    const m = info.warnings.join('\n');
                    assert.match(m, /no usable apiKey/);
                    assert.ok(!m.includes(API_KEY));
                    assert.strictEqual(fake.requests.length, 0);
                    done();
                }
            );
        });

        it('warns about invalid and implausible options, keeping strict defaults', done => {
            make().init(
                [
                    options({
                        minDetections: 0,
                        requestsPerMinute: -4,
                        maxWaitMs: 'soon',
                        countSuspicious: 'yes',
                    }),
                    options({ minDetections: 200 }),
                    options({ minDetections: true }),
                ],
                (err, info) => {
                    assert.ifError(err);
                    const m = info.warnings.join('\n');
                    assert.match(
                        m,
                        /entry 1: "minDetections" must be a number of at least 1; using 2/
                    );
                    assert.match(m, /entry 1: "requestsPerMinute" must be .* using 4/);
                    assert.match(m, /entry 1: "maxWaitMs" must be .* using 2000/);
                    assert.match(m, /entry 1: "countSuspicious" must be true or false/);
                    assert.match(m, /entry 2: "minDetections" is 200/);
                    assert.match(m, /entry 3: "minDetections" must be/);
                    done();
                }
            );
        });

        it('falls back to the strict default for a bad minDetections', async () => {
            const h = sha('min0');
            fake.json(h, 200, report({ malicious: 1, undetected: 60 }));
            for (const minDetections of [0, -1, 'x', true]) {
                const res = await scan(make(), h, options({ minDetections }));
                assert.strictEqual(res.result, 'clean', String(minDetections));
            }
            fake.json(h, 200, report({ malicious: 2, undetected: 60 }));
            const res = await scan(make(), h, options({ minDetections: 0 }));
            assert.strictEqual(res.result, 'infected');
        });

        it('is request-free with good keys', done => {
            make().init([options()], (err, info) => {
                assert.ifError(err);
                assert.strictEqual(info, undefined);
                assert.strictEqual(fake.requests.length, 0);
                assert.strictEqual(logLines.length, 1);
                done();
            });
        });

        it('says nothing when no entry uses it', done => {
            make().init([], err => {
                assert.ifError(err);
                assert.strictEqual(logLines.length, 0);
                done();
            });
        });
    });
});
