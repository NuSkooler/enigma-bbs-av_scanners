/* jslint node: true */
'use strict';

const assert = require('assert');
const fs = require('fs');
const os = require('os');
const path = require('path');
const crypto = require('crypto');
const net = require('net');
const { execFile } = require('child_process');

const clamd = require('../lib/clamd.js');
const clamav = require('../lib/clamav.js');
const log = require('../lib/log.js');
const FakeClamd = require('./helpers/fake_clamd.js');

function tempDir() {
    //  Unix socket paths are limited to ~104-108 bytes
    let base = os.tmpdir();
    if (base.length > 60) {
        base = '/tmp';
    }
    return fs.mkdtempSync(path.join(base, 'avs-'));
}

function sha256File(p) {
    return crypto.createHash('sha256').update(fs.readFileSync(p)).digest('hex');
}

function scanWith(options, filePath, ctxExtra = {}) {
    const scanner = clamav.createClamAvScanner();
    return new Promise(resolve => {
        let calls = 0;
        scanner.scan(filePath, Object.assign({ options }, ctxExtra), (err, res) => {
            ++calls;
            assert.strictEqual(calls, 1, 'scan() called back more than once');
            assert.ifError(err);
            //  give a second callback a chance to show up
            setTimeout(() => resolve(res), 20);
        });
    });
}

function freePort() {
    return new Promise(resolve => {
        const s = net.createServer();
        s.listen(0, '127.0.0.1', () => {
            const port = s.address().port;
            s.close(() => resolve(port));
        });
    });
}

describe('clamd protocol helpers', () => {
    it('frames chunk lengths as 4-byte big-endian', () => {
        assert.deepStrictEqual([...clamd.chunkHeader(0x01020304)], [1, 2, 3, 4]);
        assert.deepStrictEqual([...clamd.chunkHeader(0)], [0, 0, 0, 0]);
    });

    it('NUL-terminates commands', () => {
        const b = clamd.nulTerminated('zPING');
        assert.strictEqual(b.length, 6);
        assert.strictEqual(b[5], 0);
        assert.strictEqual(b.subarray(0, 5).toString(), 'zPING');
    });

    it('maps replies strictly; nothing unrecognised is clean', () => {
        assert.deepStrictEqual(clamd.parseScanReply('stream: OK'), { result: 'clean' });
        assert.deepStrictEqual(
            clamd.parseScanReply('stream: Eicar-Test-Signature FOUND'),
            {
                result: 'infected',
                signature: 'Eicar-Test-Signature',
            }
        );
        assert.strictEqual(
            clamd.parseScanReply('INSTREAM size limit exceeded. ERROR').result,
            'error'
        );
        [
            'stream: OK but not really',
            'OK',
            'stream: ok',
            'UNKNOWN COMMAND',
            'COMMAND READ TIMED OUT',
            '',
            'PONG',
            'stream: FOUND',
        ].forEach(reply =>
            assert.strictEqual(clamd.parseScanReply(reply).result, 'error', reply)
        );
    });
});

describe('clamd reply hardening', () => {
    it('does not treat non-ASCII whitespace as padding', () => {
        assert.strictEqual(clamd.parseScanReply('stream: OK\u00a0').result, 'error');
        assert.strictEqual(clamd.parseScanReply('\u00a0stream: OK').result, 'error');
        assert.strictEqual(clamd.parseScanReply('stream: OK\r\n').result, 'clean');
    });

    it('does not take "stream: OK" sent before the whole file was', async function () {
        this.timeout(20000);
        const dir = tempDir();
        const big = path.join(dir, 'big.bin');
        fs.closeSync(fs.openSync(big, 'w'));
        fs.truncateSync(big, 64 * 1024 * 1024); //  sparse
        //  answers OK at once, then stops reading: the client never gets to
        //  the end of the file
        const conns = new Set();
        const server = net.createServer(s => {
            conns.add(s);
            s.on('error', () => {});
            s.once('data', () => {
                s.write('stream: OK\0');
                s.pause();
            });
        });
        await new Promise(r => server.listen(path.join(dir, 'early.sock'), r));
        try {
            const res = await scanWith({ socket: path.join(dir, 'early.sock') }, big, {
                timeout: 5000,
            });
            assert.strictEqual(res.result, 'error');
            assert.match(res.detail, /answered OK before the whole file was sent/);
        } finally {
            conns.forEach(c => c.destroy());
            await new Promise(r => server.close(r));
            fs.rmSync(dir, { recursive: true, force: true });
        }
    });
});

describe('clamav target resolution', () => {
    it('uses an explicit socket', () => {
        assert.deepStrictEqual(clamav.resolveTarget({ socket: '/x/clamd.sock' }), {
            target: { path: '/x/clamd.sock' },
        });
    });

    it('uses TCP with defaults for whichever of host/port is missing', () => {
        assert.deepStrictEqual(clamav.resolveTarget({ port: 3311 }).target, {
            host: '127.0.0.1',
            port: 3311,
        });
        assert.deepStrictEqual(clamav.resolveTarget({ host: 'clamd.lan' }).target, {
            host: 'clamd.lan',
            port: 3310,
        });
    });

    it('refuses socket together with host/port, and a bad port', () => {
        assert.ok(clamav.resolveTarget({ socket: '/x', port: 3310 }).error);
        assert.ok(clamav.resolveTarget({ port: 70000 }).error);
        assert.ok(clamav.resolveTarget({ port: 'abc' }).error);
    });

    it('on Windows, needs host/port: TCP is never assumed', () => {
        const r = clamav.resolveTarget({}, { platform: 'win32', isSocket: () => true });
        assert.strictEqual(r.target, undefined);
        assert.match(r.error, /on Windows, set "host" and "port"/);
    });

    it('elsewhere, takes the first trusted default socket, else is an error', () => {
        const r = clamav.resolveTarget(
            {},
            {
                platform: 'linux',
                isSocket: p => p === '/run/clamd.scan/clamd.sock',
            }
        );
        assert.deepStrictEqual(r.target, { path: '/run/clamd.scan/clamd.sock' });

        const none = clamav.resolveTarget(
            {},
            { platform: 'freebsd', isSocket: () => false }
        );
        assert.strictEqual(none.target, undefined);
        assert.match(none.error, /No clamd socket found at .*; set "socket"/);
    });
});

describe('clamav: no implicit TCP fallback (squatting 127.0.0.1:3310)', () => {
    let dir;
    let file;

    before(() => {
        dir = tempDir();
        file = path.join(dir, 'f.bin');
        fs.writeFileSync(file, 'hello');
    });

    after(() => fs.rmSync(dir, { recursive: true, force: true }));

    it('does not connect to a listener on 3310 when no socket is found', async function () {
        //  what any local user could do while clamd is absent or restarting
        const connections = [];
        const squat = net.createServer(s => {
            connections.push(s);
            s.on('error', () => {});
            s.on('data', d => {
                if (d.includes(Buffer.from([0, 0, 0, 0]))) {
                    s.end('stream: OK\0');
                }
            });
        });
        const listening = await new Promise(resolve => {
            squat.once('error', () => resolve(false));
            squat.listen(clamav.DEFAULT_PORT, '127.0.0.1', () => resolve(true));
        });
        if (!listening) {
            this.skip(); //  3310 is taken (a real clamd on TCP?)
        }
        try {
            const scanner = clamav.createClamAvScanner({
                socketPaths: [path.join(dir, 'not-here.ctl')],
            });
            const res = await new Promise(resolve =>
                scanner.scan(file, { options: {}, timeout: 2000 }, (err, r) => resolve(r))
            );
            assert.strictEqual(res.result, 'error');
            assert.match(res.detail, /No clamd socket found/);
            await new Promise(r => setTimeout(r, 50));
            assert.strictEqual(connections.length, 0, 'connected to the squatter');
        } finally {
            await new Promise(r => squat.close(r));
        }
    });

    it('on Windows, with no host/port, scans are errors without connecting', async () => {
        const scanner = clamav.createClamAvScanner({ platform: 'win32' });
        const res = await new Promise(resolve =>
            scanner.scan(file, { options: {}, timeout: 2000 }, (err, r) => resolve(r))
        );
        assert.strictEqual(res.result, 'error');
        assert.match(res.detail, /on Windows/);
    });

    it('init says so, clearly, when no clamd is configured or found', done => {
        clamav
            .createClamAvScanner({ socketPaths: [path.join(dir, 'none.ctl')] })
            .init([{ scanner: 'clamav' }, { scanner: 'clamav' }], err => {
                assert.ok(err);
                assert.match(err.message, /^clamav: No clamd socket found at /);
                //  once, not once per entry
                assert.strictEqual(err.message.split('No clamd socket').length, 2);
                done();
            });
    });
});

describe('clamav: which guessed sockets are trusted', () => {
    let dir;
    let server;

    beforeEach(async () => {
        dir = tempDir(); //  0700, ours
        server = net.createServer(s => s.destroy());
        await new Promise(r => server.listen(path.join(dir, 'clamd.sock'), r));
    });

    afterEach(async () => {
        await new Promise(r => server.close(r));
        fs.chmodSync(dir, 0o700);
        fs.rmSync(dir, { recursive: true, force: true });
    });

    it('trusts a socket in a directory only its owner can write to', () => {
        assert.strictEqual(clamav.isTrustedSocket(path.join(dir, 'clamd.sock')), true);
    });

    it('does not trust one in a group- or world-writable directory', () => {
        const sock = path.join(dir, 'clamd.sock');
        fs.chmodSync(dir, 0o777);
        assert.strictEqual(clamav.isTrustedSocket(sock), false);
        fs.chmodSync(dir, 0o770);
        assert.strictEqual(clamav.isTrustedSocket(sock), false);
    });

    it('does not trust a symlink placed in a writable directory', () => {
        const open = path.join(dir, 'open');
        fs.mkdirSync(open, 0o777);
        fs.chmodSync(open, 0o777);
        const link = path.join(open, 'clamd.ctl');
        fs.symlinkSync(path.join(dir, 'clamd.sock'), link);
        assert.strictEqual(clamav.isTrustedSocket(link), false);
    });

    it('does not trust a missing path or a plain file', () => {
        assert.strictEqual(clamav.isTrustedSocket(path.join(dir, 'missing')), false);
        fs.writeFileSync(path.join(dir, 'plain'), '');
        assert.strictEqual(clamav.isTrustedSocket(path.join(dir, 'plain')), false);
    });

    it('finds a real default socket through the trust check', () => {
        const sock = path.join(dir, 'clamd.sock');
        const r = clamav.resolveTarget({}, { socketPaths: ['/nonexistent/x', sock] });
        assert.deepStrictEqual(r.target, { path: sock });
    });
});

['unix', 'tcp'].forEach(transport => {
    describe(`clamav scanner over ${transport}`, () => {
        let dir;
        let fake;
        let where;
        let small;
        let empty;

        const start = async (behaviour, options) => {
            fake = new FakeClamd(behaviour, options);
            where = await fake.listen(
                'unix' === transport ? { path: path.join(dir, 'c.sock') } : null
            );
            return 'unix' === transport ? { socket: where.path } : where;
        };

        before(() => {
            dir = tempDir();
            small = path.join(dir, 'small.bin');
            fs.writeFileSync(small, crypto.randomBytes(200 * 1024 + 17));
            empty = path.join(dir, 'empty.bin');
            fs.writeFileSync(empty, '');
        });

        afterEach(async () => {
            if (fake) {
                await fake.close();
                fake = null;
            }
        });

        after(() => fs.rmSync(dir, { recursive: true, force: true }));

        it('streams the file with correct framing and maps OK to clean', async () => {
            const opts = await start(() => ({ reply: 'stream: OK' }));
            const res = await scanWith(opts, small);
            assert.deepStrictEqual(res, { result: 'clean' });

            const s = fake.sessions[0];
            assert.strictEqual(s.command, 'zINSTREAM');
            assert.strictEqual(s.terminated, true);
            assert.strictEqual(s.protocolError, null);
            assert.strictEqual(s.totalBytes, fs.statSync(small).size);
            assert.strictEqual(s.sha256, sha256File(small));
            assert.ok(Math.max(...s.chunkSizes) <= clamd.DEFAULT_CHUNK_SIZE);
        });

        it('sends a properly framed empty stream for an empty file', async () => {
            const opts = await start(() => ({ reply: 'stream: OK' }));
            const res = await scanWith(opts, empty);
            assert.strictEqual(res.result, 'clean');
            assert.strictEqual(fake.sessions[0].command, 'zINSTREAM');
            assert.strictEqual(fake.sessions[0].terminated, true);
            assert.strictEqual(fake.sessions[0].totalBytes, 0);
        });

        it('maps FOUND to infected with the signature', async () => {
            const opts = await start(() => ({
                reply: 'stream: Win.Test.EICAR_HDB-1 FOUND',
            }));
            const res = await scanWith(opts, small);
            assert.deepStrictEqual(res, {
                result: 'infected',
                signature: 'Win.Test.EICAR_HDB-1',
            });
        });

        it('maps "INSTREAM size limit exceeded" (sent mid-stream) to error', async () => {
            const opts = await start(null, { sizeLimit: 64 * 1024 });
            const res = await scanWith(opts, small);
            assert.strictEqual(res.result, 'error');
            //  usually the reply; a write racing clamd's close is an error too
            assert.match(res.detail, /size limit exceeded|Connection/);
        });

        it('maps an ERROR reply to error', async () => {
            const opts = await start(() => ({ reply: "Can't allocate memory ERROR" }));
            const res = await scanWith(opts, small);
            assert.strictEqual(res.result, 'error');
            assert.match(res.detail, /allocate memory ERROR/);
        });

        it('maps garbage to error', async () => {
            const opts = await start(() => ({ reply: 'UNKNOWN COMMAND' }));
            const res = await scanWith(opts, small);
            assert.strictEqual(res.result, 'error');
            assert.match(res.detail, /Unexpected reply/);
        });

        it('maps a close without a reply to error', async () => {
            const opts = await start(() => ({ close: true }));
            const res = await scanWith(opts, small);
            assert.strictEqual(res.result, 'error');
        });

        it('maps a reply with no NUL terminator to error', async () => {
            const opts = await start(() => ({ reply: Buffer.from('stream: OK') }));
            const res = await scanWith(opts, small);
            assert.strictEqual(res.result, 'error');
        });

        it('bounds the reply size', async () => {
            const opts = await start(() => ({
                reply: Buffer.alloc(clamd.MAX_REPLY_BYTES + 100, 0x41),
            }));
            const res = await scanWith(opts, small);
            assert.strictEqual(res.result, 'error');
            assert.match(res.detail, /Reply longer/);
        });

        it('stops on abortSignal, closing the connection, with one callback', async () => {
            const opts = await start(() => ({ hang: true }));
            const ac = new AbortController();
            setTimeout(() => ac.abort(), 100);
            const t0 = Date.now();
            const res = await scanWith(opts, small, { abortSignal: ac.signal });
            assert.strictEqual(res.result, 'error');
            assert.match(res.detail, /Aborted/);
            assert.ok(Date.now() - t0 < 2000);
            await new Promise(r => setTimeout(r, 50));
            assert.strictEqual(fake.sessions[0].clientClosed, true);
        });

        it('times out on ctx.timeout when there is no abortSignal', async () => {
            const opts = await start(() => ({ hang: true }));
            const res = await scanWith(opts, small, { timeout: 150 });
            assert.strictEqual(res.result, 'error');
            assert.match(res.detail, /No reply within 150ms/);
        });

        it('checks the bytes sent against ctx.sha256 (any case), and passes', async () => {
            const opts = await start(() => ({ reply: 'stream: OK' }));
            const res = await scanWith(opts, small, {
                sha256: sha256File(small).toUpperCase(),
            });
            assert.deepStrictEqual(res, { result: 'clean' });
            assert.strictEqual(fake.sessions[0].terminated, true);
        });

        it('is an error, with the stream left unfinished, when the file changed after hashing', async () => {
            const opts = await start(() => ({ reply: 'stream: OK' }));
            //  what core hashed is not what is on disk by the time clamd reads
            const res = await scanWith(opts, small, { sha256: sha256File(empty) });
            assert.strictEqual(res.result, 'error');
            assert.match(res.detail, /file changed while it was being scanned/);
            await new Promise(r => setTimeout(r, 50));
            assert.strictEqual(fake.sessions[0].terminated, false);
        });

        it('is an error when the file cannot be read', async () => {
            const opts = await start(() => ({ reply: 'stream: OK' }));
            const res = await scanWith(opts, path.join(dir, 'missing.bin'));
            assert.strictEqual(res.result, 'error');
            assert.match(res.detail, /Cannot read the file \(ENOENT\)/);
        });
    });
});

describe('clamav scanner: connection failures', () => {
    it('maps a refused TCP connection to error', async () => {
        const port = await freePort();
        const res = await scanWith({ host: '127.0.0.1', port }, __filename);
        assert.strictEqual(res.result, 'error');
        assert.match(res.detail, /ECONNREFUSED/);
        assert.match(res.detail, new RegExp(`127\\.0\\.0\\.1:${port}`));
    });

    it('maps a missing Unix socket to error', async () => {
        const res = await scanWith({ socket: '/nonexistent/clamd.sock' }, __filename);
        assert.strictEqual(res.result, 'error');
        assert.match(res.detail, /ENOENT/);
    });

    it('maps a config conflict to error without connecting', async () => {
        const res = await scanWith({ socket: '/x', host: '127.0.0.1' }, __filename);
        assert.strictEqual(res.result, 'error');
        assert.match(res.detail, /not both/);
    });
});

describe('clamav scanner: large files', function () {
    this.timeout(30000);

    let dir;
    let big;
    let fake;
    const BIG_SIZE = 64 * 1024 * 1024;

    before(() => {
        dir = tempDir();
        big = path.join(dir, 'big.bin');
        //  sparse: cheap to create, still 64 MiB to read
        fs.closeSync(fs.openSync(big, 'w'));
        fs.truncateSync(big, BIG_SIZE);
    });

    afterEach(async () => {
        if (fake) {
            await fake.close();
            fake = null;
        }
    });

    after(() => fs.rmSync(dir, { recursive: true, force: true }));

    it('streams in chunks no larger than chunkSize', async () => {
        fake = new FakeClamd(() => ({ reply: 'stream: OK' }));
        const where = await fake.listen({ path: path.join(dir, 'c.sock') });
        const chunkSize = 256 * 1024;
        const res = await scanWith({ socket: where.path, chunkSize }, big);
        assert.strictEqual(res.result, 'clean');
        const s = fake.sessions[0];
        assert.strictEqual(s.totalBytes, BIG_SIZE);
        assert.ok(Math.max(...s.chunkSizes) <= chunkSize, 'a chunk exceeded chunkSize');
        assert.ok(s.chunkSizes.length >= BIG_SIZE / chunkSize);
    });

    it('stops reading the file while clamd is not reading (backpressure)', async () => {
        fake = new FakeClamd(() => ({ reply: 'stream: OK' }), { pauseMs: 600 });
        const where = await fake.listen({ path: path.join(dir, 'p.sock') });

        //  watch how far the client has read the file while clamd is paused
        const realCreateReadStream = fs.createReadStream;
        let stream = null;
        fs.createReadStream = (...args) => {
            stream = realCreateReadStream.apply(fs, args);
            return stream;
        };

        let readWhilePaused;
        try {
            const scanning = scanWith({ socket: where.path }, big);
            await new Promise(r => setTimeout(r, 400));
            readWhilePaused = stream.bytesRead;
            const res = await scanning;
            assert.strictEqual(res.result, 'clean');
        } finally {
            fs.createReadStream = realCreateReadStream;
        }

        assert.strictEqual(fake.sessions[0].resumed, true);
        assert.strictEqual(fake.sessions[0].totalBytes, BIG_SIZE);
        //  without backpressure the whole 64 MiB is read into the socket's
        //  write queue in well under 400ms; with it, only what the kernel
        //  buffers hold plus a chunk or so
        assert.ok(
            readWhilePaused < 16 * 1024 * 1024,
            `read ${readWhilePaused} bytes while clamd was not reading`
        );
    });
});

describe('clamav init', () => {
    let dir;
    let fake;
    let lines;

    before(() => {
        dir = tempDir();
    });

    beforeEach(() => {
        lines = [];
        log.setLogger({
            info: (obj, msg) => lines.push({ level: 'info', obj, msg }),
            warn: (obj, msg) => lines.push({ level: 'warn', obj, msg }),
        });
    });

    afterEach(async () => {
        log.setLogger(null);
        if (fake) {
            await fake.close();
            fake = null;
        }
    });

    after(() => fs.rmSync(dir, { recursive: true, force: true }));

    it('PINGs each configured clamd once and logs the version', done => {
        fake = new FakeClamd(s => {
            if ('zPING' === s.command) {
                return { reply: 'PONG' };
            }
            if ('zVERSION' === s.command) {
                return { reply: 'ClamAV 1.5.4/27000/Tue Nov 18 2026' };
            }
            return { close: true };
        });
        fake.listen({ path: path.join(dir, 'i.sock') }).then(where => {
            const scanner = clamav.createClamAvScanner();
            scanner.init(
                [
                    { scanner: 'clamav', socket: where.path },
                    { scanner: 'clamav', socket: where.path },
                ],
                err => {
                    assert.ifError(err);
                    const pings = fake.sessions.filter(s => 'zPING' === s.command);
                    assert.strictEqual(pings.length, 1);
                    assert.strictEqual(lines.length, 1);
                    assert.strictEqual(lines[0].msg, 'clamd answered PING');
                    assert.strictEqual(lines[0].obj.clamd, where.path);
                    assert.strictEqual(
                        lines[0].obj.version,
                        'ClamAV 1.5.4/27000/Tue Nov 18 2026'
                    );
                    done();
                }
            );
        });
    });

    it('copes with VERSION being disabled', done => {
        fake = new FakeClamd(s =>
            'zPING' === s.command ? { reply: 'PONG' } : { reply: 'COMMAND UNAVAILABLE' }
        );
        fake.listen({ path: path.join(dir, 'v.sock') }).then(where => {
            clamav.createClamAvScanner().init([{ socket: where.path }], err => {
                assert.ifError(err);
                assert.strictEqual(lines[0].obj.version, undefined);
                done();
            });
        });
    });

    it('a hung clamd does not keep the process alive (oputil)', async function () {
        this.timeout(10000);
        //  accepts and never answers
        const conns = new Set();
        const hung = net.createServer(s => {
            conns.add(s);
            s.on('error', () => {});
        });
        await new Promise(r => hung.listen(path.join(dir, 'hung.sock'), r));
        const script = [
            `const c = require(${JSON.stringify(path.join(__dirname, '..', 'lib', 'clamav.js'))});`,
            `c.createClamAvScanner().init([{ socket: ${JSON.stringify(
                path.join(dir, 'hung.sock')
            )} }], () => process.stdout.write('called back'));`,
        ].join('\n');
        const t0 = Date.now();
        try {
            const out = await new Promise((resolve, reject) =>
                execFile(
                    process.execPath,
                    ['-e', script],
                    { timeout: 8000 },
                    (err, so) => (err ? reject(err) : resolve(so))
                )
            );
            //  exits at once rather than after the 5 s PING timeout
            assert.ok(Date.now() - t0 < 4000, `took ${Date.now() - t0}ms`);
            assert.strictEqual(out, '');
        } finally {
            conns.forEach(c => c.destroy());
            await new Promise(r => hung.close(r));
        }
    });

    it('reports (does not throw) an unreachable clamd', async () => {
        const port = await freePort();
        const err = await new Promise(resolve =>
            clamav.createClamAvScanner({ initTimeoutMs: 1000 }).init(
                [
                    { host: '127.0.0.1', port },
                    { socket: '/x', port: 1 },
                ],
                resolve
            )
        );
        assert.ok(err);
        assert.match(
            err.message,
            /did not answer PING \(Connection failed \(ECONNREFUSED\)\)/
        );
        assert.match(err.message, /not both/);
    });
});
