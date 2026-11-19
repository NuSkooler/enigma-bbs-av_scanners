/* jslint node: true */
'use strict';

//
//  Against a real clamd, when there is one at the Debian/Ubuntu socket (or
//  CLAMD_SOCKET). Skipped otherwise.
//

const assert = require('assert');
const fs = require('fs');
const os = require('os');
const path = require('path');

const clamav = require('../lib/clamav.js');
const { eicar, storedZip, EICAR_SHA256 } = require('./helpers/eicar.js');

const SOCKET = process.env.CLAMD_SOCKET || '/var/run/clamav/clamd.ctl';

//  the owner's sample files, when present: copied, never touched in place
const SAMPLE_DIR = '/mnt/nu64_incoming/temp/up_test';

function haveClamd() {
    try {
        return fs.statSync(SOCKET).isSocket();
    } catch (e) {
        return false;
    }
}

//  StreamMaxLength from the Debian/Ubuntu clamd.conf, in bytes, if readable
function streamMaxLength() {
    let conf;
    try {
        conf = fs.readFileSync('/etc/clamav/clamd.conf', 'utf8');
    } catch (e) {
        return null;
    }
    const m = /^StreamMaxLength\s+(\d+)([kKmM]?)\s*$/m.exec(conf);
    if (!m) {
        return 100 * 1024 * 1024; //  clamd's default
    }
    const unit = { k: 1024, m: 1024 * 1024 }[m[2].toLowerCase()] || 1;
    return Number(m[1]) * unit;
}

function scan(filePath, ctxExtra = {}) {
    return new Promise((resolve, reject) => {
        const ac = new AbortController();
        const timer = setTimeout(() => ac.abort(), 30000);
        clamav.createClamAvScanner().scan(
            filePath,
            Object.assign(
                {
                    options: { socket: SOCKET },
                    abortSignal: ac.signal,
                    timeout: 30000,
                },
                ctxExtra
            ),
            (err, res) => {
                clearTimeout(timer);
                return err ? reject(err) : resolve(res);
            }
        );
    });
}

describe('clamav against a real clamd', function () {
    this.timeout(60000);

    let dir;

    before(function () {
        if (!haveClamd()) {
            this.skip();
        }
        //  0700, as ENiGMA½'s upload temp dirs are: clamd (another user)
        //  could not open these by path, so this also proves INSTREAM
        dir = fs.mkdtempSync(path.join(os.tmpdir(), 'avs-live-'));
        fs.chmodSync(dir, 0o700);

        const e = eicar();
        const zip = storedZip([{ name: 'eicar.com', data: e }]);
        fs.writeFileSync(path.join(dir, 'eicar.com'), e);
        fs.writeFileSync(path.join(dir, 'eicar.zip'), zip);
        fs.writeFileSync(
            path.join(dir, 'eicar2.zip'),
            storedZip([{ name: 'eicar.zip', data: zip }])
        );
        fs.writeFileSync(path.join(dir, 'safe.txt'), 'Nothing to see here.\r\n');
        fs.writeFileSync(path.join(dir, 'empty.bin'), '');
    });

    after(() => {
        if (dir) {
            fs.rmSync(dir, { recursive: true, force: true });
        }
    });

    ['eicar.com', 'eicar.zip', 'eicar2.zip'].forEach(name => {
        it(`finds EICAR in ${name}`, async () => {
            const res = await scan(path.join(dir, name));
            assert.strictEqual(res.result, 'infected', JSON.stringify(res));
            assert.match(res.signature, /Eicar/i);
        });
    });

    it("finds EICAR with core's SHA-256 of the file passed along", async () => {
        const res = await scan(path.join(dir, 'eicar.com'), { sha256: EICAR_SHA256 });
        assert.strictEqual(res.result, 'infected', JSON.stringify(res));
    });

    it('auto-detects the socket when none is configured', async function () {
        if (SOCKET !== clamav.DEFAULT_SOCKET_PATHS[0]) {
            this.skip();
        }
        const res = await new Promise(resolve =>
            clamav
                .createClamAvScanner()
                .scan(
                    path.join(dir, 'eicar.com'),
                    { options: {}, timeout: 30000 },
                    (e, r) => resolve(r)
                )
        );
        assert.strictEqual(res.result, 'infected', JSON.stringify(res));
    });

    it('passes a clean text file', async () => {
        assert.deepStrictEqual(await scan(path.join(dir, 'safe.txt')), {
            result: 'clean',
        });
    });

    it('passes an empty file', async () => {
        assert.deepStrictEqual(await scan(path.join(dir, 'empty.bin')), {
            result: 'clean',
        });
    });

    it('is an error, not clean, past StreamMaxLength', async function () {
        const limit = streamMaxLength();
        if (!limit || limit > 512 * 1024 * 1024) {
            this.skip();
        }
        const big = path.join(dir, 'too-big.bin');
        fs.closeSync(fs.openSync(big, 'w'));
        fs.truncateSync(big, limit + 1024 * 1024); //  sparse
        const res = await scan(big);
        assert.strictEqual(res.result, 'error', JSON.stringify(res));
        fs.unlinkSync(big);
    });

    describe('the sample files', () => {
        const expected = {
            'eicar.com': 'infected',
            'eicar.zip': 'infected',
            'eicar2.zip': 'infected',
            'safe.txt': 'clean',
        };

        Object.keys(expected).forEach(name => {
            it(`${name} is ${expected[name]}`, async function () {
                const src = path.join(SAMPLE_DIR, name);
                if (!fs.existsSync(src)) {
                    this.skip();
                }
                const copy = path.join(dir, `sample-${name}`);
                fs.copyFileSync(src, copy);
                const res = await scan(copy);
                assert.strictEqual(res.result, expected[name], JSON.stringify(res));
            });
        });
    });
});
