/* jslint node: true */
'use strict';

//
//  Against ENiGMA½'s own core/file_scanner.js, when there is a checkout at
//  $ENIGMA_BBS_DIR (or ../enigma-bbs next to this repository) with its
//  dependencies installed. Skipped otherwise.
//

const assert = require('assert');
const fs = require('fs');
const os = require('os');
const path = require('path');
const http = require('http');

const clamav = require('../lib/clamav.js');
const virustotal = require('../lib/virustotal.js');
const FakeClamd = require('./helpers/fake_clamd.js');

const ENIGMA_DIR =
    process.env.ENIGMA_BBS_DIR || path.resolve(__dirname, '..', '..', 'enigma-bbs');

function loadCore() {
    try {
        return {
            configModule: require(path.join(ENIGMA_DIR, 'core', 'config.js')),
            FileScanner: require(path.join(ENIGMA_DIR, 'core', 'file_scanner.js')),
        };
    } catch (e) {
        return null;
    }
}

describe("with ENiGMA½'s core file scanning", function () {
    this.timeout(30000);

    let core;
    let savedGet;
    let dir;
    let fakeClamd;
    let vt;

    before(async function () {
        core = loadCore();
        if (!core) {
            this.skip();
        }
        savedGet = core.configModule.get;
        dir = fs.mkdtempSync(path.join(os.tmpdir(), 'avs-core-'));

        fakeClamd = new FakeClamd(s =>
            'zPING' === s.command ? { reply: 'PONG' } : { reply: 'stream: OK' }
        );
        const where = await fakeClamd.listen();

        //  VirusTotal knows nothing
        vt = http.createServer((req, res) => {
            res.writeHead(404);
            res.end();
        });
        await new Promise(r => vt.listen(0, '127.0.0.1', r));

        core.configModule.get = () => ({
            fileBase: {
                scanning: {
                    enabled: true,
                    //  core's defaults: two scans at once, a long queue wait
                    scanners: [
                        {
                            scanner: 'clamav',
                            host: where.host,
                            port: where.port,
                            timeout: 60000,
                        },
                        {
                            scanner: 'virustotal',
                            apiKey: 'FAKEKEY-not-a-real-key',
                            onError: 'accept',
                            timeout: 30000,
                        },
                    ],
                },
            },
        });

        core.FileScanner.registerScanner('clamav', clamav.createClamAvScanner());
        core.FileScanner.registerScanner(
            'virustotal',
            virustotal.createVirusTotalScanner({
                testBaseUrl: `http://127.0.0.1:${vt.address().port}/api/v3`,
                windowMs: 6000, //  4 lookups per 6 s: a scaled-down minute
            })
        );
        core.FileScanner.markModRegistrationComplete();
    });

    after(async () => {
        if (!core) {
            return;
        }
        core.configModule.get = savedGet;
        await fakeClamd.close();
        await new Promise(r => vt.close(r));
        fs.rmSync(dir, { recursive: true, force: true });
    });

    it('a burst of distinct files does not starve the shared scan slots', async () => {
        //  Each VirusTotal lookup waiting for the rate limit would hold one of
        //  core's two scan slots, so ClamAV too would run at 4 files a window
        //  core logs each accepted failure to the console when it has no logger
        const consoleError = console.error; //  eslint-disable-line no-console
        console.error = () => {}; //  eslint-disable-line no-console
        const t0 = Date.now();
        const verdicts = await Promise.all(
            Array.from({ length: 12 }, (_, i) => {
                const f = path.join(dir, `u${i}.bin`);
                fs.writeFileSync(f, `distinct ${i}`);
                return new Promise(resolve =>
                    core.FileScanner.scanFile(f, { source: 'web' }, (err, v) =>
                        resolve({ err, v })
                    )
                );
            })
        );
        const elapsed = Date.now() - t0;
        console.error = consoleError; //  eslint-disable-line no-console

        verdicts.forEach(({ err, v }) => {
            assert.ifError(err);
            assert.strictEqual(v.result, 'clean');
            assert.strictEqual(v.results[0].scanner, 'clamav');
            assert.strictEqual(v.results[0].result, 'clean');
        });
        const vtResults = verdicts.map(({ v }) => v.results[1].result);
        assert.strictEqual(vtResults.filter(r => 'skipped' === r).length, 4);
        assert.strictEqual(vtResults.filter(r => 'error' === r).length, 8);
        //  before: 12 s (three windows); now no lookup waits for one
        assert.ok(elapsed < 3000, `took ${elapsed}ms`);
    });
});
