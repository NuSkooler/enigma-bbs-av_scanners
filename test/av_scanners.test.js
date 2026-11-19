/* jslint node: true */
'use strict';

const assert = require('assert');

describe('av_scanners mod entry', () => {
    it('has no side effects at require time', () => {
        const before = process.getActiveResourcesInfo().length;
        const mod = require('../av_scanners.js');
        assert.strictEqual(process.getActiveResourcesInfo().length, before);
        assert.strictEqual(typeof mod.moduleInfo, 'object');
        assert.strictEqual(typeof mod.moduleInitialize, 'undefined');
    });

    it('registers clamav and virustotal through registerFileScanners', done => {
        const registered = new Map();
        const registry = {
            registerScanner: (name, impl) => registered.set(name, impl),
            ScanResults: {
                Clean: 'clean',
                Infected: 'infected',
                Error: 'error',
                Skipped: 'skipped',
            },
        };
        const mod = require('../av_scanners.js');
        assert.strictEqual(mod.registerFileScanners.length, 2);
        mod.registerFileScanners(registry, err => {
            assert.ifError(err);
            assert.deepStrictEqual([...registered.keys()].sort(), [
                'clamav',
                'virustotal',
            ]);
            registered.forEach(impl => {
                assert.strictEqual(typeof impl.scan, 'function');
                assert.strictEqual(typeof impl.init, 'function');
                assert.strictEqual(impl.init.length, 2);
            });
            done();
        });
    });
});
