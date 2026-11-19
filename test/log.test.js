/* jslint node: true */
'use strict';

//
//  lib/log.js must log through the core/logger.js the running ENiGMA½ has
//  loaded, and never load one from a path guessed relative to a symlinked
//  checkout. Each case runs a small fake ENiGMA½ in a child process, since
//  require.main and require.cache are what is being tested.
//

const assert = require('assert');
const fs = require('fs');
const os = require('os');
const path = require('path');
const { execFileSync } = require('child_process');

const LOG_JS = path.join(__dirname, '..', 'lib', 'log.js');

//
//  <root>/a/core/logger.js            planted, outside ENiGMA½
//  <root>/a/b/checkout/lib/log.js     this mod's checkout
//  <root>/enigma/core/{logger,config}.js
//  <root>/enigma/mods/av_scanners  -> ../../a/b/checkout
//
//  From the checkout's real path, '../../..' is <root>/a, so the old
//  lookup found the planted file first.
//
function buildTree(root, mainBody) {
    const w = (rel, text) => {
        const p = path.join(root, rel);
        fs.mkdirSync(path.dirname(p), { recursive: true });
        fs.writeFileSync(p, text);
    };
    w('a/core/logger.js', "process.stdout.write('PLANTED;'); exports.log = null;\n");
    w('a/core/config.js', "process.stdout.write('PLANTED-CONFIG;');\n");
    fs.mkdirSync(path.join(root, 'a/b/checkout/lib'), { recursive: true });
    fs.copyFileSync(LOG_JS, path.join(root, 'a/b/checkout/lib/log.js'));
    w(
        'enigma/core/logger.js',
        'exports.log = { info: (o, m) => process.stdout.write(`real:${m};`) };\n'
    );
    w('enigma/core/config.js', 'exports.get = () => ({});\n');
    fs.mkdirSync(path.join(root, 'enigma/mods'), { recursive: true });
    fs.symlinkSync('../../a/b/checkout', path.join(root, 'enigma/mods/av_scanners'));
    w('enigma/main.js', mainBody);
    return path.join(root, 'enigma', 'main.js');
}

function run(main) {
    return execFileSync(process.execPath, [main], {
        cwd: path.dirname(main),
        encoding: 'utf8',
        timeout: 10000,
    });
}

describe('log.js finds the logger', () => {
    let root;

    beforeEach(() => {
        root = fs.mkdtempSync(path.join(os.tmpdir(), 'avs-log-'));
    });

    afterEach(() => fs.rmSync(root, { recursive: true, force: true }));

    it("uses the running ENiGMA½'s logger, never a planted core/logger.js", () => {
        const main = buildTree(
            root,
            [
                "require('./core/config.js');",
                "require('./core/logger.js');",
                "require('./mods/av_scanners/lib/log.js')('info', {}, 'hello');",
            ].join('\n')
        );
        assert.strictEqual(run(main), 'real:hello;');
    });

    it('loads nothing when ENiGMA½ has not loaded its logger', () => {
        const main = buildTree(
            root,
            "require('./mods/av_scanners/lib/log.js')('info', {}, 'hello');\n"
        );
        assert.strictEqual(run(main), '');
    });

    it('ignores a loaded logger.js with no config.js beside it', () => {
        const main = buildTree(
            root,
            [
                //  some unrelated package's core/logger.js
                "require('../a/core/logger.js');",
                "require('./mods/av_scanners/lib/log.js')('info', {}, 'hello');",
            ].join('\n')
        );
        assert.strictEqual(run(main), 'PLANTED;');
    });

    it('sends warnings to the console when there is no logger', () => {
        const main = buildTree(
            root,
            [
                'console.error = m => process.stdout.write(`console:${m};`);',
                "require('./mods/av_scanners/lib/log.js')('warn', { a: 1 }, 'careful');",
                "require('./mods/av_scanners/lib/log.js')('info', {}, 'dropped');",
            ].join('\n')
        );
        assert.strictEqual(run(main), 'console:careful: {"a":1};');
    });
});
