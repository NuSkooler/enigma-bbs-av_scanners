/* jslint node: true */
'use strict';

//
//  Logging through ENiGMA½'s own logger, when there is one.
//
//  A mod under mods/ would normally reach it with '../../core/logger.js'. That
//  breaks when this checkout is symlinked into mods/, because Node resolves a
//  symlink to its realpath before resolving the requires inside it. So look
//  for a directory that really holds core/logger.js, the way sc_door does, and
//  require it from there: the same absolute path core uses, so the same
//  module instance.
//
//  oputil runs without the logger (its |log| is null), and so do the tests:
//  then nothing is logged. Nothing here may throw.
//

const path = require('path');
const fs = require('fs');
const { createRequire } = require('module');

let override = null;
let enigLogger; //  undefined: not looked for yet; null: not found

function findEnigmaLoggerModule() {
    const root = [
        path.resolve(__dirname, '..', '..', '..'), //  copied into mods/av_scanners/
        process.env.ENIGMA_ROOT,
        require.main && path.dirname(require.main.filename), //  main.js or oputil.js
        process.cwd(),
    ].find(dir => {
        try {
            return dir && fs.existsSync(path.join(dir, 'core', 'logger.js'));
        } catch (e) {
            return false;
        }
    });

    if (!root) {
        return null;
    }

    try {
        return createRequire(path.join(root, 'core', 'logger.js'))('./logger.js');
    } catch (e) {
        return null;
    }
}

function getLogger() {
    if (override) {
        return override;
    }
    if (undefined === enigLogger) {
        enigLogger = findEnigmaLoggerModule();
    }
    //  logger.log is only set once ENiGMA½ has initialized it
    return enigLogger ? enigLogger.log : null;
}

function log(level, obj, msg) {
    try {
        const logger = getLogger();
        if (logger && 'function' === typeof logger[level]) {
            logger[level](obj, msg);
        }
    } catch (e) {
        //  logging must never break a scan
    }
}

//  For tests: route log lines to |logger| ({ info, warn, ... }), or back to
//  ENiGMA½'s with null.
log.setLogger = logger => {
    override = logger || null;
};

module.exports = log;
