/* jslint node: true */
'use strict';

//
//  Logging through ENiGMA½'s own logger, when there is one.
//
//  A mod under mods/ would normally reach it with '../../core/logger.js'. That
//  breaks when this checkout is symlinked into mods/, because Node resolves a
//  symlink to its realpath before resolving the requires inside it -- and a
//  path guessed from there can name some other directory's core/logger.js.
//
//  So nothing is ever require()d from a guessed path. The logger used is the
//  core/logger.js module the running ENiGMA½ has already loaded: one in
//  require.cache whose sibling core/config.js is loaded too, preferring the
//  one next to require.main (main.js or oputil.js). That is the same module
//  instance core logs through.
//
//  oputil runs without the logger (its |log| is null), and so do the tests:
//  then warnings and errors go to the console, as core's own do, and
//  anything else is dropped. Nothing here may throw.
//

const path = require('path');

let override = null;
let enigLogger = null; //  the module, once found

function findEnigmaLoggerModule() {
    const suffix = path.join(path.sep, 'core', 'logger.js');
    const candidates = Object.keys(require.cache).filter(
        file =>
            file.endsWith(suffix) &&
            require.cache[path.join(path.dirname(file), 'config.js')]
    );
    if (0 === candidates.length) {
        return null;
    }

    const mainCore =
        require.main && require.main.filename
            ? path.join(path.dirname(require.main.filename), 'core', 'logger.js')
            : null;
    const file = candidates.includes(mainCore) ? mainCore : candidates[0];
    const mod = require.cache[file];
    return mod && mod.exports ? mod.exports : null;
}

function getLogger() {
    if (override) {
        return override;
    }
    //  looked for until found: it may be loaded after this module is
    if (!enigLogger) {
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
        } else if (!logger && ('warn' === level || 'error' === level)) {
            console.error(`${msg}: ${JSON.stringify(obj)}`); //  eslint-disable-line no-console
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
