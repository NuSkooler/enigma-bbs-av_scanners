/* jslint node: true */
'use strict';

//
//  The |clamav| file scanner: streams each file to clamd with zINSTREAM.
//
//  Entry options (beside core's scanner, sources, timeout, onError, ...):
//
//    socket      Path to clamd's Unix socket (LocalSocket in clamd.conf)
//    host, port  clamd over TCP (TCPAddr/TCPSocket). Either may be given
//                alone: host defaults to 127.0.0.1, port to 3310
//    chunkSize   Bytes per INSTREAM chunk, 1 KiB - 8 MiB (default 64 KiB)
//
//  socket and host/port are exclusive. With neither, the first of
//  DEFAULT_SOCKET_PATHS that is a socket in a directory only its owner can
//  write to. TCP is never assumed: any local user can listen on a free
//  127.0.0.1:3310 and answer "stream: OK", so TCP is used only when host or
//  port is set. On Windows, where clamd has no Unix socket, they must be.
//

const fs = require('fs');
const path = require('path');
const clamd = require('./clamd.js');
const log = require('./log.js');

const SCANNER_NAME = 'clamav';

const DEFAULT_HOST = '127.0.0.1';
const DEFAULT_PORT = 3310;

//  Tried in this order when neither socket nor host/port is set (not on
//  Windows, where clamd has no Unix socket).
const DEFAULT_SOCKET_PATHS = [
    '/var/run/clamav/clamd.ctl', //  Debian, Ubuntu
    '/run/clamav/clamd.ctl', //  Arch; Debian/Ubuntu via /run
    '/run/clamd.scan/clamd.sock', //  Fedora, RHEL (clamd@scan)
    '/var/run/clamav/clamd.sock', //  FreeBSD
    '/opt/homebrew/var/run/clamav/clamd.sock', //  Homebrew, Apple silicon
    '/usr/local/var/run/clamav/clamd.sock', //  Homebrew, Intel
];

//  The startup health check's own limit; scans use the entry's timeout.
const INIT_TIMEOUT_MS = 5000;

exports.SCANNER_NAME = SCANNER_NAME;
exports.DEFAULT_HOST = DEFAULT_HOST;
exports.DEFAULT_PORT = DEFAULT_PORT;
exports.DEFAULT_SOCKET_PATHS = DEFAULT_SOCKET_PATHS;
exports.resolveTarget = resolveTarget;
exports.isTrustedSocket = isTrustedSocket;
exports.createClamAvScanner = createClamAvScanner;

//
//  Whether |p| is a socket that nobody but root, us, or the socket's owner
//  (clamd's user) could have put there: every directory above it, by the
//  path as given and by its real path, is owned by one of those and is not
//  group- or world-writable unless sticky (like /tmp: others may add entries
//  there, but not replace ours). A socket found by guessing is only used if
//  so; one named in the config is used as it is.
//
function isTrustedSocket(p) {
    try {
        const real = fs.realpathSync(p);
        const st = fs.statSync(real);
        if (!st.isSocket()) {
            return false;
        }
        const owners = new Set([0, st.uid]);
        if ('function' === typeof process.getuid) {
            owners.add(process.getuid());
        }
        const dirTrusted = dir => {
            const d = fs.statSync(dir);
            return (
                d.isDirectory() &&
                owners.has(d.uid) &&
                (0 === (d.mode & 0o022) || 0 !== (d.mode & 0o1000))
            );
        };
        return [path.dirname(path.resolve(p)), path.dirname(real)].every(start => {
            for (let dir = start; ; dir = path.dirname(dir)) {
                if (!dirTrusted(dir)) {
                    return false;
                }
                if (path.dirname(dir) === dir) {
                    return true;
                }
            }
        });
    } catch (e) {
        return false;
    }
}

function isSet(v) {
    return undefined !== v && null !== v && '' !== v;
}

//
//  Works out where clamd is from an entry's options. Returns { target } or
//  { error }. |env| is for tests: { platform, isSocket, socketPaths }.
//
function resolveTarget(options, env = {}) {
    const platform = env.platform || process.platform;
    const socketCheck = env.isSocket || isTrustedSocket;
    const socketPaths = env.socketPaths || DEFAULT_SOCKET_PATHS;
    const opts = options || {};

    if (isSet(opts.socket) && (isSet(opts.host) || isSet(opts.port))) {
        return { error: 'Set either "socket" or "host"/"port", not both' };
    }

    if (isSet(opts.socket)) {
        if ('string' !== typeof opts.socket) {
            return { error: '"socket" must be a path' };
        }
        return { target: { path: opts.socket } };
    }

    if (isSet(opts.host) || isSet(opts.port)) {
        const host = isSet(opts.host) ? opts.host : DEFAULT_HOST;
        const port = isSet(opts.port) ? Number(opts.port) : DEFAULT_PORT;
        if ('string' !== typeof host) {
            return { error: '"host" must be a host name or address' };
        }
        if (!Number.isInteger(port) || port < 1 || port > 65535) {
            return { error: '"port" must be a TCP port number' };
        }
        return { target: { host, port } };
    }

    //  never TCP by default: see the top of this file
    if ('win32' === platform) {
        return {
            error: 'No clamd configured: on Windows, set "host" and "port" (e.g. 127.0.0.1 and 3310)',
        };
    }

    const found = socketPaths.find(p => socketCheck(p));
    if (found) {
        return { target: { path: found } };
    }
    return {
        error: `No clamd socket found at ${socketPaths.join(', ')}; set "socket" (or "host"/"port" for TCP)`,
    };
}

function chunkSizeOf(options) {
    const n = Number(options && options.chunkSize);
    if (!Number.isFinite(n) || n <= 0) {
        return clamd.DEFAULT_CHUNK_SIZE;
    }
    return Math.min(clamd.MAX_CHUNK_SIZE, Math.max(clamd.MIN_CHUNK_SIZE, Math.floor(n)));
}

//  |env| is for tests; see resolveTarget().
function createClamAvScanner(env = {}) {
    function scan(filePath, ctx, cb) {
        const { target, error } = resolveTarget(ctx.options, env);
        if (error) {
            return cb(null, { result: 'error', detail: `clamav: ${error}` });
        }

        clamd.instream(
            target,
            filePath,
            {
                chunkSize: chunkSizeOf(ctx.options),
                //  core's hash of the file: what was hashed is what is scanned
                sha256: ctx.sha256,
                signal: ctx.abortSignal,
                //  core's abortSignal is the real limit; this only matters
                //  when scan() is called without one
                timeout: ctx.abortSignal ? 0 : ctx.timeout,
            },
            (err, reply) => {
                if (err) {
                    return cb(null, {
                        result: 'error',
                        detail: `clamd at ${clamd.describeTarget(target)}: ${err.message}`,
                    });
                }
                return cb(null, clamd.parseScanReply(reply));
            }
        );
    }

    //
    //  PING each configured clamd and log what answered. Never fails startup:
    //  an unreachable clamd is reported back to core, which logs a warning,
    //  and scans are held (or accepted, per onError) until it is back. The
    //  PINGs never keep the process alive (oputil exits when it is done).
    //
    function init(entries, cb) {
        const seen = new Set();
        const targets = [];
        const problems = [];

        (Array.isArray(entries) ? entries : []).forEach(entry => {
            const { target, error } = resolveTarget(entry, env);
            if (error) {
                if (!problems.includes(error)) {
                    problems.push(error);
                }
                return;
            }
            const desc = clamd.describeTarget(target);
            if (!seen.has(desc)) {
                seen.add(desc);
                targets.push(target);
            }
        });

        const next = i => {
            if (i >= targets.length) {
                return cb(
                    problems.length > 0
                        ? new Error(`clamav: ${problems.join('; ')}`)
                        : null
                );
            }

            const target = targets[i];
            const desc = clamd.describeTarget(target);
            const opts = { timeout: env.initTimeoutMs || INIT_TIMEOUT_MS, unref: true };

            clamd.command(target, 'PING', opts, (err, reply) => {
                if (err || 'PONG' !== String(reply).trim()) {
                    problems.push(
                        `clamd at ${desc} did not answer PING (${
                            err ? err.message : 'unexpected reply'
                        })`
                    );
                    return next(i + 1);
                }

                //  VERSION may be disabled ("COMMAND UNAVAILABLE")
                clamd.command(target, 'VERSION', opts, (verErr, version) => {
                    const v = String(version || '').trim();
                    log(
                        'info',
                        {
                            scanner: SCANNER_NAME,
                            clamd: desc,
                            version: !verErr && /^ClamAV /.test(v) ? v : undefined,
                        },
                        'clamd answered PING'
                    );
                    return next(i + 1);
                });
            });
        };

        next(0);
    }

    return { scan, init };
}
