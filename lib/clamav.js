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
//  socket and host/port are exclusive. With neither, on Windows: TCP
//  127.0.0.1:3310. Elsewhere: the first of DEFAULT_SOCKET_PATHS that exists
//  and is a socket, else TCP 127.0.0.1:3310.
//

const fs = require('fs');
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
exports.createClamAvScanner = createClamAvScanner;

function isSocket(p) {
    try {
        return fs.statSync(p).isSocket();
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
    const socketCheck = env.isSocket || isSocket;
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

    if ('win32' !== platform) {
        const found = socketPaths.find(p => socketCheck(p));
        if (found) {
            return { target: { path: found } };
        }
    }

    return { target: { host: DEFAULT_HOST, port: DEFAULT_PORT } };
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
    //  and scans are held (or accepted, per onError) until it is back.
    //
    function init(entries, cb) {
        const seen = new Set();
        const targets = [];
        const problems = [];

        (Array.isArray(entries) ? entries : []).forEach(entry => {
            const { target, error } = resolveTarget(entry, env);
            if (error) {
                problems.push(error);
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
            const timeout = env.initTimeoutMs || INIT_TIMEOUT_MS;

            clamd.command(target, 'PING', { timeout }, (err, reply) => {
                if (err || 'PONG' !== String(reply).trim()) {
                    problems.push(
                        `clamd at ${desc} did not answer PING (${
                            err ? err.message : 'unexpected reply'
                        })`
                    );
                    return next(i + 1);
                }

                //  VERSION may be disabled ("COMMAND UNAVAILABLE")
                clamd.command(target, 'VERSION', { timeout }, (verErr, version) => {
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
