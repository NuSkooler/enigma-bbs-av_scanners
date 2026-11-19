/* jslint node: true */
'use strict';

//
//  A minimal clamd client: zINSTREAM, PING and VERSION, over a Unix socket or
//  TCP. See SPIKE.md for why this is not the |clamscan| package.
//
//  The protocol (clamd(8), "INSTREAM"):
//
//    -> "zINSTREAM" NUL
//    -> <uint32 big-endian length><that many bytes>   ...once per chunk
//    -> <uint32 0>                                    end of stream
//    <- "stream: OK" NUL
//     | "stream: <signature> FOUND" NUL
//     | "<reason> ERROR" NUL           e.g. "INSTREAM size limit exceeded. ERROR"
//
//  The "z" prefix asks for NUL-terminated replies. clamd may answer (and
//  close) before the stream is finished -- when StreamMaxLength is exceeded,
//  for one -- so a reply is taken whenever it arrives.
//
//  Only the file's bytes are sent, never its path: clamd may run as another
//  user, in a container or on another host.
//

const net = require('net');
const fs = require('fs');

const DEFAULT_CHUNK_SIZE = 64 * 1024;
const MIN_CHUNK_SIZE = 1024;
const MAX_CHUNK_SIZE = 8 * 1024 * 1024;

//  clamd's replies are a line of text; anything longer is not clamd.
const MAX_REPLY_BYTES = 4096;

exports.DEFAULT_CHUNK_SIZE = DEFAULT_CHUNK_SIZE;
exports.MIN_CHUNK_SIZE = MIN_CHUNK_SIZE;
exports.MAX_CHUNK_SIZE = MAX_CHUNK_SIZE;
exports.MAX_REPLY_BYTES = MAX_REPLY_BYTES;
exports.command = command;
exports.instream = instream;
exports.parseScanReply = parseScanReply;
exports.describeTarget = describeTarget;
exports.nulTerminated = nulTerminated;
exports.chunkHeader = chunkHeader;

function nulTerminated(text) {
    return Buffer.concat([Buffer.from(text, 'ascii'), Buffer.alloc(1)]);
}

function chunkHeader(length) {
    const header = Buffer.alloc(4);
    header.writeUInt32BE(length, 0);
    return header;
}

//  |target|: { path } for a Unix socket, { host, port } for TCP.
function describeTarget(target) {
    return target.path ? target.path : `${target.host}:${target.port}`;
}

function codeOf(err) {
    return err && 'string' === typeof err.code && /^[A-Z0-9_]+$/.test(err.code)
        ? err.code
        : null;
}

//
//  One request: connect, |start(socket, fail)| once connected, then wait for
//  a single NUL-terminated reply. Calls back exactly once, (err) or
//  (null, replyText), and always destroys the socket.
//
//  |opts.signal|: an AbortSignal; aborting destroys the connection.
//  |opts.timeout|: milliseconds for the whole exchange (0/absent: none, for
//  callers that rely on |signal|).
//  |opts.cleanup|: called once on completion, whatever the outcome.
//
function request(target, opts, start, cb) {
    let done = false;
    let timer = null;
    let socket = null;
    const reply = [];
    let replyBytes = 0;

    const onAbort = () => finish(new Error('Aborted'));

    function finish(err, text) {
        if (done) {
            return;
        }
        done = true;
        clearTimeout(timer);
        if (opts.signal) {
            opts.signal.removeEventListener('abort', onAbort);
        }
        if (socket) {
            socket.destroy();
        }
        if ('function' === typeof opts.cleanup) {
            try {
                opts.cleanup();
            } catch (e) {
                //  ignored: we are done either way
            }
        }
        return cb(err || null, text);
    }

    if (opts.signal && opts.signal.aborted) {
        return finish(new Error('Aborted'));
    }

    if (opts.signal) {
        opts.signal.addEventListener('abort', onAbort, { once: true });
    }

    if (opts.timeout > 0) {
        timer = setTimeout(
            () => finish(new Error(`No reply within ${opts.timeout}ms`)),
            opts.timeout
        );
    }

    try {
        socket = net.createConnection(
            target.path ? { path: target.path } : { host: target.host, port: target.port }
        );
    } catch (e) {
        return finish(new Error(`Cannot connect: ${e.message}`));
    }

    socket.on('connect', () => {
        if (done) {
            return;
        }
        try {
            start(socket, finish);
        } catch (e) {
            finish(e);
        }
    });

    socket.on('data', data => {
        if (done) {
            return;
        }
        const nul = data.indexOf(0);
        const part = -1 === nul ? data : data.subarray(0, nul);
        replyBytes += part.length;
        if (replyBytes > MAX_REPLY_BYTES) {
            return finish(new Error(`Reply longer than ${MAX_REPLY_BYTES} bytes`));
        }
        reply.push(part);
        if (-1 !== nul) {
            return finish(null, Buffer.concat(reply).toString('latin1'));
        }
    });

    socket.on('end', () => {
        finish(
            new Error(
                replyBytes > 0
                    ? 'Connection closed before the reply was complete'
                    : 'Connection closed without a reply'
            )
        );
    });

    socket.on('close', () => {
        finish(new Error('Connection closed without a reply'));
    });

    socket.on('error', err => {
        const code = codeOf(err);
        finish(new Error(code ? `Connection failed (${code})` : 'Connection failed'));
    });
}

//
//  Sends a simple command ("PING", "VERSION") and calls back (err, reply).
//
function command(target, name, opts, cb) {
    request(
        target,
        opts,
        socket => {
            socket.write(nulTerminated(`z${name}`));
        },
        cb
    );
}

//
//  Streams |filePath| to clamd and calls back (err, replyText). The file is
//  read |opts.chunkSize| bytes at a time, and reading pauses while the socket
//  cannot take more, so memory use is bounded by the chunk size whatever the
//  file's size or clamd's speed.
//
function instream(target, filePath, opts, cb) {
    const chunkSize = opts.chunkSize || DEFAULT_CHUNK_SIZE;
    let fileStream = null;

    const requestOpts = {
        signal: opts.signal,
        timeout: opts.timeout,
        cleanup: () => {
            if (fileStream) {
                fileStream.destroy();
            }
        },
    };

    request(
        target,
        requestOpts,
        (socket, fail) => {
            socket.write(nulTerminated('zINSTREAM'));

            fileStream = fs.createReadStream(filePath, { highWaterMark: chunkSize });

            fileStream.on('data', chunk => {
                socket.write(chunkHeader(chunk.length));
                if (!socket.write(chunk)) {
                    fileStream.pause();
                    socket.once('drain', () => fileStream.resume());
                }
            });

            fileStream.on('end', () => {
                socket.write(chunkHeader(0));
            });

            fileStream.on('error', err => {
                const code = codeOf(err);
                fail(
                    new Error(
                        code ? `Cannot read the file (${code})` : 'Cannot read the file'
                    )
                );
            });
        },
        cb
    );
}

//
//  Maps an INSTREAM reply to a scan result. Only the exact clean reply is
//  clean; anything unrecognised is an error, never clean.
//
function parseScanReply(text) {
    const reply = String(text).trim();

    if ('stream: OK' === reply) {
        return { result: 'clean' };
    }

    const found = /^stream: (.+) FOUND$/.exec(reply);
    if (found) {
        return { result: 'infected', signature: found[1].trim() };
    }

    if (/ ERROR$/.test(reply)) {
        return { result: 'error', detail: `clamd: ${reply}` };
    }

    return {
        result: 'error',
        detail: reply
            ? `Unexpected reply from clamd: ${reply}`
            : 'Empty reply from clamd',
    };
}
