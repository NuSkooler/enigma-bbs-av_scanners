/* jslint node: true */
'use strict';

//
//  A fake clamd for tests. It parses the client's bytes strictly -- a
//  NUL-terminated "z" command, then for INSTREAM 4-byte big-endian lengths
//  and a zero-length terminator -- and records what it saw, so tests can
//  check the framing as well as the client's handling of each reply.
//
//  behaviour(session) is called when the stream is complete (or, for
//  commands, when the command arrives) and returns what to do:
//    { reply: Buffer|string }   write it (a string gets a NUL appended) and close
//    { close: true }            close without replying
//    { hang: true }             do nothing (the client must time out/abort)
//
//  Options: sizeLimit (reply "INSTREAM size limit exceeded. ERROR" and close
//  once more than this many bytes arrive, as clamd does), pauseMs (stop
//  reading for this long after the first chunk, to exercise backpressure).
//

const net = require('net');
const crypto = require('crypto');

function nul(text) {
    return Buffer.concat([Buffer.from(text, 'latin1'), Buffer.alloc(1)]);
}

class FakeClamd {
    constructor(behaviour, options = {}) {
        this.behaviour = behaviour || (() => ({ reply: 'stream: OK' }));
        this.options = options;
        this.sessions = [];
        this.sockets = new Set();
        this.server = net.createServer(socket => this._onConnection(socket));
    }

    listen(where) {
        return new Promise((resolve, reject) => {
            this.server.once('error', reject);
            if (where && where.path) {
                this.server.listen(where.path, () => resolve({ path: where.path }));
            } else {
                this.server.listen(0, '127.0.0.1', () =>
                    resolve({ host: '127.0.0.1', port: this.server.address().port })
                );
            }
        });
    }

    close() {
        for (const s of this.sockets) {
            s.destroy();
        }
        return new Promise(resolve => this.server.close(() => resolve()));
    }

    _onConnection(socket) {
        this.sockets.add(socket);
        const session = {
            command: null,
            chunkSizes: [],
            totalBytes: 0,
            terminated: false,
            hash: crypto.createHash('sha256'),
            sha256: null,
            clientClosed: false,
            protocolError: null,
        };
        this.sessions.push(session);

        let buf = Buffer.alloc(0);
        let need = null; //  bytes still to read of the current chunk
        let paused = false;
        let finished = false;

        const respond = action => {
            finished = true;
            if (!action || action.hang) {
                return;
            }
            if (action.close) {
                return socket.end();
            }
            const reply = Buffer.isBuffer(action.reply)
                ? action.reply
                : nul(action.reply);
            socket.end(reply);
        };

        const pump = () => {
            while (!finished) {
                if (null === session.command) {
                    const z = buf.indexOf(0);
                    if (-1 === z) {
                        return;
                    }
                    session.command = buf.subarray(0, z).toString('latin1');
                    buf = buf.subarray(z + 1);
                    if ('zINSTREAM' !== session.command) {
                        return respond(this.behaviour(session));
                    }
                    continue;
                }

                if (null === need) {
                    if (buf.length < 4) {
                        return;
                    }
                    const len = buf.readUInt32BE(0);
                    buf = buf.subarray(4);
                    if (0 === len) {
                        session.terminated = true;
                        session.sha256 = session.hash.digest('hex');
                        if (buf.length > 0) {
                            session.protocolError = 'bytes after the terminator';
                        }
                        return respond(this.behaviour(session));
                    }
                    session.chunkSizes.push(len);
                    need = len;
                }

                if (0 === buf.length) {
                    return;
                }
                const take = Math.min(need, buf.length);
                session.hash.update(buf.subarray(0, take));
                session.totalBytes += take;
                buf = buf.subarray(take);
                need -= take;
                if (0 === need) {
                    need = null;
                }

                if (
                    this.options.sizeLimit &&
                    session.totalBytes > this.options.sizeLimit
                ) {
                    return respond({ reply: 'INSTREAM size limit exceeded. ERROR' });
                }

                if (this.options.pauseMs && !paused) {
                    paused = true;
                    socket.pause();
                    session.pausedAt = session.totalBytes;
                    setTimeout(() => {
                        session.resumed = true;
                        socket.resume();
                        pump();
                    }, this.options.pauseMs);
                    return;
                }
            }
        };

        socket.on('data', data => {
            if (finished) {
                return;
            }
            buf = Buffer.concat([buf, data]);
            pump();
        });
        socket.on('error', () => {});
        socket.on('close', () => {
            session.clientClosed = true;
            this.sockets.delete(socket);
        });
    }
}

module.exports = FakeClamd;
module.exports.nul = nul;
