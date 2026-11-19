# Spike: `clamscan` (npm) vs. a hand-rolled `zINSTREAM` client

Date: 2026-11-18. Package examined: `clamscan@2.4.0` (kylefarris), the tarball from
npm, read in full along the socket/TCP path (`_initSocket`, `ping`, `isInfected`,
`scanStream`, `_processResult`, `lib/NodeClamTransform.js`), and run against the
local clamd 1.5.4 (`/var/run/clamav/clamd.ctl`).

## Decision

**Hand-roll the client** (`lib/clamd.js`, about 200 lines with comments). `clamscan`
is not used.

The owner's preference for an upstream-maintained dependency (decision 11) assumes
the dependency is sound on the path we use. Here it is not: on that path it
reports an unscannable file as a successful scan, sends file *paths* over a Unix
socket, has no way to abort, and buffers without limit. Wrapping it would mean
working around most of it, and we would still be maintaining protocol-level fixes,
just in someone else's repo.

## Evidence

### Basic facts

| | |
|---|---|
| Licence | MIT |
| Dependencies | none (pure `net`, `tls`, `fs`, `child_process`) |
| Last release | 2.4.0, 2024-10-21; no commits since (repo last pushed the same day) |
| Open issues | 8, e.g. #81 (3.8 GB file: `RangeError ERR_OUT_OF_RANGE`), #101 (premature end of socket stream behind a proxy), #117 (no retry on `ECONNREFUSED`), #131 (INSTREAM size limit confusion), #145 (asks for a way to suppress its unconditional `console.error` warnings) |

### Windows

The README's "not intended to work on a Windows server" is about the binary mode
(`/usr/bin/clamscan` defaults, `execFile`). The socket/TCP path is plain `net`/`tls`
and would work over TCP on Windows. But `init()` still runs `_isClamavBinary()`
(an `fs.access` plus `execFile('/usr/bin/clamdscan', ['--version'])`) even when only
a socket or host is configured. On Windows that fails harmlessly, so this was
**not** the blocker.

### Problems on the path we would use

1. **A Unix socket means `SCAN <path>`, not INSTREAM.** `isInfected(file)` with
   `clamdscan.socket` set writes `MULTISCAN <path>`/`SCAN <path>`. clamd then opens
   the path as its own user. That is exactly the "clamd cannot read our 0700 upload
   temp dir" failure in the design doc and core's docs. Only the TCP branch streams.
   To get INSTREAM over a socket we would have to call `scanStream()` ourselves,
   which skips most of the package anyway.
2. **An empty file "scans" without an error.** `NodeClamTransform` writes the
   `zINSTREAM` command lazily, in `_transform()`, which never runs for a zero-byte
   stream. clamd then receives four NUL bytes, replies `UNKNOWN COMMAND`, and
   `scanStream()` **resolves** (it does not reject) with
   `{ isInfected: null, resultString: 'UNKNOWN COMMAND' }`. Verified locally:
   ```
   empty.bin {"isInfected":null,"viruses":[],"file":null,"resultString":"UNKNOWN COMMAND","timeout":false}
   safe.txt  {"isInfected":false,"viruses":[],"file":null,"resultString":"stream: OK\u0000","timeout":false}
   ```
   Any reply that is not OK, FOUND or ERROR (garbage, `COMMAND READ TIMED OUT`, a
   proxy's error page) resolves the same way. A caller testing `if (!isInfected)`
   passes the file. Mapping `null` to error is possible in a wrapper, but it makes
   empty files permanently unscannable (held). Real clamd says `stream: OK` for a
   properly framed empty stream (verified).
3. **No abort, no clean timeout.** Neither `scanStream()` nor `isInfected()` accepts
   an `AbortSignal` or exposes the socket. The only timeout is the socket idle
   timeout from settings. Its handler calls `reject()` on the already-settled
   connect promise and `client.end()` (a half-close, not a destroy), so a stalled
   clamd keeps the socket and the read stream open. Core's `ctx.abortSignal` could
   not be honoured.
4. **No backpressure.** `stream.on('data') -> transform.write()` and
   `transform.on('data') -> socket.write()` ignore the return values, so a fast disk
   and a slow clamd buffer the file in the socket's write queue, up to the whole
   file. It does stream from a path (`fs.createReadStream`), but it does not bound
   memory.
5. **Unbounded reply buffer**: every `data` chunk is pushed onto an array until
   `end`.
6. **Multiple callbacks.** The input stream, transform and socket `error` handlers
   each call `cb`/`reject` independently, and `socket.on('error')` calls
   `console.error` unconditionally (issue #145). That output would land in
   ENiGMA's console and in oputil's.
7. **`ping()` leaks the socket.** It resolves with the open client and never closes
   it.
8. **ERROR handling is fine as far as it goes.** `_processResult` returns (does not
   throw) a `NodeClamError` for `... ERROR`, and `scanStream()` rejects with it. So
   `INSTREAM size limit exceeded. ERROR` does map to an error. If clamd closes
   before our terminator is written, the result is a "Scan aborted" error. Both are
   correct, but they are the only error mappings that are.

### The hand-rolled alternative

The protocol is small and stable (unchanged since INSTREAM appeared in 0.95):

- send `zINSTREAM\0`;
- send `<uint32 BE length><bytes>` per chunk;
- send `<00 00 00 00>`;
- read one NUL-terminated reply: `stream: OK`, `stream: <sig> FOUND`, or
  `<text> ERROR`.

`PING` -> `PONG` is the health check. `VERSION` may be disabled (`COMMAND
UNAVAILABLE` on this box). A client that does what we need is under 200 lines:
backpressure (`pause` on a full write, `resume` on `drain`), an `AbortSignal` that
destroys both streams, a single-callback guard, a capped reply buffer, strict reply
parsing where anything unrecognised is an error, and early-reply handling (clamd
answers `size limit exceeded` and closes while we are still sending). It is pure
`net`, so the same code covers a Unix socket on POSIX and TCP everywhere,
Windows included.

Maintenance risk is low: no dependency, a frozen wire protocol, and the test suite
includes a fake clamd that checks the framing byte for byte, plus an integration
test against a real clamd when one is present.
