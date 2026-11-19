# ENiGMA½ AV Scanners

Two file scanners for [ENiGMA½ BBS](https://github.com/NuSkooler/enigma-bbs)'s
[file scanning](https://enigma-bbs.github.io/filebase/file-scanning/) (`fileBase.scanning`):

| Scanner | What it does |
|---------|--------------|
| `clamav` | Streams each file to a ClamAV daemon (`clamd`) with `INSTREAM`, over a Unix socket or TCP. Works on Linux, macOS, the BSDs and Windows (TCP). |
| `virustotal` | Looks the file's SHA-256 up on [VirusTotal](https://www.virustotal.com/). **It sends only the hash and never uploads a file.** |

You can use either scanner, or both. ENiGMA½ runs the scanners on telnet/SSH uploads,
REST uploads, TIC imports (including passthrough echoes) and `oputil fb scan
--virus-scan`, before it opens or extracts anything.

Requires an ENiGMA½ with file scanning and the `registerFileScanners` mod export
(master from [#1114](https://github.com/NuSkooler/enigma-bbs/pull/1114) on) and
Node.js 22 or later. The mod has no npm dependencies.

## Install

Put this repository in your `mods` directory as `av_scanners`:

```bash
cd /path/to/enigma-bbs/mods
git clone <this repository's URL> av_scanners
```

A copy works too. The entry point must end up at `mods/av_scanners/av_scanners.js`.
A symlink to a checkout elsewhere also works. There is nothing to `npm install`
to run it (`npm install` is only needed to run the tests).

Then configure one or both scanners under `fileBase.scanning.scanners` (see below) and
restart ENiGMA½. At startup the log shows `clamd answered PING` for each clamd it can
reach, and `VirusTotal hash lookup ready` when a `virustotal` entry is configured. If
clamd cannot be reached, or no clamd is configured and none is found, or an option is
invalid, you get a `File scanner failed to initialize` warning saying why. Startup
carries on regardless, and files are held until clamd is back (see
[onError](#when-a-scanner-fails)).

`oputil fb scan AREA --virus-scan` uses these scanners too: it loads them through the
same `registerFileScanners` export, without running anything else of the mod.

## ClamAV (`clamav`)

```hjson
fileBase: {
    scanning: {
        enabled: true
        scanners: [
            {
                scanner: clamav
                socket: "/var/run/clamav/clamd.ctl"    //  Debian/Ubuntu
            }
        ]
    }
}
```

| Option | Default | Description |
|--------|---------|-------------|
| `socket` | see below | Path to clamd's Unix socket (`LocalSocket` in `clamd.conf`) |
| `host` | `127.0.0.1` | clamd's TCP address (`TCPAddr`). Setting `host` or `port` selects TCP; when only `port` is set, `host` is `127.0.0.1` |
| `port` | `3310` | clamd's TCP port (`TCPSocket`); when only `host` is set, `port` is `3310` |
| `chunkSize` | `65536` | Bytes per `INSTREAM` chunk, 1 KiB to 8 MiB. Memory use per scan is about this much, whatever the file's size |

Set either `socket` or `host`/`port`, not both. Setting both is a configuration
error: every scan by that entry is an error, so the file is held (or accepted, with
`onError: accept`).

With none of them set, the scanner looks for clamd's Unix socket at each scan, at the
first of these paths that is a socket:

1. `/var/run/clamav/clamd.ctl` (Debian, Ubuntu)
2. `/run/clamav/clamd.ctl` (Arch)
3. `/run/clamd.scan/clamd.sock` (Fedora, RHEL)
4. `/var/run/clamav/clamd.sock` (FreeBSD)
5. `/opt/homebrew/var/run/clamav/clamd.sock` (Homebrew, Apple silicon)
6. `/usr/local/var/run/clamav/clamd.sock` (Homebrew, Intel)

A socket found this way is only used if nobody but root, the ENiGMA½ user or the
socket's owner (clamd's user) could have put it there: every directory above it must
be owned by one of them and not be group- or world-writable (sticky directories such
as `/tmp` excepted). A socket you name with `socket` is used as it is.

If none is found, every scan is an error. **The scanner never falls back to TCP on
its own:** any local user can listen on a free `127.0.0.1:3310` while clamd is down or
restarting and answer "clean". TCP is used only when you set `host` or `port`. On
**Windows**, where clamd has no Unix socket, you must set them (see
[Windows](#setting-up-clamd)).

Setting `socket` (or `host`/`port`) explicitly is still recommended: it says what you
mean, and a clamd that is down shows up as an error naming the place you expected it.

Core's own entry options apply as usual: `sources`, `fileTypes`, `timeout` (default
60 s), and `onError`.

### What it reports

| clamd says | Result |
|------------|--------|
| `stream: OK` | `clean` |
| `stream: <signature> FOUND` | `infected`, with the signature (e.g. `Eicar-Test-Signature`) |
| `INSTREAM size limit exceeded. ERROR` | `error` |
| anything else ending in `ERROR` | `error` |
| any other reply, an empty reply, a reply over 4 KB, no reply | `error` |
| connection refused, socket missing, connection dropped | `error` |
| no clamd configured and no socket found | `error` |
| `stream: OK` before the whole file was sent | `error` |
| the file changed after ENiGMA½ hashed it (the bytes sent do not match the SHA-256 core worked out, which is also what VirusTotal looks up) | `error`; the stream is not finished |
| timeout (`timeout`) | `error`; the connection is closed at once |

**A scan that fails never comes back `clean`.** Only clamd's exact `stream: OK`, after
the whole file has been sent, is clean; everything else that is not `FOUND` is an
`error`, which holds the file unless the entry says `onError: accept`.

The scanner sends the file's **bytes**, never its path. clamd usually runs as its own
user and cannot open files in ENiGMA½'s private (`0700`) upload directories, and it
may be in a container or on another machine. Streaming avoids all of that.

### Size limits: read this

ClamAV stops at its limits, and **a file it stopped on reports `OK`** unless you tell
it otherwise. Set this in `clamd.conf`:

```
AlertExceedsMax yes
```

With it, a file over `MaxFileSize` or `MaxScanSize`, or an archive nested deeper than
`MaxRecursion`, reports `Heuristics.Limits.Exceeded` (`FOUND`), which rejects the file.
Without it, anyone can get a file past by padding it or nesting it in archives.

The limits that matter:

| `clamd.conf` | Default | Notes |
|--------------|---------|-------|
| `StreamMaxLength` | `100M` | The most clamd accepts over `INSTREAM`. A longer file is cut off with `INSTREAM size limit exceeded`, an **error**: the file is held (or accepted, with `onError: accept`) |
| `MaxFileSize` | `100M` | Files larger than this are not scanned (with `AlertExceedsMax yes`: rejected) |
| `MaxScanSize` | `400M` | The most data scanned from one file, archives included |

Keep **`StreamMaxLength` ≥ `MaxFileSize`**, and keep **both at least as large as
the largest upload or TIC file you accept**. Otherwise every larger file is held (by
`StreamMaxLength`) or rejected (by `MaxFileSize`). Raising them costs clamd memory
and time per scan.

### Encrypted archives: read this too

**A password-protected archive scans clean**, whatever is inside, even with
`AlertExceedsMax yes`: clamd cannot look inside it. (Checked against clamd 1.5.4: the
EICAR test file in a `zip -P` archive, and in a 7z with AES and encrypted headers,
both came back `OK`.) To reject them instead, set one of these in `clamd.conf`:

| `clamd.conf` | Flags |
|--------------|-------|
| `AlertEncrypted yes` | encrypted archives and documents (`.zip`, `.7z`, `.rar`, `.pdf`) |
| `AlertEncryptedArchive yes` | encrypted archives only (`.zip`, `.7z`, `.rar`) |
| `AlertEncryptedDoc yes` | encrypted documents only (`.pdf`) |

They report `Heuristics.Encrypted.*` (`FOUND`; e.g. `Heuristics.Encrypted.Zip` and
`Heuristics.Encrypted.7Zip` for the two files above), which rejects the file. The trade-off:
**every legitimately encrypted upload is rejected too**, so say so in your upload
rules if you turn this on. `AlertEncryptedArchive` is the usual choice for a BBS.

### Old archive formats

clamd unpacks ZIP, RAR, 7z, ARJ and LZH/LHA, among others, and scans what is inside.
It **does not unpack ARC or ZOO**: those are scanned only as raw bytes, which finds
something stored uncompressed but nothing compressed inside them. What was checked,
against clamd 1.5.4 with a signature that only matches an extracted file:

* ZIP (stored), ARJ (method 0) and LZH/LHA (`-lh0-`, header levels 0 and 1): unpacked
  and scanned inside. Compressed ARJ and LZH methods were not tested, but are the
  same unpackers.
* ARC and ZOO: not recognised as archives at all (libclamav has no file type for
  either), so only a raw scan.

If you accept ARC or ZOO uploads, ClamAV alone does not check their contents.

### Security notes

* **clamd's TCP port has no authentication and no encryption.** Anyone who can reach
  it can use your clamd, and some clamd commands (`SHUTDOWN`, `RELOAD`, `SCAN <path>`)
  do more than scan. Anyone on the path can also read what is sent, and forge the
  reply. Prefer the Unix socket where you have one. If clamd must be on TCP, bind it
  to localhost (`TCPAddr 127.0.0.1`). For a clamd on another machine, carry the
  connection over a tunnel (WireGuard, an SSH tunnel, stunnel) and bind clamd to the
  tunnel's address only; a "private network" alone is not enough.
* The ENiGMA½ user needs permission to connect to the Unix socket. Prefer adding the
  ENiGMA½ user to clamd's socket group (`LocalSocketGroup`) with `LocalSocketMode
  660` over `LocalSocketMode 666`: with `666`, any local user can talk to clamd,
  including sending it `SHUTDOWN`. (Debian/Ubuntu ship `666`.)

### Setting up clamd

You need `clamd` running, and `freshclam` keeping its signatures current.

**Debian / Ubuntu**

```bash
sudo apt install clamav-daemon clamav-freshclam
sudo systemctl enable --now clamav-freshclam clamav-daemon
```

Config: `/etc/clamav/clamd.conf`. Socket: `/var/run/clamav/clamd.ctl`. Add
`AlertExceedsMax yes`, check the size limits, then `sudo systemctl restart
clamav-daemon`.

**Fedora / RHEL** (RHEL, Rocky and Alma need [EPEL](https://docs.fedoraproject.org/en-US/epel/))

```bash
sudo dnf install clamav clamd clamav-update
```

* In `/etc/clamd.d/scan.conf`, delete the `Example` line, uncomment
  `LocalSocket /run/clamd.scan/clamd.sock`, and add `AlertExceedsMax yes`.
* In `/etc/freshclam.conf`, delete the `Example` line.

Then:

```bash
sudo freshclam
sudo systemctl enable --now clamav-freshclam clamd@scan
```

Check who may connect with `ls -l /run/clamd.scan/clamd.sock`. Then add the ENiGMA½
user to the socket's group (`LocalSocketGroup` in `scan.conf`) with `sudo usermod -aG
<group> <enigma user>` (see [Security notes](#security-notes) on why not
`LocalSocketMode 666`).

**macOS (Homebrew)**

```bash
brew install clamav
cd "$(brew --prefix)/etc/clamav"
cp freshclam.conf.sample freshclam.conf
cp clamd.conf.sample clamd.conf
```

Edit both files and comment out the `Example` line. In `clamd.conf`, set:

```
LocalSocket /opt/homebrew/var/run/clamav/clamd.sock
AlertExceedsMax yes
```

Use `/usr/local/...` instead on an Intel Mac. Then:

```bash
mkdir -p "$(brew --prefix)/var/run/clamav"
freshclam
clamd
```

Run `clamd` (and `freshclam -d`) at login with launchd, or however you start
ENiGMA½. macOS has no on-demand command-line scanner of its own (XProtect has none),
so ClamAV is the option here.

**FreeBSD**

```sh
pkg install clamav
sysrc clamav_freshclam_enable=YES clamav_clamd_enable=YES
service clamav_freshclam start
service clamav_clamd start
```

Config: `/usr/local/etc/clamd.conf` (add `AlertExceedsMax yes`). Socket:
`/var/run/clamav/clamd.sock`.

**Windows**

clamd on Windows has no Unix socket, so use TCP.

1. Install ClamAV from [clamav.net](https://www.clamav.net/downloads).
2. In the install directory (e.g. `C:\Program Files\ClamAV`), copy
   `conf_examples\clamd.conf.sample` to `clamd.conf` and
   `conf_examples\freshclam.conf.sample` to `freshclam.conf`.
3. Delete the `Example` line in both.
4. In `clamd.conf`, set:

   ```
   TCPSocket 3310
   TCPAddr 127.0.0.1
   AlertExceedsMax yes
   ```
5. Run `freshclam.exe`, then start `clamd.exe` (it can install itself as a service:
   `clamd.exe --install-service`).

Configure the scanner with `host` and `port`. On Windows they are **required**: the
scanner never assumes TCP, and without them every scan is an error.

```hjson
{
    scanner: clamav
    host: "127.0.0.1"
    port: 3310
}
```

### Testing

The [EICAR test file](https://www.eicar.org/download-anti-malware-testfile/) is
harmless and every scanner flags it. Drop `eicar.com`, a zip of it, and a zip of
that zip into an upload area's storage directory, then run:

```bash
./oputil.js fb scan uploads --virus-scan
```

All three should be rejected and quarantined (`Eicar-Test-Signature`).

## VirusTotal (`virustotal`)

```hjson
{
    scanner: virustotal
    apiKey: "@environment:VT_API_KEY"
    onError: accept
}
```

| Option | Default | Description |
|--------|---------|-------------|
| `apiKey` | (required) | Your VirusTotal API key. Keep it out of `config.hjson`; see below |
| `minDetections` | `2` | How many engines must say "malicious" before the file is rejected |
| `countSuspicious` | `false` | Also count engines that say "suspicious" |
| `requestsPerMinute` | `4` | Client-side rate limit (the free tier's). Lookups past it wait their turn, for up to `maxWaitMs` |
| `maxWaitMs` | `2000` | The longest a lookup waits for the rate limit. One whose turn is further off is an error at once; `0` means never wait. Keep it short: see below |
| `dailyLimit` | `500` | Lookups per UTC day (the free tier's). Past it, every lookup is an error until 00:00 UTC. `0` means no limit (a paid key). Counted per process: see below |
| `cacheMinutes` | `60` | How long to remember an answer by SHA-256 (`0`: off). Errors are never cached |
| `cacheMaxEntries` | `1000` | The most answers remembered |
| `maxQueue` | `100` | The most lookups that may be waiting for the rate limit at once. Any more are errors at once (a lookup that need not wait is never refused by it) |

An invalid value (say `minDetections: 0`) is reported at startup and the default is
used instead. Lookups of the same hash at the same time share one request.

**Keep the key out of the config file.** ENiGMA½ resolves these specs in any config
value:

* `apiKey: "@environment:VT_API_KEY"` reads the environment variable `VT_API_KEY`;
* `apiKey: "@file:secrets/vt_api_key"` reads the file. A relative path is relative
  to `config.hjson`'s directory; leading and trailing whitespace is trimmed.

If the variable or file is missing, ENiGMA½ leaves the spec as written (with a
console warning). This scanner refuses such a key, and every lookup is an error;
it never sends the spec as a key.

The key goes only in the `x-apikey` request header, over HTTPS to
`www.virustotal.com`, and redirects are refused, so it can't be carried to another
host. It is never written to a log, a result, an error or an operator notice.

### What it reports

| VirusTotal says | Result |
|-----------------|--------|
| `malicious` (+ `suspicious` with `countSuspicious`) ≥ `minDetections` | `infected`, e.g. `VirusTotal: 5/70 (trojan.pklite/dropper)`. The label is VirusTotal's `suggested_threat_label`, or else the name most flagging engines agree on |
| fewer detections | `clean` |
| 404: hash not known | `skipped` |
| known but not analysed yet | `skipped` |
| 401/403 (bad key), 429 (quota), 5xx, other statuses | `error` |
| network failure, timeout, redirect, malformed or oversized response | `error` |
| a report without whole-number `malicious`, `suspicious`, `undetected` and `harmless` counts | `error` (never read as 0) |
| no usable `apiKey`, no SHA-256, over `dailyLimit`, `maxQueue` full, no turn within `maxWaitMs` | `error` |

After a 429, the scanner stops asking for as long as VirusTotal's `Retry-After`
header says (seconds or a date; a minute if it does not say, an hour at most), and the
lookups already waiting fail at once rather than being sent. A spent quota does not
cost a request per file.

As with ClamAV, **a lookup that fails never comes back `clean`.**

`minDetections` defaults to 2 because a handful of engines routinely flag old DOS
files (PKLITE'd executables, trainers, cracks) as riskware. That is why ClamAV ships
with PUA detection off.

### Read before relying on it

* **The free API is for non-commercial use only**, and is limited to 4 lookups a
  minute and 500 a day. See VirusTotal's terms.
* **Only the hash is sent.** Nothing about the file's contents leaves your system,
  but VirusTotal does learn that someone had a file with that hash. This scanner
  never uploads files and has no option to: files uploaded to VirusTotal are shared
  with its partners.
* **An unknown hash is `skipped`, and a skipped file is accepted.** Anything new,
  repacked or one byte different is unknown to VirusTotal. **VirusTotal alone is not
  protection.** Pair it with ClamAV, which looks at the contents.
* **Use `onError: accept`** on the VirusTotal entry. Otherwise a spent quota, a
  rate-limit wait longer than `maxWaitMs`, or a VirusTotal outage holds every file.
  Remember that with `accept`, anyone who can make the lookup fail gets past this
  scanner, which is one more reason to run ClamAV first.
* **A lookup holds one of ENiGMA½'s scan slots while it runs**, including while it
  waits for the rate limit. Those slots (`fileBase.scanning.maxConcurrent`, default 2)
  are shared by every scanner, ClamAV and TIC imports included, so a scan slot is
  held for at most `maxWaitMs` plus the request (the entry's `timeout` bounds the
  whole lookup). Keep `maxWaitMs` short and `timeout` modest; with the defaults, a
  burst of new uploads makes the lookups past the rate limit fail (and, with
  `onError: accept`, pass) at once instead of throttling all scanning to 4 files a
  minute.
* **`dailyLimit` is counted per process, from when it started.** The BBS and each
  `oputil` run count separately, and a restart starts again from 0. It is a
  courtesy, not a guarantee: VirusTotal's own 429 answer is what really stops
  lookups, and the scanner honours it.

## Recommended: both

ClamAV first, as the real gate (it fails closed). VirusTotal second, as a second
opinion that never holds files. Order matters: a file ClamAV rejects never costs a
VirusTotal lookup, or a scan slot spent waiting for one.

```hjson
fileBase: {
    scanning: {
        enabled: true
        failAction: quarantine
        notifyUserIds: [
            1
        ]
        scanners: [
            {
                scanner: clamav
                socket: "/var/run/clamav/clamd.ctl"
                timeout: 60000
                //  onError defaults to hold: a clamd outage holds files
            }
            {
                scanner: virustotal
                apiKey: "@environment:VT_API_KEY"
                minDetections: 2
                onError: accept
                timeout: 30000
            }
        ]
    }
}
```

The first scanner to find something rejects the file, and the rest are skipped. A
file ClamAV passes and VirusTotal does not know is accepted.

### When a scanner fails

That is core behaviour: see ENiGMA½'s [file scanning docs](https://enigma-bbs.github.io/filebase/file-scanning/#when-a-scanner-fails).
In short, an `error` holds the file (quarantines it as "could not be checked") unless
the entry says `onError: accept`.

## Development

```bash
npm install
npm test          # unit tests; the real-clamd tests run only if clamd is at
                  # /var/run/clamav/clamd.ctl (or $CLAMD_SOCKET), and the
                  # core tests only if an installed ENiGMA½ checkout is at
                  # ../enigma-bbs (or $ENIGMA_BBS_DIR); else they skip
npm run lint
npm run pretty:check
```

The tests use a fake clamd, which checks the `INSTREAM` framing byte for byte, and a
fake VirusTotal server. The real-clamd tests build their EICAR files at run time, so
this repository never contains the test string. See [SPIKE.md](SPIKE.md) for why the
clamd client is ours rather than the `clamscan` npm package.

`createVirusTotalScanner({ testBaseUrl })` sends lookups to a local server, for tests
only. Only code can set it; there is no config option. It accepts `https://`, or
`http://` to a loopback address and nothing else, so a production config cannot
downgrade the scanner to plain HTTP.

## Licence

BSD 2-Clause, the same as ENiGMA½. See [LICENSE](LICENSE).
