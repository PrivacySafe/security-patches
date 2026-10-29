# Node.js: Brotli decoder guard (CVE-2026-111497)

Part of the [PrivacySafe Security Patches](../README.md) collection.

<a name="nodejs-october-2026-interim-mitigation"></a>

## Node.js October 2026 Interim Mitigation

**Scripts:** [`node/node-oct2026-mitigate.sh`](node-oct2026-mitigate.sh), [`node/brotli-guard.cjs`](brotli-guard.cjs)

Node.js 22.23.4, 24.22.1 and 26.12.1 (21 October 2026) fix ten CVEs. The serious one is **CVE-2026-111497**, an out-of-bounds write in the Brotli decoder that can lead to remote code execution. Any code that decodes attacker-controlled Brotli reaches it, and on an unfixed runtime that includes every `fetch()`, because fetch decodes `Content-Encoding: br` responses on its own. Node lines 25 and older are end of life and get no fix.

CVE-2026-111497 is also known as Broccoli2Shell (it was first called Node2Shell). It is rated High by Node.js and 9.2 Critical by GitHub. Three kinds of code reach it on an unfixed runtime:

- **Anything that fetches a URL.** Built-in `fetch()` decodes the response, so any server you talk to can send the payload.
- **Anything that accepts request bodies.** Express 5.0.0 to 5.3.0 and body-parser 2.0.0 to 2.3.0 inflate Brotli request bodies in parsers such as `raw()` and `json()`. Express and body-parser do not contain the bug, so upgrading them does not help. A bare `node:http` server does not decode bodies by itself.
- **Anything that calls the decoder directly:** `zlib.brotliDecompress*()` and `createBrotliDecompress()`, including libraries that use them on archives, caches or queue messages.

Node.js bundles its own Brotli, so the system `libbrotli` does not matter for Node; only the Node.js version does. You can read the bundled version with `node -p "process.versions.brotli"`. The Imperva Red Team has run attacker-supplied code on the official, unmodified Node.js 24.22.0 arm64 GNU/Linux image, through both a fetched response and an Express request body, so treat this as exploitable. Node.js has published no workaround of its own: upgrading the runtime is the only complete fix, and the guard below is our interim measure for services you cannot upgrade yet. After upgrading, restart every process and rebuild every container image, because a running process keeps the old decoder until it restarts.

We wrote these for the Node services we couldn't upgrade the same day. There are two parts:

1. **`brotli-guard.cjs`** is a small file Node loads before your application, through `--require`. It makes Node's Brotli decoder refuse to run, for CommonJS and ES modules alike, and stops `fetch()` asking servers for `br`. Compression keeps working, and so do gzip and deflate. A blocked decode fails the way corrupt input does, so code that already copes with a bad compressed body copes with this too. On a fixed runtime it goes idle by itself.
2. **`node-oct2026-mitigate.sh`** finds every Node runtime and process on the host, tells you which are exposed, finds the code that decodes Brotli, and loads the guard into systemd services for you. It checks the guard works on each service's own runtime before installing it, and rolls back if the service won't start with it.

### Node.js quick start

1. Download both files into the same directory. The script looks for `brotli-guard.cjs` next to itself. The repository is mirrored on GitHub and Codeberg; pick a base URL.

   ```bash
   # BASE from GitHub:   https://raw.githubusercontent.com/PrivacySafe/security-patches/refs/heads/main
   # BASE from Codeberg: https://codeberg.org/PrivacySafe/security-patches/raw/branch/main
   # curl -fLO "$BASE/node/node-oct2026-mitigate.sh" -fLO "$BASE/node/brotli-guard.cjs"
   curl -fLO https://raw.githubusercontent.com/PrivacySafe/security-patches/refs/heads/main/node/node-oct2026-mitigate.sh \
        -fLO https://raw.githubusercontent.com/PrivacySafe/security-patches/refs/heads/main/node/brotli-guard.cjs
   ```

2. Read them before running them. Always.

   ```bash
   less node-oct2026-mitigate.sh brotli-guard.cjs
   ```

3. Make the script executable.

   ```bash
   chmod +x node-oct2026-mitigate.sh
   ```

4. See what's exposed. This changes nothing. Root is optional, but without it you won't see other users' runtimes and processes.

   ```bash
   sudo ./node-oct2026-mitigate.sh check
   ```

5. Find what in your applications decodes Brotli, and any single executable applications or startup snapshots you'll need to rebuild. Also read-only.

   ```bash
   sudo ./node-oct2026-mitigate.sh scan
   ```

6. Test the guard on your runtime. Every check should pass.

   ```bash
   node brotli-guard.cjs --self-test
   ```

7. Guard each systemd service you can't upgrade yet.

   ```bash
   sudo ./node-oct2026-mitigate.sh guard --unit myapp
   ```

To confirm GitHub and Codeberg serve the same files, compare checksums:

```bash
sha256sum node-oct2026-mitigate.sh brotli-guard.cjs
curl -fsSL https://codeberg.org/PrivacySafe/security-patches/raw/branch/main/node/node-oct2026-mitigate.sh | sha256sum
curl -fsSL https://codeberg.org/PrivacySafe/security-patches/raw/branch/main/node/brotli-guard.cjs | sha256sum
```

After guarding, let real traffic run and check what the guard blocked. Each blocked call names the code that tried to decode Brotli:

```bash
sudo ./node-oct2026-mitigate.sh status
```

Once Node is upgraded, take the guard out again:

```bash
sudo ./node-oct2026-mitigate.sh unguard --unit myapp
```

### Node.js commands

| Command | What it does |
|---|---|
| `check` (default) | Reports every Node runtime on disk, every running Node process and every container image that declares `NODE_VERSION`, with whether each is fixed. Flags processes still running a binary that's been replaced on disk, processes that are guarded, and processes using startup snapshots. Changes nothing, root optional. Exits `0` if nothing running is exposed, `1` if unfixed Node is running without the guard, `2` if some version couldn't be read |
| `scan` | Read-only. Finds application code and dependencies that call Node's Brotli decoder, grouped by application, plus single executable applications and startup snapshots that must be rebuilt (CVE-2026-106074). Exits `0` if it found nothing, `1` if it found something |
| `guard --unit U` | Installs the guard to `/usr/local/lib/privacysafe/brotli-guard.cjs`, self-tests it on `U`'s runtime as `U`'s user, and adds it to `NODE_OPTIONS` through a systemd drop-in. Then restarts `U`, checks it stays up and the guard is live, and rolls back if not. Skips a runtime that's already fixed (`--force` guards anyway), and doesn't start a service you'd stopped. Repeat `--unit` to guard several services |
| `unguard --unit U` | Removes the drop-in, restarts `U` and checks it comes back without the guard. Refuses to touch a drop-in this script didn't write |
| `status` | Lists guarded services, their Node version and whether it's fixed, and the call sites the guard blocked in the last 7 days. Tells you when a service is fixed and can be unguarded |
| `hunt` | Read-only log triage. Scans the journal, syslog, kernel log and pm2 logs for Node segfaults, V8 fatal errors, Brotli decoder frames in crashes, services killed by a crash signal, and guard events. Exits `0` if nothing matched, `1` if it found something to look at |
| `version` | Prints the script version. Every other command prints it on its first line too |

### What `check` looks at

1. **Runtimes on disk.** Everything on `PATH`, the usual system locations (`/usr/bin`, `/usr/local/bin`, `/opt`, snap), and every user's version manager: nvm, n, fnm, volta, asdf and mise.
2. **Running processes.** Every Node process, including renamed copies of the binary, with its user and systemd unit. It flags a process whose binary was replaced on disk since it started, because it still runs the old code until you restart it.
3. **Container images.** Images in Docker or Podman whose metadata declares `NODE_VERSION`, which covers the official `node` images and most images built on them. It reads image metadata only; nothing is started. Images that install Node another way aren't detected.
4. **Places it can't see.** Electron apps bundle their own Node and need an update from their vendor. The fixed Node releases also update Node's built-in CA store for the eMudhra compromise; see [below](../pki/README.md#emudhra-intermediate-ca-compromise-interim-mitigation).

The script reads each Node version from the binary's contents instead of running it, so root never executes a binary planted in a user's `~/.nvm` or inside a container. It only runs a binary when it can't read the version, and only if root owns it and nobody else can write to it.

### Node.js patch detection

For each runtime, three checks run in order, and the first that applies decides:

1. **`FIXED_BUILDS`.** Distro builds you list as fixed, for a backport the script doesn't know about. A build only counts for the same upstream version.
2. **Changelog.** For a runtime installed from a Debian or Ubuntu package, the package changelog names CVE-2026-111497. The changelog only counts if its newest entry is the installed version. This catches a distro that backports the fix to an end-of-life line without changing the upstream version, for example to the Node 20 a stable release ships.
3. **Upstream version.** The runtime is at or above the first fixed release for its line: 22.23.4, 24.22.1 or 26.12.1. Lines 25 and older have no fixed release, so without a backport they read as not fixed.

The result is *fixed*, *not fixed*, or *unknown*. *Unknown* means the version couldn't be read, usually because the script wasn't run as root.

### The guard on its own

`guard` needs systemd. Anywhere else, load the guard yourself. It has to load before your application code, so use `--require` or `NODE_OPTIONS`:

```bash
# directly
node --require /usr/local/lib/privacysafe/brotli-guard.cjs app.js

# through the environment, for anything that starts node for you
NODE_OPTIONS="--require=/usr/local/lib/privacysafe/brotli-guard.cjs" npm start

# pm2
pm2 start app.js --node-args="--require=/usr/local/lib/privacysafe/brotli-guard.cjs"
```

In a container, copy the file into the image and set `ENV NODE_OPTIONS=--require=/path/to/brotli-guard.cjs`. When the guard loads, it prints one line to stderr, `[brotli-guard] active ...`, so you can confirm it from the service's log.

Its behavior is set through the environment:

| Variable | Default | Purpose |
|---|---|---|
| `BROTLI_GUARD` | `block` | `block` refuses to decode. `log` decodes normally but reports each caller, so you can see what uses Brotli before you block it. `off` does nothing |
| `BROTLI_GUARD_FORCE` | *(unset)* | `1` keeps the guard active on a runtime that already has the fix |
| `BROTLI_GUARD_QUIET` | *(unset)* | `1` drops the startup line. Blocked calls are still reported |

### Node.js hunting for exploitation

A crash in Node's Brotli decoder doesn't show in application logs; it shows as a dead process. `hunt` reads the journal and system logs, never changes anything, and reports what it finds:

```bash
sudo ./node-oct2026-mitigate.sh hunt
```

It looks for Node segfaults and protection faults in the kernel log, V8 fatal errors, Brotli decoder frames in crash backtraces, services killed by `SIGSEGV`, `SIGABRT` or `SIGBUS`, and every decode the guard blocked. `HUNT_SINCE` sets how far back it reads.

A match is a lead, not proof. Buggy native addons crash Node too, and a segfaulting service may not be running Node at all. A crash in the Brotli decoder on an unfixed runtime is worth treating as an incident: check what the process could reach (secrets in its environment, database credentials, API tokens) and rotate them. A blocked decode on a route attackers can reach tells you which request to look at.

### Node.js configuration

| Variable | Default | Purpose |
|---|---|---|
| `NODE_FIXED_22`, `NODE_FIXED_24`, `NODE_FIXED_26` | `22.23.4`, `24.22.1`, `26.12.1` | First fixed release for each line |
| `FIXED_BUILDS` | *(empty)* | Extra fixed distro builds, space-separated full versions, for example a Debian backport to Node 20 |
| `SCAN_PATHS` | `/srv /opt /var/www /home /usr/local/lib /usr/lib/node_modules` | Where `scan` looks for code, SEAs and snapshots |
| `SCAN_DEPTH` | `8` | How deep `scan` goes |
| `GUARD_DST` | `/usr/local/lib/privacysafe/brotli-guard.cjs` | Where `guard` installs the guard |
| `HUNT_SINCE` | `2026-10-14` | How far back `hunt` reads the journal |

### Node.js know before you run it

- **This is not a patch.** Upgrade to Node.js 22.23.4, 24.22.1 or 26.12.1, restart, then run `unguard`. Node 25 and older will never be fixed; move to a supported line.
- **The guard only covers CVE-2026-111497.** The other nine CVEs (TLS hostname checks, DNS, keep-alive sockets, the permission model, ZipFile, random value caching) have no workaround here.
- **The guard covers Node's decoder as reached from JavaScript.** A native addon that calls the bundled Brotli library directly isn't covered, and neither is code that saved a reference to the zlib functions before the guard loaded. That's why it must load first.
- **Anything that really needs Brotli will fail.** A service that fetches from a server sending Brotli whatever it's asked for, or accepts Brotli-encoded request bodies, gets a decode error until you upgrade. Run with `BROTLI_GUARD=log` first if you're not sure.
- **`guard` refuses when an `EnvironmentFile` sets `NODE_OPTIONS`**, because that would silently override the drop-in. Add `--require=/usr/local/lib/privacysafe/brotli-guard.cjs` there yourself.
- **Processes that reset `NODE_OPTIONS`** won't carry the guard. Some wrapper scripts, pm2 ecosystem files and containers do this. `guard` warns when it can't confirm the guard is live.
- **Single executable applications and startup snapshots must be rebuilt** with a fixed Node (CVE-2026-106074). Treat `crypto.randomUUID()` and `randomInt()` values they produced as guessable, and rotate any that need to be secret.
- **Containers get their own fix.** Each image carries its own Node. Rebuild on a fixed base image; `check` lists the images it can see.
- **GNU/Linux only.** `check`, `scan` and `hunt` run on any GNU/Linux; `guard` and `unguard` need systemd.
- **Drop-ins** go to `/etc/systemd/system/<unit>.d/50-privacysafe-brotli-guard.conf`, and each records the script version that wrote it.
- **A pre-release is not the release.** `v24.22.1-pre`, `-rc.0` and `-nightly…` are builds made before 24.22.1, so at a fix version they are reported as unknown and the check exits `2`; one past the fix version is fixed. A runtime that cannot be read (including one the script declines to execute because of who owns it) is reported as unknown and no longer ends the run.
- **Runtimes are found anywhere on `PATH`**, as well as in the usual install locations and the common version-manager directories.

---

## 🏛️ Support PrivacySafe Foundation

[PrivacySafe Foundation](https://privacysafe.foundation) is a 501(c)(3) nonprofit public charity supporting Free/Libre and Open Source Software (FLOSS), cybersecurity education, decentralized technology, documentation, standards work, and public-interest privacy and security research.

Security work doesn't stop when a disclosure drops at midnight. If this repository helped you protect your users, please help us keep doing it:

* **[Donate directly to the Foundation](https://privacysafe.foundation)**
* [Open Collective](https://opencollective.com/privacysafe)
* [Ko-fi](https://ko-fi.com/R6R1194HN7)
* [Liberapay](https://liberapay.com/PrivacySafe/donate)

The Foundation website provides options for card donations, PayPal/Venmo, cryptocurrency, checks, and other forms of support. Donations are often tax-deductible in the USA. Federal EIN: 41-5237617.

## 🤝 Contributing

Found a bug in a script, or have a mitigation that belongs here? Please fork and submit a focused pull request.

⚠️ **Do not report unpatched vulnerabilities in a public issue.** Follow our [security policy](../SECURITY.md) instead. Never send sensitive information through ordinary direct messages or unencrypted email.

- **Contribution terms:** [`CONTRIBUTING.md`](../CONTRIBUTING.md)
- **Code of Conduct:** [`CODE_OF_CONDUCT.md`](../CODE_OF_CONDUCT.md)
- **AI Contribution Policy:** [`AI_POLICY.md`](../AI_POLICY.md)
- **Security and vulnerability reporting:** [`SECURITY.md`](../SECURITY.md)

## 🔐 More from PrivacySafe

* **[PrivacySafe](https://privacysafe.app):** Privacy-by-design software for home, teams, and organizations. Sign up free, no phone number required.
* **[Bits On Tape](https://bitsontape.com):** Our newsletter covering cybersecurity, privacy, FLOSS, AI, and digital culture.
* **[Ivy Cyber](https://ivycyber.com):** Hosting, enterprise deployment, training, and technical support, including help hardening your own infrastructure.

## ⚖️ License

<a href="https://creativecommons.org/publicdomain/zero/1.0/" rel="nofollow"><img src="https://licensebuttons.net/p/zero/1.0/88x31.png" alt="CC0" /></a>

Security patches belong to everyone. To the extent possible under law, <a href="https://ivycyber.com" rel="nofollow">Ivy Cyber LLC</a> has waived all copyright and related or neighboring rights to this repository, including its scripts and documentation, under the <a href="https://creativecommons.org/publicdomain/zero/1.0/" rel="nofollow">Creative Commons CC0 1.0 Universal Public Domain Dedication</a> (`CC0-1.0`). Feel free to copy, remix, and share. If you'd like to give back, please [donate to PrivacySafe Foundation](https://privacysafe.foundation) 501c3 nonprofit.

See [`NOTICE`](../NOTICE) and [`LICENSE`](../LICENSE). Third-party components retain their original copyrights and licenses.

CC0 does not waive trademark or patent rights. PrivacySafe® and 3NWeb® are registered trademarks. PrivacySafe Foundation™ and Ivy Cyber™ are pending trademarks. This dedication does not grant permission to use these marks in a manner that suggests sponsorship, endorsement, affiliation, or origin.
