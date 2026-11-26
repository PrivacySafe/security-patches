# nginx security releases

Part of the [PrivacySafe Security Patches](../../README.md) collection.

<a name="nginx2root"></a>

## nginx2root: HTTP/2, HTTP/3, resolver, mail-proxy and TLS flaws

**Script:** [`servers/nginx/nginx2root-check.sh`](nginx2root-check.sh)

nginx 1.30.7 (stable) and 1.31.9 (mainline), released 18 November 2026, [fix ten flaws](https://nginx.org/en/security_advisories.html) in all. This script actively audits for five of them, detailed below; the other five are fixed by the exact same two releases but not separately audited: CVE-2026-118899 (high: a TLS 1.3 worker can hang in a loop reading a request body on any `listen ... ssl;` server that allows TLS 1.3, a denial of service rather than code execution, with no F5 workaround published), CVE-2026-120967 (medium), and CVE-2026-120993, CVE-2026-125283, CVE-2026-123640 (low, opt-in features or limited impact). Upgrading closes all ten at once; an unpatched version is exposed to CVE-2026-118899 on nothing more than an ordinary TLS 1.3-enabled server block, the same way CVE-2026-123007 needs nothing but HTTP/2, so treat it the same way in your own risk accounting even though `check`'s audit output doesn't name it directive-by-directive.

F5 and nginx both rate two of the five audited flaws 9.2 (CVSS 4.0) critical. Two were independently found by five separate teams: Wiz Research, [Xint](https://nginx2root.com/), Metnir, Rapid7 and Ikotas Labs, who also call it NGINX2Shell (the same two bugs, not a sixth): CVE-2026-123007, an HTTP/2 flow-control integer underflow exploitable even on a plain static-file server with no backend, and CVE-2026-123633, a use-after-free reachable when HTTP/2 is proxied to an upstream and the worker is short of connection slots. Xint found three more on its own as part of research it names nginx2root: CVE-2026-123634 (a resolver use-after-free, reachable through `mirror` plus a request-derived `proxy_pass` target), CVE-2026-121810 (the same shape of bug over HTTP/3 instead of HTTP/2), and CVE-2026-113425 (a use-after-free in the mail proxy's `auth_http` path). Xint also chained CVE-2026-123007 with an undisclosed, unpatched, not-yet-numbered Linux kernel SCTP use-after-free to get root on the host, including out of a Docker container; that kernel bug is a different, newer issue from three already-fixed 2026 SCTP flaws in the kernel's own advisory history, one of them nicknamed "SCTPhantom", and this script cannot check for it, only help block the module that carries it. As of 22 November 2026 the fix for that kernel bug has merged into mainline (net-7.4-rc4, 19 November) but no stable kernel release carries it yet, and Docker's default seccomp profile does not block SCTP sockets, so blocking the module remains the only stopgap for anyone who can't run that unreleased kernel.

CVE-2026-123007 affects nginx 1.9.5 through 1.31.8 and needs nothing but HTTP/2 turned on; it was present in every official release for more than a decade. The other four each need a more specific setup:

| CVE | Needs, besides an unpatched version | First affected | `http2`/`http3 off` helps? |
|---|---|---|---|
| CVE-2026-123007 | HTTP/2 on, nothing else | 1.9.5 | yes |
| CVE-2026-123633 | HTTP/2 on, proxied to an upstream | 1.19.7 | yes |
| CVE-2026-123634 | `resolver`, a request-derived `proxy_pass`, and `mirror` | 0.6.18 | no |
| CVE-2026-121810 | HTTP/3 (`quic`) on, proxied to an upstream | 1.25.0 | no (`http3 off` helps) |
| CVE-2026-113425 | a `mail` block with `proxy on` and `auth_http` | 0.5.33 | no |

Rapid7 published a working proof of concept; it needs about 128 GB of HTTP/2 traffic over one connection and a glibc `memcpy` implementation chosen at runtime on CPUs with AVX-512. Xint's own write-up and demo instead walk through a build that resolves to the AVX2 `memcpy` path. Both are real, CPU-dependent variants of the same bug, not a disagreement between them: glibc picks one of several vectorized `memcpy` implementations at runtime based on the CPU's feature flags, and the backward-copy quirk both researchers describe exists in more than one of them. As of 19 November 2026 this is a complete, public, unauthenticated RCE: Rapid7's repository includes a runnable client that negotiates the attack over real TLS and HTTP/2, confirms the flow-control accounting error in-band, and then demonstrates arbitrary command execution against a freshly started nginx 1.31.8 container, with no backend and no authentication. The PoC itself cautions that it targets a single, lightly-loaded container and may not succeed against a server with a "messy" heap from prior traffic or multiple concurrent clients, so treat "works less reliably against a busy production server" as a property of this specific demonstration, not as a reason an unpatched server is safe. The fix (upgrade, or `mitigate --http2-off`) is unchanged by any of this.

`check` and `hunt` change nothing. `check` reports the nginx version on the host and in containers, and audits the running configuration (`nginx -T`) for each flaw's trigger directives, the same approach as [the October tool below](#nginx-october-2026-check): a match shows the ingredients are present, not a guarantee, and matches are not confirmed to share a server or location block. `hunt` looks for signs in the logs that match what Xint's own write-up says an attack leaves: sustained one-way traffic, requests that stay small while received bytes climb, and abnormal worker exits. None of it can see the `WINDOW_UPDATE` and `RST_STREAM` control frames the attack itself sends: those are not logged requests, and TLS hides them from a packet capture at the host. `mitigate` edits `nginx.conf` for three of the five flaws (`--http2-off` also covers the one chained with the kernel bug), backs up every file it touches, and rolls back automatically if nginx rejects the result. The fourth, the resolver and mirror flaw, needs a fixed upstream address only you know, so `rules` explains it instead of editing anything. The kernel flaw has its own `mitigate --block-sctp` option, since it is not an `nginx.conf` change.

### nginx2root quick start

1. Download the script.

   ```bash
   curl -fLO https://raw.githubusercontent.com/PrivacySafe/security-patches/refs/heads/main/servers/nginx/nginx2root-check.sh
   ```

2. Read it before running it, then make it executable.

   ```bash
   less nginx2root-check.sh
   chmod +x nginx2root-check.sh
   ```

3. See what's exposed. Run as root so `nginx -T` can read the full config and the package checks work.

   ```bash
   sudo ./nginx2root-check.sh check
   ```

4. The single broadest fix, if you can't upgrade yet:

   ```bash
   sudo ./nginx2root-check.sh mitigate --http2-off
   ```

### nginx2root commands

| Command | What it does |
|---|---|
| `check` (default) | nginx version on the host and in containers, and a configuration audit for the five flaws' trigger directives. Root optional, but `nginx -T` usually needs root to read the full config. Exits `0` if nothing is exposed, `1` if a vulnerable nginx is present, `2` if something couldn't be read |
| `hunt` | Read-only: connection and log signals from Section 3.2 of Xint's write-up (long-lived connections with far more received than sent, HTTP/2 requests whose logged length stays small while bytes climb, and abnormal nginx worker exits). None of this proves an attack on its own. Exits `0` if nothing found, `1` if it found a lead |
| `mitigate --http2-off \| --http3-off \| --mail-loopback \| --block-sctp [--force] [--dry-run] [--reload]` | **Changes the host (root).** With no option, applies `--http2-off`. Every `nginx.conf` file is copied first and checked with `nginx -t` before and after; if nginx rejects the result the originals are put back at once. `--block-sctp` is a `/etc/modprobe.d/` drop-in, not an `nginx.conf` change, and applies regardless of what `nginx -T` reports |
| `rollback [--dry-run] [--reload]` | Puts back everything `mitigate` changed, `nginx.conf` and the `modprobe.d` drop-in alike |
| `rules` | Prints the manual fix for CVE-2026-123634 and the exact `modprobe.d` line `--block-sctp` writes, for anyone who would rather add either by hand |
| `version` | Prints the script version |

### nginx2root workarounds: `mitigate`

| Option | Flaw(s) | What it does | What it changes |
|---|---|---|---|
| `--http2-off` | CVE-2026-123007, CVE-2026-123633 | Sets `http2 off;` (nginx >= 1.25.1) or drops the `http2` listen parameter (older), per F5's own workaround | Breaks anything that specifically needs HTTP/2, such as native gRPC |
| `--http3-off` | CVE-2026-121810 | Removes `quic` listen parameters, sets `http3 off;`, and replaces (or adds) an `Alt-Svc` header advertising HTTP/3 with `Alt-Svc 'clear'` | Breaks QUIC/HTTP/3 access; HTTP/1.1 and HTTP/2 keep working |
| `--mail-loopback` | CVE-2026-113425 | Binds every mail proxy `listen` directive on a standard mail port to `127.0.0.1` | Only this host can reach the mail proxy; remote mail clients lose access. Use a firewall instead, and skip this, if the proxy needs outside access |
| `--block-sctp` | the undisclosed kernel flaw | Adds `install sctp /bin/false` under `/etc/modprobe.d/` | `modprobe` refuses to load the `sctp` module from then on. Does not unload a copy already loaded (`lsmod \| grep sctp`), and does nothing on a kernel with SCTP compiled in rather than as a module. Skip this on a host that uses SCTP |

CVE-2026-123634 is **not** automated, because the fix needs your own backend address; see `rules`. After a change, `mitigate` re-runs the audit and says what is still exposed. `STATE_DIR` (default `/var/lib/psf-security-patches/nginx2root`) holds the backups and manifest.

Verified on nginx 1.24 (Ubuntu): the audit reported all of CVE-2026-123007, CVE-2026-123633, CVE-2026-123634 and CVE-2026-113425 against test configurations matching each flaw's trigger directives, and correctly reported CVE-2026-121810 as not configured when no HTTP/3 directive was present. After `mitigate --http2-off`, `nginx -t` accepted the result and the re-audit no longer reported either HTTP/2 flaw; `rollback` restored the file exactly. The same cycle was confirmed for `--mail-loopback`, including that a mail proxy already bound to loopback alone is correctly reported as not exposed, and a second, public-bound listener added alongside it is correctly caught. `--block-sctp` was confirmed idempotent (a second run reports the block is already in place) and its rollback removes the file. `--http3-off` could not be run through a live `nginx -t`, because this build's nginx has no `http_v3_module`; its text transformation was instead verified directly, including that it replaces an existing `Alt-Svc` header's value in place rather than deleting it, and that re-running it a second time (recomputing the same way `mitigate` does) makes no further change either way.

## Before you run it (nginx2root)

- The fix is to upgrade to 1.30.7 (stable) or 1.31.9 (mainline), or your distribution's backport, then reload. As of 18 November 2026, Debian's and Ubuntu's own security trackers both still marked every supported release vulnerable; no distro had shipped a backport yet.
- CVE-2026-123007 needs nothing but HTTP/2 turned on, so treat an unpatched version as exposed to it even if you skip or can't run the configuration audit. The other four each need their own directive combination; see the table above.
- The config audit matches directives across the whole `nginx -T` output and cannot prove they share one server or location block, so treat an "exposed" line as "review this," not a verdict.
- `mitigate --http2-off` and `--http3-off` break anything that specifically depends on that protocol (native gRPC needs HTTP/2; QUIC-only clients need HTTP/3). `--mail-loopback` cuts off remote mail clients; use it only if the proxy doesn't need outside access, and prefer a firewall rule otherwise.
- `--block-sctp` does nothing for a kernel that already has the module loaded, or one with SCTP compiled in rather than built as a loadable module; check `lsmod | grep sctp` first, and skip this option entirely on a host that uses SCTP.
- The kernel flaw is CVE-2026-64564 (Linux SCTP ASCONF use-after-free, present since 4.15, Red Hat CVSS 3.1 7.8). Its fix merged into mainline on 19 November 2026, but no stable kernel release carried it as of 22 November, so judge a kernel by your distribution's advisory, not by the upstream version number. This script cannot detect it; `--block-sctp` only reduces exposure to the one chain Xint demonstrated, and does nothing about any other local-privilege-escalation path.
- GNU/Linux only.

<a name="nginx-october-2026-check"></a>

## nginx October 2026 Check

**Script:** [`servers/nginx/nginx-oct2026-check.sh`](nginx-oct2026-check.sh)

nginx 1.30.6 (stable) and 1.31.7 (mainline), released 14 October 2026, [fix five flaws](https://nginx.org/en/security_advisories.html). Three are memory bugs in a worker process (a crash, and possibly code execution): CVE-2026-15176 (`alias` with a `rewrite`), CVE-2026-93479 (a regex `map` whose captures are used by `root` or `log_format`), and CVE-2026-97205 (`aio` with SSI). One forges a TLS session that can bypass client-certificate checks (CVE-2026-97629, in the automatic rotation of session-ticket keys). One slips extra bytes into a proxied request (CVE-2026-95101, HTTP/3). The `njs` JavaScript module separately shipped 1.0.2 with two XML-module fixes (CVE-2026-101019, CVE-2026-101025). nginx rates all five medium. F5 scores the three memory bugs 9.2 (critical), the TLS flaw 8.3, and the HTTP/3 flaw 6.9. None was reported exploited as of mid-October 2026.

Each flaw needs a specific directive, so a vulnerable nginx version is not necessarily reachable. `check` and `hunt` change nothing. `check` reports the nginx and njs versions on the host and in containers, and audits the running configuration with `nginx -T` for the directive combination each flaw needs, printing F5's workaround for the ones you are exposed to. The fix is to upgrade to 1.30.6 or 1.31.7 (or your distribution's backport) and reload. Nginx publishes fixes for those two branches only, so an older branch such as 1.28 stays in the affected range unless your distribution backported the patches. `mitigate` applies the three simple workarounds for you, with a backup and an automatic undo; the others need an administrator to read the configuration.

### nginx quick start

1. Download the script. The repository is mirrored on GitHub and Codeberg; pick a base URL.

   ```bash
   # BASE from GitHub:   https://raw.githubusercontent.com/PrivacySafe/security-patches/refs/heads/main
   # BASE from Codeberg: https://codeberg.org/PrivacySafe/security-patches/raw/branch/main
   # curl -fLO "$BASE/servers/nginx/nginx-oct2026-check.sh"
   curl -fLO https://raw.githubusercontent.com/PrivacySafe/security-patches/refs/heads/main/servers/nginx/nginx-oct2026-check.sh
   ```

2. Read it before running it, then make it executable.

   ```bash
   less nginx-oct2026-check.sh
   chmod +x nginx-oct2026-check.sh
   ```

3. See what's exposed. Run as root so `nginx -T` can read the full config and the package checks work.

   ```bash
   sudo ./nginx-oct2026-check.sh check
   ```

4. Look for worker crashes.

   ```bash
   sudo ./nginx-oct2026-check.sh hunt
   ```

### nginx commands

| Command | What it does |
|---|---|
| `check` (default) | Reports the nginx and njs versions on the host and in running containers, and audits the running configuration (`nginx -T`) for the five flaws' trigger directives, printing F5's workaround for each one you are exposed to. Changes nothing, root recommended. Exits `0` if nothing is exposed, `1` if a vulnerable nginx/njs is present, `2` if something couldn't be read |
| `hunt` | Read-only log triage for nginx worker crashes (workers exited on a crash signal, segfaults, use-after-free/heap aborts), the likely symptom of the memory bugs. Exits `0` if nothing matched, `1` if it found something |
| `mitigate --tickets-off \| --aio-off \| --proxy-buffering-off [--force] [--dry-run] [--reload]` | **Changes the host (root).** Applies three of F5's workarounds, only for flaws the same configuration audit as `check` reports as exposed (a patched build, or a flaw your configuration cannot reach, is left alone unless you add `--force`). With no option it applies `--tickets-off` and `--aio-off`, the two low-impact measures; `--proxy-buffering-off` is added on request (see below). Every file is copied first and checked with `nginx -t` before and after; if nginx rejects the result the originals are put back at once. Reloads nothing unless you add `--reload` |
| `rollback [--dry-run] [--reload]` | Puts back every file `mitigate` changed |
| `version` | Prints the script version. Every command prints it on its first line too |

Commands that change the host need root. Run them with `sudo` from an admin account, not from a root login, so the change is recorded against a person. The script stops and prints the exact command if you forget:

```bash
sudo ./nginx-oct2026-check.sh mitigate --tickets-off --dry-run
sudo ./nginx-oct2026-check.sh mitigate --tickets-off
sudo ./nginx-oct2026-check.sh rollback
```

### nginx patch detection

nginx fixes land on the two current branches only: 1.30.6 (stable) and 1.31.7 (mainline). The script judges a version accordingly. A 1.30.x build is fixed at 1.30.6, a 1.31.x build at 1.31.7, and anything 1.32.0 or newer is fixed. An older branch (1.28 and earlier) upgrades to 1.30.6 or 1.31.7. For an nginx installed from a Debian or Ubuntu package, the package build and changelog are checked first (`FIXED_BUILDS` plus the changelog naming one of the CVEs), because a distribution can backport the fix while keeping the upstream version number. `njs` is judged against 1.0.2.

### nginx and CVE-2026-42533 (July)

A separate, critical flaw was fixed three months before this release. CVE-2026-42533 is a heap buffer overflow in nginx's script engine, the code that builds strings from variables for `set`, `rewrite`, `proxy_pass` and similar directives (CVSS 4.0 score 9.2). It is reached when a `map` does regular expression matching and a string expression uses captures that the map changed, or when a non-cacheable variable changes between the length pass and the copy pass of a script. Open source nginx 0.9.6 through 1.30.3 and 1.31.2 are affected, and 1.30.4 (stable) and 1.31.3 (mainline), released on 15 July 2026, fix it. A public proof of concept was reported on 27 July.

This tool does not audit for it by name. Its version bar, 1.30.6 and 1.31.7, is newer than that fix, so an nginx that passes `check` has it, and a distribution package is judged by its changelog for the October flaws. If you can only apply the July fix, 1.30.4 or 1.31.3, or your distribution's backport, closes that flaw and not the five of October.

**A reported regression in the Red Hat family backport.** On 4 November a downstream distribution reported that the backport of the CVE-2026-42533 fix in Red Hat family packages makes nginx answer a small share of requests with HTTP 500 and log `[alert] ... no buffer space in script copy`. It happens on configurations where a `set` or `rewrite` uses a variable from a `map` marked `volatile` whose value itself contains variables. The report traces it to nested script evaluation overwriting a global buffer end that the backport uses to avoid changing nginx's ABI, and describes the upstream fix as keeping that end per script engine, so only the Red Hat family backport is described as affected. It was reported to Red Hat as RHEL-300689, and Red Hat's packages did not have a fix when it was written. This report is not reproduced here; it is relayed as the downstream distribution's own account.

What to do: keep the CVE-2026-42533 fix, because the flaw is critical and reachable without a login. If you see that alert, look for a `volatile` map used in a `set` or `rewrite`. The report notes that a map without `volatile` is computed once and does not nest, which changes how often the value is recomputed, so check that before you rely on it. `check` prints an information line, and changes no verdict or exit code, when the running configuration has a `volatile` map on a Red Hat family host.

### nginx configuration audit

The valuable part. Each of the five flaws needs a particular directive combination, so the script runs `nginx -T` and reports, per flaw, whether your configuration reaches it:

- CVE-2026-15176: `alias` with a `rewrite` and a reference to `$request_filename`.
- CVE-2026-93479: a regex `map` whose captures are read by `root` or `log_format`.
- CVE-2026-97205: `aio` enabled together with SSI pages.
- CVE-2026-95101: HTTP/3 (`quic`) with `proxy_request_buffering` on (the default).
- CVE-2026-97629: `ssl_session_cache shared` without `ssl_session_ticket_key` (and not `ssl_session_tickets off`).

For each, it prints F5's workaround. The matches cover the whole dumped config, so check that the directives share a server or location block; the permanent fix is upgrading.

### nginx configuration

| Variable | Default | Purpose |
|---|---|---|
| `NGINX_STABLE_FIXED` | `1.30.6` | First fixed stable release |
| `NGINX_MAINLINE_FIXED` | `1.31.7` | First fixed mainline release |
| `NJS_FIXED` | `1.0.2` | First fixed njs release |
| `FIXED_BUILDS` | *(empty)* | Distro nginx builds known to carry the backported fix, space-separated full versions |
| `NGINX_T` | `1` | `0` skips the `nginx -T` config audit |
| `SCAN_CONTAINERS` | `1` | `0` skips reading nginx inside running containers |
| `HUNT_SINCE` | `2026-10-01` | How far back `hunt` reads the journal |
| `HUNT_LOGS` | *(empty)* | Extra log globs for `hunt` |

### nginx workarounds: `mitigate`

| Option | Flaw | What it does | What it changes |
|---|---|---|---|
| `--tickets-off` | CVE-2026-97629 | Where `ssl_session_cache` is `shared`, adds `ssl_session_tickets off` (an explicit `on` becomes `off`) | TLS session resumption through the shared cache still works; ticket resumption stops |
| `--aio-off` | CVE-2026-97205 | Replaces `aio on` and `aio threads` with `aio off` | Slower file serving under load; nothing breaks |
| `--proxy-buffering-off` | CVE-2026-95101 | Sets `proxy_request_buffering off` at the `http` level, or turns an explicit `on` into `off` (only when the configuration sets it nowhere else) | Request bodies are streamed to the upstream: retries stop, and an upstream that needs `Content-Length` may fail |

CVE-2026-15176 (`alias` with a `rewrite` and `$request_filename`) and CVE-2026-93479 (a regex `map` whose captures feed `root` or `log_format`) are **not** automated, because they need someone to read the configuration. `mitigate` prints F5's advice for them when they are exposed. After a change it re-runs the audit and says what is still exposed. `STATE_DIR` (default `/var/lib/psf-security-patches/nginx`) holds the backups and manifest. `NGINX_BIN`, `NGINX_MAIN_CONF` and `NGINX_CONF_FILES` point it at a binary, a non-default main file and the files to edit.

Verified on nginx 1.24 serving TLS: the audit reported CVE-2026-97629 and CVE-2026-97205. After `mitigate --tickets-off --aio-off` and a reload the TLS 1.2 handshake no longer issued a session ticket, pages were served as before and the audit reported nothing exposed. `rollback` restored the file exactly. A configuration that does not validate is left untouched.

## Before you run it

- Updating for the July flaw, CVE-2026-42533, is covered by this tool's version bar. A Red Hat family build with that fix has a reported regression for configurations that use a `volatile` map (see the section above); keep the fix.
- The fix. Upgrade to 1.30.6 or 1.31.7 (or your distribution's backport) and reload. Upgrade njs to 1.0.2. The config audit tells you which workarounds apply in the meantime.
- A vulnerable version is not always reachable. Each flaw needs its directive, which is why the config audit matters. A build with none of the five directives configured is not a path, though upgrading is still the right move.
- `check` reads the configuration with `nginx -T`, which is nginx's own configuration test. If the configuration does not pass that test, nginx writes the error to its own error log, exactly as it does when you run the command yourself.
- The config audit matches directives across the whole `nginx -T` output and cannot prove they share one server or location, so treat an "exposed" line as "review this," not a verdict.
- `nginx -T` needs root and a valid config. Without them the audit is skipped and reported as unknown; the version checks still run.
- Distribution backports read correctly. A package can carry the fix under the old upstream number. Add a known-fixed build to `FIXED_BUILDS` if its changelog doesn't name a CVE.
- GNU/Linux only.

## Output for automation

`nginx-oct2026-check.sh` writes JSON Lines with `--output jsonl` (or `PSF_OUTPUT=jsonl`) for monitoring and language models, and says so when a host has no nginx or njs (`applicable: false`); `psf-report` turns the records into a summary, Markdown, HTML or PDF. `PSF_READ_ONLY=1` refuses its `mitigate` and `rollback` before they start. The other nginx tools here follow. The format and the reports: [Output for automation](../../automation/README.md).

<!-- rhsa:begin (generated by packaging/rhsa/rhsa.py from Red Hat's advisory list: edit placement.json or the data, not this block) -->
## Red Hat advisories

Red Hat's advisory list (security advisories released 2026-04-01 to 2026-11-25) names the CVEs below. A Red Hat build is judged by its RPM release, not by the upstream version number, because Red Hat backports fixes: the advisory names the release that fixes it. A CVE with no advisory in the list has none for that period, which is not the same as not affected. The current state is on [Red Hat's CVE database](https://access.redhat.com/security/security-updates/#/cve).

| Advisory | Released | Severity | Package and stream | CVEs on this page |
|---|---|---|---|---|
| [RHSA-2026:46012](https://access.redhat.com/errata/RHSA-2026:46012) | 2026-07-26 | Important | `nginx-1.30.4-2.hum1` (Hummingbird) | CVE-2026-42533 |
| [RHSA-2026:66542](https://access.redhat.com/errata/RHSA-2026:66542) | 2026-09-11 | Important | `nginx-1.20.1-28.el9_8.6` (RHEL 9.8) | CVE-2026-42533 |
| [RHSA-2026:67283](https://access.redhat.com/errata/RHSA-2026:67283) | 2026-09-14 | Moderate | `nginx-1.26.3-9.module+el9.8.0+24845+a897661e.4` (RHEL 9.8) | CVE-2026-42533 |
| [RHSA-2026:67308](https://access.redhat.com/errata/RHSA-2026:67308) | 2026-09-14 | Moderate | `nginx-1.24.0-7.module+el9.8.0+24846+e7eec568.5` (RHEL 9.8) | CVE-2026-42533 |
| [RHSA-2026:67314](https://access.redhat.com/errata/RHSA-2026:67314) | 2026-09-14 | Important | `nginx-1.26.3-6.el10_2.7` (RHEL 10.2) | CVE-2026-42533 |
| [RHSA-2026:67315](https://access.redhat.com/errata/RHSA-2026:67315) | 2026-09-14 | Moderate | `nginx-1.24.0-3.module+el8.10.0+24848+0300f002.5` (RHEL 8.10) | CVE-2026-42533 |
| [RHSA-2026:79357](https://access.redhat.com/errata/RHSA-2026:79357) | 2026-10-08 | Important | `costmanagement/costmanagement-ui-rhel10` (container image) | CVE-2026-42533 |
| [RHSA-2026:83427](https://access.redhat.com/errata/RHSA-2026:83427) | 2026-10-15 | Important | `nginx-1.30.6-1.hum1` (Hummingbird) | CVE-2026-15176, CVE-2026-95101, CVE-2026-97205, CVE-2026-97629, CVE-2026-120993 |
| [RHSA-2026:93467](https://access.redhat.com/errata/RHSA-2026:93467) | 2026-11-02 | Important | `nginx-1.20.1-22.el9_6.7` (RHEL 9.6) | CVE-2026-42533 |
| [RHSA-2026:93468](https://access.redhat.com/errata/RHSA-2026:93468) | 2026-11-02 | Important | `nginx-1.20.1-16.el9_4.7` (RHEL 9.4) | CVE-2026-42533 |
| [RHSA-2026:93472](https://access.redhat.com/errata/RHSA-2026:93472) | 2026-11-02 | Important | `nginx-1.20.1-14.el9_2.7` (RHEL 9.2) | CVE-2026-42533 |
| [RHSA-2026:98527](https://access.redhat.com/errata/RHSA-2026:98527) | 2026-11-11 | Important | `nginx-1.26.3-10.module+el9.9.0+25249+8b47ea83.1` (RHEL 9.9) | CVE-2026-15176, CVE-2026-97205 |
| [RHSA-2026:98528](https://access.redhat.com/errata/RHSA-2026:98528) | 2026-11-11 | Important | `nginx-1.24.0-9.module+el9.9.0+25250+16ab46e3.1` (RHEL 9.9) | CVE-2026-15176, CVE-2026-97205 |
| [RHSA-2026:98529](https://access.redhat.com/errata/RHSA-2026:98529) | 2026-11-11 | Important | `nginx-1.20.1-32.el9_9.1` (RHEL 9.9) | CVE-2026-15176, CVE-2026-97205 |
| [RHSA-2026:98634](https://access.redhat.com/errata/RHSA-2026:98634) | 2026-11-11 | Important | `nginx-1.26.3-16.el10_3.1` (RHEL 10.3) | CVE-2026-15176, CVE-2026-97205 |
| [RHSA-2026:98671](https://access.redhat.com/errata/RHSA-2026:98671) | 2026-11-11 | Important | `nginx-1.24.0-3.module+el8.10.0+25265+69171071.6` (RHEL 8.10) | CVE-2026-15176, CVE-2026-97205 |
| [RHSA-2026:99156](https://access.redhat.com/errata/RHSA-2026:99156) | 2026-11-11 | Important | `nginx-1.26.3-6.el10_2.8` (RHEL 10.2) | CVE-2026-15176, CVE-2026-97205 |
| [RHSA-2026:99157](https://access.redhat.com/errata/RHSA-2026:99157) | 2026-11-12 | Important | `nginx-1.20.1-28.el9_8.7` (RHEL 9.8) | CVE-2026-15176, CVE-2026-97205 |
| [RHSA-2026:99158](https://access.redhat.com/errata/RHSA-2026:99158) | 2026-11-12 | Important | `nginx-1.24.0-7.module+el9.8.0+25264+0c16c726.6` (RHEL 9.8) | CVE-2026-15176, CVE-2026-97205 |
| [RHSA-2026:99159](https://access.redhat.com/errata/RHSA-2026:99159) | 2026-11-12 | Important | `nginx-1.26.3-9.module+el9.8.0+25246+e156b854.5` (RHEL 9.8) | CVE-2026-15176, CVE-2026-97205 |
| [RHSA-2026:100744](https://access.redhat.com/errata/RHSA-2026:100744) | 2026-11-20 | Critical | `nginx-1.26.3-16.el10_3.3` (RHEL 10.3) | CVE-2026-113425, CVE-2026-118899, CVE-2026-121810, CVE-2026-123007, CVE-2026-123633, CVE-2026-123634 |
| [RHSA-2026:100745](https://access.redhat.com/errata/RHSA-2026:100745) | 2026-11-20 | Critical | `nginx-1.26.3-10.module+el9.9.0+25360+9b756829.4` (RHEL 9.9) | CVE-2026-113425, CVE-2026-118899, CVE-2026-121810, CVE-2026-123007, CVE-2026-123633, CVE-2026-123634 |
| [RHSA-2026:100746](https://access.redhat.com/errata/RHSA-2026:100746) | 2026-11-20 | Critical | `nginx-1.24.0-9.module+el9.9.0+25361+10e8035d.4` (RHEL 9.9) | CVE-2026-113425, CVE-2026-118899, CVE-2026-123007, CVE-2026-123633, CVE-2026-123634 |
| [RHSA-2026:100747](https://access.redhat.com/errata/RHSA-2026:100747) | 2026-11-20 | Critical | `nginx-1.24.0-3.module+el8.10.0+25364+53b7037a.9` (RHEL 8.10) | CVE-2026-113425, CVE-2026-118899, CVE-2026-123007, CVE-2026-123633, CVE-2026-123634 |
| [RHSA-2026:100748](https://access.redhat.com/errata/RHSA-2026:100748) | 2026-11-20 | Critical | `nginx-1.20.1-32.el9_9.2` (RHEL 9.9) | CVE-2026-113425, CVE-2026-118899, CVE-2026-123007, CVE-2026-123633, CVE-2026-123634 |
| [RHSA-2026:100750](https://access.redhat.com/errata/RHSA-2026:100750) | 2026-11-20 | Critical | `nginx-1.24.0-7.module+el9.8.0+25374+40bd8b35.7` (RHEL 9.8) | CVE-2026-113425, CVE-2026-118899, CVE-2026-123007, CVE-2026-123633, CVE-2026-123634 |
| [RHSA-2026:100751](https://access.redhat.com/errata/RHSA-2026:100751) | 2026-11-20 | Critical | `nginx-1.26.3-9.module+el9.8.0+25375+bc5d6e7a.6` (RHEL 9.8) | CVE-2026-113425, CVE-2026-118899, CVE-2026-121810, CVE-2026-123007, CVE-2026-123633, CVE-2026-123634 |
| [RHSA-2026:100753](https://access.redhat.com/errata/RHSA-2026:100753) | 2026-11-20 | Critical | `nginx-1.20.1-28.el9_8.8` (RHEL 9.8) | CVE-2026-113425, CVE-2026-118899, CVE-2026-123007, CVE-2026-123633, CVE-2026-123634 |
| [RHSA-2026:100755](https://access.redhat.com/errata/RHSA-2026:100755) | 2026-11-20 | Critical | `nginx-1.24.0-1.module+el9.4.0+25370+afae48b9.6` (RHEL 9.4) | CVE-2026-15176, CVE-2026-42533, CVE-2026-97205, CVE-2026-113425, CVE-2026-118899, CVE-2026-123007, CVE-2026-123633, CVE-2026-123634 |
| [RHSA-2026:100756](https://access.redhat.com/errata/RHSA-2026:100756) | 2026-11-20 | Critical | `nginx-1.24.0-4.module+el9.6.0+25376+6e355f8f.4` (RHEL 9.6) | CVE-2026-15176, CVE-2026-42533, CVE-2026-97205, CVE-2026-113425, CVE-2026-118899, CVE-2026-123007, CVE-2026-123633, CVE-2026-123634 |
| [RHSA-2026:100757](https://access.redhat.com/errata/RHSA-2026:100757) | 2026-11-20 | Critical | `nginx-1.26.3-1.module+el9.6.0+25380+29da9a4e.5` (RHEL 9.6) | CVE-2026-15176, CVE-2026-42533, CVE-2026-97205, CVE-2026-113425, CVE-2026-118899, CVE-2026-121810, CVE-2026-123007, CVE-2026-123633, CVE-2026-123634 |
| [RHSA-2026:100768](https://access.redhat.com/errata/RHSA-2026:100768) | 2026-11-20 | Critical | `nginx-1.26.3-1.el10_0.10` (RHEL 10.0) | CVE-2026-15176, CVE-2026-42533, CVE-2026-97205, CVE-2026-113425, CVE-2026-118899, CVE-2026-121810, CVE-2026-123007, CVE-2026-123633, CVE-2026-123634 |
| [RHSA-2026:100769](https://access.redhat.com/errata/RHSA-2026:100769) | 2026-11-20 | Critical | `nginx-1.20.1-14.el9_2.8` (RHEL 9.2) | CVE-2026-15176, CVE-2026-97205, CVE-2026-113425, CVE-2026-118899, CVE-2026-123007, CVE-2026-123633, CVE-2026-123634 |
| [RHSA-2026:100804](https://access.redhat.com/errata/RHSA-2026:100804) | 2026-11-20 | Critical | `nginx-1.26.3-6.el10_2.9` (RHEL 10.2) | CVE-2026-113425, CVE-2026-118899, CVE-2026-121810, CVE-2026-123007, CVE-2026-123633, CVE-2026-123634 |
| [RHSA-2026:100814](https://access.redhat.com/errata/RHSA-2026:100814) | 2026-11-20 | Critical | `nginx-1.20.1-22.el9_6.8` (RHEL 9.6) | CVE-2026-15176, CVE-2026-97205, CVE-2026-113425, CVE-2026-118899, CVE-2026-123007, CVE-2026-123633, CVE-2026-123634 |
| [RHSA-2026:100822](https://access.redhat.com/errata/RHSA-2026:100822) | 2026-11-20 | Critical | `nginx-1.20.1-16.el9_4.8` (RHEL 9.4) | CVE-2026-15176, CVE-2026-97205, CVE-2026-113425, CVE-2026-118899, CVE-2026-123007, CVE-2026-123633, CVE-2026-123634 |
| [RHSA-2026:100838](https://access.redhat.com/errata/RHSA-2026:100838) | 2026-11-21 | Critical | `nginx-1.30.7-1.hum1` (Hummingbird) | CVE-2026-113425, CVE-2026-118899, CVE-2026-120967, CVE-2026-121810, CVE-2026-123007, CVE-2026-123633, CVE-2026-123634, CVE-2026-123640, CVE-2026-125283 |
| [RHSA-2026:102947](https://access.redhat.com/errata/RHSA-2026:102947) | 2026-11-24 | Critical | `rhui5/cds-kubernetes-rhel9` (container image); `rhui5/cds-rhel9` (container image); `rhui5/haproxy-rhel9` (container image); and 2 more | CVE-2026-15176, CVE-2026-97205, CVE-2026-113425, CVE-2026-118899, CVE-2026-121810, CVE-2026-123007, CVE-2026-123633, CVE-2026-123634 |

[CVE-2026-64564](https://access.redhat.com/security/cve/CVE-2026-64564): 25 advisories, listed in the [Red Hat advisories section of the linux-kernel README](../../system/linux-kernel/README.md#red-hat-advisories).

<!-- rhsa:end -->

---

## ⚠️ Important notice

These scripts are used on our production systems and undergo testing, but they may require adaptation for other environments. Review the source code before running any script, test changes in a non-production environment where possible, and maintain current backups. This software is provided without warranty.

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

⚠️ **Do not report unpatched vulnerabilities in a public issue.** Follow our [security policy](../../SECURITY.md) instead. Never send sensitive information through ordinary direct messages or unencrypted email.

- **Contribution terms:** [`CONTRIBUTING.md`](../../CONTRIBUTING.md)
- **Code of Conduct:** [`CODE_OF_CONDUCT.md`](../../CODE_OF_CONDUCT.md)
- **AI Contribution Policy:** [`AI_POLICY.md`](../../AI_POLICY.md)
- **Security and vulnerability reporting:** [`SECURITY.md`](../../SECURITY.md)

## 🔐 More from PrivacySafe

* **[PrivacySafe](https://privacysafe.app):** Privacy-by-design software for home, teams, and organizations. Sign up free, no phone number required.
* **[Bits On Tape](https://bitsontape.com):** Our newsletter covering cybersecurity, privacy, FLOSS, AI, and digital culture.
* **[Ivy Cyber](https://ivycyber.com):** Hosting, enterprise deployment, training, and technical support, including help hardening your own infrastructure.

## ⚖️ License

<a href="https://creativecommons.org/publicdomain/zero/1.0/" rel="nofollow"><img src="https://licensebuttons.net/p/zero/1.0/88x31.png" alt="CC0" /></a>

Security patches belong to everyone. To the extent possible under law, <a href="https://ivycyber.com" rel="nofollow">Ivy Cyber LLC</a> has waived all copyright and related or neighboring rights to this repository, including its scripts and documentation, under the <a href="https://creativecommons.org/publicdomain/zero/1.0/" rel="nofollow">Creative Commons CC0 1.0 Universal Public Domain Dedication</a> (`CC0-1.0`). Feel free to copy, remix, and share. If you'd like to give back, please [donate to PrivacySafe Foundation](https://privacysafe.foundation) 501c3 nonprofit.

See [`NOTICE`](../../NOTICE) and [`LICENSE`](../../LICENSE). Third-party components retain their original copyrights and licenses.

CC0 does not waive trademark or patent rights. PrivacySafe® and 3NWeb® are registered trademarks. PrivacySafe Foundation™ and Ivy Cyber™ are pending trademarks. This dedication does not grant permission to use these marks in a manner that suggests sponsorship, endorsement, affiliation, or origin.
