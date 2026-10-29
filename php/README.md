# PHP: PHP2Shell and session audit

Part of the [PrivacySafe Security Patches](../README.md) collection.

## PHP2Shell Interim Mitigation

**Script:** [`php/php2shell-mitigate.sh`](php2shell-mitigate.sh)

We published this script before upstream fixes became available for two zero-day vulnerabilities in PHP. It adds two layers of defense to every installed PHP-FPM from 7.0 through 8.5:

1. **An ini drop-in** that turns off `session.upload_progress`. PHP core developers dispute that this setting alone fully mitigates the vulnerability, so treat it as one layer, not a fix.
2. **An AppArmor profile** that stops FPM from executing shells and other binaries. This is the layer that keeps a successful exploit from turning into remote code execution. The profile is built from each version's own FPM config (log paths, sessions, sockets, extension directory), so it fits your server instead of a generic template. It lets FPM signal readiness to systemd, which every Debian, Ubuntu and sury unit requires (`Type=notify`). Where the parser supports it (AppArmor 3.0 and later), it declares `abi <abi/3.0>`, so the rules mean the same thing on Ubuntu and Debian 13.

The script includes checks and rollback procedures intended to reduce the risk of service disruption. It syntax-checks each profile before installing it. Then it tests FPM with a config check, a restart, a reload, and a socket check. Under systemd it also checks that the unit didn't restart itself during the test. PHP 8.4 and later units use `Restart=on-failure`, which can make a crash-looping FPM look active. If FPM won't come up, it falls back to complain mode, and if that still fails, it unloads the profile. Each PHP version is handled on its own, so a problem with one never blocks the others.

### PHP2Shell quick start

1. Download it. The repository is mirrored on GitHub and Codeberg; pick a base URL.

   ```bash
   # BASE from GitHub:   https://raw.githubusercontent.com/PrivacySafe/security-patches/refs/heads/main
   # BASE from Codeberg: https://codeberg.org/PrivacySafe/security-patches/raw/branch/main
   # curl -fLO "$BASE/php/php2shell-mitigate.sh"
   curl -fLO https://raw.githubusercontent.com/PrivacySafe/security-patches/refs/heads/main/php/php2shell-mitigate.sh
   ```

2. Read it before running it. Always.

   ```bash
   less php2shell-mitigate.sh
   ```

3. Make it executable.

   ```bash
   chmod +x php2shell-mitigate.sh
   ```

4. Check the environment. This changes nothing and needs no root.

   ```bash
   ./php2shell-mitigate.sh check
   ```

5. Apply, to every installed PHP-FPM, in complain mode.

   ```bash
   sudo ./php2shell-mitigate.sh
   ```

The repository lives on [GitHub](https://github.com/PrivacySafe/security-patches) and [Codeberg](https://codeberg.org/PrivacySafe/security-patches). To confirm both serve the same script, compare checksums:

```bash
sha256sum php2shell-mitigate.sh
curl -fsSL https://codeberg.org/PrivacySafe/security-patches/raw/branch/main/php/php2shell-mitigate.sh | sha256sum
```

Every command begins with an environment check and refuses to proceed on unsupported systems. See [Environment check](#php2shell-environment-check).

New profiles start in **complain mode**, which logs but does not block. Let real traffic run, then review and enforce:

```bash
sudo ./php2shell-mitigate.sh status     # what the profile would have blocked
sudo ./php2shell-mitigate.sh enforce    # start blocking
```

If `status` lists paths your app legitimately needs, such as an uploads or cache directory, add them to `/etc/apparmor.d/local/usr.sbin.php-fpm<version>` and rerun the script. That file is never overwritten.

### PHP2Shell commands

| Command | What it does |
|---|---|
| `check` | Environment report only. Changes nothing and doesn't need root. Exits `0` if clear, `1` on a hard blocker, `2` if `--ignore-env` would be needed |
| `apply` (default) | Installs the drop-in and profile, then tests FPM |
| `status` | Shows mitigation state and the AppArmor events logged under the current profile (since it was last written, at most 24 hours) |
| `enforce` | Switches to enforce mode. Refuses if complain mode logged accesses you haven't handled (override with `--force`) |
| `complain` | Switches back to log-only mode |
| `hunt` | Read-only log triage. Scans PHP-FPM, Apache and nginx logs for the memory-corruption crashes these bugs cause (including AddressSanitizer/debug-build double-free and use-after-free backtraces, and crashes through the built-in CLI server, `php -S`), and for signs of exploitation. Changes nothing, doesn't need root. Exits `0` if nothing matched, `1` if it found something to look at |
| `version` | Prints the script version. Every other command prints it on its first line too |
| `cleanup` | Removes the ini drop-in once you're patched, except `session.upload_progress = Off`, which stays until the build is also fixed for CVE-2026-115560 (set `PATCHED_115560_X_Y` once PHP names the release, or the package changelog naming the CVE is enough; `--force` removes it anyway). The AppArmor profile is left loaded, since it confines FPM against the next bug too (the patch doesn't). Once patched, either switch it on for real with `enforce`, or take it out with `remove` |
| `remove` | Removes the AppArmor profile entirely: unloads it from the kernel, deletes the profile, the `local/` override and any disable symlink, then confirms `aa-status` no longer lists FPM. Leaves the ini drop-in (that's `cleanup`'s job) and needs no patch. Refuses to touch a profile this script didn't create |

Add `--php 8.2` to any command to act on a single version.

### PHP2Shell environment check

Before changing anything, the script checks your server in this order and prints what it found:

1. **Operating system.** Debian, Ubuntu and Trisquel are supported, and so is any derivative. The check recognizes Linux Mint, Pop!_OS, elementary OS, Zorin OS, KDE neon, Kali, Raspberry Pi OS, PureOS, Parrot, deepin, TUXEDO OS, Devuan, MX Linux, antiX, SparkyLinux, Q4OS, Peppermint, BunsenLabs and siduction by name. It also accepts anything else whose `ID_LIKE` names Debian or Ubuntu, or that has `/etc/debian_version`. A derivative never stops the run. The check also reports the base release and the PHP version it ships.
2. **PHP.** Every PHP-FPM under `/usr/sbin`, its package version, whether it came from your distro or the ondrej/sury repository, and whether it's patched (see [Patch detection](#php2shell-patch-detection)). It flags PHP it can't protect: versions outside `SUPPORTED_VERS`, PHP-FPM built outside dpkg, LiteSpeed's `lsphp`, and Ubuntu 14.04's `php5` packages (reported against the ESM Legacy fix). Where no package fix is coming, it points to a third-party extension; see [Know before you run it](#php2shell-know-before-you-run-it).
3. **Web servers.** Apache and nginx (plus angie, lighttpd and caddy), whether each is running, and which PHP-FPM version each one actually sends traffic to.
4. **System.** Root, the init system, containers, AppArmor in the kernel, SELinux, and required tools. Without systemd (sysvinit or OpenRC, as on Devuan, MX and antiX), the script uses `service` and the PHP-FPM init scripts. It reads AppArmor events from `audit.log`, `kern.log` and `dmesg`.

Problems fall into two groups. **Hard blockers** always stop the run: a distribution that isn't Debian-based, no way to restart FPM (no systemd and no init script), no AppArmor in the kernel for `apply`, `enforce` or `complain`, not running as root, or no supported PHP-FPM. **Soft blockers** stop the run until you've looked at them, and `--ignore-env` lets you proceed:

- Apache running an **unpatched** mod_php. PHP inside Apache is not covered by this script, so you'd get a clean summary while Apache stays exposed. The report prints the upgrade and a one-line interim drop-in. Patched mod_php is only reported.
- Your running web server only uses PHP-FPM versions this run won't touch, for example nginx serving everything from PHP 8.4.

`--ignore-env` doesn't affect `--force`, and `--force` doesn't skip the environment check.

### PHP2Shell patch detection

For each PHP version, the report, `status` and `cleanup` say whether the installed package is fixed. Three checks run in order, and any one is enough:

1. **Upstream version.** The package is at or above the first fixed release: 8.2.35, 8.3.36, 8.4.27 or 8.5.12. This covers Debian, which ships the new upstream release (for example `8.4.27-1~deb13u1` in DSA-6574-1), and the sury repository.
2. **Known distro backport.** Ubuntu backports fixes without changing the upstream version, so `8.3.6-0ubuntu0.24.04.13` is fixed even though it says 8.3.6. The script carries the fixed builds from USN-8948 for 16.04 through 26.10 and compares the full version. On 14.04, whose `php5` packages Ubuntu also fixed (`5.5.9+dfsg-1ubuntu4.29+esm18`, ESM Legacy), the environment check reports whether `php5-fpm`, `libapache2-mod-php5` and `php5-cgi` carry the fix, but doesn't mitigate them. Add builds as they're published with `FIXED_BUILDS`.
3. **Changelog.** The package changelog names both CVEs. This catches backports the script doesn't know about. The changelog only counts if its newest entry is the installed version.

If none of those finds a fix, a build below the first fixed release counts as *not patched* unless it's an Ubuntu build. sury and Debian ship the new upstream release rather than backporting, so their older upstream versions are unfixed even when there's no changelog to read, as on Docker images.

The result is *patched*, *not patched*, or *unknown*. *Unknown* usually means an Ubuntu build on a minimized image that dropped `/usr/share/doc`, with no entry in the table. Package dates aren't used: distributions prepare embargoed fixes before the public release, and a later unrelated rebuild doesn't contain the fix.

A patched package isn't enough on its own, because a running FPM keeps executing the old binary until it restarts. The script checks for FPM processes still running a binary that dpkg has replaced, and for Apache holding an old `libphp*.so`, and tells you which service to restart.

### PHP2Shell hunting for exploitation

These vulnerabilities affect PHP below the application layer, so application logs may contain little evidence. Possible indicators include memory-corruption crashes and unexpected commands executed by PHP worker processes. `hunt` reads your logs (never changes anything) and reports both:

```bash
sudo ./php2shell-mitigate.sh hunt
```

It looks for crashed PHP-FPM and Apache workers (segfault, abort, bus error), allocator panics including the `double free detected` message a separate unpatched PHP bug produces, AddressSanitizer and debug-build crash backtraces that name the Zend allocator (`attempting double-free`, `heap-use-after-free`, the `__zend_free`/`_efree` frames in `zend_alloc.c`), crashes that pass through PHP's built-in CLI server (`php_cli_server_*` frames, the `PHP x.y.z Development Server` banner), bursts of `memory_limit` fatals (php2shell's out-of-memory trigger), the `PHP_SESSION_UPLOAD_PROGRESS` field, PHP processes that ran a shell or download tool, and, if a profile from this script is loaded, any exec attempt it logged. Where log lines are dated it prints a rough before/after split around the disclosure date, so a spike stands out.

It also covers the serialized-object variant of the upload-progress attack seen on 2026-10-21, where a PHP gadget chain is sent in the upload-progress field, lands in the session file, and fires on the next page load. The object travels in the POST body and sits in the session file, neither of which a log tailer can see, so `hunt` and `php2shell-watch.sh` catch this one only when it surfaces an error: the `p2s:s` campaign marker reaching a log (the broken probe command echoes it under bash), a shell spawned by a worker that then fails, or the object failing to deserialize (`unserialize()` errors, incomplete-class, session-decode failures). A silent, successful chain leaves nothing in the logs; the payload in the session file is the ground truth, so check `session.save_path` directly if you suspect this.

A separate crash signature turned up on 2026-10-22: the same allocator double-free (`free` -> `__zend_free` -> `_efree` in `zend_alloc.c`), reported by AddressSanitizer and reproduced through PHP's built-in CLI server (`php -S`) with a crafted POST body. Two things make it easy to miss. First, a sanitizer or debug build phrases the double-free differently from the `double free detected` line a release build prints, so the older allocator pattern didn't catch it; `hunt` now matches the ASan verdict lines and the Zend allocator frames as well. Second, the CLI server writes its crash backtrace to the process's **stderr** rather than a logfile, so neither `hunt` nor the watcher sees it unless you redirect `php -S` (or FPM) stderr into one of the scanned files. Most important, it reproduced on **8.5.12**, the release this script otherwise treats as fixed: it is unconfirmed on a stock release build and may be a distinct bug, so the script's patched baseline is left unchanged, but if you want your hosts to stop reading 8.5.12 as safe, set `PATCHED_8_5=8.5.13` (or the real fixed release once one ships) and the mitigations stay applied. The AppArmor layer confines PHP-FPM only; it does not wrap the `php` CLI binary, so on the dev server the only real defenses are patching PHP and not exposing `php -S` to untrusted traffic.

A match is a lead, not proof. Buggy extensions crash workers too, and the upload-progress field appears in legitimate forms. Compare the counts against a quiet period, correlate crashes with memory-limit fatals and multipart POSTs from the same client, and check the web root for new files. The core signatures were confirmed against real PHP-FPM 8.4 output; the sanitizer and CLI-server signatures were confirmed against the 2026-10-22 `php -S` AddressSanitizer trace. Applying this script's AppArmor profile in complain mode first makes `hunt` more useful, because it turns any FPM attempt to run a binary into a logged signal.

`hunt` also checks the indicators from a 24 October 2026 honeypot report by the phpot project ([the phpot report](https://github.com/0x4D31/honeypot-data/blob/main/reports/php2shell/2026-10-24-confirmed-rce.md)) that tied 35 Apache-parent `/bin/sh` starts to complete HTTP requests on single-worker Apache `mod_php` running PHP 8.4.26, which is below the 8.4.27 fix. Read them as leads ordered by strength. The strongest are process-level: a shell or fetch tool running now under a web or PHP worker (with its TCP peers), repeated pre-script out-of-memory errors from one client, and proof-style files (`id` output) in temp directories and web roots. Weaker are the request fingerprint (`?q0=v&q1=v&q2=v...` in its short form or `?q0000000=v&q0000001=v...` in its long form; both are matched), traffic from the two source addresses the phpot report confirmed (`HUNT_IPS`) and from two that sent exploit-shaped requests with no shell seen (`HUNT_ATTEMPT_IPS`, attempt indicators only), and leak-sized responses: a `PHPSESSID` value thousands of characters long (the disclosure stage returned a `PHPSESSID` of 819,200 bytes decoded, about 2 MB on the wire) or a POST whose logged response is half a megabyte or more. The size lead works only in a log that counts header bytes (Apache `%O`, which is the Debian and Ubuntu default, or nginx `$bytes_sent`), and `hunt` never prints a cookie value, because it is leaked process memory. On nginx, whose default access log cannot show response header size, the matching lead is the `upstream sent too big header` error in its error log. If the auditd rule from [`php/detect/`](detect/README.md) is loaded, `hunt` also reads the program starts it recorded, the one way to see a shell that started and exited between process samples.

None of these is proof on its own. The phpot report's final request could fail to reach the access log because the worker died, so a missing line is not evidence that nothing ran, and an HTTP 200 on one stage is not evidence the attempt failed.

### Watching live

`hunt` is a one-shot scan. To watch continuously, the standalone [`php/php2shell-watch.sh`](php2shell-watch.sh) follows the same logs with `tail -F` and prints one line per hit, so a sysadmin can leave it running and watch the output:

```bash
sudo nohup ./php2shell-watch.sh >/var/log/php2shell-watch.log 2>&1 &
tail -f /var/log/php2shell-watch.log
```

It survives log rotation, prints a count summary on stop, and changes nothing. A [systemd unit](php2shell-watch.service) is included for running it as a managed service (`journalctl -fu php2shell-watch`). The same caveat applies: a hit is a lead to investigate, not proof of compromise.

Since 2026-10-23 it also carries two signals ReliaQuest reported from lab reproduction of CVE-2026-109618. First, a memory error that ends with `in Unknown on line 0`: during exploitation PHP reports the failure before an application file is in scope, so the error names no file, which is a stronger tell than an ordinary memory-limit fatal (and the failed allocation can be small, so the signal does not depend on its size). Second, a correlation: a POST that returns HTTP 500 followed within a few seconds by the worker that handled it crashing, tied together by the worker PID appearing in both logs. The watch arms a PID when an access-log line shows a POST with a 500 status, and raises an `ALERT` if a same-PID crash (`zend_mm_heap corrupted`, `AH00052`, an abort/segfault signal, or `in Unknown on line 0`) lands within `CORRELATE_WINDOW` seconds (default 10). This needs an access log that records the PID among the watched files; for Apache that means `%P` in the `LogFormat`. With no access log present the correlation stays off and the per-line signatures still work. The default log set now includes the common access-log paths for this reason.

The watcher also runs a process watch: it samples `/proc` once a second and reports a new shell or tool (`sh`, `curl`, `wget`, PHP CLI and similar) whose ancestry includes a web server or PHP worker, which was the phpot report's strongest signal. It is a poller, so it can miss a process that lives less than the interval, and a shell whose worker has already died is re-parented and no longer links to it (the phpot report's worker crashed about 0.7 seconds after starting the shell). The auditd rule in [`php/detect/`](detect/README.md) has no such gap. Set `PROCS=0` to turn the watch off, or `PROC_ALLOW` to ignore an application that legitimately shells out. A flagged process shows its TCP peers, for example `[tcp: SYN-SENT->203.0.113.9:8080]`. Two more signals work from logs and need no access-log line: a pre-script out-of-memory error followed by a crash of the same worker (the shape of the confirmed chain), and repeated pre-script out-of-memory errors from one client. It also matches the short numbered request fingerprint, raises a `LEAD` for a POST with a very large response or a `PHPSESSID` value thousands of characters long, and flags the edge cookie guard's log line and nginx's `upstream sent too big header` error.

Two of those alerts, the per-client burst and the same-worker chain, need the error-log line to carry the worker PID and the client address. Apache's own error log does. PHP's own `error_log` file format (`[23-Oct-2026 09:08:35 UTC] PHP Fatal error: ...`) carries neither, so those two alerts cannot fire from it, although the single-line signature still does. Under `mod_php`, leave `error_log` unset so PHP errors go to Apache's error log. The watcher prints a one-time `NOTE` when it sees an out-of-memory line it cannot attribute, and `hunt` says how many such lines it could not count.

### PHP2Shell configuration

| Variable | Default | Purpose |
|---|---|---|
| `WEB_ROOTS` | `/var/www /srv/www` | Read-only document roots |
| `WRITABLE_PATHS` | *(empty)* | Paths your app writes to, such as uploads |
| `PATCHED_X_Y` (for example `PATCHED_8_4`) | `8.2.35`, `8.3.36`, `8.4.27`, `8.5.12`; empty for 7.0-8.1 | First fixed upstream release for each branch |
| `GUARD_HINT` | `1` | Set to `0` to stop the environment check pointing to the third-party extension for PHP this script can't cover |
| `PATCHED_115560_X_Y` | *(empty)* | First release fixing CVE-2026-115560 for branch X.Y. Until set, only a changelog naming the CVE counts |
| `SUPPORTED_VERS` | `7.0 7.1 7.2 7.3 7.4 8.0 8.1 8.2 8.3 8.4 8.5` | Versions the script will touch |
| `FIXED_BUILDS` | *(empty)* | Extra fixed distro builds, space-separated full versions, for example a Debian LTS 7.4 update |
| `HUNT_IPS` | `15.204.59.70 162.35.99.94` | Source addresses reported in confirmed exploitation. An ageing indicator: a hit means the address touched you, not what it did. Empty turns it off |
| `HUNT_ATTEMPT_IPS` | `104.28.208.84 144.48.4.242` | Addresses that sent exploit-shaped requests with no shell seen: attempt indicators, not confirmed RCE, and shared addresses are possible. Empty turns it off |
| `PROOF_SINCE` | `2026-10-01` | `hunt`'s proof-file scan ignores older files |
| `HUNT_PROC_ALLOW` | `rotatelogs\|cronolog\|logger` | Regex on the command line: `hunt`'s live process check ignores matches |
| `COOKIE_MAX` | `4096` | Flag a `PHPSESSID` value this many characters long, in a log that records response cookies. `0` turns it off. Also read by `php2shell-watch.sh` |
| `RESP_BYTES_MAX` | `500000` | Flag a POST whose logged response is this many bytes. Needs a log that counts header bytes. `0` turns it off. Also read by `php2shell-watch.sh` |

`php2shell-watch.sh` reads its own variables, each documented at the top of the script: `LOGS`, `WATCH_IPS`, `PROCS`, `PROC_INTERVAL`, `PROC_CMD_MAX`, `PROC_ALLOW`, `CORRELATE_WINDOW`, `CHAIN_WINDOW`, `OOM_CLIENT_THRESHOLD`, `OOM_CLIENT_WINDOW`, `COOKIE_MAX` and `RESP_BYTES_MAX`.

When no upstream fixed version is set for a branch, the script checks your distro's changelog for both CVEs instead. That catches backported fixes from Ubuntu, Debian, and the ondrej/sury PPAs, which often keep the old version number.

### PHP2Shell on cPanel (EasyApache 4)

`php2shell-mitigate.sh` assumes Debian-family packages and does not touch a cPanel server's EasyApache 4 PHP (`/opt/cpanel/ea-php74` to `ea-php85`). `php2shell-cpanel-mitigate.sh` covers it, under any handler (`mod_php`, PHP-FPM, CGI or LSAPI). It writes one drop-in per PHP version, named so that it loads after every other file in that version's `php.d` directory and therefore wins over `php.ini` and the MultiPHP INI Editor. It never edits `php.ini`.

1. Download it. The repository is mirrored on GitHub and Codeberg; pick a base URL.

   ```bash
   # BASE from GitHub:   https://raw.githubusercontent.com/PrivacySafe/security-patches/refs/heads/main
   # BASE from Codeberg: https://codeberg.org/PrivacySafe/security-patches/raw/branch/main
   # curl -fLO "$BASE/php/php2shell-cpanel-mitigate.sh"
   curl -fLO https://raw.githubusercontent.com/PrivacySafe/security-patches/refs/heads/main/php/php2shell-cpanel-mitigate.sh
   ```

2. Read it before running it. Always.

   ```bash
   less php2shell-cpanel-mitigate.sh
   ```

3. Make it executable.

   ```bash
   chmod +x php2shell-cpanel-mitigate.sh
   ```

4. See what you have. This changes nothing.

   ```bash
   sudo ./php2shell-cpanel-mitigate.sh check
   ```

5. If a version is unpatched and you cannot update the `ea-php` packages today, apply the interim drop-in. This restarts Apache and any running `ea-php` FPM pools; add `--no-restart` to do that yourself at a time you choose.

   ```bash
   sudo ./php2shell-cpanel-mitigate.sh apply
   ```

| Command | What it does |
|---|---|
| `check` (default) | Read-only report, and the file `apply` would write for each version |
| `apply` | Writes the drop-in for every version, confirms PHP reports the values, and restarts Apache and FPM |
| `status` | What is in place now, and whether any web server or FPM process still runs with the old settings |
| `restore` | Removes the drop-ins this script wrote |
| `cleanup` | Once a version is patched, reduces its drop-in to the single line CVE-2026-115560 still needs (`--force` does this for an unpatched version too) |

The options are `--post-max SIZE`, `--upload-max SIZE`, `--memory-unlimited`, `--no-restart`, `--no-scan` and `--force`; `--help` describes each.

What the drop-in sets:

| Setting | When | Why |
|---|---|---|
| `session.upload_progress.enabled = 0` | Every version, patched or not | CVE-2026-115560 is not fixed by the 21 October releases |
| `fatal_error_backtraces = 0` | PHP 8.5, unpatched builds only | Removes the fatal-error-backtrace variant |
| `memory_limit = -1` | Only with `--memory-unlimited`, unpatched builds only | PHP's own interim measure; it trades the remote code execution for denial of service, so pair it with a request body cap (see [`php/edge/`](edge/README.md)) |
| `post_max_size`, `upload_max_filesize` | Only with `--post-max` (and `--upload-max`) | Capped to the smaller of the current value and your ceiling; never raised. A chunked request can pass `post_max_size`, so this narrows the exposure and does not close it |

Besides the version table, `check` reports:

- the PHP handler of each version, read from WHM when `whmapi1` is present (best effort: a version it cannot place shows as `unknown`);
- whether each version is patched, by version number or because its package changelog names both CVEs. An end-of-life branch counts as unpatched unless a changelog names both;
- settings elsewhere that can undo the drop-in: FPM pool entries, and `.htaccess` `php_value` and `php_flag` lines and `.user.ini` files under the home directories (a `php.ini` in a home directory loads before the drop-in, so the drop-in wins over it);
- Apache `RLimitMEM` and `RLimitCPU`. They limit processes Apache itself forks (CGI, suEXEC, suPHP), and PHP's advisory warns against an address-space limit as a memory cap, because a failed allocation sends PHP down the vulnerable path. WHM regenerates `httpd.conf`, so change them in WHM, not by hand.

`check` exits 0 when every version is patched and nothing needs review, 1 when an unpatched version is present, and 2 when everything is patched but something above is worth a look.

Limits:

- `check` prints the exact plan before `apply` makes any change, and `restore` reverts a drop-in it wrote.
- The drop-in loses to settings applied later: `.htaccess` and `.user.ini` values, and FPM pool values. `check` lists them; the script does not change them.
- `apply` restarts Apache through cPanel's `restartsrv_httpd`, which interrupts connections briefly. LiteSpeed's own workers are not restarted: restart LiteSpeed yourself.
- The [Apache edge guard](edge/README.md) can be added through WHM's Apache include editor, so that cPanel keeps it when it regenerates `httpd.conf`.

### Edge guards and detection content

Two optional folders sit beside the scripts. Both are compensating controls, not fixes. [`php/edge/`](edge/README.md) has Apache and nginx guards that reject a multipart POST to a path that takes no uploads (log-only until you enforce) and, on Apache, replace an oversized `Set-Cookie`, plus guidance on a request body size limit, measured against the phpot report's stage sizes. They were verified with real PHP handlers (Apache 2.4.58 with `mod_php`, nginx 1.24.0 with PHP-FPM), and they matter most for Apache `mod_php`, which the AppArmor layer does not confine. [`php/detect/`](detect/README.md) has an auditd rule that records every program the web-server account starts, a Tetragon filter for the same signal, a log-only outbound-connection rule, and a table of how strong each signal is. The auditd rule and the nftables rule load on a live kernel.

### How exploitable is it, and since when

PHP's advisory says complete remote code execution for CVE-2026-109618 was validated over HTTP against Apache `mod_php` with default PHP input and memory limits, and that PHP validated remote code execution against PHP-FPM for CVE-2026-109619 (as quoted by HeroDevs and Rescana). Wiz demonstrated chains against stock WordPress, Drupal and Joomla images (as summarized by Corgea), and the phpot honeypot report recorded 35 Apache-parent shell starts on single-worker `mod_php` running PHP 8.4.26. The phpot report found the observed chain consistent with CVE-2026-109618 and did not establish a CVE-2026-109619 path. Early claims that the public proofs of concept were fake or hard to use did not hold up.

Exploitation also began before the release. Amazon reported its first in-the-wild attempt on 17 October 2026 (as summarized by Corgea), four days before the 21 October fix, so start log hunting from 17 October, not 21 October. `hunt`'s dated before and after split uses 21 October as its baseline, so a count from before that date is not a quiet baseline.

### PHP interim measures and what they cost

PHP's advisories name interim measures beyond the ones `php2shell-mitigate.sh` applies. PHP says they "reduce exposure to specific attack paths but do not make an installation safe", and its releases state that updating is the only complete fix. The table lists each measure, what it addresses, what it costs, and whether this script applies it. The details come from PHP's advisories ([CVE-2026-109618](https://github.com/php/php-src/security/advisories/GHSA-w8hw-w9fx-j79w) and [CVE-2026-109619](https://github.com/php/php-src/security/advisories/GHSA-6wmf-4rv5-p3rp)) as summarized by HeroDevs and Corgea. Check the advisories for their exact wording before relying on a setting.

| Measure | What it addresses | Cost or risk | Applied by this script? |
|---|---|---|---|
| `memory_limit = -1`, set administratively (`php_admin_value` or the main `php.ini`, not `.user.ini`), every worker restarted, and confirmed that no pool, directory or application setting restores a finite limit | Removes the out-of-memory condition CVE-2026-109618 depends on | Trades the RCE for denial of service: one request can consume all memory. Pair it with a body cap | No. A host-wide memory decision is yours |
| `session.upload_progress.enabled = 0` | The upload-progress producer and consumer paths, and the cookie-disclosure path | Breaks upload progress bars | Yes (the drop-in) |
| `fatal_error_backtraces = 0` (PHP 8.5) | The fatal-error-backtrace variant | Loses backtraces in fatal errors | Yes, on 8.5 |
| A conservative `post_max_size`, plus a cap on the decoded body at the web server | A multipart request with no usable `Content-Length` can pass `post_max_size` | Refuses large uploads | Guidance in [`php/edge/`](edge/README.md), tested |
| A lower `max_input_nesting_level`; bounds on `max_input_vars`, multipart parts and headers per part | Limits the structures that consume memory cheaply. `max_file_uploads` does not count empty file controls | May break unusual forms | No |
| Block `multipart/form-data` where the application takes none | Removes the request shape the out-of-memory producers use | Breaks uploads | The multipart guard in `php/edge/`, log-only first |
| Remove per-request INI overrides that emit diagnostics (`.htaccess` `php_value`, `PHP_VALUE`) | A consumer of stale error state before request initialization | Per-application changes | No |
| `pm.max_requests = 1` on FPM pools that can absorb it | Limits stale state surviving across requests | A large performance cost | No |

**Do not** use `RLIMIT_AS`, `RLIMIT_DATA`, `ulimit -v` or systemd `LimitAS` as a stand-in for `memory_limit`. Per the same summaries they make `mmap()` fail, which sends PHP back down the vulnerable `longjmp()` path. This project sets no such limit. The advisories do not address cgroup memory limits, so test one before relying on it.

Which server API is exposed: for CVE-2026-109618, PHP says complete remote code execution was validated over HTTP against Apache `mod_php`, and that source analysis supports PHP-FPM as susceptible, with no complete FPM exploit at publication. For CVE-2026-109619, PHP says it validated remote code execution against PHP-FPM as well (as quoted by Rescana). Treat FPM as exposed, and `mod_php` as the higher priority.

### PHP2Shell know before you run it

- **This is not a patch.** PHP released fixes on 21 October 2026 in 8.5.12, 8.4.27, 8.3.36 and 8.2.35, and distributions are shipping backports under their own version numbers. Upgrade, then run `cleanup`.
- **The profile blocks `mail()`**, because PHP runs sendmail through `/bin/sh`. It also blocks ImageMagick delegates. If your app sends mail, use SMTP from PHP.
- **PHP 7.0 through 8.1 are past upstream end of life.** PHP fixed only 8.2 through 8.5. For older branches a fix can only come as a distro or PPA backport, such as Debian LTS, Ubuntu ESM or the sury PPA. Without one, this mitigation is permanent, so plan your upgrade.
- **PHP 5.x is reported affected but not covered.** The environment check flags it, and on Ubuntu 14.04 tells you whether the ESM Legacy fix is installed.
- **Checking by hand, check the package your server actually runs.** `apt list '?installed ?name(^php[0-9.]+$)'` lists the `php8.3`-style metapackages, which a server with only `php8.3-fpm` or `libapache2-mod-php8.3` may not have installed. Query those packages directly: `dpkg-query -W 'php*-fpm' 'libapache2-mod-php*'`.
- **Debian, Ubuntu, Trisquel and their derivatives only**, with systemd, sysvinit or OpenRC. RHEL, Remi, and other SELinux-based layouts need a different approach. The environment check refuses to run on them.
- **PHP-FPM only.** Apache mod_php and LiteSpeed lsphp are reported but not mitigated. mod_php is a demonstrated exploitation surface for this bug, and the AppArmor profile cannot reach PHP running inside Apache, so on a mod_php host the fix is to upgrade `libapache2-mod-php<version>` and restart Apache, not this profile. On a cPanel server with EasyApache 4 PHP, use [the cPanel script](#php2shell-on-cpanel-easyapache-4).
- **For PHP nothing here covers and no package will fix** (an end-of-life branch with no distro backport, PHP 5, unpatched mod_php, PHP built outside dpkg), the environment check points to [php_uploadprogress_guard](https://github.com/HOSTED-POWER/php_uploadprogress_guard), a third-party PHP extension (5.4 to 8.5, any SAPI) that removes the session upload-progress handler and carries a fixed multipart parser. It's not part of this project and we haven't reviewed it. It runs inside every PHP process, so read the source, build it yourself rather than installing the prebuilt binaries, and test on staging. Upgrading remains the fix. `GUARD_HINT=0` turns the pointer off.
- **Every server API that serves web requests is in scope**, not only PHP-FPM and `mod_php`: PHP's advisory names `php-cgi`, FrankenPHP and LiteSpeed as well. What this project covers is limited to what its scripts and guards say they cover.
- **PHP inside other products** (control panels, network and security appliances, management consoles, container images) can bundle its own copy. Updating the system PHP package does not touch it, and `php2shell-mitigate.sh` only reads packages. The fix there is the vendor's update or a rebuilt image, so check the vendor's advisory, and look for PHP binaries outside the package manager.
- **A quiet application log is not proof you are safe.** The demonstrated exploits run against stock production settings with `display_errors` off, so a successful attempt need not surface as a visible PHP error in a response or an application log. Rely on the crash and error-log signatures `hunt` looks for, and on patching, rather than on the absence of visible errors.
- **Backups** of everything the script touches go to `/var/backups/php2shell/<timestamp>/<version>/`.

### Why `cleanup` leaves the AppArmor profile loaded

That's deliberate. The patch fixes these bugs; the profile confines PHP-FPM against the next one, which no patch does. After `cleanup` you choose: `enforce` to start blocking (review `status` first), or `remove` to unload the profile and delete its files. Until you pick one, it stays in complain mode and only logs.

### `php -v` and backported fixes

`php -v` reports PHP's upstream version, never the distro build, so Ubuntu's `8.3.6-0ubuntu0.24.04.13` shows as plain 8.3.6. The script reads the package build with dpkg and prints it in every patch verdict. To check by hand: `dpkg-query -W -f='${Version}\n' php8.3-fpm` (or `libapache2-mod-php8.3` for mod_php).

<a name="php-session-audit-cve-2026-115560"></a>

## PHP Session Audit (CVE-2026-115560)

**Script:** [`php/php-session-audit.sh`](php-session-audit.sh)

CVE-2026-115560 needs three things at once: `session.serialize_handler` set to `php_binary` or `php_serialize` in config, application code switching it to `php` at runtime before `session_start()`, and session upload progress left on. Turning upload progress off closes it, and `php2shell-mitigate.sh` does that. This read-only script tells you whether the other two conditions exist, so you know whether you were exposed:

- the configured handler and upload-progress setting for every PHP-FPM version and pool, and for mod_php;
- per-directory overrides in Apache config, `.htaccess` and `.user.ini`;
- code under `WEB_ROOTS` that switches the serializer through `ini_set()` or `session_start([...])`;
- a `session.save_path` shared by pools with different serializers.

```bash
WEB_ROOTS="/var/www /srv" ./php-session-audit.sh
```

Exits `0` if nothing matched, `1` if all three conditions are present, `2` for a partial match worth reviewing. The code scan is a grep: it finds literal switches, and flags non-literal ones for you to check.

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
