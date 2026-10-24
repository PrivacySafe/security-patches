<p align="center">
  <a href="https://privacysafe.app"><img src="privacysafe_horizontal_logo_lock_reg_padded.svg" width="600" /></a>
</p>
<h1 align="center">Security Patches</h1>

<h3 align="center">
Security mitigations and auditing tools shared for the public good.
</h3>

<p align="center">
  <a href="https://privacysafe.foundation"><strong>❤️ Support PrivacySafe Foundation</strong></a>
</p>

This repository contains security mitigations, system-hardening scripts, and auditing tools developed for PrivacySafe and Ivy Cyber infrastructure. We publish these tools so that others can study, adapt, and use them to protect their own systems, including when upstream security fixes are not yet available.

**9 scripts addressing 22 CVEs across 10 software projects and 6 programming languages, plus 2 other global security incidents.**

> 💚 If this work has been useful, please consider [supporting PrivacySafe Foundation](https://privacysafe.foundation), a 501(c)(3) nonprofit public charity supporting Free/Libre and Open Source Software (FLOSS), cybersecurity education, and public-interest privacy and security research.

---

## 📦 Available tools

| Patch | Targets | CVEs | Type |
|---|---|---|---|
| [PHP2Shell](#php2shell-interim-mitigation) | PHP-FPM 7.0 through 8.5 on Debian/Ubuntu/Trisquel and derivatives | CVE-2026-109618, CVE-2026-109619, CVE-2026-115560 | Interim mitigation |
| [PHP2Shell live watch](#watching-live) | PHP-FPM, Apache and nginx logs on any GNU/Linux; optional systemd unit | CVE-2026-109618, CVE-2026-109619 | Read-only live monitor |
| [PHP session audit](#php-session-audit-cve-2026-115560) | Any PHP host | CVE-2026-115560 | Read-only audit |
| [Node.js October 2026](#nodejs-october-2026-interim-mitigation) | Node.js on GNU/Linux; systemd for the guard | CVE-2026-111497 (Brotli, ecosystem-wide) and 9 Node CVEs | Interim mitigation (Node only) |
| [Brotli checker](#brotli-checker-quick-start) | libbrotli, and Node/Bun/Python/Envoy/Istio on GNU/Linux | CVE-2026-111497 | Read-only check and audit |
| [Ruby and GitLab Regexp](#ruby-and-gitlab-regexp-check) | Ruby runtimes, Ruby apps and GitLab on GNU/Linux | CVE-2026-89078, CVE-2026-93577, CVE-2026-97229, CVE-2026-110264 | Read-only check and audit |
| [libheif HEIF/AVIF Decoder](#libheif-heifavif-decoder-check) | libheif, ImageMagick and Discourse on GNU/Linux | [writeup](https://www.hacktron.ai/blog/hacking-openai); DSA-6417-1 | Check, audit and ImageMagick coder mitigation |
| [eMudhra CA Compromise](#emudhra-intermediate-ca-compromise-interim-mitigation) | System CA store on Debian/Ubuntu/Trisquel and derivatives | [disclosure](https://emudhra.we-have-a-problem.com/); Go: CVE-2026-111943 | Interim mitigation |

> ⚠️ **Update 2026-10-24:** the early read that php2shell was "hard to exploit" (most public proof-of-concepts only worked against a server that already carried a separate flaw) has not held up. Working, production-grade exploitation has since been demonstrated against unmodified, real-world applications, MediaWiki among them, with WordPress, phpBB and Laravel also reported, under stock `php.ini-production` (so `display_errors` off, an ordinary `memory_limit`, ASLR, and several workers under load), on both nginx with PHP-FPM and Apache with `mod_php`, on x86-64 and ARM64. Treat this as a live, reachable pre-auth path to code execution and patch now. If PHP runs inside Apache as `mod_php`, the AppArmor layer here confines PHP-FPM only and does not reach it, so for a `mod_php` host patching is the mitigation: see [PHP2Shell know before you run it](#php2shell-know-before-you-run-it). We do not link to or ship exploit code.

> ℹ️ **Update 2026-10-24:** the [Brotli checker](#brotli-checker-quick-start) now also detects Python's `brotlicffi` binding (its own four-part version, fixed at 1.2.1.0) alongside `brotli`. A Python HTTP client such as urllib3 or requests decodes `Content-Encoding: br` on its own whenever either binding is importable, so a present binding is a live decode path, not dormant code.

> ℹ️ **Update 2026-10-23:** CVE-2026-111497 is not only a Node.js bug. It is an out-of-bounds write in Google's Brotli C decoder (`libbrotli`), and the same CVE now has advisories across Node.js, Bun, Envoy, Istio, the Python `brotli` and `brotlicffi` bindings and OS packages (some are calling the broadened picture "HTTP2Shell"). The Node.js guard here still applies; for everything else, update the library or runtime. A read-only [Brotli checker](#brotli-checker-quick-start) finds `libbrotli` on the host, the runtimes that bundle it, and `libbrotli` inside containers, and reports which are fixed. See [CVE-2026-111497 is not only a Node.js bug](#cve-2026-111497-is-not-only-a-nodejs-bug).

> ℹ️ **Update 2026-10-23:** a [libheif checker](#libheif-heifavif-decoder-check) for the HEIF/AVIF decoder heap overflow used to compromise a Discourse forum through an image upload. Detection is read-only, and finds Discourse and MediaWiki installs that feed images to ImageMagick. Update libheif and rebuild containers that bundle it; `harden` disables HEIF in ImageMagick host-wide, and `mw-harden` blocks HEIF uploads in a MediaWiki, as defence in depth.

> ℹ️ **Update 2026-10-23:** a read-only [Ruby and GitLab checker](#ruby-and-gitlab-regexp-check) for the Regexp fixes in Ruby 4.0.9, 3.4.12 and 3.3.13 and the four GitLab CVEs behind them. If you run GitLab, upgrade it first: two of the CVEs need no login.

> ℹ️ **Update 2026-10-23:** PHP announced **CVE-2026-115560**, an RCE through session upload progress that the 21 October releases don't fix. `php2shell-mitigate.sh` v5 keeps `session.upload_progress` off after `cleanup` until your build is fixed for it, and on PHP 8.5 also turns off `fatal_error_backtraces`. **If you ran `cleanup` with v4, upload progress is back on: download v5 and run `cleanup` again.** It writes back a drop-in that keeps upload progress off, and leaves everything else as `cleanup` did. Every script now prints its version on the first line of output; please include that line when you send us a report. Later the same day, 5.0.1 started reporting Ubuntu 14.04's `php5` packages against the ESM Legacy fix, and 5.0.2 started pointing to a [third-party extension](#php2shell-know-before-you-run-it) for PHP that neither this script nor a package update can cover.

> ℹ️ **Update 2026-10-23:** `php2shell-watch.sh` adds two detection signals ReliaQuest reported from lab reproduction of CVE-2026-109618: a memory error ending in `in Unknown on line 0`, and a correlation of a POST that returns HTTP 500 with the same worker crashing within seconds (by PID). See [Watching live](#watching-live). The correlation needs an access log that records the worker PID.

> ℹ️ **Update 2026-10-22:** an allocator double-free in this class (`free` -> `__zend_free` -> `_efree`, `zend_alloc.c`) was reproduced on **8.5.12**, the release listed as fixed, through PHP's built-in CLI server (`php -S`) with a crafted POST body. It's unconfirmed on a stock (non-ASan) release build and may be a distinct bug rather than an incomplete fix for CVE-2026-109618/-109619. `hunt` and `php2shell-watch.sh` now detect this signature; see [Hunting for exploitation](#php2shell-hunting-for-exploitation). Note that the AppArmor layer confines **PHP-FPM**, not the `php` CLI binary, so it does **not** contain an exploit of the dev server; don't expose `php -S` to untrusted traffic.

---

## PHP2Shell Interim Mitigation

**Script:** [`php/php2shell-mitigate.sh`](php/php2shell-mitigate.sh)

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

### Watching live

`hunt` is a one-shot scan. To watch continuously, the standalone [`php/php2shell-watch.sh`](php/php2shell-watch.sh) follows the same logs with `tail -F` and prints one line per hit, so a sysadmin can leave it running and watch the output:

```bash
sudo nohup ./php2shell-watch.sh >/var/log/php2shell-watch.log 2>&1 &
tail -f /var/log/php2shell-watch.log
```

It survives log rotation, prints a count summary on stop, and changes nothing. A [systemd unit](php/php2shell-watch.service) is included for running it as a managed service (`journalctl -fu php2shell-watch`). The same caveat applies: a hit is a lead to investigate, not proof of compromise.

Since 2026-10-23 it also carries two signals ReliaQuest reported from lab reproduction of CVE-2026-109618. First, a memory error that ends with `in Unknown on line 0`: during exploitation PHP reports the failure before an application file is in scope, so the error names no file, which is a stronger tell than an ordinary memory-limit fatal (and the failed allocation can be small, so the signal does not depend on its size). Second, a correlation: a POST that returns HTTP 500 followed within a few seconds by the worker that handled it crashing, tied together by the worker PID appearing in both logs. The watch arms a PID when an access-log line shows a POST with a 500 status, and raises an `ALERT` if a same-PID crash (`zend_mm_heap corrupted`, `AH00052`, an abort/segfault signal, or `in Unknown on line 0`) lands within `CORRELATE_WINDOW` seconds (default 10). This needs an access log that records the PID among the watched files; for Apache that means `%P` in the `LogFormat`. With no access log present the correlation stays off and the per-line signatures still work. The default log set now includes the common access-log paths for this reason.

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

When no upstream fixed version is set for a branch, the script checks your distro's changelog for both CVEs instead. That catches backported fixes from Ubuntu, Debian, and the ondrej/sury PPAs, which often keep the old version number.

### PHP2Shell know before you run it

- **This is not a patch.** PHP released fixes on 21 October 2026 in 8.5.12, 8.4.27, 8.3.36 and 8.2.35, and distributions are shipping backports under their own version numbers. Upgrade, then run `cleanup`.
- **The profile blocks `mail()`**, because PHP runs sendmail through `/bin/sh`. It also blocks ImageMagick delegates. If your app sends mail, use SMTP from PHP.
- **PHP 7.0 through 8.1 are past upstream end of life.** PHP fixed only 8.2 through 8.5. For older branches a fix can only come as a distro or PPA backport, such as Debian LTS, Ubuntu ESM or the sury PPA. Without one, this mitigation is permanent, so plan your upgrade.
- **PHP 5.x is reported affected but not covered.** The environment check flags it, and on Ubuntu 14.04 tells you whether the ESM Legacy fix is installed.
- **Checking by hand, check the package your server actually runs.** `apt list '?installed ?name(^php[0-9.]+$)'` lists the `php8.3`-style metapackages, which a server with only `php8.3-fpm` or `libapache2-mod-php8.3` may not have installed. Query those packages directly: `dpkg-query -W 'php*-fpm' 'libapache2-mod-php*'`.
- **Debian, Ubuntu, Trisquel and their derivatives only**, with systemd, sysvinit or OpenRC. RHEL, Remi, and other SELinux-based layouts need a different approach. The environment check refuses to run on them.
- **PHP-FPM only.** Apache mod_php and LiteSpeed lsphp are reported but not mitigated. mod_php is a demonstrated exploitation surface for this bug, and the AppArmor profile cannot reach PHP running inside Apache, so on a mod_php host the fix is to upgrade `libapache2-mod-php<version>` and restart Apache, not this profile.
- **For PHP nothing here covers and no package will fix** (an end-of-life branch with no distro backport, PHP 5, unpatched mod_php, PHP built outside dpkg), the environment check points to [php_uploadprogress_guard](https://github.com/HOSTED-POWER/php_uploadprogress_guard), a third-party PHP extension (5.4 to 8.5, any SAPI) that removes the session upload-progress handler and carries a fixed multipart parser. It's not part of this project and we haven't reviewed it. It runs inside every PHP process, so read the source, build it yourself rather than installing the prebuilt binaries, and test on staging. Upgrading remains the fix. `GUARD_HINT=0` turns the pointer off.
- **A quiet application log is not proof you are safe.** The demonstrated exploits run against stock production settings with `display_errors` off, so a successful attempt need not surface as a visible PHP error in a response or an application log. Rely on the crash and error-log signatures `hunt` looks for, and on patching, rather than on the absence of visible errors.
- **Backups** of everything the script touches go to `/var/backups/php2shell/<timestamp>/<version>/`.

### Why `cleanup` leaves the AppArmor profile loaded

That's deliberate. The patch fixes these bugs; the profile confines PHP-FPM against the next one, which no patch does. After `cleanup` you choose: `enforce` to start blocking (review `status` first), or `remove` to unload the profile and delete its files. Until you pick one, it stays in complain mode and only logs.

### `php -v` and backported fixes

`php -v` reports PHP's upstream version, never the distro build, so Ubuntu's `8.3.6-0ubuntu0.24.04.13` shows as plain 8.3.6. The script reads the package build with dpkg and prints it in every patch verdict. To check by hand: `dpkg-query -W -f='${Version}\n' php8.3-fpm` (or `libapache2-mod-php8.3` for mod_php).

---

<a name="php-session-audit-cve-2026-115560"></a>

## PHP Session Audit (CVE-2026-115560)

**Script:** [`php/php-session-audit.sh`](php/php-session-audit.sh)

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

<a name="nodejs-october-2026-interim-mitigation"></a>

## Node.js October 2026 Interim Mitigation

**Scripts:** [`node/node-oct2026-mitigate.sh`](node/node-oct2026-mitigate.sh), [`node/brotli-guard.cjs`](node/brotli-guard.cjs)

Node.js 22.23.4, 24.22.1 and 26.12.1 (21 October 2026) fix ten CVEs. The serious one is **CVE-2026-111497**, an out-of-bounds write in the Brotli decoder that can lead to remote code execution. Any code that decodes attacker-controlled Brotli reaches it, and on an unfixed runtime that includes every `fetch()`, because fetch decodes `Content-Encoding: br` responses on its own. Node lines 25 and older are end of life and get no fix.

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
4. **Places it can't see.** Electron apps bundle their own Node and need an update from their vendor. The fixed Node releases also update Node's built-in CA store for the eMudhra compromise; see [below](#emudhra-intermediate-ca-compromise-interim-mitigation).

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

<a name="cve-2026-111497-is-not-only-a-nodejs-bug"></a>

### CVE-2026-111497 is not only a Node.js bug

The guard and scripts here cover Node.js, because that is what we run. The underlying flaw is in Google's Brotli C decoder (`libbrotli` / `libbrotlidec`): the decoder fails to propagate an invalid block-switch when a stream declares only one block type, so a crafted Brotli stream writes past the decoder's output buffer. Node.js bundles that decoder, but so do many other things, and the same CVE has advisories across the ecosystem (some people are now calling the broadened picture "HTTP2Shell", since any HTTP path that decodes untrusted Brotli can be a route to it). Review all applications and services that decompress Brotli data from untrusted sources, not only those using Node.js.

The fix is the upstream library, so for everything other than Node.js the answer is to update the package or runtime. A read-only checker, [`brotli/brotli-oct2026-check.sh`](brotli/brotli-oct2026-check.sh), finds `libbrotli` on the host, the runtimes that bundle their own Brotli (Node.js, Bun, Python's `brotli` and `brotlicffi`, Envoy, Istio) and `libbrotli` inside running containers, and reports which are fixed. It changes nothing; it only tells you what to update. Fixed versions, reviewed 23 October 2026:

| Where Brotli lives | Fixed versions |
|---|---|
| Google Brotli (upstream C library, `libbrotli`/`libbrotlidec`) | 1.0.10, 1.1.1, 1.2.1 (pick the one for your branch) |
| OS packages (`libbrotli1`, `libbrotlidec1`) | your distribution's build containing 1.0.10, 1.1.1 or 1.2.1 |
| Node.js | 22.23.4, 24.22.1, 26.12.1 |
| Bun | 1.4.4 (bundles Brotli 1.2.1) |
| Envoy | 1.40.0, 1.39.3, 1.38.6, 1.37.8 (1.36.12 has the fix but 1.36 is unsupported) |
| Istio | 1.29.9, 1.30.6, 1.31.2 |
| Python `brotli` extension | 1.2.1 |
| Python `brotlicffi` | 1.2.1.0 (bundles Brotli 1.2.1) |

The upstream library is [github.com/google/brotli](https://github.com/google/brotli); update the package your system installs from it rather than vendoring it. If a fixed build is not yet available for something you run, disable Brotli decoding of untrusted data until it is: reject `Content-Encoding: br` before anything decompresses it, turn off automatic Brotli decoding in HTTP clients (dropping `br` from `Accept-Encoding` does not stop a server sending it anyway), and disable Brotli decompressor filters in Envoy and Istio in both directions. Apache and nginx do not decode Brotli by default, so the usual risk is an application, proxy or client that was configured to. OpenAI's write-up at [patchtheplanet.org/brotli](https://patchtheplanet.org/brotli) has per-stack mitigation snippets; the fixed-version facts above come from the Node.js, Envoy and upstream advisories.

### Brotli checker quick start

1. Download the script. The repository is mirrored on GitHub and Codeberg; pick a base URL.

   ```bash
   # BASE from GitHub:   https://raw.githubusercontent.com/PrivacySafe/security-patches/refs/heads/main
   # BASE from Codeberg: https://codeberg.org/PrivacySafe/security-patches/raw/branch/main
   # curl -fLO "$BASE/brotli/brotli-oct2026-check.sh"
   curl -fLO https://raw.githubusercontent.com/PrivacySafe/security-patches/refs/heads/main/brotli/brotli-oct2026-check.sh
   ```

2. Read it before running it, then make it executable.

   ```bash
   less brotli-oct2026-check.sh
   chmod +x brotli-oct2026-check.sh
   ```

3. See what's exposed. Root is optional, but without it you won't read every library or exec into other users' containers.

   ```bash
   sudo ./brotli-oct2026-check.sh check
   ```

4. Look for crashes that suggest someone already tried.

   ```bash
   sudo ./brotli-oct2026-check.sh hunt
   ```

### Brotli checker commands

| Command | What it does |
|---|---|
| `check` (default) | Reports every `libbrotli` on the host (`libbrotlidec`, `libbrotlienc`, `libbrotlicommon`), the runtimes that bundle their own Brotli (Node.js, Bun, Python's `brotli` and `brotlicffi`, Envoy, Istio), and `libbrotlidec` inside running containers, with whether each carries the fix. Changes nothing, root optional. Exits `0` if nothing is exposed, `1` if a vulnerable Brotli is present, `2` if something couldn't be read |
| `hunt` | Read-only log triage for process crashes that look like a Brotli decoder overflow: segfaults with `libbrotlidec`/`BrotliDecoder` frames, protection faults, heap corruption aborts, and services killed by a crash signal. Exits `0` if nothing matched, `1` if it found something |
| `version` | Prints the script version. Every command prints it on its first line too |

### Brotli checker patch detection

For a `libbrotli` installed from a Debian or Ubuntu package, the script judges it by the package build first (`FIXED_BUILDS`, then the package changelog naming `CVE-2026-111497`), because a distribution can backport the fix under an older upstream number. For a self-built or bundled library it uses the upstream per-branch fix: 1.0.10 for the 1.0 branch, 1.1.1 for 1.1, 1.2.1 for 1.2. Runtimes are judged by their own fixed releases (Node.js 22.23.4 / 24.22.1 / 26.12.1; Bun 1.4.4; Envoy 1.40.0 / 1.39.3 / 1.38.6 / 1.37.8; Istio 1.29.9 / 1.30.6 / 1.31.2; Python `brotli` 1.2.1; Python `brotlicffi` 1.2.1.0). All of these are overridable with the environment variables documented in the script header.

### Brotli checker know before you run it

- **It is a check, not a fix, and not a mitigation.** The fix is to update `libbrotli` and the runtimes that bundle it, rebuild anything that embeds it, and restart. Unlike the ImageMagick coder policy for libheif, Brotli has no host-wide switch to turn off, so there is nothing safe for a script to write; disabling Brotli decoding is application-specific (see the paragraph above).
- **The decoder is the vulnerable path.** `libbrotlidec` is what matters; `libbrotlienc` and `libbrotlicommon` ship from the same package and are shown so you can see the whole install.
- **Distribution backports read correctly.** If you know a distro build is fixed and its changelog doesn't name the CVE, add it to `FIXED_BUILDS`.
- **Runtime detection reads the command line only.** It reports the versions of Node.js, Bun, Envoy and Istio it can run; it does not inspect every container image or embedded copy. Containers are read for `libbrotlidec` only, and only while running.
- **A Python Brotli binding is a live decode path just by being installed.** Python HTTP clients such as urllib3 and requests decode `Content-Encoding: br` on their own whenever `brotli` or `brotlicffi` is importable, so the risk is present wherever the package exists, not only where code calls a decode function. The checker imports both bindings (confirming each exposes a real `decompress`) and judges `brotli` per branch and `brotlicffi` against 1.2.1.0.
- **For Node.js, this only reports the version.** The interim require-guard is the separate [Node.js mitigation](#nodejs-october-2026-interim-mitigation).
- **GNU/Linux only.** Library discovery and container inspection assume it.

---

## Ruby and GitLab Regexp Check

**Script:** [`ruby/ruby-regexp-oct2026-check.sh`](ruby/ruby-regexp-oct2026-check.sh)

On 23 October 2026 Ruby released [4.0.9, 3.4.12 and 3.3.13](https://www.ruby-lang.org/en/news/2026/10/23/regexp-fixes-for-gitlab-cves/), fixing memory corruption bugs in Onigmo, the engine that compiles Ruby's regular expressions. GitLab found that a crafted pattern could turn them into remote code execution on GitLab servers, and published four CVEs: **CVE-2026-89078**, **CVE-2026-93577**, **CVE-2026-97229** and **CVE-2026-110264**. Two of them, CVE-2026-97229 and CVE-2026-110264, need no login, and CVE-2026-110264 affects every GitLab version from 7.0.

Any Ruby application is exposed if it compiles a pattern an attacker controls: through `Regexp.new`, `Regexp.compile` or `Regexp.union`, or by interpolating it into a literal such as `/#{input}/`. Regexps written by the application's own developers are not affected. Ruby requested no CVEs of its own for these fixes, so a scanner that tracks Ruby CVEs reports nothing; track the GitLab CVEs instead.

There is no switch to turn these bugs off. Ruby says `Regexp.timeout` doesn't protect against them, and limiting pattern length doesn't reliably either, because some are triggered by short patterns. Interpolated literals compile without passing through any method a guard could wrap, so unlike the Node.js section there is no in-process guard. This script is read-only. It finds what needs upgrading, which applications compile patterns from strings, and whether anything has crashed in a way that looks like exploitation.

### Ruby quick start

1. Download the script. The repository is mirrored on GitHub and Codeberg; pick a base URL.

   ```bash
   # BASE from GitHub:   https://raw.githubusercontent.com/PrivacySafe/security-patches/refs/heads/main
   # BASE from Codeberg: https://codeberg.org/PrivacySafe/security-patches/raw/branch/main
   # curl -fLO "$BASE/ruby/ruby-regexp-oct2026-check.sh"
   curl -fLO https://raw.githubusercontent.com/PrivacySafe/security-patches/refs/heads/main/ruby/ruby-regexp-oct2026-check.sh
   ```

2. Read it before running it. Always.

   ```bash
   less ruby-regexp-oct2026-check.sh
   ```

3. Make it executable.

   ```bash
   chmod +x ruby-regexp-oct2026-check.sh
   ```

4. See what's exposed. Root is optional, but without it you won't see other users' Rubies and processes.

   ```bash
   sudo ./ruby-regexp-oct2026-check.sh check
   ```

5. Find the code that compiles patterns from strings. Point `SCAN_PATHS` at your application roots if they live somewhere else.

   ```bash
   sudo SCAN_PATHS="/srv /var/www" ./ruby-regexp-oct2026-check.sh scan
   ```

6. Look for crashes that suggest someone already tried.

   ```bash
   sudo ./ruby-regexp-oct2026-check.sh hunt
   ```

To confirm GitHub and Codeberg serve the same file, compare checksums:

```bash
sha256sum ruby-regexp-oct2026-check.sh
curl -fsSL https://codeberg.org/PrivacySafe/security-patches/raw/branch/main/ruby/ruby-regexp-oct2026-check.sh | sha256sum
```

**If you run GitLab, upgrade it first.** The fixed releases are 18.11.13, 19.0.10, 19.1.9, 19.2.9, 19.3.6, 19.4.3 and 19.5.1. GitLab patched the Ruby it ships, so upgrading the system `ruby` package does nothing for a GitLab install, and upgrading GitLab is the whole fix for it.

### Ruby commands

| Command | What it does |
|---|---|
| `check` (default) | Reports every GitLab and Discourse install, every Ruby runtime on disk and every running Ruby process, with whether each is fixed. Flags processes still running a Ruby that was replaced on disk since they started. Changes nothing, root optional. Exits `0` if nothing running is exposed, `1` if unfixed Ruby is running or a bundled app is unfixed, `2` if some version couldn't be read |
| `scan` | Read-only. Finds application code that compiles regexps from strings, grouped by application, and grades each line (see [Ruby scan grades](#ruby-scan-grades)). Exits `0` if nothing needs review, `1` if something does |
| `hunt` | Read-only log triage. Scans the journal, syslog, kernel log, GitLab's Puma, Sidekiq and Rails logs, and application logs under `/srv` and `/var/www`, for Ruby crash reports, Onigmo frames in backtraces, heap corruption aborts, services killed by a crash signal, and `RegexpError`. Exits `0` if nothing matched, `1` if it found something to look at |
| `version` | Prints the script version. Every other command prints it on its first line too |

### What the Ruby check looks at

1. **GitLab.** Omnibus installs under `/opt/gitlab`, source installs under `/home/git/gitlab`, and `gitlab/gitlab-ce` and `gitlab/gitlab-ee` images in Docker or Podman. The version comes from GitLab's own `VERSION` file or version manifest, or from the image tag. An image tagged `latest` can't be judged and is reported as unknown.
2. **Discourse.** The Docker launcher under `/var/discourse`, a bare-metal checkout under `/var/www/discourse` (or a user home, or `/srv/discourse`), and `discourse/discourse` and `discourse/base` images. Discourse has published no Discourse-version fix for these CVEs, so each install is judged by the Ruby it runs: a bare-metal checkout by its `.ruby-version`, the Docker launcher by the running web process, since that Ruby lives inside the container. Discourse compiles patterns from admin and user input (watched words, search, theme and automation settings), so an unfixed Ruby is reachable. This is the Ruby Regexp issue, separate from the Discourse `libheif` image-upload RCE, which is fixed by rebuilding the container, not by upgrading Ruby.
3. **Ruby runtimes on disk.** Everything on `PATH`, `/usr/bin/ruby*`, `/usr/local/bin/ruby`, chruby's `/opt/rubies`, and every user's rbenv, rvm, asdf, mise and chruby installs.
4. **Vendor-bundled Rubies.** Rubies that ship inside another product, under `/opt/*/embedded` (Chef, Fluentd, Vagrant and others) or `/opt/puppetlabs`, are listed but not judged by version: their fix comes from that vendor's update. GitLab's embedded Ruby is judged by the GitLab version, since GitLab patched it.
5. **Running processes.** Every process whose binary is a Ruby or that has `libruby` loaded, which catches Puma, Sidekiq and Unicorn under their own names, with its user and systemd unit. A process whose Ruby binary or `libruby` was replaced on disk since it started still runs the old code until you restart it.

The script reads each Ruby version from the description string compiled into the binary or into the `libruby` it links. It never executes a Ruby binary, so root never runs one planted in a user's version manager.

### Ruby patch detection

For each runtime, three checks run in order, and the first that applies decides:

1. **`FIXED_BUILDS`.** Distro builds you list as fixed, for a backport the script doesn't know about. A build only counts for the same upstream version.
2. **Changelog.** For a Ruby installed from a Debian or Ubuntu package, the changelog of the interpreter package or of its `libruby` package names one of the four GitLab CVEs. The changelog only counts if its newest entry is the installed version. Because Ruby requested no CVEs, a distro may describe the fix without naming them; if you know your build is fixed, add it to `FIXED_BUILDS`.
3. **Upstream version.** The runtime is at or above the fixed release for its line: 3.3.13, 3.4.12 or 4.0.9. Older lines got no fixed release, so they read as not fixed. A line newer than 4.0 reads as unknown: check that the build includes ruby/ruby#13332, #19020 and #16801.

GitLab is judged the same way against its fixed release for each minor line. A minor line older than 18.11 got no fixed release; a line newer than 19.5 shipped after the fixes and reads as fixed.

### Ruby scan grades

`scan` searches `.rb`, `.rake`, `.erb`, `.haml`, `.slim` and `.ru` files and skips literal patterns. What's left gets one of two grades:

| Grade | Meaning |
|---|---|
| `review` | The pattern comes from a variable or expression. Trace where it comes from: if a user can set it (request parameters, CI configuration, saved filters, webhook payloads, search syntax), that application is exposed until its Ruby is fixed |
| `escaped` | The dynamic part goes through `Regexp.escape` or `Regexp.quote`, or it's a `Regexp.union` of strings, which escapes them. A much smaller surface that is still compiled, so still worth a look |

The interim fix lives in the application: stop compiling the user's text, or pass it through `Regexp.escape` so it is matched literally. GitLab's tree is skipped because GitLab is judged by its version. Installed gems and `vendor/bundle` are skipped by default because they are noisy; set `SCAN_GEMS=1` to include them.

### Ruby hunting for exploitation

These bugs corrupt memory while a pattern compiles, so a failed attempt usually shows as a crashed worker rather than an application error. `hunt` reads the journal and logs, never changes anything, and reports:

- Ruby crash reports, the `[BUG] Segmentation fault` blocks Ruby prints when it dies;
- Onigmo and Regexp frames (`onig_compile`, `rb_reg_initialize`, `regparse.c` and others) in a backtrace;
- glibc heap corruption aborts such as `double free or corruption`;
- kernel segfault and protection fault lines from Ruby, Puma, Sidekiq and Unicorn processes;
- services killed by `SIGSEGV`, `SIGABRT` or `SIGBUS`;
- `RegexpError`, which someone probing patterns leaves behind.

`HUNT_SINCE` sets how far back it reads the journal, and `HUNT_LOGS` adds your own log files.

A match is a lead, not proof. Native gems crash Ruby too, and `RegexpError` is ordinary when users type bad patterns. A crash with Onigmo frames on an unfixed Ruby, or a burst of `RegexpError` from one source just before a worker died, is worth treating as an incident: check what the process could reach and rotate it. On GitLab that includes runner registration tokens and CI/CD variables.

### Ruby configuration

| Variable | Default | Purpose |
|---|---|---|
| `RUBY_FIXED_33`, `RUBY_FIXED_34`, `RUBY_FIXED_40` | `3.3.13`, `3.4.12`, `4.0.9` | First fixed release for each line |
| `FIXED_BUILDS` | *(empty)* | Extra fixed distro builds, space-separated full versions |
| `GITLAB_FIXED` | `18.11.13 19.0.10 19.1.9 19.2.9 19.3.6 19.4.3 19.5.1` | First fixed GitLab release for each minor line |
| `GITLAB_ROOT` | `/opt/gitlab` | Where Omnibus GitLab is installed |
| `DISCOURSE_ROOT` | `/var/discourse` | Where the Discourse Docker launcher lives |
| `DISCOURSE_APP` | `/var/www/discourse` | Where a bare-metal Discourse checkout lives |
| `SCAN_PATHS` | `/srv /opt /var/www /home /usr/local/lib` | Where `scan` looks for code |
| `SCAN_DEPTH` | `10` | How deep `scan` goes |
| `SCAN_GEMS` | `0` | `1` also scans installed gems and `vendor/bundle` |
| `SCAN_SHOW` | `5` | Findings printed per application and grade |
| `HUNT_SINCE` | `2026-09-01` | How far back `hunt` reads the journal |
| `HUNT_LOGS` | *(empty)* | Extra log globs for `hunt` |

### Ruby know before you run it

- **This is a check, not a mitigation.** Upgrade GitLab, upgrade Ruby to 4.0.9, 3.4.12 or 3.3.13, and restart what runs on it. Ruby 3.3 normally gets only security fixes; Ruby says it included these as an exception.
- **No setting protects you.** `Regexp.timeout` and length limits don't. Until you can upgrade, the only interim fix is in the application: don't compile patterns from untrusted input.
- **GitLab is fixed by upgrading GitLab**, not by upgrading the system Ruby.
- **Vendor-bundled Rubies need the vendor's update.** The script lists them so you know they exist.
- **Containers get their own fix.** Each image carries its own Ruby; rebuild on `ruby:3.3.13`, `3.4.12`, `4.0.9` or later. The script checks GitLab images by tag but can't see Rubies inside other images.
- **`scan` is a grep.** It misses patterns built across several lines or in another file, and it can flag interpolated strings that aren't regexps. Use it to find where to look, not as a verdict.
- **GNU/Linux only.** Process inspection reads `/proc`.

---

<a name="libheif-heifavif-decoder-check"></a>

## libheif HEIF/AVIF Decoder Check

**Script:** [`heif/libheif-oct2026-check.sh`](heif/libheif-oct2026-check.sh)

A heap buffer overflow in `libheif`, the HEIF and AVIF image decoder, was used to get remote code execution on a Discourse forum and then pivot further into the services behind it. The decode path is reached by uploading a crafted HEIF or AVIF image: an app that processes user images hands the file to ImageMagick (or libvips), which calls `libheif`. Disabling a single "image uploads" setting does not reliably close it, because avatars, emoji, oneboxed remote images and other surfaces feed the same conversion path.

The fix is to update `libheif` (and `libde265`, the HEVC codec it calls) and rebuild anything that bundles them. For a Discourse Docker install this means a container rebuild, not a web-interface update, because the old library stays in the image until it is rebuilt:

```bash
cd /var/discourse
git pull
./launcher rebuild app
```

Fixed-version information varies across upstream releases and distribution packages. The upstream heap-write class was fixed across 1.21.0, 1.22.0 and 1.22.1, with security releases continuing into the 1.23.x line. Debian fixed a batch in [DSA-6417-1](https://lists.debian.org/debian-security-announce/2026/msg00328.html) (`libheif 1.19.8-1+deb13u1`, trixie, 8 August 2026), and other distributions backport under their own version strings, so a package can carry the fixes under an older-looking upstream number. This script accounts for that: a distribution build is judged by `FIXED_BUILDS` and its package changelog first, and only falls back to the upstream version floor when it is not a distribution package.

This is a separate issue from the Ruby Regexp CVEs. For Ruby and GitLab, use [`ruby/ruby-regexp-oct2026-check.sh`](#ruby-and-gitlab-regexp-check) instead.

### libheif quick start

1. Download the script. The repository is mirrored on GitHub and Codeberg; pick a base URL.

   ```bash
   # BASE from GitHub:   https://raw.githubusercontent.com/PrivacySafe/security-patches/refs/heads/main
   # BASE from Codeberg: https://codeberg.org/PrivacySafe/security-patches/raw/branch/main
   # curl -fLO "$BASE/heif/libheif-oct2026-check.sh"
   curl -fLO https://raw.githubusercontent.com/PrivacySafe/security-patches/refs/heads/main/heif/libheif-oct2026-check.sh
   ```

2. Read it before running it. Always.

   ```bash
   less libheif-oct2026-check.sh
   ```

3. Make it executable.

   ```bash
   chmod +x libheif-oct2026-check.sh
   ```

4. See what's exposed. Root is optional, but without it you won't read every library or exec into other users' containers.

   ```bash
   sudo ./libheif-oct2026-check.sh check
   ```

5. Check whether ImageMagick still lets HEIF through. `policy` reports and prints the lines to block it; `harden` writes them for you (reversible with `unharden`).

   ```bash
   sudo ./libheif-oct2026-check.sh policy
   sudo ./libheif-oct2026-check.sh harden
   ```

6. Look for crashes that suggest someone already tried.

   ```bash
   sudo ./libheif-oct2026-check.sh hunt
   ```

To confirm GitHub and Codeberg serve the same file, compare checksums:

```bash
sha256sum libheif-oct2026-check.sh
curl -fsSL https://codeberg.org/PrivacySafe/security-patches/raw/branch/main/heif/libheif-oct2026-check.sh | sha256sum
```

### libheif commands

| Command | What it does |
|---|---|
| `check` (default) | Reports every `libheif` and `libde265` on the host, the ImageMagick and libvips that reach them, every Discourse install, and `libheif` inside running containers, with whether each `libheif` carries the fixes. For a Discourse container it says a rebuild is needed, not a restart. Changes nothing, root optional. Exits `0` if nothing is exposed, `1` if a vulnerable `libheif` is reachable, `2` if something couldn't be judged |
| `policy` | Read-only. Checks whether ImageMagick's `policy.xml` still lets HEIC, HEIF or AVIF through, and prints the lines that block them. Exits `0` if HEIF is blocked everywhere a policy was found, `1` if it is still allowed, `2` if no policy was found |
| `harden` | Writes a managed block into ImageMagick's `policy.xml` that refuses the HEIC, HEIF and AVIF coders, so a crafted upload never reaches `libheif` through ImageMagick. Backs the file up first, is idempotent, and is the one thing this script changes. Needs root. Defence in depth, not a substitute for updating `libheif` |
| `unharden` | Removes the managed block and restores. Needs root. Only touches a block this script wrote; a block added by hand is left alone |
| `mw-harden` | Blocks HEIF, HEIC and AVIF uploads in every MediaWiki found, by adding those MIME types to `$wgMimeTypeExclusions` in `LocalSettings.php`, so a crafted upload is rejected by its detected type before the scaler runs. Backs the file up first, is idempotent, checks the result still parses as PHP before saving, and is reversible. Needs root. Application-level defence, not a substitute for updating `libheif` |
| `mw-unharden` | Removes the MediaWiki block and restores. Needs root. Only touches a block this script wrote |
| `hunt` | Read-only log triage for image-processor crashes: ImageMagick, `libheif` and `libde265` segfaults, HEIF decoder frames in backtraces, services killed by a crash signal, and repeated HEIF decode errors. Exits `0` if nothing matched, `1` if it found something |
| `version` | Prints the script version. Every other command prints it on its first line too |

### What the libheif check looks at

1. **`libheif` on the host.** Every `libheif` shared object on the standard library paths and in `ldconfig`'s cache, judged by its package build or, if it is not a distribution package, by the upstream version floor. The version is read from the library's own soname, never from a stray build string inside it, and the library is never executed.
2. **`libde265`.** The HEVC codec `libheif` calls for HEIC. It has its own CVE history and its own fixed versions, so the script reports its version but does not judge it against the `libheif` floor. Update it from your distribution too.
3. **What reaches `libheif`.** ImageMagick (`magick` or `convert`) and libvips, with whether ImageMagick can even decode HEIF or AVIF. A build with no HEIF delegate is not a path to this bug through that tool.
4. **Discourse.** The Docker launcher under `/var/discourse`, a bare-metal checkout under `/var/www/discourse`, and `discourse/discourse` and `discourse/base` images. A forum's image-upload path runs an attacker-supplied file through ImageMagick into `libheif`, so a Discourse install on top of a vulnerable `libheif` is a path to it. For a Docker install the library lives inside the web container, so the script points at the container section and tells you to rebuild rather than restart.
5. **MediaWiki.** `LocalSettings.php` under the usual web roots. MediaWiki is a path to this bug only when it is configured for it, so the script reads the config rather than assuming: the scaler must be ImageMagick (`$wgUseImageMagick`), not GD (its default when both are installed), and a HEIF-family extension must be in `$wgFileExtensions` (not a default). It reports a wiki as exposed only when both are true, and otherwise says why it is not a path. Reading the PHP config file is not executing it.
6. **`libheif` inside running containers.** For each running Docker or Podman container, the script reads the `libheif` the container actually loads. This is how a Discourse web container still carrying the old library gets caught: a web-interface update does not replace it, only a rebuild does.

### libheif patch detection

For each `libheif` the checks run in order, and the first that applies decides:

1. **`FIXED_BUILDS`.** Distribution builds you list as fixed, for a backport the script doesn't know about. A build only counts for the same upstream version.
2. **Changelog.** For a `libheif` installed from a Debian or Ubuntu package, the package changelog names DSA-6417-1 or one of the batch CVEs, and its newest entry is the installed build. Because distributions backport under old upstream numbers, this overrides the version floor: a package at `1.17.6` can read as fixed when its changelog proves it.
3. **Upstream floor.** For a library that is not a distribution package (self-built or bundled), the version is at or above `HEIF_FIXED_UPSTREAM` (default 1.22.0). A dpkg-owned build with no changelog proof is reported as unknown rather than fixed, because its number alone cannot clear it.

### libheif disabling the coder as defence in depth

Even after `libheif` is patched, more decoder bugs in this format are likely, so it is worth refusing untrusted HEIF and AVIF at the converter. `policy` reports whether ImageMagick already does, and prints the lines to add inside `<policymap>` in `policy.xml`:

```xml
<policy domain="coder" rights="none" pattern="HEIC" />
<policy domain="coder" rights="none" pattern="HEIF" />
<policy domain="coder" rights="none" pattern="AVIF" />
```

`harden` writes those lines for you, as a marked, managed block, so you don't have to edit the XML by hand:

```bash
sudo ./libheif-oct2026-check.sh harden      # write the block (backs the file up first)
sudo ./libheif-oct2026-check.sh unharden    # take it back out
```

`harden` is the only host-wide change this script makes. It backs the file up under `/var/backups/libheif-oct2026/` first, writes one managed block (running it again refreshes that block rather than adding a second), and creates a `policy.xml` if none exists, since ImageMagick with no policy decodes HEIF by default. `unharden` removes only the block this script wrote and leaves any coder lines you added by hand alone. This stops ImageMagick handing HEIF and AVIF to `libheif`. It is not a substitute for updating the library, and it does not help a caller that reaches `libheif` without going through ImageMagick. Discourse added ImageMagick sandboxing as its own defence in depth.

### libheif blocking HEIF uploads in MediaWiki

The ImageMagick coder policy above is host-wide. If you run a MediaWiki that is configured to accept HEIF (ImageMagick scaler plus a HEIF-family extension in `$wgFileExtensions`), `mw-harden` blocks the upload at the application instead, which is more targeted and survives an ImageMagick reconfigure:

```bash
sudo ./libheif-oct2026-check.sh mw-harden      # block HEIF/HEIC/AVIF uploads in every wiki found
sudo ./libheif-oct2026-check.sh mw-unharden    # take the block back out
```

It appends a marked, managed block to `LocalSettings.php` that adds the HEIF-family MIME types (`image/heif`, `image/heic`, `image/avif`, and the `-sequence` variants) to `$wgMimeTypeExclusions`, mirrors it to the pre-1.37 `$wgMimeTypeBlacklist` name when that is in use, and drops `heif`, `heic` and `avif` from `$wgFileExtensions` if they are there. Excluding by MIME type rejects a crafted file by its detected type, so renaming it to `.jpg` does not get it past. The edit is backed up first, is idempotent, and is checked with `php -l` before it is saved, so a file that would not parse is left untouched (and its backup kept). This is an application-level block; the host `libheif` still needs updating.

### libheif hunting for exploitation

A crafted image corrupts memory while it decodes, so a failed attempt usually shows as a crashed image worker rather than an application error. `hunt` reads the journal and logs, never changes anything, and reports ImageMagick, `libheif` and `libde265` segfaults, `libheif` and `libde265` frames in a backtrace, services killed by a crash signal, heap corruption aborts, and repeated HEIF, HEIC or AVIF handling errors. `HUNT_SINCE` sets how far back it reads the journal, and `HUNT_LOGS` adds your own log files.

A match is a lead, not proof. Image decoders crash on genuinely broken files too. A crash with `libheif` or `libde265` frames on a vulnerable build, or a burst of HEIF decode errors from one source just before a worker died, is worth treating as an incident: check what the process could reach and rotate it. On a forum that includes its admin and session stores.

### libheif configuration

| Variable | Default | Purpose |
|---|---|---|
| `HEIF_FIXED_UPSTREAM` | `1.22.0` | Upstream floor the heap-write class is fixed at, used only for libraries that are not distribution packages |
| `FIXED_BUILDS` | *(empty)* | Extra fixed distribution builds, space-separated full versions |
| `DISCOURSE_ROOT` | `/var/discourse` | Where the Discourse Docker launcher lives |
| `DISCOURSE_APP` | `/var/www/discourse` | Where a bare-metal Discourse checkout lives |
| `POLICY_PATHS` | ImageMagick-6 and -7 config dirs | Where `policy` looks for `policy.xml` |
| `MW_PATHS` | common web roots | Where `check` and `mw-harden` look for MediaWiki's `LocalSettings.php` |
| `HUNT_SINCE` | `2026-07-01` | How far back `hunt` reads the journal |
| `HUNT_LOGS` | *(empty)* | Extra log globs for `hunt` |

### libheif know before you run it

- **The real fix is the update, which this script does not run for you.** Update `libheif` and `libde265`, rebuild anything that bundles them, and for Discourse rebuild the container (`/var/discourse/launcher rebuild app`), which a web-interface update does not do. A package upgrade or a container rebuild is an operator's call to time, so the script prints it rather than firing it.
- **It changes only two things, and only when asked.** `harden` writes the ImageMagick coder block; `mw-harden` writes the MediaWiki upload block. Both back the file up first and are reversible (`unharden`, `mw-unharden`). Everything else is read-only. A single upload setting is not the fix on its own, because many surfaces reach the decoder; blocking the coder at the converter (or the upload at the wiki) is the reliable interim step while you schedule the update.
- **MediaWiki is only exposed when configured for it.** The check flags a wiki only when it uses ImageMagick and accepts HEIF; a default install uses GD and does not accept HEIF, so it is not a path. `mw-harden` edits `LocalSettings.php`, so it checks the result parses with `php -l` before saving and leaves a file that wouldn't parse untouched.
- **Distribution backports read correctly.** A package can carry the fixes under an older upstream number; the script trusts the package changelog over the version. If you know a build is fixed and the changelog doesn't name it, add it to `FIXED_BUILDS`.
- **`libde265` is reported, not judged.** It has its own fixed versions. Update it from your distribution.
- **Containers need their own fix.** Each image carries its own `libheif`; rebuild on a fixed base. The script reads the library inside running containers but can't see one that was installed in an unusual way.
- **GNU/Linux only.** Library discovery and container inspection assume it.

---

## eMudhra Intermediate CA Compromise Interim Mitigation

**Script:** [`pki/emudhra-mitigate.sh`](pki/emudhra-mitigate.sh)

On 20 October 2026 it was [disclosed](https://emudhra.we-have-a-problem.com/) that the private keys of eight eMudhra intermediate CAs can be recovered from their certificates. Anyone holding one can impersonate any website. Browsers already block them through OneCRL, CRLite and CRLSets, but your server's system CA store doesn't. Everything that reads it keeps trusting the compromised intermediates until `ca-certificates` is updated: OpenSSL, GnuTLS, curl, wget, apt, git, Python, PHP, Go, Ruby, and Java through ca-certificates-java.

The intermediates reach the store through two roots: emSign ECC Root CA - G3, which cross-signs emSign Root TLS CA - G3, and Sectigo's AAA Certificate Services, which cross-signs all eight. This script:

1. **Distrusts those roots in the system store**, using `!` lines in `/etc/ca-certificates.conf`, and rebuilds it. It finds affected certificates by public key, not file name, so it also catches copies someone added by hand to `/usr/local/share/ca-certificates` or `/etc/ssl/certs`. It moves those out of the store into the backup directory.
2. **Proves the store rejects all of them.** The script embeds the 16 published intermediate certificates and checks each against its published SHA-256 before using it. After every change it tests all 16 against the bundle file, the hash directory, and OpenSSL's built-in default paths. It also checks the bundle holds none of the affected certificates, because Go and GnuTLS will treat a lone intermediate in the store as a trust anchor.

The script is designed so it can't break your CA store or leave you exposed by mistake. It checks that the rebuilt bundle lost only affected certificates and still has hash links, and rolls back if not. If `TEST_HOSTS` is set, it checks those hosts before and after so you see any collateral breakage immediately. `cleanup` never removes the distrust unless the store still rejects every compromised intermediate without it, and re-applies it if not.

### eMudhra quick start

1. Download it. The repository is mirrored on GitHub and Codeberg; pick a base URL.

   ```bash
   # BASE from GitHub:   https://raw.githubusercontent.com/PrivacySafe/security-patches/refs/heads/main
   # BASE from Codeberg: https://codeberg.org/PrivacySafe/security-patches/raw/branch/main
   # curl -fLO "$BASE/pki/emudhra-mitigate.sh"
   curl -fLO https://raw.githubusercontent.com/PrivacySafe/security-patches/refs/heads/main/pki/emudhra-mitigate.sh
   ```

2. Read it before running it. Always.

   ```bash
   less emudhra-mitigate.sh
   ```

3. Make it executable.

   ```bash
   chmod +x emudhra-mitigate.sh
   ```

4. Check the environment. This changes nothing and needs no root.

   ```bash
   ./emudhra-mitigate.sh check
   ```

5. Apply. Set `TEST_HOSTS` to hosts your server actually talks to, so the script flags any that stop verifying after the change.

   ```bash
   sudo TEST_HOSTS="api.example.com:443 mirror.example.org" ./emudhra-mitigate.sh
   ```

To confirm GitHub and Codeberg serve the same script, compare checksums:

```bash
sha256sum emudhra-mitigate.sh
curl -fsSL https://codeberg.org/PrivacySafe/security-patches/raw/branch/main/pki/emudhra-mitigate.sh | sha256sum
```

Set `TEST_HOSTS` to the hosts your server actually talks to: APIs, package mirrors, webhooks. A host that verifies before the change and fails after it most likely chains to one of the two distrusted roots.

### eMudhra commands

| Command | What it does |
|---|---|
| `check` | Environment report only. Changes nothing and doesn't need root. Exits `0` if clear, `1` on a hard blocker, `2` if `--ignore-env` would be needed |
| `apply` (default) | Distrusts the affected certificates, rebuilds the store, cleans the Java keystore, then verifies |
| `status` | What this script changed, all store tests, Java keystore state, and processes that still need a restart. Exits `1` if the store trusts a compromised intermediate |
| `restore` | Undoes everything this script distrusted. This re-exposes you if `ca-certificates` isn't patched |
| `cleanup` | Once `ca-certificates` is patched, removes this script's distrust, but only if the store still rejects every compromised intermediate. Otherwise it puts the distrust back. `--force` skips the patch check, never the store test |

### eMudhra environment check

Before changing anything, the script checks your server in this order and prints what it found:

1. **Operating system.** The same set as PHP2Shell: Debian, Ubuntu, Trisquel, the derivatives the check knows by name, and anything whose `ID_LIKE` names Debian or Ubuntu. It works out the base release so it can compare against the right fixed `ca-certificates` build. Other systems are refused with a pointer to their workaround on the disclosure page.
2. **System CA store.** The `ca-certificates` version and its patch status (see [Patch detection](#emudhra-patch-detection)). It lists every affected certificate it finds, whether shipped, already distrusted, or added by hand, and tests the current bundle.
3. **Other CA stores.** This run doesn't fix these, so they're reported with the command that does:
   - **Java.** The system keystore follows the store; other JDKs carry their own `cacerts`.
   - **Bundled CA files** such as Python certifi, vendored pip and Homebrew, found under `SCAN_PATHS`. Debian's patched certifi reads the system store and is recognized as such.
   - **Node.js.** It ships its own roots unless started with `--use-openssl-ca`.
   - **NSS builtin roots**, unless `libnssckbi` is p11-kit.
   - **Overrides.** `SSL_CERT_FILE` or `SSL_CERT_DIR` set in `/etc/environment` or `/etc/profile.d`.
   - **Separate environments.** Containers, snaps and Flatpaks.
4. **System.** Root, OpenSSL, the self-check of the embedded certificates, the init system (for restart hints), and required tools.

**Hard blockers** always stop the run: a distribution that isn't Debian-based, `ca-certificates` or `update-ca-certificates` missing, no `openssl`, a failed self-check, missing tools, or not running as root for `apply`, `restore` or `cleanup`.

**Soft blockers** stop the run until you've looked at them, and `--ignore-env` lets you proceed. They cover a process that would keep trusting the compromised intermediates even after a clean run:

- a running Node.js process using its bundled roots;
- a running Java process on a JDK whose own `cacerts` still holds affected certificates;
- a system-wide `SSL_CERT_FILE` or `SSL_CERT_DIR` that points at an exposed store.

### eMudhra patch detection

For `ca-certificates`, three checks run in order, and any one is enough:

1. **Fixed build for your release.** These are the builds from the disclosure page:

   | Release | Fixed build |
   |---|---|
   | Debian 12 | `20250419~deb12u2` |
   | Debian 13 | `20250419+deb13u1` |
   | Debian testing/unstable | `20260816+nmu1` |
   | Ubuntu 22.04, 24.04, 26.04, 26.10 | `20260816ubuntu0.XX.YY.1` |

   It only compares against the build for your own release, because Debian 12 and 13 share the upstream version `20250419`.
2. **`FIXED_BUILDS`.** Builds you add, such as an Ubuntu ESM or Debian LTS update. A build only counts for the same upstream version.
3. **Changelog.** The package changelog names Launchpad bug 2171507 or Debian bug 1151413, both from the disclosure page. The changelog only counts if its newest entry is the installed version. (CVE-2026-111943 is deliberately *not* used here: that CVE is the Go standard library's own `crypto/x509` denylist, fixed in Go 1.26.10 / 1.27.3, so a `ca-certificates` changelog won't cite it. See the Go note below.)

The result is *patched*, *not patched*, or *unknown*. The store tests decide what actually happens: `cleanup` checks the patch status first, but it removes the distrust only if the store still rejects every intermediate without it.

A fixed store isn't enough on its own, because a long-running process keeps the trust it loaded at start. `status` and `apply` list processes started before the current store that loaded a TLS library or a JVM, or are Node.js, and tell you what to restart. One-shot tools like curl, apt and git need nothing.

### eMudhra configuration

| Variable | Default | Purpose |
|---|---|---|
| `TEST_HOSTS` | *(empty)* | `host[:port]` list to TLS-test before and after `apply`, to catch collateral breakage |
| `FIXED_BUILDS` | *(empty)* | Extra fixed `ca-certificates` builds, space-separated full versions |
| `SCAN_PATHS` | `/opt /srv /usr/local /usr/lib /usr/share /home /root /var/www` | Where to look for bundled CA files. Empty disables the scan |
| `SCAN_DEPTH` | `9` | How deep that scan goes |
| `JAVA_STOREPASS` | `changeit` | Password for the Java keystores |

### eMudhra know before you run it

- **This is not a patch.** Upgrade `ca-certificates` when your distribution ships the fix, then run `cleanup`.
- **It distrusts two whole roots, not just the eight intermediates.** The system store can only drop roots, so every site whose chain ends at emSign ECC Root CA - G3 or AAA Certificate Services fails verification until you run `cleanup` or `restore`. Set `TEST_HOSTS` and check `status` after applying. If the store already rejects every compromised intermediate, for example because a patched package cut the path, `apply` leaves those two roots trusted.
- **Your browsers are already protected.** Firefox, Chrome, Edge and Safari block these intermediates themselves. This script is for everything else on your servers.
- **Other CA stores are reported, not changed.** Python certifi, Node.js, other JDKs and NSS builtins need their own updates. The report prints the command for each. Programs that compile their roots in, such as Rust's webpki-roots and Electron apps, can't be detected and need updating. One common case is [uv](https://github.com/astral-sh/uv), the Python package manager: Plone's 6.2.2.1 release notes tell uv users to upgrade to 0.13.4 for this incident. For a Node.js or Electron app you can't immediately upgrade, the [`kill-emudhra`](https://github.com/IAmJSD/kill-emudhra) package distrusts the eight intermediates from inside the process by their public-key hash, as a stopgap until you reach a fixed Node.js (22.23.4 / 24.22.1 / 26.12.1) or Electron (44.9.1 / 43.8.1 / 42.11.16).
- **Go binaries need their own fix.** A Go program built with CGO reads the system store this script fixes, but a pure-Go build carries Go's own certificate verifier, which got a built-in denylist for these intermediates in Go 1.26.10 and 1.27.3 ([CVE-2026-111943](https://pkg.go.dev/vuln/GO-2026-6809)). Rebuild such binaries with a fixed toolchain; this script's check reminds you if a `go` toolchain is present but can't tell which existing binaries are affected.
- **Containers get their own fix.** Each image carries its own `ca-certificates`. Rebuild images on patched bases; running this inside a container fixes that container only.
- **The distrust survives package upgrades and `dpkg-reconfigure ca-certificates`.** Both keep `!` lines in `/etc/ca-certificates.conf`. Check with `status` after any upgrade anyway.
- **Debian, Ubuntu, Trisquel and their derivatives only.** Fedora/RHEL, openSUSE, Arch, Alpine, NixOS, FreeBSD and macOS need a different approach. See the [disclosure page](https://emudhra.we-have-a-problem.com/#linux).
- **Backups** of everything the script touches go to `/var/backups/emudhra-mitigation/<timestamp>/`. The record of what it changed is `/var/lib/emudhra-mitigation/state`.

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

⚠️ **Do not report unpatched vulnerabilities in a public issue.** Follow our [security policy](SECURITY.md) instead. Never send sensitive information through ordinary direct messages or unencrypted email.

- **Contribution terms:** [`CONTRIBUTING.md`](CONTRIBUTING.md)
- **Code of Conduct:** [`CODE_OF_CONDUCT.md`](CODE_OF_CONDUCT.md)
- **AI Contribution Policy:** [`AI_POLICY.md`](AI_POLICY.md)
- **Security and vulnerability reporting:** [`SECURITY.md`](SECURITY.md)

## 🔐 More from PrivacySafe

* **[PrivacySafe](https://privacysafe.app):** Privacy-by-design software for home, teams, and organizations. Sign up free, no phone number required.
* **[Bits On Tape](https://bitsontape.com):** Our newsletter covering cybersecurity, privacy, FLOSS, AI, and digital culture.
* **[Ivy Cyber](https://ivycyber.com):** Hosting, enterprise deployment, training, and technical support, including help hardening your own infrastructure.

## ⚖️ License

<a href="https://creativecommons.org/publicdomain/zero/1.0/" rel="nofollow"><img src="https://licensebuttons.net/p/zero/1.0/88x31.png" alt="CC0" /></a>

Security patches belong to everyone. To the extent possible under law, <a href="https://ivycyber.com" rel="nofollow">Ivy Cyber LLC</a> has waived all copyright and related or neighboring rights to this repository, including its scripts and documentation, under the <a href="https://creativecommons.org/publicdomain/zero/1.0/" rel="nofollow">Creative Commons CC0 1.0 Universal Public Domain Dedication</a> (`CC0-1.0`). Feel free to copy, remix, and share. If you'd like to give back, please [donate to PrivacySafe Foundation](https://privacysafe.foundation) 501c3 nonprofit.

See [`NOTICE`](NOTICE) and [`LICENSE`](LICENSE). Third-party components retain their original copyrights and licenses.

CC0 does not waive trademark or patent rights. PrivacySafe® and 3NWeb® are registered trademarks. PrivacySafe Foundation™ and Ivy Cyber™ are pending trademarks. This dedication does not grant permission to use these marks in a manner that suggests sponsorship, endorsement, affiliation, or origin.
