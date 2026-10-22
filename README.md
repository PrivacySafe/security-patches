<p align="center">
  <a href="https://privacysafe.app"><img src="privacysafe_horizontal_logo_lock_reg_padded.svg" width="600" /></a>
</p>
<h1 align="center">Security Patches</h1>

<h3 align="center">
Security patches we use, shared here for the public good 🛡️
</h3>

<p align="center">
  <a href="https://privacysafe.foundation"><strong>❤️ Donate to PrivacySafe Foundation</strong></a>
</p>

This repository holds the mitigations, hardening scripts, and interim fixes we run on PrivacySafe and Ivy Cyber infrastructure. When a vulnerability lands before a vendor patch does, we write something to keep our own systems safe, and then we publish it here so every other admin can use it too.

> 💚 **If one of these saved you a long night, please [donate to PrivacySafe Foundation](https://privacysafe.foundation).** The Foundation is a 501(c)(3) nonprofit, and your support pays for exactly this kind of public-interest security work.

---

## 📦 Patches

| Patch | Targets | CVEs | Type |
|---|---|---|---|
| [PHP2Shell](#php2shell-interim-mitigation) | PHP-FPM 7.0 through 8.5 on Debian/Ubuntu/Trisquel and derivatives | CVE-2026-109618, CVE-2026-109619 | Interim mitigation |
| [eMudhra CA Compromise](#emudhra-intermediate-ca-compromise-interim-mitigation) | System CA store on Debian/Ubuntu/Trisquel and derivatives | [disclosure](https://emudhra.we-have-a-problem.com/); Go: CVE-2026-111943 | Interim mitigation |

> ℹ️ **Update 2026-10-22:** an allocator double-free in this class (`free` -> `__zend_free` -> `_efree`, `zend_alloc.c`) was reproduced on **8.5.12**, the release listed as fixed, through PHP's built-in CLI server (`php -S`) with a crafted POST body. It's unconfirmed on a stock (non-ASan) release build and may be a distinct bug rather than an incomplete fix for CVE-2026-109618/-109619. `hunt` and `php2shell-watch.sh` now detect this signature; see [Hunting for exploitation](#hunting-for-exploitation). Note that the AppArmor layer confines **PHP-FPM**, not the `php` CLI binary, so it does **not** contain an exploit of the dev server; don't expose `php -S` to untrusted traffic.

---

## PHP2Shell Interim Mitigation

**Script:** [`php/php2shell-mitigate.sh`](php/php2shell-mitigate.sh)

We released this script ahead of upstream patches for two 0day vulnerabilities in PHP. It adds two layers of defense to every installed PHP-FPM from 7.0 through 8.5:

1. **An ini drop-in** that turns off `session.upload_progress`. PHP core developers dispute that this setting alone fully mitigates the vulnerability, so treat it as one layer, not a fix.
2. **An AppArmor profile** that stops FPM from executing shells and other binaries. This is the layer that keeps a successful exploit from turning into remote code execution. The profile is built from each version's own FPM config (log paths, sessions, sockets, extension directory), so it fits your server instead of a generic template. It lets FPM signal readiness to systemd, which every Debian, Ubuntu and sury unit requires (`Type=notify`). Where the parser supports it (AppArmor 3.0 and later), it declares `abi <abi/3.0>`, so the rules mean the same thing on Ubuntu and Debian 13.

The script is designed so that it can't take your site down. It syntax-checks each profile before installing it. Then it tests FPM with a config check, a restart, a reload, and a socket check. Under systemd it also checks that the unit didn't restart itself during the test. PHP 8.4 and later units use `Restart=on-failure`, which can make a crash-looping FPM look active. If FPM won't come up, it falls back to complain mode, and if that still fails, it unloads the profile. Each PHP version is handled on its own, so a problem with one never blocks the others.

### Quick start

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

Every command starts with an environment check and refuses to run if your server isn't a fit. See [Environment check](#environment-check).

New profiles start in **complain mode**, which logs but does not block. Let real traffic run, then review and enforce:

```bash
sudo ./php2shell-mitigate.sh status     # what the profile would have blocked
sudo ./php2shell-mitigate.sh enforce    # start blocking
```

If `status` lists paths your app legitimately needs, such as an uploads or cache directory, add them to `/etc/apparmor.d/local/usr.sbin.php-fpm<version>` and rerun the script. That file is never overwritten.

### Commands

| Command | What it does |
|---|---|
| `check` | Environment report only. Changes nothing and doesn't need root. Exits `0` if clear, `1` on a hard blocker, `2` if `--ignore-env` would be needed |
| `apply` (default) | Installs the drop-in and profile, then tests FPM |
| `status` | Shows mitigation state and the AppArmor events logged under the current profile (since it was last written, at most 24 hours) |
| `enforce` | Switches to enforce mode. Refuses if complain mode logged accesses you haven't handled (override with `--force`) |
| `complain` | Switches back to log-only mode |
| `hunt` | Read-only log triage. Scans PHP-FPM, Apache and nginx logs for the memory-corruption crashes these bugs cause (including AddressSanitizer/debug-build double-free and use-after-free backtraces, and crashes through the built-in CLI server, `php -S`), and for signs of exploitation. Changes nothing, doesn't need root. Exits `0` if nothing matched, `1` if it found something to look at |
| `cleanup` | Removes the ini drop-in once you're patched. The AppArmor profile is left loaded, since it confines FPM against the next bug too (the patch doesn't). Once patched, either switch it on for real with `enforce`, or take it out with `remove` |
| `remove` | Removes the AppArmor profile entirely: unloads it from the kernel, deletes the profile, the `local/` override and any disable symlink, then confirms `aa-status` no longer lists FPM. Leaves the ini drop-in (that's `cleanup`'s job) and needs no patch. Refuses to touch a profile this script didn't create |

Add `--php 8.2` to any command to act on a single version.

### Environment check

Before changing anything, the script checks your server in this order and prints what it found:

1. **Operating system.** Debian, Ubuntu and Trisquel are supported, and so is any derivative. The check recognizes Linux Mint, Pop!_OS, elementary OS, Zorin OS, KDE neon, Kali, Raspberry Pi OS, PureOS, Parrot, deepin, TUXEDO OS, Devuan, MX Linux, antiX, SparkyLinux, Q4OS, Peppermint, BunsenLabs and siduction by name. It also accepts anything else whose `ID_LIKE` names Debian or Ubuntu, or that has `/etc/debian_version`. A derivative never stops the run. The check also reports the base release and the PHP version it ships.
2. **PHP.** Every PHP-FPM under `/usr/sbin`, its package version, whether it came from your distro or the ondrej/sury repository, and whether it's patched (see [Patch detection](#patch-detection)). It flags PHP it can't protect: versions outside `SUPPORTED_VERS`, PHP-FPM built outside dpkg, and LiteSpeed's `lsphp`.
3. **Web servers.** Apache and nginx (plus angie, lighttpd and caddy), whether each is running, and which PHP-FPM version each one actually sends traffic to.
4. **System.** Root, the init system, containers, AppArmor in the kernel, SELinux, and required tools. Without systemd (sysvinit or OpenRC, as on Devuan, MX and antiX), the script uses `service` and the PHP-FPM init scripts. It reads AppArmor events from `audit.log`, `kern.log` and `dmesg`.

Problems fall into two groups. **Hard blockers** always stop the run: a distribution that isn't Debian-based, no way to restart FPM (no systemd and no init script), no AppArmor in the kernel for `apply`, `enforce` or `complain`, not running as root, or no supported PHP-FPM. **Soft blockers** stop the run until you've looked at them, and `--ignore-env` lets you proceed:

- Apache running an **unpatched** mod_php. PHP inside Apache is not covered by this script, so you'd get a clean summary while Apache stays exposed. The report prints the upgrade and a one-line interim drop-in. Patched mod_php is only reported.
- Your running web server only uses PHP-FPM versions this run won't touch, for example nginx serving everything from PHP 8.4.

`--ignore-env` doesn't affect `--force`, and `--force` doesn't skip the environment check.

### Patch detection

For each PHP version, the report, `status` and `cleanup` say whether the installed package is fixed. Three checks run in order, and any one is enough:

1. **Upstream version.** The package is at or above the first fixed release: 8.2.35, 8.3.36, 8.4.27 or 8.5.12. This covers Debian, which ships the new upstream release (for example `8.4.27-1~deb13u1` in DSA-6574-1), and the sury repository.
2. **Known distro backport.** Ubuntu backports fixes without changing the upstream version, so `8.3.6-0ubuntu0.24.04.13` is fixed even though it says 8.3.6. The script carries the fixed builds from USN-8948 for 16.04 through 26.10 and compares the full version. Add builds as they're published with `FIXED_BUILDS`.
3. **Changelog.** The package changelog names both CVEs. This catches backports the script doesn't know about. The changelog only counts if its newest entry is the installed version.

If none of those finds a fix, a build below the first fixed release counts as *not patched* unless it's an Ubuntu build. sury and Debian ship the new upstream release rather than backporting, so their older upstream versions are unfixed even when there's no changelog to read, as on Docker images.

The result is *patched*, *not patched*, or *unknown*. *Unknown* usually means an Ubuntu build on a minimized image that dropped `/usr/share/doc`, with no entry in the table. Package dates aren't used: distributions prepare embargoed fixes before the public release, and a later unrelated rebuild doesn't contain the fix.

A patched package isn't enough on its own, because a running FPM keeps executing the old binary until it restarts. The script checks for FPM processes still running a binary that dpkg has replaced, and for Apache holding an old `libphp*.so`, and tells you which service to restart.

### Hunting for exploitation

These bugs run below the application, so your app logs won't show much. What they leave behind is memory-corruption crashes, and, on a server that was actually exploited, a PHP worker doing something it shouldn't. `hunt` reads your logs (never changes anything) and reports both:

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

### Configuration

| Variable | Default | Purpose |
|---|---|---|
| `WEB_ROOTS` | `/var/www /srv/www` | Read-only document roots |
| `WRITABLE_PATHS` | *(empty)* | Paths your app writes to, such as uploads |
| `PATCHED_X_Y` (for example `PATCHED_8_4`) | `8.2.35`, `8.3.36`, `8.4.27`, `8.5.12`; empty for 7.0-8.1 | First fixed upstream release for each branch |
| `SUPPORTED_VERS` | `7.0 7.1 7.2 7.3 7.4 8.0 8.1 8.2 8.3 8.4 8.5` | Versions the script will touch |
| `FIXED_BUILDS` | *(empty)* | Extra fixed distro builds, space-separated full versions, for example a Debian LTS 7.4 update |

When no upstream fixed version is set for a branch, the script checks your distro's changelog for both CVEs instead. That catches backported fixes from Ubuntu, Debian, and the ondrej/sury PPAs, which often keep the old version number.

### Know before you run it

- **This is not a patch.** PHP released fixes on 21 October 2026 in 8.5.12, 8.4.27, 8.3.36 and 8.2.35, and distributions are shipping backports under their own version numbers. Upgrade, then run `cleanup`.
- **The profile blocks `mail()`**, because PHP runs sendmail through `/bin/sh`. It also blocks ImageMagick delegates. If your app sends mail, use SMTP from PHP.
- **PHP 7.0 through 8.1 are past upstream end of life.** PHP fixed only 8.2 through 8.5. For older branches a fix can only come as a distro or PPA backport, such as Debian LTS, Ubuntu ESM or the sury PPA. Without one, this mitigation is permanent, so plan your upgrade.
- **PHP 5.x is reported affected but not covered.** The environment check flags it.
- **Debian, Ubuntu, Trisquel and their derivatives only**, with systemd, sysvinit or OpenRC. RHEL, Remi, and other SELinux-based layouts need a different approach. The environment check refuses to run on them.
- **PHP-FPM only.** Apache mod_php and LiteSpeed lsphp are reported but not mitigated.
- **Backups** of everything the script touches go to `/var/backups/php2shell/<timestamp>/<version>/`.

---

## eMudhra Intermediate CA Compromise Interim Mitigation

**Script:** [`pki/emudhra-mitigate.sh`](pki/emudhra-mitigate.sh)

On 20 October 2026 it was [disclosed](https://emudhra.we-have-a-problem.com/) that the private keys of eight eMudhra intermediate CAs can be recovered from their certificates. Anyone holding one can impersonate any website. Browsers already block them through OneCRL, CRLite and CRLSets, but your server's system CA store doesn't. Everything that reads it keeps trusting the compromised intermediates until `ca-certificates` is updated: OpenSSL, GnuTLS, curl, wget, apt, git, Python, PHP, Go, Ruby, and Java through ca-certificates-java.

The intermediates reach the store through two roots: emSign ECC Root CA - G3, which cross-signs emSign Root TLS CA - G3, and Sectigo's AAA Certificate Services, which cross-signs all eight. This script:

1. **Distrusts those roots in the system store**, using `!` lines in `/etc/ca-certificates.conf`, and rebuilds it. It finds affected certificates by public key, not file name, so it also catches copies someone added by hand to `/usr/local/share/ca-certificates` or `/etc/ssl/certs`. It moves those out of the store into the backup directory.
2. **Proves the store rejects all of them.** The script embeds the 16 published intermediate certificates and checks each against its published SHA-256 before using it. After every change it tests all 16 against the bundle file, the hash directory, and OpenSSL's built-in default paths. It also checks the bundle holds none of the affected certificates, because Go and GnuTLS will treat a lone intermediate in the store as a trust anchor.

The script is designed so it can't break your CA store or leave you exposed by mistake. It checks that the rebuilt bundle lost only affected certificates and still has hash links, and rolls back if not. If `TEST_HOSTS` is set, it checks those hosts before and after so you see any collateral breakage immediately. `cleanup` never removes the distrust unless the store still rejects every compromised intermediate without it, and re-applies it if not.

### Quick start

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

### Commands

| Command | What it does |
|---|---|
| `check` | Environment report only. Changes nothing and doesn't need root. Exits `0` if clear, `1` on a hard blocker, `2` if `--ignore-env` would be needed |
| `apply` (default) | Distrusts the affected certificates, rebuilds the store, cleans the Java keystore, then verifies |
| `status` | What this script changed, all store tests, Java keystore state, and processes that still need a restart. Exits `1` if the store trusts a compromised intermediate |
| `restore` | Undoes everything this script distrusted. This re-exposes you if `ca-certificates` isn't patched |
| `cleanup` | Once `ca-certificates` is patched, removes this script's distrust, but only if the store still rejects every compromised intermediate. Otherwise it puts the distrust back. `--force` skips the patch check, never the store test |

### Environment check

Before changing anything, the script checks your server in this order and prints what it found:

1. **Operating system.** The same set as PHP2Shell: Debian, Ubuntu, Trisquel, the derivatives the check knows by name, and anything whose `ID_LIKE` names Debian or Ubuntu. It works out the base release so it can compare against the right fixed `ca-certificates` build. Other systems are refused with a pointer to their workaround on the disclosure page.
2. **System CA store.** The `ca-certificates` version and its patch status (see [Patch detection](#patch-detection-1)). It lists every affected certificate it finds, whether shipped, already distrusted, or added by hand, and tests the current bundle.
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

### Patch detection

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

### Configuration

| Variable | Default | Purpose |
|---|---|---|
| `TEST_HOSTS` | *(empty)* | `host[:port]` list to TLS-test before and after `apply`, to catch collateral breakage |
| `FIXED_BUILDS` | *(empty)* | Extra fixed `ca-certificates` builds, space-separated full versions |
| `SCAN_PATHS` | `/opt /srv /usr/local /usr/lib /usr/share /home /root /var/www` | Where to look for bundled CA files. Empty disables the scan |
| `SCAN_DEPTH` | `9` | How deep that scan goes |
| `JAVA_STOREPASS` | `changeit` | Password for the Java keystores |

### Know before you run it

- **This is not a patch.** Upgrade `ca-certificates` when your distribution ships the fix, then run `cleanup`.
- **It distrusts two whole roots, not just the eight intermediates.** The system store can only drop roots, so every site whose chain ends at emSign ECC Root CA - G3 or AAA Certificate Services fails verification until you run `cleanup` or `restore`. Set `TEST_HOSTS` and check `status` after applying. If the store already rejects every compromised intermediate, for example because a patched package cut the path, `apply` leaves those two roots trusted.
- **Your browsers are already protected.** Firefox, Chrome, Edge and Safari block these intermediates themselves. This script is for everything else on your servers.
- **Other CA stores are reported, not changed.** Python certifi, Node.js, other JDKs and NSS builtins need their own updates. The report prints the command for each. Programs that compile their roots in, such as Rust's webpki-roots and Electron apps, can't be detected and need updating. For a Node.js or Electron app you can't immediately upgrade, the [`kill-emudhra`](https://github.com/IAmJSD/kill-emudhra) package distrusts the eight intermediates from inside the process by their public-key hash, as a stopgap until you reach a fixed Node.js (22.23.4 / 24.22.1 / 26.12.1) or Electron (44.9.1 / 43.8.1 / 42.11.16).
- **Go binaries need their own fix.** A Go program built with CGO reads the system store this script fixes, but a pure-Go build carries Go's own certificate verifier, which got a built-in denylist for these intermediates in Go 1.26.10 and 1.27.3 ([CVE-2026-111943](https://pkg.go.dev/vuln/GO-2026-6809)). Rebuild such binaries with a fixed toolchain; this script's check reminds you if a `go` toolchain is present but can't tell which existing binaries are affected.
- **Containers get their own fix.** Each image carries its own `ca-certificates`. Rebuild images on patched bases; running this inside a container fixes that container only.
- **The distrust survives package upgrades and `dpkg-reconfigure ca-certificates`.** Both keep `!` lines in `/etc/ca-certificates.conf`. Check with `status` after any upgrade anyway.
- **Debian, Ubuntu, Trisquel and their derivatives only.** Fedora/RHEL, openSUSE, Arch, Alpine, NixOS, FreeBSD and macOS need a different approach. See the [disclosure page](https://emudhra.we-have-a-problem.com/#linux).
- **Backups** of everything the script touches go to `/var/backups/emudhra-mitigation/<timestamp>/`. The record of what it changed is `/var/lib/emudhra-mitigation/state`.

---

## ⚠️ Use at Your Own Risk

These scripts are what we run in production, and we test them carefully, but your systems are not our systems. Read every script before you run it, try it on staging first when you can, and keep backups. Everything here comes with no warranty, as described in the license.

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

Security patches belong to everyone. To the extent possible under law, <a href="https://ivycyber.com" rel="nofollow">Ivy Cyber LLC</a> has waived all copyright and related or neighboring rights to this repository, including its scripts and documentation, under the <a href="https://creativecommons.org/publicdomain/zero/1.0/" rel="nofollow">Creative Commons CC0 1.0 Universal Public Domain Dedication</a> (`CC0-1.0`). Copy, modify, and redistribute it however you like, with no attribution required. If you'd still like to give back, please [donate to PrivacySafe Foundation](https://privacysafe.foundation).

See [`NOTICE`](NOTICE) and [`LICENSE`](LICENSE). Third-party components retain their original copyrights and licenses.

CC0 does not waive trademark or patent rights. PrivacySafe® and 3NWeb® are registered trademarks. PrivacySafe Foundation™ and Ivy Cyber™ are pending trademarks. This dedication does not grant permission to use these marks in a manner that suggests sponsorship, endorsement, affiliation, or origin.
