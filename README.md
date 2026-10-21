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
| [PHP2Shell](#-php2shell-interim-mitigation) | PHP-FPM 7.0 through 8.5 on Debian/Ubuntu/Trisquel and derivatives | CVE-2026-109618, CVE-2026-109619 | Interim mitigation |

---

## 🐘 PHP2Shell Interim Mitigation

**Script:** [`php/php2shell-mitigate.sh`](php/php2shell-mitigate.sh)

We released this script ahead of upstream patches for two 0day vulnerabilities in PHP. It adds two layers of defense to every installed PHP-FPM from 7.0 through 8.5:

1. **An ini drop-in** that turns off `session.upload_progress`. PHP core developers dispute that this setting alone fully mitigates the vulnerability, so treat it as one layer, not a fix.
2. **An AppArmor profile** that stops FPM from executing shells and other binaries. This is the layer that keeps a successful exploit from turning into remote code execution. The profile is built from each version's own FPM config (log paths, sessions, sockets, extension directory), so it fits your server instead of a generic template.

The script is designed so that it can't take your site down. It syntax-checks each profile before installing it. Then it tests FPM with a config check, a restart, a reload, and a socket check. If FPM won't come up, it falls back to complain mode, and if that still fails, it unloads the profile. Each PHP version is handled on its own, so a problem with one never blocks the others.

### Quick start

```bash
curl -fLO https://raw.githubusercontent.com/PrivacySafe/security-patches/refs/heads/main/php/php2shell-mitigate.sh
less php2shell-mitigate.sh          # read it first, always
chmod +x php2shell-mitigate.sh
./php2shell-mitigate.sh check       # environment report only, changes nothing
sudo ./php2shell-mitigate.sh        # apply to every installed PHP-FPM, complain mode
```

This repository is mirrored on [GitHub](https://github.com/PrivacySafe/security-patches) and [Codeberg](https://codeberg.org/PrivacySafe/security-patches). To confirm both serve the same script, compare checksums:

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
| `status` | Shows mitigation state and AppArmor events from the last 24 hours |
| `enforce` | Switches to enforce mode. Refuses if complain mode logged accesses you haven't handled (override with `--force`) |
| `complain` | Switches back to log-only mode |
| `cleanup` | Removes the ini drop-in once you're patched. The AppArmor profile stays as defense in depth |

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

The result is *patched*, *not patched*, or *unknown*. *Unknown* usually means a minimized image dropped `/usr/share/doc` and the build isn't in the table. Package dates aren't used: distributions prepare embargoed fixes before the public release, and a later unrelated rebuild doesn't contain the fix.

A patched package isn't enough on its own, because a running FPM keeps executing the old binary until it restarts. The script checks for FPM processes still running a binary that dpkg has replaced, and for Apache holding an old `libphp*.so`, and tells you which service to restart.

### Configuration

| Variable | Default | Purpose |
|---|---|---|
| `WEB_ROOTS` | `/var/www /srv/www` | Read-only document roots |
| `WRITABLE_PATHS` | *(empty)* | Paths your app writes to, such as uploads |
| `PATCHED_X_Y` (for example `PATCHED_8_4`) | `8.2.35`, `8.3.36`, `8.4.27`, `8.5.12`; empty for 7.0–8.1 | First fixed upstream release for each branch |
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
