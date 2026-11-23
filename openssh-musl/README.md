# OpenSSH: password authentication bypass on musl Linux without PAM

Part of the [PrivacySafe Security Patches](../README.md) collection.

<a name="openssh-musl-password-bypass"></a>

## OpenSSH password authentication bypass on musl Linux without PAM

**Script:** [`openssh-musl/openssh-musl-check.sh`](openssh-musl-check.sh)

On 5 November 2026, OpenSSH released 10.6p2 with an emergency fix for sshd on Linux systems that use musl libc (Alpine Linux, OpenWrt, buildroot, Yocto, and many container base images) without PAM. When sshd checks a password itself, it hashes the attempt with `crypt()` and compares the result to the account's stored field in `/etc/shadow`. musl's `crypt()` returns the literal string `*` as its error indicator for a password over 256 bytes, and `*` is also the stored field of every account that has no password set. A password between 257 and 1024 bytes therefore matches, and the login succeeds, for any account whose shadow field is `*`, as long as some other local account has a real password hash for sshd to borrow a salt from (sshd borrows a real salt so that an unknown user takes as long to reject as a known one, a long-standing defense against username probing by timing). The 256/257 byte boundary and the exact `*` return hold on a real musl build for this release, with both `$5$` and `$6$` salts.

This is **CVE-2026-123158**, nicknamed "sshole" by its finder; CVSS 3.1 8.1 (High). CISA added it to the Known Exploited Vulnerabilities catalog on 9 November 2026, with multiple independent reports describing exploitation attempts within hours of disclosure, including one claim of a successful root compromise on an Alpine honeypot by chasing the passwordless `doas` path described below. This script was written the same week the bug was reported and before the CVE number was assigned; the detection and mitigation logic is unchanged by that, since it was always built around the underlying mechanism rather than a version string tied to the CVE.

Reported by Özgün Kültekin of [Wakefield](https://wakefield.co), with advisories the same day from [Alpine Linux](https://alpinelinux.org/posts/2026-11-05-openssh-password-authentication-bypass/) and [OpenSSH's own 10.6p2 release notes](https://www.openssh.com/releasenotes.html#10.6p2), which describe it as a critical fix and say the OpenSSH team considers the root cause to be outside sshd but exploitable through it.

| | |
|---|---|
| CVE | None at time of writing |
| Affected | sshd linked against musl, with PAM not in effect (built without it, or built with it and run with `UsePAM no`), `PasswordAuthentication yes` (OpenSSH's own default), an account whose shadow field is exactly `*`, and at least one other account with a `$5$` or `$6$` hash |
| Not affected | glibc, any system using PAM with `UsePAM yes`, `PasswordAuthentication no`, an account locked with `!` instead of `*`, a host with no `$`-style hash anywhere, and every non-Linux system |
| Fixed | OpenSSH 10.6p2 (5 November 2026); Alpine has backported it to every release still receiving updates and several that no longer do (table below) |
| Remedy | Update, or run `mitigate` as a stopgap: it sets `PasswordAuthentication no`, which closes this regardless of OpenSSH's version |

## Why this needs all of those conditions

`*` cannot be produced by a successful `crypt()` call: it is musl's own, deliberate "this failed" signal, chosen in 2012 so that a program comparing hashes would see a mismatch instead of crashing on a NULL return. It is unrelated to, and eleven years older than, musl's own password-length cap of 256 bytes added three weeks later; the two only combine into this bug because `/etc/shadow` also uses `*` to mean "no password", a convention from 1980. The account's own field is never read as a salt: for an account whose field is too short to contain one, sshd borrows a working salt from another account and hashes the attempt against that, a 2016 fix for a user-enumeration timing flaw. That borrowed real salt is what lets a 257+ byte password reach musl's length cap and fail, rather than simply hashing to something else.

An account locked with `!` is never reachable this way, because `!` is not a string `crypt()` can return on failure; the two never match whatever the attempted password is.

PAM changes everything, because PAM modules (`pam_unix`, `pam_ldap` and so on) do their own password checking and typically refuse a `*` or `!` field outright, without ever calling `crypt()` on it the way sshd's own check does. A PAM-linked sshd run with `UsePAM no`, however, falls back to checking the password itself exactly like a build with no PAM at all, so it is exposed in the same way.

## Checking a Match block matters too

Confirmed directly against a real sshd: a `Match` block's own `PasswordAuthentication yes` overrides a global `PasswordAuthentication no` for the connections it matches, even when that global `no` comes from a drop-in file read earlier in the configuration. `check` reports any Match block that does this on its own, independent of the global setting, and `mitigate` changes every explicit `PasswordAuthentication ... yes` line it finds, including ones inside a Match block, not only the global default. A drop-in alone would miss a Match block like this.

## Alpine fixed versions

| Alpine branch | Fixed `openssh` version |
|---|---|
| edge | `10.6_p2-r0` |
| 3.24 | `10.3_p1-r2` |
| 3.23 | `10.2_p1-r1` |
| 3.22 | `10.0_p1-r11` |
| 3.21 | `9.9_p2-r1` |
| 3.20 | `9.7_p1-r6` |
| 3.19 | `9.6_p1-r3` |
| 3.18 | `9.3_p2-r4` |
| 3.17 | `9.1_p1-r7` |
| 3.16 | `9.0_p1-r6` |

On a non-Alpine musl system, `check` compares the OpenSSH version number itself against 10.6p2, the portable release that carries the fix. A distribution may have backported the fix under an older version number, the way Alpine has; this script does not know of a version table for OpenWrt, buildroot or Yocto, so it says to check your own vendor's advisory when the version number alone looks affected.

## Alpine's official cloud images

Alpine's own tiny-cloud AWS and Azure images, from 3.18.11 through 3.24.3, ship an `alpine` user with a `*` password field and passwordless `doas`. OpenSSH's own `PermitRootLogin prohibit-password` default blocks root directly, but it does nothing once another account that can log in can become root through `doas`. These images are safe on first boot; they become exposed as soon as any `$5$` or `$6$` hash exists on the host, for example when an admin sets a console password or cloud-init user-data adds a user with `hashed_passwd`. Images from 3.21.10, 3.22.8, 3.23.8, 3.24.4 and later carry the fixed package already. Cloud-init itself writes `PasswordAuthentication no` on most cloud images, which closes this regardless of the package version; check that it is still set before relying on it.

## Quick start

Download the script. The repository is mirrored on GitHub and Codeberg; pick a base URL.

```bash
# BASE from GitHub: https://raw.githubusercontent.com/PrivacySafe/security-patches/refs/heads/main
# BASE from Codeberg: https://codeberg.org/PrivacySafe/security-patches/raw/branch/main
# curl -fLO "$BASE/openssh-musl/openssh-musl-check.sh"
curl -fLO https://raw.githubusercontent.com/PrivacySafe/security-patches/refs/heads/main/openssh-musl/openssh-musl-check.sh
```

Read it before running it, then make it executable.

```bash
less openssh-musl-check.sh
chmod +x openssh-musl-check.sh
```

Check this host. It changes nothing and needs no root, though root sees more (it can read `/etc/shadow`).

```bash
sudo ./openssh-musl-check.sh check
```

If it is exposed and you cannot update immediately:

```bash
sudo ./openssh-musl-check.sh mitigate --restart
```

## Commands

| Command | What it does |
|---|---|
| `check` (default) | Read-only. Finds sshd without executing it (its ELF interpreter tells `check` whether it is musl, its dynamic section whether it links PAM), reads the effective configuration with `sshd -T`, scans for a Match block that re-enables password authentication on its own, and reads `/etc/shadow` for an account with no password set and another with a usable salt. Exit `0` not affected, `1` affected, `2` it could not be judged (sshd or `/etc/shadow` could not be read) |
| `hunt` | Read-only. Reads the journal's `sshd` messages and `/var/log/auth.log`, `/var/log/secure` and `/var/log/messages` where they exist, for an `Accepted password` line naming an account whose shadow field is `*` right now. This can only check the account's *current* field, not what it was when an old log line was written. Exit `0` nothing found, `1` a lead, `2` no log could be read |
| `mitigate [--dry-run] [--restart]` | **Changes the host (root).** Sets `PasswordAuthentication no` two ways: a drop-in file where `sshd_config` includes one, or the top of `sshd_config` itself where it does not; and every other explicit `PasswordAuthentication ... yes` line already in `sshd_config`, including one inside a Match block. Every file is copied first, the result is checked with `sshd -t`, and the originals are put back at once if that check fails. Nothing is restarted unless you add `--restart` |
| `rollback [--dry-run] [--restart]` | Restores every file `mitigate` changed |
| `version` | Prints the script version |

Env: `SSHD_BIN`, `SSHD_CONFIG` (default `/etc/ssh/sshd_config`), `SSHD_CONFIG_D` (default `/etc/ssh/sshd_config.d`), `SHADOW_FILE` (default `/etc/shadow`), `OS_RELEASE_FILE` (default `/etc/os-release`), `APK_PKG_VERSION` (the installed `openssh` package version, instead of `apk`), `HUNT_LOG_FILES` (the log files `hunt` reads, instead of the defaults), and `STATE_DIR` and `PSF_LOCK_WAIT` for `mitigate` and `rollback`.

## How to read the result

- **Affected:** update OpenSSH, or run `mitigate` as a stopgap. Upgrading the package does not replace a running `sshd`; restart it, or pass `--restart` to `mitigate`.
- **Not affected, but a Match block re-enables password authentication:** `check` reports this as exit `1` on its own, even when the global setting looks safe, because the Match block's connections are still exposed.
- **Could not be judged:** usually `/etc/shadow` was not readable (run as root) or `sshd -T` could not be run. Neither condition it covers could be checked.
- **`hunt` found nothing:** this is not clearance. It only means the logs it could read show no accepted password login for an account that currently has no password; an older login, before the field last changed, would not show up this way.
- **`hunt` found a lead:** treat the host as compromised. Check `doas` or `sudo` use, new administrator accounts, `authorized_keys` and crontabs, then update OpenSSH and rotate anything the account could reach.

## Sources

- [Alpine Linux security advisory, 5 November 2026](https://alpinelinux.org/posts/2026-11-05-openssh-password-authentication-bypass/): who is affected, the fixed package versions, the cloud-image detail, and the detection and fix commands this tool follows.
- [OpenSSH 10.6p2 release notes](https://www.openssh.com/releasenotes.html#10.6p2): the primary source for the fix itself, described as "a critical security workaround" for Linux systems that run musl libc with PAM disabled. Credits Özgün Kültekin of Wakefield.

## Before you run it

The fix is OpenSSH 10.6p2, or your distribution's backport of it; `mitigate`'s `PasswordAuthentication no` is a stopgap that closes this regardless of OpenSSH's version, on any libc. The script never attempts a login and never executes `sshd` with attacker-controlled input: it reads the binary's ELF headers, asks `sshd -T` for the configuration it would use, and reads `/etc/shadow`. The musl `crypt()` behavior this script relies on (256 bytes succeeds, 257 returns `*`) was confirmed against a real musl build for this release, not taken only from the advisories. The Alpine package-version table is read from Alpine's own advisory; the generic, non-Alpine version comparison and the Match-block scan were confirmed against a real `sshd -t`, but `apk version -t`, the comparator `check` uses for Alpine packages, was not independently run in the environment this script was built in, since that environment has no `apk`.

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
