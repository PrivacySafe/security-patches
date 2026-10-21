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
| [PHP2Shell](#-php2shell-interim-mitigation) | PHP-FPM 8.1, 8.2, 8.3 on Debian/Ubuntu | CVE-2026-109618, CVE-2026-109619 | Interim mitigation |

---

## 🐘 PHP2Shell Interim Mitigation

**Script:** [`php/php2shell/php2shell-mitigate.sh`](php/php2shell/php2shell-mitigate.sh)

We released this script ahead of upstream patches for two 0day vulnerabilities in PHP. It adds two layers of defense to every installed PHP-FPM 8.1, 8.2, and 8.3:

1. **An ini drop-in** that turns off `session.upload_progress`. PHP core developers dispute that this setting alone fully mitigates the vulnerability, so treat it as one layer, not a fix.
2. **An AppArmor profile** that stops FPM from executing shells and other binaries. This is the layer that keeps a successful exploit from turning into remote code execution. The profile is built from each version's own FPM config (log paths, sessions, sockets, extension directory), so it fits your server instead of a generic template.

The script is designed so that it can't take your site down. It syntax-checks each profile before installing it. Then it tests FPM with a config check, a restart, a reload, and a socket check. If FPM won't come up, it falls back to complain mode, and if that still fails, it unloads the profile. Each PHP version is handled on its own, so a problem with one never blocks the others.

### Quick start

```bash
curl -O https://raw.githubusercontent.com/PrivacySafe/security-patches/main/php/php2shell/php2shell-mitigate.sh
less php2shell-mitigate.sh          # read it first, always
chmod +x php2shell-mitigate.sh
sudo ./php2shell-mitigate.sh        # apply to every installed PHP-FPM, complain mode
```

New profiles start in **complain mode**, which logs but does not block. Let real traffic run, then review and enforce:

```bash
sudo ./php2shell-mitigate.sh status     # what the profile would have blocked
sudo ./php2shell-mitigate.sh enforce    # start blocking
```

If `status` lists paths your app legitimately needs, such as an uploads or cache directory, add them to `/etc/apparmor.d/local/usr.sbin.php-fpm<version>` and rerun the script. That file is never overwritten.

### Commands

| Command | What it does |
|---|---|
| `apply` (default) | Installs the drop-in and profile, then tests FPM |
| `status` | Shows mitigation state and AppArmor events from the last 24 hours |
| `enforce` | Switches to enforce mode. Refuses if complain mode logged accesses you haven't handled (override with `--force`) |
| `complain` | Switches back to log-only mode |
| `cleanup` | Removes the ini drop-in once you're patched. The AppArmor profile stays as defense in depth |

Add `--php 8.2` to any command to act on a single version.

### Configuration

| Variable | Default | Purpose |
|---|---|---|
| `WEB_ROOTS` | `/var/www /srv/www` | Read-only document roots |
| `WRITABLE_PATHS` | *(empty)* | Paths your app writes to, such as uploads |
| `PATCHED_8_1`, `PATCHED_8_2`, `PATCHED_8_3` | 8.3 is `8.3.36`; others empty | First fixed upstream release for each branch |
| `SUPPORTED_VERS` | `8.1 8.2 8.3` | Versions the script will touch |

When no upstream fixed version is set for a branch, the script checks your distro's changelog for both CVEs instead. That catches backported fixes from Ubuntu, Debian, and the ondrej/sury PPAs, which often keep the old version number.

### Know before you run it

- **This is not a patch.** Upgrade PHP as soon as a fixed build is available for your branch, then run `cleanup`.
- **The profile blocks `mail()`**, because PHP runs sendmail through `/bin/sh`. It also blocks ImageMagick delegates. If your app sends mail, use SMTP from PHP.
- **PHP 8.1 is past upstream end of life.** A fix may only arrive as a distro or PPA backport. Plan your upgrade.
- **Debian and Ubuntu only.** RHEL, Remi, and other SELinux-based layouts need a different approach.
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

© 2026 <a href="https://ivycyber.com" rel="nofollow">Ivy Cyber LLC</a>. This project is dedicated to ethical <a href="https://fsf.org/" rel="nofollow">Free/Libre and Open Source Software (FLOSS)</a>.

Unless otherwise noted, scripts in this repository are licensed under the <a href="https://www.gnu.org/licenses/agpl-3.0.html" rel="nofollow">GNU Affero General Public License version 3 or later</a> (`AGPL-3.0-or-later`). Documentation is licensed under the <a href="https://www.apache.org/licenses/LICENSE-2.0" rel="nofollow">Apache License 2.0</a> (`Apache-2.0`).

PrivacySafe® and 3NWeb® are registered trademarks. PrivacySafe Foundation™ and Ivy Cyber™ are pending trademarks. Software and documentation licenses do not grant trademark rights or permission to use such marks in a manner that suggests sponsorship, endorsement, affiliation, or origin.
