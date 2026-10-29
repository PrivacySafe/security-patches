# Roundcube Webmail 1.6.20 and 1.7.5: CVE-2026-114716 check

Part of the [PrivacySafe Security Patches](../README.md) collection.

<a name="roundcube-webmail-october-2026-check"></a>

## Roundcube Webmail October 2026 check

**Script:** [`roundcube/roundcube-oct2026-check.sh`](roundcube-oct2026-check.sh)

Roundcube released 1.6.20 (the LTS line) and 1.7.5 (mainline) on 19 October 2026. Both carry the same 20 security fixes, the largest batch since 1.7.0: IMAP command injection through a CRLF in the `_uid` and `_flag` parameters, four mail header injection flaws, cross-site scripting, server-side request forgery, cross-site request forgery, an object injection primitive in session handling, and ImageMagick limit bypasses. The project says it strongly recommends updating every production installation.

CVE-2026-114716 is one of the mail header injection fixes. The release notes list four: through the From display-name in the Bounce action, through the `References`, `In-Reply-To`, `Message-ID` and `From` parameters, through the subject of a message forwarded as an attachment, and through the media type of an inline image. The advisory does not say which fix carries which CVE number, so this tool does not claim to tell them apart. A header injection lets an attacker add or change headers on an outgoing message, which feeds phishing and forged mail that leaves your own trusted server.

| | |
|---|---|
| CVE | CVE-2026-114716 (mail header injection), rated High 8.5. The release carries 19 other fixes |
| Affected | Roundcube 1.6.x below 1.6.20, and 1.7.x below 1.7.5 |
| Fixed | 1.6.20 and 1.7.5 |
| Not covered | 1.5 and earlier: these releases only cover the 1.6 and 1.7 lines |
| Exploited | None confirmed for these 20 fixes in the release notes. Roundcube flaws have been exploited in the past, and CISA's Known Exploited Vulnerabilities catalog lists 11 of them |
| Hosting panels | cPanel and Plesk ship and update their own copy. The fix arrives with the panel's update, so the panel's changelog decides |

## Quick start

1. Download the script. The repository is mirrored on GitHub and Codeberg; pick a base URL.

   ```bash
   # BASE from GitHub:   https://raw.githubusercontent.com/PrivacySafe/security-patches/refs/heads/main
   # BASE from Codeberg: https://codeberg.org/PrivacySafe/security-patches/raw/branch/main
   # curl -fLO "$BASE/roundcube/roundcube-oct2026-check.sh"
   curl -fLO https://raw.githubusercontent.com/PrivacySafe/security-patches/refs/heads/main/roundcube/roundcube-oct2026-check.sh
   ```

2. Read it before running it, then make it executable.

   ```bash
   less roundcube-oct2026-check.sh
   chmod +x roundcube-oct2026-check.sh
   ```

3. Check this host. By default it searches `/var/www /srv /opt /home`, the distribution paths `/usr/share/roundcube`, `/usr/share/roundcubemail` and `/var/lib/roundcube`, and the cPanel and Plesk bundle paths.

   ```bash
   ./roundcube-oct2026-check.sh check
   ./roundcube-oct2026-check.sh check /var/www/webmail
   ```

4. Look for probing of the IMAP injection parameters in your web server logs.

   ```bash
   sudo ./roundcube-oct2026-check.sh hunt
   ```

## Commands

| Command | What it does |
|---|---|
| `check [DIR ...]` (default) | Finds installs by `program/include/iniset.php`, reads `RCMAIL_VERSION` (falling back to the first release in `CHANGELOG.md`), and compares it with 1.6.20 and 1.7.5 |
| `hunt` | Searches readable Apache, nginx and httpd access logs for `_uid` or `_flag` values that contain an encoded carriage return or line feed (`%0d`, `%0a`). Set `HUNT_LOGS` to add a log path |
| `version` | Prints the script version |

Exit codes: `0` nothing affected (or nothing found), `1` an affected install (or suspicious requests) found, `2` bad arguments.

## How to read the result

- **Distribution packages.** Debian, Ubuntu, RHEL and others backport fixes without changing the version string. For copies owned by a `dpkg` or `rpm` package the script reads the package changelog and reports a mention of the CVE. Check your distribution's security tracker as well.
- **Panel-bundled copies** are labelled. The panel's own update delivers the fix, so check the panel's changelog.
- **Hunt hits** are probes of the IMAP injection parameter that this same release fixes. They show someone has been testing your webmail. A hit is a lead, not proof of a successful attack; update first, then look at the IMAP server's own log for commands you did not expect.
- **A clean hunt** is not proof of safety: logs rotate, and POST bodies are not logged.

## Fixing it

Back up the Roundcube files and database first, as the project advises, then move to 1.6.20 on the LTS line or 1.7.5 on mainline, following the upgrade steps in the release notes. On a panel-managed server, update the panel.

## Sources

- [Roundcube 1.6.20 release](https://github.com/roundcube/roundcubemail/releases/tag/1.6.20)
- [Roundcube: security updates 1.6.20 and 1.7.5](https://roundcube.net/news/2026/10/19/security-updates-1.6.20-and-1.7.5)

## Roundcube know before you run it

- **This is a check, not a fix.** Update to 1.6.20 or 1.7.5, which carry the same 20 security fixes. These releases do not cover 1.5 and earlier.
- **Hosting panels bundle their own copy.** cPanel and Plesk ship Roundcube and update it with the panel, so the panel's changelog decides when it is safe.
- **`hunt` searches web server logs for CRLF probing** of the `_uid` and `_flag` parameters (the IMAP injection the same release fixes). A hit means someone has been testing your webmail, not that an attack succeeded.
- **The version is read from `program/include/iniset.php`.**
- **It also reads running containers.** With no directory argument and `SCAN_CONTAINERS=1` (the default), the check finds installs inside running docker and podman containers by their marker file, copies only the files it reads into a private temporary directory, and judges them like a host install. A path shown as `.../docker_NAME_PATH` is the PATH inside the container NAME. It never runs anything in a container beyond `find` and a file copy, never copies `.env` or `wp-config.php`, never keeps a staged symlink, and is skipped when you name directories yourself.

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
