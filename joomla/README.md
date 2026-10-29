# Joomla core, September 2026 security release (CVE-2026-90915, CVE-2026-92222 and others)

Part of the [PrivacySafe Security Patches](../README.md) collection.

<a name="joomla-check"></a>

## Joomla core check

**Script:** [`joomla/joomla-check.sh`](joomla-check.sh)

Joomla 5.4.9 and 6.1.4, released on 29 September 2026, fix 16 core security issues (CVE-2026-90906 to CVE-2026-92232). The Joomla Security Strike Team rates two of them High and thirteen Moderate.

| CVE | Severity | What | Affected |
|---|---|---|---|
| CVE-2026-90915 | High | Arbitrary directory deletion. The cache purge action (System, Clear Cache) did not confine the cache group name, so a path traversal in the file-based cache could delete any directory the web server can write to | 4.0.0 to 5.4.8, 6.0.0 to 6.1.3 |
| CVE-2026-92222 | High | Server-side request forgery through URL fields (feed and request URLs) in several core extensions. Needs a Manager account or above | 3.0.0 and later |
| CVE-2026-92227 | Moderate, high impact | A multi-factor authentication bypass through remember-me cookies issued too early. Needs the password first | 4.0.0 to 5.4.8, 6.0.0 to 6.1.3 |
| CVE-2026-90916 | | Improper access checks in the content history comparison view | 4.0.0 to 5.4.8, 6.0.0 to 6.1.3 |
| CVE-2026-90906, CVE-2026-92224 | | Cross-site scripting in `HTMLHelper::link` and the link toolbar | |
| CVE-2026-90917 | | A flaw in tagged items | |
| CVE-2026-92231, CVE-2026-92232 | | Two `InputFilter` bypasses (HTML5 entity decoding, whitespace in data URIs) | |
| CVE-2026-90913, CVE-2026-92226 | | Access-control fixes in the Joomla API | |

The release also fixes issues that the sources used here describe without an identifier, including unauthorized account creation while registration is disabled. The table lists only the identifiers those sources name.

| | |
|---|---|
| Affected | Joomla 6.0.0 to 6.1.3, and 4.0.0 to 5.4.8. The SSRF flaw reaches back to 3.0.0, one XSS flaw to 1.5.0 |
| Fixed | 5.4.9 and 6.1.4 |
| No fix | 3.x, 4.x and 5.0 to 5.3 are past security support. Move to 5.4.9 or later, or to 6.1.4 or later |
| Exploited | No exploitation reported in the sources used. Most of the flaws need a logged-in account |

## How the script reads an install

`libraries/src/Version.php` holds the version as constants (`MAJOR_VERSION`, `MINOR_VERSION`, `PATCH_VERSION`). The script also reads one file the fix changed, `libraries/src/Cache/Storage/FileStorage.php`: the cache-purge fix adds `Path::check($dir, $this->_root)`. That signature confirms the High cache flaw and catches a partial update, a fixed version number on a file that still has the old code, or the reverse. It cannot confirm the other fifteen fixes, so the version decides.

## Quick start

```bash
curl -fLO https://raw.githubusercontent.com/PrivacySafe/security-patches/refs/heads/main/joomla/joomla-check.sh
less joomla-check.sh
chmod +x joomla-check.sh
./joomla-check.sh check
```

By default it searches `/var/www /srv /home /opt /usr/share`; pass directories to narrow it. Everything is read-only.

## Commands

| Command | What it does |
|---|---|
| `check` (default) | Finds each Joomla by `libraries/src/Version.php`, reads the version and the cache-purge signature, and reports. Exit `0` nothing exposed, `1` exposed or unclear |
| `version` | Prints the script version |

## Update

Update from the administrator (System, Update, Joomla) or with the update package. Joomla documents no workaround. Until then the project suggests limiting who holds Manager or higher and restricting the administrator path by address, since most of these flaws need a logged-in account. That is not Joomla's guidance.

## Sources

- [Joomla security centre](https://developer.joomla.org/security-centre.html)
- [mySites.guru: Joomla 5.4.9 and 6.1.4 security release](https://mysites.guru/blog/joomla-5-4-9-and-6-1-4-security-release/)
- [Joomla 5.4.9 release](https://github.com/joomla/joomla-cms/releases/tag/5.4.9)

## Joomla know before you run it

- **This is a check, not a fix.** Update to 5.4.9 or later in 5.x, or to 6.1.4 or later. There is no fixed release for 3.x, 4.x or 5.0 to 5.3: those branches are past security support.
- **Two flaws are rated High.** CVE-2026-90915 (arbitrary directory deletion through the cache purge action) and CVE-2026-92222 (server-side request forgery, which needs a Manager account or above). The SSRF flaw reaches back to 3.0.0.
- **The release is broader than the CVE list.** 5.4.9 and 6.1.4 fix 16 core issues; the script names the ones in its README, and the same update fixes the rest.
- **There is no hunt.** No indicators of exploitation have been published.
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
