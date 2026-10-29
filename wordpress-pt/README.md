# WordPress core page-template path traversal (CVE-2026-87902)

Part of the [PrivacySafe Security Patches](../README.md) collection.

<a name="wordpress-pt-check"></a>

## WordPress page-template path traversal check

**Script:** [`wordpress-pt/wordpress-pt-check.sh`](wordpress-pt-check.sh)

CVE-2026-87902 is an unauthenticated path traversal in WordPress core's page-template resolver, rated CVSS 9.2 (Critical). Every release from 4.7.0 through 7.1.1 is affected. WordPress fixed it on 22 September 2026. Exploitation attempts began within hours, turned into active compromises by 23 September, and CISA added the flaw to its Known Exploited Vulnerabilities catalog on 25 September.

| | |
|---|---|
| CVE | CVE-2026-87902 (CWE-98, GHSA-7hp8-65ch-5whp) |
| Severity | 9.2 Critical (CVSS 4.0) |
| Authentication | None |
| Affected | WordPress 4.7.0 through 7.1.1, on every branch. Before 4.7.0 is not affected |
| Fixed | 7.1.2, 7.0.6, 6.9.9, 6.8.10, 6.7.9, 6.6.9, 6.5.12, 6.4.12, 6.3.12, 6.2.13, 6.1.14, 6.0.16, 5.9.18, 5.8.17, 4.8.32, 4.7.37, all released 22 September 2026. 4.6 and earlier get no update |
| Exploited | Yes (CISA KEV, 25 September 2026) |
| Reported by | Robert Ressl |

The sources used for this document list a fixed number for each branch above. They do not list one for 5.0 to 5.7 or 4.9, so for those branches the script reads the source files instead of trusting a version number.

## How the flaw works

`get_page_template()` in `wp-includes/template.php` URL-decodes the `pagename` query variable after it has been sanitized. A value that is encoded twice survives the sanitizer as percent literals and is decoded into `../` by that later call. WordPress then builds a template candidate from it, and `locate_template()` loaded whatever file existed at the resulting path, including files outside the theme directories. Whether that becomes code execution depends on the server and the active theme: it needs a readable PHP file at a reachable path, for example one installed by PEAR, and a theme with a `page-` template directory.

The fix changes only `wp-includes/template.php`, in two places. A decoded pagename that differs from the raw one is used only if `validate_file()` accepts it, and a template found by `locate_template()` is loaded only if the new `_wp_is_template_path_allowed()` function accepts its real path.

## Quick start

```bash
curl -fLO https://raw.githubusercontent.com/PrivacySafe/security-patches/refs/heads/main/wordpress-pt/wordpress-pt-check.sh
less wordpress-pt-check.sh
chmod +x wordpress-pt-check.sh
./wordpress-pt-check.sh check
./wordpress-pt-check.sh hunt
```

By default `check` searches `/var/www /srv /home /opt /usr/share/wordpress /usr/share/nginx /var/lib/wordpress`; pass directories to narrow it. Everything is read-only.

## Commands

| Command | What it does |
|---|---|
| `check` (default) | Finds each WordPress install by `wp-includes/version.php`, reads the version, and reads `template.php` for the two fixes. Exit `0` nothing exposed, `1` an install without the fix or whose state is unclear |
| `hunt` | Reads web server logs (plain and rotated `.gz`) for an encoded traversal in the `pagename` parameter and for the scanner user agents seen in the attacks. Exit `0` nothing found, `1` a strong lead |
| `version` | Prints the script version |

Env: `WPT_LOGS` (space separated paths or globs) names web server logs that are not in the usual places.

## How the check decides

- **The source decides when it can be read.** Both fixes present means fixed, whatever the version string says; a distribution can carry the fix under an older number. Neither present means exposed. Only one present is reported as partially patched, naming which is missing.
- **A fixed version whose file still has the vulnerable code** is reported as a mismatch: a partial or failed update.
- **If `template.php` cannot be read,** the script falls back to the per-branch version table, and says so.
- Branches whose fixed number is not published (5.0 to 5.7, 4.9) are judged by the source, or reported as unclear when it cannot be read.

## What `hunt` looks for

A `pagename` value that contains an encoded dot or slash, however many times it is encoded (an N-times encoded dot is a percent sign, then `25` repeated N-1 times, then `2E`), a plain `../`, and the user agents `cve-2026-87902-poc` and `nuclei-cve-2026-87902` that were seen in attacks. An ordinary encoded slash in a page path is not a match. The public exploits send the payload in a POST body, which an access log does not record, so a quiet log does not rule out an attempt.

## Update

```bash
wp core update
```

or use Dashboard, Updates. WordPress documents no workaround. Researchers suggest, as a stopgap at a web application firewall, rejecting traversal sequences and their encodings in `pagename`, in query strings and in POST bodies; that is a stopgap, not a fix.

## If the site was reachable after 22 September 2026

Run `hunt`. Then look for PHP files outside the theme and plugin directories, new administrator accounts and unexpected scheduled tasks, and rotate credentials if you find any.

## Sources

- [WordPress 7.1.2 release](https://wordpress.org/news/2026/09/wordpress-7-1-2-release/)
- [GHSA-7hp8-65ch-5whp](https://github.com/WordPress/wordpress-develop/security/advisories/GHSA-7hp8-65ch-5whp)
- [SecurityWeek: exploited immediately after disclosure](https://www.securityweek.com/critical-wordpress-vulnerability-exploited-immediately-after-disclosure/)
- [CrowdSec: CVE-2026-87902 tracking](https://www.crowdsec.net/vulntracking-report/cve-2026-87902-wordpress-vulnerability)
- [Equixly: from path traversal to RCE via PEAR](https://equixly.com/blog/2026/09/24/cve-2026-87902-from-wordpress-path-traversal-to-rce-via-pear/)

## WordPress path traversal know before you run it

- **This is a check, not a fix.** Update within your branch: 7.1.2, 7.0.6, 6.9.9, 6.8.10, 6.7.9 or 6.6.9, or the backports down to 4.7.37. WordPress 4.6 and earlier have no fix, and there is no official workaround.
- **It reads the fix, not just the version.** The fix changes one file, `wp-includes/template.php`, in two places. The script looks for both, so a distribution backport under an older version number is recognised.
- **It finds installs by `wp-includes/version.php`.** A WordPress that exists only inside a container's filesystem is not seen unless you point the script at that directory.
- **Exploitation was observed the day of disclosure** and CISA listed it on 25 September 2026, so an unpatched site should be treated as possibly probed. `hunt` reads web server logs for requests with encoded traversal sequences in the `pagename` parameter; a hit shows probing, not necessarily success.
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
