# WordPress core upgrade-window remote code execution (CVE-2026-119977)

Part of the [PrivacySafe Security Patches](../README.md) collection.

<a name="wordpress-upgrade-check"></a>

## WordPress upgrade-window check

**Script:** [`wordpress-upgrade/wordpress-upgrade-check.sh`](wordpress-upgrade-check.sh)

CVE-2026-119977 is a race condition in the way WordPress applies a core update (CWE-367). While a full-package update runs, the new release is unpacked into a folder under `wp-content/upgrade/`, and on most servers that folder can be reached over HTTP. The unpacked copy is a second WordPress with its own `setup-config.php` installer. It cannot see the live `wp-config.php`, so it offers to set itself up, and anyone on the network can finish that setup during the update. The updater then copies the `wp-config.php` that was just written over the live one. The site now connects to the attacker's database, the attacker creates the first administrator, and uploading a plugin runs PHP as the web server user. WordPress 7.1.4 fixed it on 28 October 2026, and CISA added it to its Known Exploited Vulnerabilities catalog on 3 November 2026.

| | |
|---|---|
| CVE | CVE-2026-119977 (CWE-367, time of check to time of use race) |
| Severity | 8.1 High (CVSS 3.1, the CVE Numbering Authority, Wordfence). The WordPress project rates it low |
| Authentication | None. It needs a core update to be running, which is seconds on most sites, and a staging folder that the web server serves |
| Affected | WordPress 4.7.0 through 7.1.3, on every branch (the CVE record). The researcher reports the same updater behavior since 2.7 and no fix for 4.6 and older |
| Fixed | 7.1.4 and the matching branch releases, listed below, all dated 28 October 2026 |
| Exploited | Yes (CISA KEV, 3 November 2026). Wordfence recorded more than 18,500 requests for staged installer paths in the first 21 hours |
| Reported by | Umut Bayram (Picus Security) |

## Fixed releases

The CVE record lists the last affected release of each branch. The first fixed release is the next one. WordPress said on 28 October that the older backports were in progress and would ship as they became ready, so a number below may not exist for a branch you run; the check then tells you to update to the newest release.

| Branch | Last affected | First fixed |
|---|---|---|
| 7.1 | 7.1.3 | 7.1.4 |
| 7.0 | 7.0.7 | 7.0.8 |
| 6.9 | 6.9.10 | 6.9.11 |
| 6.8 | 6.8.11 | 6.8.12 |
| 6.7 | 6.7.10 | 6.7.11 |
| 6.6 | 6.6.10 | 6.6.11 |
| 6.5 | 6.5.13 | 6.5.14 |
| 6.4 | 6.4.13 | 6.4.14 |
| 6.3 | 6.3.13 | 6.3.14 |
| 6.2 | 6.2.14 | 6.2.15 |
| 6.1 | 6.1.15 | 6.1.16 |
| 6.0 | 6.0.17 | 6.0.18 |
| 5.9 | 5.9.19 | 5.9.20 |
| 5.8 | 5.8.18 | 5.8.19 |
| 5.7 | 5.7.20 | 5.7.21 |
| 5.6 | 5.6.22 | 5.6.23 |
| 5.5 | 5.5.23 | 5.5.24 |
| 5.4 | 5.4.24 | 5.4.25 |
| 5.3 | 5.3.26 | 5.3.27 |
| 5.2 | 5.2.29 | 5.2.30 |
| 5.1 | 5.1.27 | 5.1.28 |
| 5.0 | 5.0.30 | 5.0.31 |
| 4.9 | 4.9.34 | 4.9.35 |
| 4.8 | 4.8.33 | 4.8.34 |
| 4.7 | 4.7.38 | 4.7.39 |

WordPress 4.6 and older no longer receive security fixes. Branches 4.4 through 5.8 add a random suffix to the staging folder name, which the researcher says makes the path guessable only if something else discloses it. They are still affected, and still need the update.

## How the fix works

WordPress 7.1.4 makes three changes, as the researcher describes them: the staging folder gets a 16 character random suffix, `wp-content/upgrade/index.php` is kept so the folder cannot be listed, and `wp-config.php` is added to the skip list of the copy in `update-core.php`, so a configuration file written into the staging tree can no longer overwrite the live one.

The update that installs the fix is still exposed. The old updater, already on the site, does the unpacking, so the staging folder is still at a predictable path during that first update. The new `update-core.php` skips `wp-config.php`, so the live configuration is safe, but an attacker can still set up the temporary copy with their own database and run PHP as the web server user from it before the folder is removed. Block the folder before the first update.

## Quick start

1. Download the script. The repository is mirrored on GitHub and Codeberg; pick a base URL.

   ```bash
   # BASE from GitHub:   https://raw.githubusercontent.com/PrivacySafe/security-patches/refs/heads/main
   # BASE from Codeberg: https://codeberg.org/PrivacySafe/security-patches/raw/branch/main
   # curl -fLO "$BASE/wordpress-upgrade/wordpress-upgrade-check.sh"
   curl -fLO https://raw.githubusercontent.com/PrivacySafe/security-patches/refs/heads/main/wordpress-upgrade/wordpress-upgrade-check.sh
   ```

2. Read it before running it, then make it executable.

   ```bash
   less wordpress-upgrade-check.sh
   chmod +x wordpress-upgrade-check.sh
   ```

3. Check this host. It changes nothing.

   ```bash
   ./wordpress-upgrade-check.sh check
   ```

4. If an install is exposed, deny web access to the staging folder before you update, then update.

   ```bash
   ./wordpress-upgrade-check.sh rules
   ```

5. After the update, look for signs that the window was used.

   ```bash
   sudo ./wordpress-upgrade-check.sh hunt
   ```

## Commands

| Command | What it does |
|---|---|
| `check [DIR ...]` (default) | Read-only. Finds WordPress by `wp-includes/version.php` under the directories you name (or `/var/www`, `/srv`, `/home`, `/opt` and the usual package folders), judges each version against the table, reads two source files for the fixes, looks for a web server rule that denies `wp-content/upgrade/`, and lists anything left in that folder. Exit `0` when nothing is exposed, `1` when an install has no fix or its state is unclear |
| `hunt [DIR ...]` | Read-only. Looks in the web server logs for requests under `/wp-content/upgrade/`, and in each install's `wp-content/upgrade/` for a `wp-config.php` or a stray PHP file. Exit `0` when nothing is found, `1` for a lead |
| `rules` | Prints the nginx, Apache and `.htaccess` lines that deny web access to `wp-content/upgrade/`. It changes nothing |
| `version` | Prints the script version |

Environment: `WUP_LOGS` (space separated paths or globs) names web server logs. `WUP_CONF` names the web server configuration to read for a blocking rule. With no directory argument the check also copies the files it reads from running docker and podman containers (`SCAN_CONTAINERS=1`, the default; `0` skips them). It runs nothing inside a container beyond `find` and a file copy.

## How the check decides

- **The version** is compared with the last affected release of its branch in the table above. A pre-release of a fixed release (7.1.4-rc1) is below it. 7.2 and later are fixed. Anything older than 4.7 is reported as unsupported and exposed.
- **The source** is read for two changes confirmed against the real WordPress 7.1.4 source: the 16 character random suffix in `class-wp-upgrader.php` (`get_working_dir_name()`), and `wp-config.php` in the skip list of `update-core.php`. When both are present, an install whose version is in the affected range is reported as a distribution backport and is not exposed. One of the two alone is reported as exposed. These patterns are only used to recognize a backport, and never to downgrade a release the table calls fixed.
- **The rule** check reads text. It looks in the nginx and Apache configuration, and in the install's `.htaccess`, for a line that names `wp-content/upgrade` together with a deny. It does not ask the web server, so confirm with a request that `/wp-content/upgrade/` answers 403.

## What `hunt` looks for

The access log shows a request for a PHP file under `/wp-content/upgrade/` as a strong lead, because WordPress never serves that folder and the temporary installer is `setup-config.php` there. A request for the folder with no PHP file is reported as a probe. The folder is also searched for a `wp-config.php` (the installer was completed there) and for PHP files outside an unpacked `wordpress` folder. A POST body is not recorded in an access log, so a quiet log does not rule out an attempt, and a clean hunt does not show that the live `wp-config.php` is the original one. If the site may have been exposed, compare its `DB_NAME` and `DB_HOST` with what you expect, and list the administrator accounts.

## Update

Update to 7.1.4 (or the fixed release of your branch) from a site where `wp-content/upgrade/` is already denied, and do not rely on `wp core update` to avoid the window, because WP-CLI uses the same updater and unpacks into the same folder. A manual update avoids it: download and unpack the release outside the web root, then copy `wp-admin`, `wp-includes` and the top-level files into place, leaving `wp-config.php` and `wp-content` alone, and run `wp core update-db`. Do not put an `.htaccess` file inside `wp-content/upgrade/`: the old updater deletes that folder's contents before it unpacks.

## Sources

- [WordPress 7.1.4 release post](https://wordpress.org/news/2026/10/wordpress-7-1-4/)
- [CVE-2026-119977 record](https://www.cve.org/CVERecord?id=CVE-2026-119977)
- [CISA alert, 3 November 2026](https://www.cisa.gov/news-events/alerts/2026/11/03/cisa-adds-one-known-exploited-vulnerability-catalog)
- [The researcher's write-up](https://www.picussecurity.com/resource/blog/cve-2026-119977-when-updating-wordpress-becomes-the-vulnerability)
- [Wordfence on the release and the first attacks](https://www.wordfence.com/blog/2026/10/wordpress-7-1-4-security-release-rce/)

## Before you run it

- The script reads files. `check` and `hunt` change nothing, and `rules` only prints.
- The CVE record lists 4.7 and later. The statement that older releases behave the same and have no fix comes from the researcher, not from the record.
- The fixed number of each branch is derived from the CVE record, and WordPress said some backports were still in progress on 28 October.

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
