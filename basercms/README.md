# baserCMS 5: admin SQL injection, path traversal and deserialization (CVE-2026-114621, CVE-2026-114622, CVE-2026-114624)

Part of the [PrivacySafe Security Patches](../README.md) collection.

<a name="basercms-check"></a>

## baserCMS check

**Script:** [`basercms/basercms-check.sh`](basercms-check.sh)

baserCMS is a website development framework and CMS written in PHP. Its security releases 5.3.2 and 5.4.2, published on 23 October 2026, fix three flaws rated High.

| CVE | CVSS | What | Affected |
|---|---|---|---|
| CVE-2026-114621 | 8.8 (v3.1) | SQL injection in the admin panel and the admin API. The list and detail actions of the Admin and Api/Admin prefixes pass request query parameters (`contain`, `conditions`, `fields`, `finder`, `order`) straight to the ORM as options, so a logged-in user can inject SQL and read data such as password hashes | 5.0.0 before 5.3.2, and 5.4.0 before 5.4.2 |
| CVE-2026-114622 | 7.2 | Path traversal (CWE-22) | 5.2.3 before 5.3.2, and 5.4.0 before 5.4.2 |
| CVE-2026-114624 | 7.2 | Deserialization of untrusted data (CWE-502). An administrator, or an attacker who gets widget-write capability through another flaw such as chained XSS, can plant an object graph that fires on unauthenticated page requests. Two gadget chains in the default dependency set reach `proc_open()` and run commands as the web server user | 5.0.0 before 5.3.2, and 5.4.0 before 5.4.2 |

| | |
|---|---|
| Fixed | **5.3.2 and 5.4.2** |
| Fixed releases | 5.3.2 and 5.4.2. Sites on 5.0 to 5.2 move to one of them |
| Needs | A logged-in account for CVE-2026-114621; an administrator or widget-write access for CVE-2026-114624. None of the three is reachable by a visitor with no account, except that the planted object of CVE-2026-114624 fires on unauthenticated page requests |
| Exploitation | None reported in the sources used |

## How the script reads a site

The version is the first line of `plugins/baser-core/VERSION.txt` (the file continues with a banner, which is ignored). Each flaw is judged on its own range. The script also reads the two things the fix for CVE-2026-114621 adds: the `removeOrmStructureFromRequest()` method in `plugins/baser-core/src/Controller/AppController.php`, and `'order'` in the list of ORM structure keys that `plugins/baser-core/src/Service/BcQueryParameterTrait.php` strips. Both present means that fix is there, whatever the version string says. A fixed version whose files lack it is a failed update. One of the two is a partial update. These signatures cover CVE-2026-114621 only, so the other two flaws are always judged by version. A pre-release of a fixed release (`5.3.2-rc1`) is below it.

```bash
curl -fLO https://raw.githubusercontent.com/PrivacySafe/security-patches/refs/heads/main/basercms/basercms-check.sh
less basercms-check.sh
chmod +x basercms-check.sh
./basercms-check.sh check
```

By default it searches `/var/www /srv /opt /home`. Pass directories to narrow it. Everything is read-only.

| Command | What it does |
|---|---|
| `check` (default) | Finds baserCMS 5 sites by `plugins/baser-core/VERSION.txt`, judges the three flaws separately, and reports. Exit `0` nothing exposed, `1` exposed or unverifiable |
| `version` | Prints the script version |

## There is no hunt

No indicators of exploitation have been published for these flaws, so the script has none. A clean `check` shows the version is fixed, not that the site was never attacked.

## Update

Update to 5.3.2 or 5.4.2 or later. Until you can, the project suggests restricting the admin area and the admin API to trusted addresses and removing accounts you do not need. This is PrivacySafe's recommendation.

## If a site was exposed

CVE-2026-114621 can read password hashes: rotate administrator passwords and review administrator accounts. CVE-2026-114624 plants an object graph through widgets: review the widget areas for entries you did not create.

## Sources

- [Advisory GHSA-2w6g-wp3r-26m3 (CVE-2026-114621)](https://github.com/baserproject/basercms/security/advisories/GHSA-2w6g-wp3r-26m3)
- [baserCMS 5.3.2 release](https://github.com/baserproject/basercms/releases/tag/5.3.2)
- [baserCMS 5.4.2 release](https://github.com/baserproject/basercms/releases/tag/5.4.2)

## Before you run it

- The fix. Update to 5.3.2 or 5.4.2. Sites on 5.0 to 5.2 move to 5.3.2 or 5.4.2.
- It reads the code as well as the version. The version comes from the first line of `plugins/baser-core/VERSION.txt`, and for CVE-2026-114621 the script also looks for the two fix signatures in the source, so a backport under an older version number is recognized.
- Not everything in the release is covered. baserCMS 5.3.1 lists unauthenticated SQL injections that are identified only by an advisory ID; they are not checked here.
- There is no hunt. No indicators of exploitation have been published for these flaws.
- It also checks running docker and podman containers, unless you name a directory or set `SCAN_CONTAINERS=0`. The check finds installs inside running docker and podman containers by their marker file, copies only the files it reads into a private temporary directory, and judges them like a host install. A path shown as `.../docker_NAME_PATH` is the PATH inside the container NAME. It never runs anything in a container beyond `find` and a file copy, never copies `.env` or `wp-config.php`, never keeps a staged symlink, and is skipped when you name directories yourself.

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
