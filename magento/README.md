# Magento, Adobe Commerce and Mage-OS email-template RCE: BlockStrap (CVE-2026-103849)

Part of the [PrivacySafe Security Patches](../README.md) collection.

<a name="magento-check"></a>

## Magento email-template RCE check

**Script:** [`magento/magento-check.sh`](magento-check.sh)

CVE-2026-103849 ("BlockStrap") is an unauthenticated remote code execution flaw in the email template engine, rated CVSS 10.0 (CVSS 3.1). It is a second-pass directive injection: a directive hidden in a child email template is signed, passes the check, and is processed again by the parent template. Researchers found four attack paths within a day of disclosure and expect exploitation; none was confirmed in the sources used for this document.

| | |
|---|---|
| CVE | CVE-2026-103849 |
| Severity | 10.0 Critical (CVSS 3.1) |
| Authentication | None |
| Affected | Adobe Commerce 2.4.4 to 2.4.9, Adobe Commerce B2B 1.3.3 to 1.5.3, and Magento Open Source (the sources give 2.4.6 or 2.4.7 as the first affected line) to 2.4.9, in builds before APSB26-153. Mage-OS up to and including 3.5.0 |
| Fixed | Adobe's October 2026 releases (APSB26-153, 13 October 2026); Mage-OS 3.6.0 (14 October 2026) |
| Workaround | Adobe documents none |

## What a version number can and cannot show

Adobe ships this fix as an isolated patch, and applying it does not change the version string, so a store on `2.4.8-p5` or `2.4.9` may or may not be fixed. The script therefore does **not** guess for Magento and Adobe Commerce: it reports "cannot confirm" and tells you what to verify. It gives a firm answer where the version can carry one:

| Install | How it is judged |
|---|---|
| Mage-OS below 3.6.0 (3.5.x included) | Exposed |
| Mage-OS 3.6.0 or later | Fixed |
| A Mage-OS pre-release of 3.6.0 (`3.6.0-beta1`, `3.6.0-rc2`) | Not judged as the release: it may not carry the fix. Warns, exit `1` |
| A dated release string such as `2.4.9-2026-oct` | By the month: before October exposed, October or later fixed |
| Any other Magento or Adobe Commerce version | Cannot confirm from the version: confirm in your patch tooling that the APSB26-153 fix is applied, or move to the October 2026 release |

The distribution and version are read from `composer.lock` (the `mage-os/product-community-edition`, `magento/product-enterprise-edition` or `magento/product-community-edition` package), and from `composer.json` on a git checkout.

## Quick start

```bash
curl -fLO https://raw.githubusercontent.com/PrivacySafe/security-patches/refs/heads/main/magento/magento-check.sh
less magento-check.sh
chmod +x magento-check.sh
./magento-check.sh check
```

By default it looks for `bin/magento` under `/var/www /srv /home /opt`; pass directories to narrow it. Everything is read-only.

| Command | What it does |
|---|---|
| `check` (default) | Finds installs, reads the distribution and version, and reports as above. Exit `0` nothing exposed, `1` exposed or unconfirmed |
| `version` | Prints the script version |

## There is no hunt

No indicators of exploitation have been published for this flaw, so the script has none. A clean `check` shows that the version is fixed, not that the store was never attacked.

## Update

Apply the APSB26-153 fix or move to the October 2026 release for your line, or to Mage-OS 3.6.0.

## If a store was exposed

Review your email templates for directives you did not add. That suggestion is the project's, not Adobe's.

## Sources

- [Sansec: BlockStrap](https://sansec.io/research/blockstrap-magento-rce)
- [BleepingComputer: BlockStrap](https://www.bleepingcomputer.com/news/security/critical-blockstrap-flaw-lets-hackers-run-code-on-magento-servers/)
- Adobe security bulletin APSB26-153

## Magento and Adobe Commerce know before you run it

- **This is a check, not a fix.** Apply Adobe's APSB26-153 fix or move to the October 2026 release for your line, or to Mage-OS 3.6.0. Adobe documents no workaround.
- **A version number cannot show this fix.** Adobe ships it as an isolated patch that does not change the version string, so for Magento and Adobe Commerce the script reports "cannot confirm" and says what to check. It gives a firm answer for Mage-OS and for a dated release string such as `2.4.9-2026-oct`.
- **A Mage-OS pre-release is not the release.** `3.6.0-beta1` and `3.6.0-rc2` are reported with a warning, not as fixed.
- **There is no hunt.** No indicators of exploitation have been published for this flaw.
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
