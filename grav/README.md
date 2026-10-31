# Grav CMS: Login plugin invitation escalation (CVE-2026-114658) and core allowlist bypass (CVE-2026-116019)

Part of the [PrivacySafe Security Patches](../README.md) collection.

<a name="grav-login-check"></a>

## Grav Login check

**Script:** [`grav/grav-login-check.sh`](grav-login-check.sh)

The Grav Login plugin has a flaw in its invitation feature (CVE-2026-114658). The `login.invite` task sends an invitation without checking who submitted the form, and it takes the new account's permissions from the page's frontmatter (`form: meta: invite: account:`) with no limit on what it grants. A page author can write an invitation form that grants **super user** access, submit it, and register the invited address to take over the site. VulnCheck says the submission can be made without authentication.

| | |
|---|---|
| CVE | CVE-2026-114658 (CWE-269, advisory GHSA-j8jx-ccrg-m7h2) |
| Severity | High: CVSS 8.7 (v4.0), 8.8 (v3.1) |
| Affected | Grav Login plugin 3.6.0 through 3.9.12, on Grav 1.7 and 2.x |
| Fixed | **3.9.13**. Only a super user can then invite someone into super access or into groups; for anyone else those are removed from the invitation |
| Behavior change | A page restricted with `access: admin.login` now needs an account management permission to send invitations |
| Needs | A page that can carry an invitation form. Per the advisory the page author defines it; VulnCheck says the submission itself needs no login |

## Quick start

1. Download the script. The repository is mirrored on GitHub and Codeberg; pick a base URL.

   ```bash
   # BASE from GitHub:   https://raw.githubusercontent.com/PrivacySafe/security-patches/refs/heads/main
   # BASE from Codeberg: https://codeberg.org/PrivacySafe/security-patches/raw/branch/main
   # curl -fLO "$BASE/grav/grav-login-check.sh"
   curl -fLO https://raw.githubusercontent.com/PrivacySafe/security-patches/refs/heads/main/grav/grav-login-check.sh
   ```

2. Read it before running it, then make it executable.

   ```bash
   less grav-login-check.sh
   chmod +x grav-login-check.sh
   ```

3. Check the version, then hunt for what an attack leaves behind.

   ```bash
   ./grav-login-check.sh check
   ./grav-login-check.sh hunt
   ```

## Commands

| Command | What it does |
|---|---|
| `check [DIR ...]` (default) | Finds Grav sites by `user/plugins/login/blueprints.yaml` under `/var/www /srv /opt /home` or the directories you pass, reads the plugin version, and scans `user/pages` frontmatter for invitation forms |
| `hunt [DIR ...]` | Runs `check`, then looks at pending invitations in `user/data/accounts/invites.yaml` and at super-user accounts in `user/accounts` |
| `version` | Prints the script version |

Environment: `HUNT_ADMIN_SINCE` (default `2026-10-01`): super-user accounts modified since this date are flagged for review.

Exit codes: `0` nothing affected or nothing found, `1` an affected or unreadable version, or an indicator, `2` bad arguments.

## What the hunt looks for

| Where | Indicator |
|---|---|
| Page frontmatter | A page whose `form: meta: invite:` block contains `super: true` (quoted forms are accepted). This is the setup the attack plants, so it fails the check **even on a fixed plugin**. Pages with an invitation form that grants nothing special are only counted |
| `user/data/accounts/invites.yaml` | Pending invitations that grant super access, reported by invited address and by who issued them |
| `user/accounts/*.yaml` | Super-user accounts created or modified since `HUNT_ADMIN_SINCE`, reported by account name and date |

The frontmatter parser reads only the frontmatter (between the first two `---` lines) and only the lines nested under `invite:`, so `super: true` in a sibling block, or in the page body, is not mistaken for it.

## Secrets are never printed

The keys of `invites.yaml` are **registration tokens**: anyone holding one can register the invited account. Account files contain password hashes. The hunt prints neither. It reports only invited addresses, issuers, account file names and modification times.

## How to read the result

- 3.6.0 through 3.9.12: affected. Update (`bin/gpm update login`, or through the Admin plugin), then run the hunt. An update does not delete accounts or invitations already created.
- Before 3.6.0: outside the advisory's range, but far out of date: update anyway.
- A page that grants super access through an invitation, or a pending super invitation: treat it as an attack in progress or already done. Remove it, remove any account you did not create, and reset the passwords of real super users.
- Version unreadable: the script cannot judge, so it exits `1`.

## Sources

- [Grav advisory GHSA-j8jx-ccrg-m7h2](https://github.com/getgrav/grav/security/advisories/GHSA-j8jx-ccrg-m7h2)
- [VulnCheck: Grav Login plugin 3.6.0 before 3.9.13](https://www.vulncheck.com/advisories/grav-login-plugin-3.6.0-before-3.9.13-privilege-escalation-via-login-invite)

<a name="grav-core-check"></a>

## Grav core check (CVE-2026-116019)

**Script:** [`grav/grav-core-check.sh`](grav-core-check.sh)

Grav 2.0.15 up to and including 2.2.12 lets a user who may edit pages run arbitrary public static methods. Grav trusts the dynamic directives of a blueprint (the `data-*@` fields that name a PHP method) only where the blueprint file itself defines them, and checks the ones that arrive from page frontmatter against an allowlist. The merge that combines the two could relocate a directive away from the path it was checked at: the vendor `deepMerge()` honors the `unset-name@` merge action as well as `replace-name@`, and it renumbers an integer key the base does not have. A relocated directive was then trusted as if the blueprint file had defined it, so the allowlist was skipped. A page editor can embed crafted fields in the Flex form overrides of a page's frontmatter and call methods such as `Folder::delete` or `Utils::download`, which deletes directories, overwrites files, or reads files outside the page tree.

| | |
|---|---|
| CVE | CVE-2026-116019 (CWE-749, advisory GHSA-47gg-mh38-9rr7) |
| Severity | High: CVSS 8.8 (v3.1), 8.7 (v4.0) |
| Affected | Grav 2.0.15 up to and including 2.2.12 |
| Fixed | **2.2.13**, released 24 October 2026 |
| Needs | An account that can edit pages |
| Exploitation | None reported in the sources used |

### How the script reads a site

The version is the `GRAV_VERSION` constant in `system/defines.php`. The script also reads `system/src/Grav/Common/Data/Blueprint.php` for the two things the fix adds: the `dynamicOf()` helper, which compares the directives before and after the merge, and the extension of the stripping from `replace-name@` to `unset-name@`. Both present means the fix is there, whatever the version string says (a backport, or files copied over an older install). Neither present on a version in the affected range means exposed. One of the two is a partial update and is reported as such. A version of 2.2.13 or later on files without the fix is reported as a mismatch. A pre-release of 2.2.13 is not judged as the release.

```bash
curl -fLO https://raw.githubusercontent.com/PrivacySafe/security-patches/refs/heads/main/grav/grav-core-check.sh
less grav-core-check.sh
chmod +x grav-core-check.sh
./grav-core-check.sh check
./grav-core-check.sh hunt
```

By default it searches `/var/www /srv /opt /home`. Pass directories to narrow it. Everything is read-only.

| Command | What it does |
|---|---|
| `check` (default) | Finds Grav sites by `system/defines.php`, reads the version and the two fix signatures, and reports. Exit `0` nothing exposed, `1` exposed or unverifiable |
| `hunt` | Runs `check`, then looks in `user/pages` for what the attack needs. Exit `0` nothing found, `1` an exposed site or a strong lead |
| `version` | Prints the script version |

### What the hunt looks for

A relocation merge action (`unset-name@`, `replace-name@`) and a static method call (`Folder::`, `Utils::`) in the **same** page file is a strong lead. Either one alone is listed for review but is not an alarm: a documentation site can mention `Utils::download()` harmlessly. These indicators are derived from the advisory text, not from published indicators, so a clean hunt does not prove that no page was edited maliciously.

### Update

Update to 2.2.13 or later (`bin/gpm selfupgrade`). Until you can, the project suggests restricting who can edit pages and who has Admin access. This is PrivacySafe's recommendation.

### Sources

- [Grav 2.2.13 release](https://github.com/getgrav/grav/releases/tag/2.2.13)
- [Advisory GHSA-47gg-mh38-9rr7](https://github.com/getgrav/grav/security/advisories/GHSA-47gg-mh38-9rr7)
- [`Blueprint.php` at 2.2.12](https://github.com/getgrav/grav/blob/2.2.12/system/src/Grav/Common/Data/Blueprint.php)

## Before you run it

- The fix. For the core flaw (CVE-2026-116019, Grav 2.0.15 to 2.2.12) update to 2.2.13. For the Login plugin flaw (CVE-2026-114658, 3.6.0 to 3.9.12) update the plugin to 3.9.13.
- The core check reads the code as well as the version. The version is `GRAV_VERSION` in `system/defines.php`. The script also looks in `Blueprint.php` for the two things the fix adds. Both present means the fix is there whatever the version string says. Neither on an affected version means exposed. One of the two is a partial patch.
- The login flaw needs a page author. A page author can define an invitation form that grants super user access. The check lists pages that declare an invitation form.
- `hunt` is read-only and never prints a secret. For the Login plugin it looks for pending invitations, page frontmatter that grants super access and recently changed super-user accounts, and reports file names, invitation email addresses and times, never invitation tokens or password hashes.
- It also checks running docker and podman containers, unless you name a directory or set `SCAN_CONTAINERS=0`. The check finds installs inside running docker and podman containers by their marker file, copies only the files it reads into a private temporary directory, and judges them like a host install. A path shown as `.../docker_NAME_PATH` is the PATH inside the container NAME. It never runs anything in a container beyond `find` and a file copy, never copies `.env` or `wp-config.php`, never keeps a staged symlink, and is skipped when you name directories yourself. The Login plugin's check of page frontmatter and its `hunt` read the host only.

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
