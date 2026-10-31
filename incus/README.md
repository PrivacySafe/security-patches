# Incus: CVE-2026-115375, CVE-2026-115377 and CVE-2026-115372

Part of the [PrivacySafe Security Patches](../README.md) collection.

<a name="incus-check"></a>

## Incus check

**Script:** [`incus/incus-check.sh`](incus-check.sh)

Incus is a system container and virtual machine manager. All three flaws let a client that the daemon is meant to **confine** (a user restricted to a project) act as **root on the host**. A full administrator is already as powerful as host root, so these matter where you have restricted projects, restricted client certificates, members of the unprivileged `incus` unix group, or where an instance can be migrated in from a server you do not control.

| | CVE-2026-115375 | CVE-2026-115377 | CVE-2026-115372 |
|---|---|---|---|
| Advisory | GHSA-hpjh-q53p-f27r | GHSA-579w-c4rw-c8q3 | GHSA-4cph-ccqv-hm3c |
| Severity | Critical, CVSS 4.0 9.4 | Critical, CVSS 4.0 9.4 | High, 8.5 |
| Affected | 7.0.0 before 7.0.2, and 7.1.0 before 7.5.0 (6.x is not affected) | before 6.0.7, 6.1.0 before 7.0.2, and 7.1.0 before 7.5.0 | 7.3.0 before 7.5.0 |
| Fixed | 7.0.2 and 7.5.0 | 6.0.7, 7.0.2 and 7.5.0 | 7.5.0 |
| What | Importing an instance backup validates the instance and snapshot names but not the names of the dependent custom volumes in the backup's `index.yaml`, which become path segments on the host. Any client allowed to create instances in a project can make the daemon create root-owned directories with attacker-controlled content at arbitrary host paths | When receiving an instance or volume by migration (copy, move, refresh, push or pull) through rsync or an optimized btrfs transfer, a malicious source can plant a symlink (`rootfs` pointing at `/`) and write through it as root. Optimized **ZFS** transfers are **not** affected | A user of a restricted project can set `block.create_options` through volume update, copy and move operations and inject arguments into `mkfs`, which runs as root |
| Needs | A client allowed to create instances | A client allowed to create an instance or custom volume, **or** any server a target is told to copy or move from | A restricted project |

The project's own release notes list many other critical project-escape advisories fixed in earlier releases this year (in 7.3 and before), so moving to a current release fixes those too. Treat a restricted project as a security boundary only on a release that has these fixes.

## Quick start

1. Download the script. The repository is mirrored on GitHub and Codeberg; pick a base URL.

   ```bash
   # BASE from GitHub:   https://raw.githubusercontent.com/PrivacySafe/security-patches/refs/heads/main
   # BASE from Codeberg: https://codeberg.org/PrivacySafe/security-patches/raw/branch/main
   # curl -fLO "$BASE/incus/incus-check.sh"
   curl -fLO https://raw.githubusercontent.com/PrivacySafe/security-patches/refs/heads/main/incus/incus-check.sh
   ```

2. Read it before running it, then make it executable.

   ```bash
   less incus-check.sh
   chmod +x incus-check.sh
   ```

3. Check this host. Run it as a user that can talk to the daemon (root or a member of `incus-admin`) so it can read projects and remotes.

   ```bash
   ./incus-check.sh check
   ```

## Commands

| Command | What it does |
|---|---|
| `check` (default) | Reads the version (the daemon's if it answers, else the package's, else the client's), looks in the package changelog for a backport of these fixes, and asks the daemon read-only questions: restricted projects (`incus project list`, `incus project get NAME restricted`), the network listener (`incus config get core.https_address`), trusted client certificates (`incus config trust list`) and configured remotes (`incus remote list`), plus the members of the unix group `incus` |
| `version` | Prints the script version |

Env: `INCUS_BIN` names the client binary, `INCUS_CHANGELOG` names a changelog file. A root user never runs a client binary that other users can write.

Exit codes: `0` nothing exposed, `1` an affected version that cannot be shown to be admin-only, or one that could not be verified, `2` bad arguments.

## How to read the result

- Version outside every affected range: done.
- Affected, and restricted projects, `incus` group members, or a network listener with trusted certificates exist: exposed. CVE-2026-115375 and CVE-2026-115377 are judged against those. CVE-2026-115372 only against restricted projects, because there is no restriction to bypass without one.
- A configured remote server (a non-public Incus remote that is not the local socket) makes **only** CVE-2026-115377 exposed, because a migration source is what that flaw needs. The public `images` remote is not a migration source.
- Affected, but only administrators can reach the daemon: a warning and exit `0`. Upgrade anyway.
- The daemon does not answer: the version is still judged, but exposure cannot be read, so the result is reported as exposed (exit `1`) for you to review.
- Distribution packages: a package can carry a fix under an old version number. The script reads the package changelog for these CVE and advisory ids and says when it finds a backport. Ubuntu 24.04's `incus 6.0.0-1ubuntu0.3` carries no backport of CVE-2026-115377, so that package is in the affected range: update it as soon as Ubuntu publishes the fixed package.

## Fixing it

Upgrade to 7.5.0, or to 7.0.2 (the 7.0 LTS) or 6.0.7 (the 6.0 LTS) at the least. Until you can (PrivacySafe recommendation): do not treat restricted projects as a security boundary on this release. Remove untrusted users from the `incus` group and the trust store. Do not copy or move instances from servers you do not control, and note that optimized ZFS transfers are not affected by CVE-2026-115377.

## Sources

- [GHSA-hpjh-q53p-f27r](https://github.com/lxc/incus/security/advisories/GHSA-hpjh-q53p-f27r)
- [GHSA-579w-c4rw-c8q3](https://github.com/lxc/incus/security/advisories/GHSA-579w-c4rw-c8q3)
- [Incus release news](https://linuxcontainers.org/incus/news/)

## Before you run it

- The fix. Update to 6.0.7 (the 6.0 LTS, which fixes CVE-2026-115377 only), 7.0.2 (the 7.0 LTS) or 7.5.0. CVE-2026-115372 affects 7.3.0 before 7.5.0, so only 7.5.0 fixes it.
- It matters where a client is confined. All three let a client the daemon is meant to confine act as root on the host. A full administrator is already as powerful as host root, so the flaws matter with restricted projects, restricted client certificates, members of the unprivileged `incus` unix group, or an instance migrated in from a server you do not control.
- The ranges differ. CVE-2026-115375 affects 7.0.0 before 7.0.2 and 7.1.0 before 7.5.0 (6.x is not affected). CVE-2026-115377 affects everything before 6.0.7, 6.1.0 before 7.0.2 and 7.1.0 before 7.5.0, and optimized ZFS transfers are not affected by it. The script reads the daemon's version if it answers, else the package's, else the client's, and asks the daemon read-only questions about restricted projects, the network listener, trusted client certificates, configured remotes and the members of the `incus` group.
- There is no hunt. No indicators of exploitation have been published.

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
