# APT: CVE-2026-109518 a package download swapped after verification

Part of the [PrivacySafe Security Patches](../README.md) collection.

<a name="apt-nov2026-check"></a>

## APT check

**Script:** [`apt/apt-nov2026-check.sh`](apt-nov2026-check.sh)

APT is the package manager of Debian, Ubuntu and the distributions built on them. When an HTTP redirect gives two package downloads the same address, APT can merge them, and when it retries a download it reuses a file through a hard link. Someone who can alter the HTTP traffic between a host and its archive (an attacker on the network path, a malicious mirror or a proxy) can use redirects and ordinary temporary server errors to make APT retry, and replace a package after APT has verified it. The replaced package is installed as root (CVE-2026-109518).

| | |
|---|---|
| CVE | CVE-2026-109518 (CWE-62, UNIX hard link, and CWE-367, time of check to time of use race; disclosed 4 November 2026) |
| Severity | High, CVSS 4.0 score 7.7 (`CVSS:4.0/AV:N/AC:L/AT:P/PR:N/UI:P/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N`, Ubuntu's rating). The APT developers call it critical |
| Reported by | Max Justicz |
| Needs | **Both** of these at once: APT follows redirects (it does by default) **and** `Acquire::Retries` is above 0. The default is 3 on Debian 12 and Ubuntu 22.04 and later, so Debian 11, Ubuntu 20.04 and older are not exposed in their default configuration, unless a script or an image turned retries on |
| Attacker | Anyone who can change the HTTP traffic between APT and the archive: a machine on the network path, a malicious mirror or a proxy. It runs while a package is being installed |
| Remedy | Update APT. Until that is possible, `mitigate` turns retries off, which removes one of the two conditions |
| Exploited | No advisory describes an attack in the wild |
| Not said | Whether sources reached over HTTPS are exposed. The advisories describe the attack over HTTP |

No workaround is published by Debian, Ubuntu or the APT developers. Setting `Acquire::Retries` to `0` is the stopgap that follows from the description of the flaw: APT then does not retry a failed download, which can make updates less reliable on a poor connection. It is not the fix.

## Fixed releases

The ranges are those of the CVE record. A version below `1.2.36` is affected, and so is any version in a line below the fixed release of that line. APT 1.8.3 through 1.8.5 are affected and the 1.8 line has no later fix. A development version between these lines (2.5, 2.7, 3.1) is not covered; the script says so and exits `2`.

| APT release line | Fixed in | Where it ships |
|---|---|---|
| 3.3 | 3.3.6 | Debian unstable: 3.3.6. Debian testing (forky) was on the affected 3.3.5 in the security tracker. Ubuntu 26.10: `3.3.3ubuntu0.1` |
| 3.2 | 3.2.1 | Ubuntu 26.04 LTS: `3.2.1ubuntu0.1` |
| 3.0 | 3.0.4 | Debian 13 (trixie): 3.0.4, DSA-6607-1 |
| 2.8 | 2.8.4 | Ubuntu 24.04 LTS: `2.8.4ubuntu0.1` |
| 2.6 | 2.6.2 | Debian 12 (bookworm): 2.6.2, DLA-4880-1 |
| 2.4 | 2.4.15 | Ubuntu 22.04 LTS: `2.4.15ubuntu0.1` |
| 2.2 | 2.2.5 | Debian 11 (bullseye): published by the APT developers after its long term support ended on 31 August 2026 |
| 2.0 | 2.0.12 | Ubuntu 20.04 with Ubuntu Pro: `2.0.12+esm1` |
| 1.8 | 1.8.2.4 | Older releases |
| 1.6 | 1.6.19 | Older releases |
| 1.4 | 1.4.12 | Older releases |
| 1.2 | 1.2.36 | Older releases; Ubuntu Pro covers some of them |

Ubuntu rates it high priority. A distribution built on Debian or Ubuntu has APT from its parent, so it is affected too; the script judges the installed APT version, whatever the distribution is called.

## Quick start

1. Download the script. The repository is mirrored on GitHub and Codeberg; pick a base URL.

   ```bash
   # BASE from GitHub:   https://raw.githubusercontent.com/PrivacySafe/security-patches/refs/heads/main
   # BASE from Codeberg: https://codeberg.org/PrivacySafe/security-patches/raw/branch/main
   # curl -fLO "$BASE/apt/apt-nov2026-check.sh"
   curl -fLO https://raw.githubusercontent.com/PrivacySafe/security-patches/refs/heads/main/apt/apt-nov2026-check.sh
   ```

2. Read it before running it, then make it executable.

   ```bash
   less apt-nov2026-check.sh
   chmod +x apt-nov2026-check.sh
   ```

3. Check this host. It changes nothing and needs no root.

   ```bash
   ./apt-nov2026-check.sh check
   ```

4. Update APT, with retries off for the update itself, so the update is not exposed to the flaw it fixes.

   ```bash
   sudo apt-get -o Acquire::Retries=0 update
   sudo apt-get -o Acquire::Retries=0 install --only-upgrade apt
   ```

5. If the update is not published for your release yet, or cannot be installed yet, apply the stopgap and remove it after the update.

   ```bash
   sudo ./apt-nov2026-check.sh mitigate --dry-run
   sudo ./apt-nov2026-check.sh mitigate
   sudo ./apt-nov2026-check.sh rollback
   ```

## Commands

| Command | What it does |
|---|---|
| `check` (default) | Read-only. Reads the installed APT version and judges it against the fixed releases, reads the effective `Acquire::Retries` and redirect settings through `apt-config`, and lists the repositories this host downloads from, with how many are plain http. Exit `0` when APT is fixed, when it is not fixed but one of the two conditions is off (a warning says so), or when APT is not installed; `1` when it is vulnerable and both conditions are on; `2` when it cannot be judged |
| `hunt` | Read-only. Looks for what the flaw would leave behind, because the advisories name no indicator: a cached package whose SHA-256 differs from the index's for the same name, version and architecture, and any file in the package and list caches with more than one hard link (a healthy cache has none). Exit `0` nothing found, `1` a lead, `2` it could not read what it needs |
| `mitigate [--dry-run]` | **Changes the host (root).** Writes `/etc/apt/apt.conf.d/99psf-cve-2026-109518-retries` with `Acquire::Retries "0";`, then asks `apt-config` for the effective value. If another file or setting overrides it, the new file is removed again and the command says so. Nothing else is touched, and nothing is restarted |
| `rollback [--dry-run] [--force]` | Removes the file `mitigate` wrote, and only that file. `--force` removes it even if someone edited it |
| `version` | Prints the script version |

Environment: `STATE_DIR` (default `/var/lib/psf-security-patches/apt`) holds the manifest. `APT_CONF_DIR` (default `/etc/apt/apt.conf.d`) is where `mitigate` writes. `ARCHIVES_DIR` and `LISTS_DIR` replace APT's package and list folders for `hunt`. `APT_HELPER` (default `/usr/lib/apt/apt-helper`) reads compressed index files. `OS_RELEASE` (default `/etc/os-release`) names the release. `PSF_LOCK_WAIT` is the number of seconds a run that changes the host waits for another one that is already changing it (default 30).

Commands that change the host need root. Run them with `sudo` from an admin account, not from a root login, so the change is recorded against a person. The script stops and prints the exact command if you forget.

## How the check decides

- **The version** is compared with `dpkg --compare-versions` against the fixed release of its line. Ubuntu fixes some lines with a build below the upstream fix (`3.3.3ubuntu0.1` for the 3.3 line), and the script accepts exactly those. An epoch is ignored.
- **Retries** are the explicit `Acquire::Retries` that `apt-config` reports, which merges `/etc/apt/apt.conf.d` and `/etc/apt/apt.conf`. When none is set, the default of the installed APT applies: 3 from APT 2.4 on, 0 before. A `-o Acquire::Retries=...` on a command line, and a script that sets it, are not visible to the check.
- **Redirects** are on unless `Acquire::http::AllowRedirect` and `Acquire::https::AllowRedirect` are both turned off. Turning redirects off also removes a condition, but it breaks mirrors that answer with a redirect, so `mitigate` does not do it.
- **Sources** are read from `apt-get indextargets`. A source over http can be altered by anyone on the network path. An https source is out of reach of an ordinary on-path attacker, but a malicious mirror, or a proxy that inspects TLS, is in scope in the advisories.

## How to read the result

- **Fixed:** nothing to do. The retry and redirect lines are shown for information.
- **Vulnerable, both conditions on:** exit `1`. Update APT. If the update is not out for your release, run `mitigate`.
- **Vulnerable, one condition off:** a warning, exit `0`. The flaw is in the installed version, and a script, an image or a command line can turn retries back on, so update anyway.
- **Cannot be judged:** a development version of APT that falls between the published ranges. Move to a release line that lists a fix.
- **After `mitigate`:** `check` shows retries at 0 and a warning, never a clean pass, because the flaw is still in the installed version.

`hunt` is limited by what is published. No indicator of exploitation is named by any advisory, so a clean hunt means only that the two things it can see are in order. Many systems remove cached packages after an install; the hunt says so when there are none to compare. A cached package that the index no longer lists cannot be compared, and is reported as such, not as a lead. If a package was installed over plain http on a host that you cannot trust the network of, reinstall it from a trusted source.

## Sources

- [Debian security advisory DSA-6607-1](https://lists.debian.org/debian-security-announce/2026/msg00526.html) (trixie, 3.0.4)
- [Debian security tracker, CVE-2026-109518](https://security-tracker.debian.org/tracker/CVE-2026-109518) (trixie 3.0.4, bookworm 2.6.2 with DLA-4880-1, unstable 3.3.6, testing 3.3.5 vulnerable)
- [Debian LTS announcement for bookworm](https://lists.debian.org/debian-lts-announce/2026/11/msg00004.html)
- [Ubuntu CVE page](https://ubuntu.com/security/CVE-2026-109518) and [USN-8996-1](https://ubuntu.com/security/notices/USN-8996-1)
- [The APT developers' announcement](https://lists.debian.org/deity/2026/11/msg00005.html)

## Before you run it

- Updating APT is the fix. `mitigate` is a stopgap that removes one of the two conditions, and it makes a failed download fail instead of being retried.
- `check` reports the APT on this host. A container image, a chroot or a build host has its own APT, and so does anything that bakes `-o Acquire::Retries=...` into a command. Check those where they run.
- No workaround is published by the vendors. The advisories describe the attack over HTTP and do not say whether HTTPS sources are exposed.
- No attack in the wild is described in the advisories.

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
