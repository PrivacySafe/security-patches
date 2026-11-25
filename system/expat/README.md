# libexpat: CVE-2026-115506 billion laughs detection delay

Part of the [PrivacySafe Security Patches](../../README.md) collection.

<a name="libexpat-billion-laughs-check"></a>

## libexpat billion laughs check

**Script:** [`system/expat/expat-check.sh`](expat-check.sh)

libexpat is the XML parser inside Python, Apache httpd, many PHP and Perl builds, Subversion, Mercurial, D-Bus, fontconfig, Firefox and a very long list of other programs. Its defense against "billion laughs" entity amplification notices the amplification too late (CVE-2026-115506), so a modest crafted XML document can still burn a lot of CPU and memory before the protection steps in. Any service that parses XML from an untrusted source can be knocked over. Upstream attached the fix to the 2.9.1 milestone.

| | |
|---|---|
| CVE | CVE-2026-115506 (published 22 October 2026; upstream issue #1160). The same release fixes CVE-2026-113351, CVE-2026-117610 and CVE-2026-118370 |
| Severity | High: 7.5 (CVSS 3), listed as 8.7 on the CVSS 4.0 scale. Authentication is not needed wherever XML from an untrusted source is parsed |
| Affected | libexpat through 2.9.0 |
| Fix | **Expat 2.10.0**, released 2 November 2026. The planned 2.9.1 was never released |
| Exploited | No exploitation has been reported |

**Install Expat 2.10.0 or later, or a distribution package that carries the fix.** The script reports every copy older than 2.10.0 as affected and 2.10.0 or newer as fixed, and a package whose changelog names any of the four CVEs as a likely backport. Expat 2.10.0 also fixes CVE-2026-113351 (denial of service through `XML_ParserReset`), CVE-2026-117610 (a crash on an initial, non-final, empty subparser parse call) and CVE-2026-118370 (signed integer overflow in `storeAtts`). Distribution status varies: Alpine ships 2.10.0-r0, while Debian's tracker still listed every Debian release, including bookworm and trixie, as vulnerable to CVE-2026-115506 in November. Upstream asks backporters to note pull request #1439 in particular. Programs that bundle their own copy (Python wheels, Firefox, CMake and many others) need their own update; `deep` finds them.

## Quick start

1. Download the script. The repository is mirrored on GitHub and Codeberg; pick a base URL.

   ```bash
   # BASE from GitHub:   https://raw.githubusercontent.com/PrivacySafe/security-patches/refs/heads/main
   # BASE from Codeberg: https://codeberg.org/PrivacySafe/security-patches/raw/branch/main
   # curl -fLO "$BASE/system/expat/expat-check.sh"
   curl -fLO https://raw.githubusercontent.com/PrivacySafe/security-patches/refs/heads/main/system/expat/expat-check.sh
   ```

2. Read it before running it, then make it executable.

   ```bash
   less expat-check.sh
   chmod +x expat-check.sh
   ```

3. Check this host: system libraries, Python interpreters and running processes.

   ```bash
   ./expat-check.sh check
   ```

4. Also look for programs that carry their own copy (vendored or statically linked). This reads files and can take a while on a large tree.

   ```bash
   sudo ./expat-check.sh deep /opt /srv /var/www /usr/local
   ```

## Commands

| Command | What it does |
|---|---|
| `check` (default) | Finds `libexpat*.so*` files under `/lib /lib64 /usr/lib /usr/lib64 /usr/local/lib /usr/local/lib64 /opt` and reads the version string compiled into each; asks each Python interpreter it can find for `pyexpat.EXPAT_VERSION`; lists running processes that have libexpat mapped and flags those still running a library that was replaced on disk |
| `deep [DIR ...]` | Everything in `check`, then scans executables and shared objects in the given directories (default `/usr/local /opt /srv /var/www /home`) for an embedded `expat_X.Y.Z` string |
| `version` | Prints the script version |

Environment: `EXPAT_LIB_DIRS` replaces the library search directories and `EXPAT_PY_DIRS` replaces the directories searched for interpreters.

Exit codes: `0` every copy found is fixed (or none found), `1` an affected copy, or a copy whose version cannot be parsed, was found, `2` bad arguments.

## How to read the result

- Every host will show affected until a fixed package ships. That is accurate, not noise. Use the script to track the position and to find the copies that will need attention.
- Package-managed copies: if the changelog does not mention the CVE yet, the script says so. If it does, the script reports a likely backported fix.
- Interpreters carry their own pyexpat. A Python built with a bundled expat (a `python.org` build, `pyenv`, or a container image) shows a different version from the system library, which is why the script asks the interpreter directly.
- Running processes keep the old library in memory until they restart. After you upgrade, restart the services the script lists. A process shown as "running a replaced libexpat" is already on borrowed time.
- `deep` finds vendored copies , which a package update will not touch. Those need an update from whoever ships the program.
- Run as root to see every process's mappings.

## Reducing exposure until the fix ships

These are PrivacySafe's recommendations. They limit damage from a hostile document, they do not remove the flaw.

- Cap the size of XML request bodies at the reverse proxy.
- Run services that parse untrusted XML under CPU and memory limits (systemd `CPUQuota` and `MemoryMax`) so a single request cannot starve the host.
- libexpat exposes calls that tune its amplification protection, but the upstream notes do not say that tightening them avoids this particular flaw, so do not rely on that.

## Sources

- [libexpat pull request #1433: precompute entity expanded sizes to detect amplification attacks early](https://github.com/libexpat/libexpat/pull/1433)
- [Expat 2.10.0 release announcement](https://blog.hartwork.org/posts/expat-2-10-0-released/) and the [oss-security post](https://www.openwall.com/lists/oss-security/2026/11/02/6)

## Before you run it

- The fix. Install Expat 2.10.0 or later (released 2 November 2026). The script reports every copy older than 2.10.0 as affected and 2.10.0 or newer as fixed. Run it again after you upgrade.
- Distribution packages usually backport without changing the version. The script checks for that before calling a packaged copy affected.
- It looks in several places. It finds libexpat shared libraries, reads the version compiled into each, asks installed Python interpreters for `pyexpat.EXPAT_VERSION`, lists running processes that have libexpat mapped (flagging those still running a replaced copy), and can scan directories for programs that carry their own copy.
- There is no hunt. The flaw is a denial of service, and no indicators have been published.
- It also checks running docker and podman containers, unless you name a directory or set `SCAN_CONTAINERS=0`. A read-only probe inside each running docker and podman container captures the libexpat shared libraries and, by running each Python interpreter's `import pyexpat`, its expat version into a private temporary directory. The script then runs once per container, in isolation, against that copy, so one container's configuration never changes another's result. Running processes are examined on the host only. The copies are removed on exit. A path shown as `.../docker_NAME/...` is inside the container NAME. It is skipped when you name a binary or directory yourself.

## Output for automation

`--output jsonl` (or `PSF_OUTPUT=jsonl`) makes `check` and `deep` write JSON Lines for monitoring and language models; `psf-report` turns them into a summary, Markdown, HTML or PDF. The tool never changes the host, so `PSF_READ_ONLY=1` has nothing to refuse. The format and the reports: [Output for automation](../../automation/README.md).

<!-- rhsa:begin (generated by packaging/rhsa/rhsa.py from Red Hat's advisory list: edit placement.json or the data, not this block) -->
## Red Hat advisories

Red Hat's advisory list (security advisories released 2026-04-01 to 2026-11-25) names the CVEs below. A Red Hat build is judged by its RPM release, not by the upstream version number, because Red Hat backports fixes: the advisory names the release that fixes it. A CVE with no advisory in the list has none for that period, which is not the same as not affected. The current state is on [Red Hat's CVE database](https://access.redhat.com/security/security-updates/#/cve).

| Advisory | Released | Severity | Package and stream | CVEs on this page |
|---|---|---|---|---|
| [RHSA-2026:90325](https://access.redhat.com/errata/RHSA-2026:90325) | 2026-10-26 | Important | `expat-2.9.0-1.1.hum1` (Hummingbird) | CVE-2026-113351, CVE-2026-115506 |
| [RHSA-2026:93593](https://access.redhat.com/errata/RHSA-2026:93593) | 2026-11-02 | Moderate | `expat-2.9.0-1.2.hum1` (Hummingbird) | CVE-2026-117610 |
| [RHSA-2026:100671](https://access.redhat.com/errata/RHSA-2026:100671) | 2026-11-20 | Important | `expat-2.5.0-10.el8_10` (RHEL 8.10) | CVE-2026-113351, CVE-2026-115506, CVE-2026-117610 |
| [RHSA-2026:100678](https://access.redhat.com/errata/RHSA-2026:100678) | 2026-11-20 | Important | `expat-2.5.0-6.el9_8.11` (RHEL 9.8) | CVE-2026-113351, CVE-2026-115506, CVE-2026-117610 |
| [RHSA-2026:100679](https://access.redhat.com/errata/RHSA-2026:100679) | 2026-11-20 | Important | `expat-2.5.0-9.el9_9.8` (RHEL 9.9) | CVE-2026-113351, CVE-2026-115506, CVE-2026-117610 |
| [RHSA-2026:100680](https://access.redhat.com/errata/RHSA-2026:100680) | 2026-11-20 | Important | `expat-2.7.3-1.el10_2.13` (RHEL 10.2) | CVE-2026-113351, CVE-2026-115506, CVE-2026-117610 |
| [RHSA-2026:100681](https://access.redhat.com/errata/RHSA-2026:100681) | 2026-11-20 | Important | `expat-2.7.3-2.el10_3.8` (RHEL 10.3) | CVE-2026-113351, CVE-2026-115506, CVE-2026-117610 |
| [RHSA-2026:102193](https://access.redhat.com/errata/RHSA-2026:102193) | 2026-11-23 | Important | `mingw-expat-2.5.0-7.el8_10` (RHEL 8.10) | CVE-2026-115506, CVE-2026-117610 |
| [RHSA-2026:102947](https://access.redhat.com/errata/RHSA-2026:102947) | 2026-11-24 | Critical | `rhui5/cds-kubernetes-rhel9` (container image); `rhui5/cds-rhel9` (container image); `rhui5/haproxy-rhel9` (container image); and 2 more | CVE-2026-113351, CVE-2026-115506, CVE-2026-117610 |

<!-- rhsa:end -->

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

⚠️ **Do not report unpatched vulnerabilities in a public issue.** Follow our [security policy](../../SECURITY.md) instead. Never send sensitive information through ordinary direct messages or unencrypted email.

- **Contribution terms:** [`CONTRIBUTING.md`](../../CONTRIBUTING.md)
- **Code of Conduct:** [`CODE_OF_CONDUCT.md`](../../CODE_OF_CONDUCT.md)
- **AI Contribution Policy:** [`AI_POLICY.md`](../../AI_POLICY.md)
- **Security and vulnerability reporting:** [`SECURITY.md`](../../SECURITY.md)

## 🔐 More from PrivacySafe

* **[PrivacySafe](https://privacysafe.app):** Privacy-by-design software for home, teams, and organizations. Sign up free, no phone number required.
* **[Bits On Tape](https://bitsontape.com):** Our newsletter covering cybersecurity, privacy, FLOSS, AI, and digital culture.
* **[Ivy Cyber](https://ivycyber.com):** Hosting, enterprise deployment, training, and technical support, including help hardening your own infrastructure.

## ⚖️ License

<a href="https://creativecommons.org/publicdomain/zero/1.0/" rel="nofollow"><img src="https://licensebuttons.net/p/zero/1.0/88x31.png" alt="CC0" /></a>

Security patches belong to everyone. To the extent possible under law, <a href="https://ivycyber.com" rel="nofollow">Ivy Cyber LLC</a> has waived all copyright and related or neighboring rights to this repository, including its scripts and documentation, under the <a href="https://creativecommons.org/publicdomain/zero/1.0/" rel="nofollow">Creative Commons CC0 1.0 Universal Public Domain Dedication</a> (`CC0-1.0`). Feel free to copy, remix, and share. If you'd like to give back, please [donate to PrivacySafe Foundation](https://privacysafe.foundation) 501c3 nonprofit.

See [`NOTICE`](../../NOTICE) and [`LICENSE`](../../LICENSE). Third-party components retain their original copyrights and licenses.

CC0 does not waive trademark or patent rights. PrivacySafe® and 3NWeb® are registered trademarks. PrivacySafe Foundation™ and Ivy Cyber™ are pending trademarks. This dedication does not grant permission to use these marks in a manner that suggests sponsorship, endorsement, affiliation, or origin.
