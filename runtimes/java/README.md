# Java4Shell: CVE-2026-114938, OpenJDK Base64 decoder

Part of the [PrivacySafe Security Patches](../../README.md) collection.

<a name="java4shell"></a>

## Java4Shell: OpenJDK Base64 intrinsic out-of-bounds write

**Script:** [`runtimes/java/java4shell-check.sh`](java4shell-check.sh)

On x86-64 processors with AVX-512 VBMI (Intel Ice Lake or newer, AMD Zen 4 or newer), the JIT's fast path for `java.util.Base64` decoding can write past the end of its buffer when it decodes input an attacker chose. Tokens, authorization headers, SAML and uploads all go through Base64, and researchers showed it against Jira, Confluence, Artifactory and Jenkins. ARM servers and older x86 processors never take that path.

| | |
|---|---|
| CVE | CVE-2026-114938 |
| Severity | 8.1 (Oracle, CVSS 3.1); 9.2 (researchers, CVSS 4.0) |
| Affected | Java 17.0.6 and later, 21, 25 and 27 from any vendor without the November 2026 fix; Oracle's Java 8 Performance Pack; Oracle GraalVM for JDK 17 and 21. Standard Java 8 and 11 are not affected |
| Fixed | Oracle 17.0.21.1, 21.0.13.1, 25.0.5.1 and 27.0.1.1 (17 November 2026); Corretto the same day; Temurin, Red Hat, Ubuntu and Debian builds followed |
| Exploited | No; memory-corruption proof of concept public |
| Workaround | `-XX:-UseBASE64Intrinsics` (AWS; not an official Oracle workaround), needs a restart |

**Bundled Java.** Jira, Confluence, Artifactory, Jenkins and many others ship their own Java. Updating the system Java does not fix them: update the product, or its bundled runtime. `check` finds those copies too.

## Quick start

1. Download the script. The repository is mirrored on GitHub and Codeberg; pick a base URL.

   ```bash
   # BASE from GitHub:   https://raw.githubusercontent.com/PrivacySafe/security-patches/refs/heads/main
   # BASE from Codeberg: https://codeberg.org/PrivacySafe/security-patches/raw/branch/main
   curl -fLO https://raw.githubusercontent.com/PrivacySafe/security-patches/refs/heads/main/runtimes/java/java4shell-check.sh
   ```

2. Read it before running it, then make it executable.

   ```bash
   less java4shell-check.sh
   chmod +x java4shell-check.sh
   ```

3. Check this machine: its CPU, every Java runtime, and every running JVM. Run it on every node, because clusters often mix CPU generations.

   ```bash
   sudo ./java4shell-check.sh check
   ```

4. If you cannot update yet, set the workaround flag for the running services, and restart them.

   ```bash
   sudo ./java4shell-check.sh mitigate --dry-run
   sudo ./java4shell-check.sh mitigate --restart
   ```

## Commands

| Command | What it does |
|---|---|
| `check` (default) | Reads the CPU flags; finds every Java runtime under `ROOTS` (default `/usr/lib/jvm /opt /srv /usr/local /var/lib /home`) and judges it by its `release` file, without running it, and a distribution package also by its changelog; lists every running JVM and whether its command line or environment already carries `-XX:-UseBASE64Intrinsics`. Read-only. Exits `0` if nothing is exposed, `1` for an affected runtime on a CPU with AVX-512 VBMI (or one whose flags could not be read), `2` if a runtime could not be judged |
| `mitigate [--dry-run] [--restart]` | For each running systemd service whose Java is affected and lacks the flag, adds a drop-in (`/etc/systemd/system/UNIT.d/90-psf-java4shell.conf`) that sets `JAVA_TOOL_OPTIONS` to the service's own value plus `-XX:+IgnoreUnrecognizedVMOptions -XX:-UseBASE64Intrinsics`, and reloads systemd. Nothing is restarted unless you add `--restart`. Java started any other way is listed with the flag to add. Takes the shared lock |
| `rollback [--dry-run] [--restart]` | Removes those drop-ins and reloads systemd |
| `version` | Prints the script version |

Environment: `ROOTS`, `MAX_DEPTH`, `CPUINFO_FILE`, `DROPIN_ROOT`, `STATE_DIR`, `PSF_LOCK_WAIT`.

## How to read the result

The CPU decides whether an affected Java is exposed today: the vulnerable path runs only with AVX-512 VBMI. A runtime that is affected on a CPU without it is reported but does not fail the check, because nothing reaches the bug there. Update it anyway: a migration, a cluster node or a new instance type can have the flag. Vendors number their builds differently (Corretto `21.0.13.1.2`, Ubuntu `21.0.13.1+2`); the first four parts are compared, and a distribution package whose changelog names CVE-2026-114938 is fixed whatever its number.

`-XX:+IgnoreUnrecognizedVMOptions` makes a JVM that does not know the flag start anyway, so a service that also runs an old Java is not broken by the drop-in.

Sources: [OpenJDK advisory](https://openjdk.org/groups/vulnerability/advisories/2026-11-17), [AWS bulletin](https://aws.amazon.com/security/security-bulletins/2026-189-aws/) (CPU condition, flag), [Red Hat RHSB-2026-018](https://access.redhat.com/security/vulnerabilities/RHSB-2026-018), [Ubuntu](https://ubuntu.com/security/CVE-2026-114938), [Debian](https://security-tracker.debian.org/tracker/CVE-2026-114938), [Adoptium](https://adoptium.net/news/2026/11/temurin-november-2026-cspu-java4shell) and the [original disclosure](https://calif.io/java4shell). Status current on 23 November 2026.

<!-- rhsa:begin (generated by packaging/rhsa/rhsa.py from Red Hat's advisory list: edit placement.json or the data, not this block) -->
## Red Hat advisories

Red Hat's advisory list (security advisories released 2026-04-01 to 2026-11-25) names the CVEs below. A Red Hat build is judged by its RPM release, not by the upstream version number, because Red Hat backports fixes: the advisory names the release that fixes it. A CVE with no advisory in the list has none for that period, which is not the same as not affected. The current state is on [Red Hat's CVE database](https://access.redhat.com/security/security-updates/#/cve).

These are the OpenJDK 17, 21 and 25 builds for RHEL 8, 9 and 10 and for the Hummingbird images.

- [CVE-2026-114938](https://access.redhat.com/security/cve/CVE-2026-114938): 27 advisories, 2026-11-18 to 2026-11-24; 27 critical; by stream, RHEL 8 2, RHEL 9 2, RHEL 10 2, Hummingbird 4, container image 11; most often `java` (10), `ocp-tools-4/jenkins-agent-base-rhel9` (6), `ocp-tools-4/jenkins-agent-base-rhel8` (4), `ocp-tools-4/jenkins-rhel9` (1). All of them: [Red Hat's CVE page](https://access.redhat.com/security/cve/CVE-2026-114938).

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
