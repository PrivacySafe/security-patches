# libexpat: CVE-2026-115506 billion laughs detection delay

Part of the [PrivacySafe Security Patches](../README.md) collection.

<a name="libexpat-billion-laughs-check"></a>

## libexpat billion laughs check

**Script:** [`expat/expat-check.sh`](expat-check.sh)

libexpat is the XML parser inside Python (`pyexpat`), Apache httpd, many PHP and Perl builds, Subversion, Mercurial, D-Bus, fontconfig, Firefox and a very long list of other programs. Its protection against "billion laughs" entity amplification works by tracking how much a parse expands. In `accountingDiffTolerated()` in `xmlparse.c` that check detects the amplification too late, so a moderately sized crafted XML document can still make the parser burn a large amount of CPU and memory before the protection steps in. The result is denial of service for any service that parses XML from an untrusted source.

| | |
|---|---|
| CVE | CVE-2026-115506 (published 22 October 2026; upstream issue #1160) |
| Severity | High: 7.5 (CVSS 3), listed as 8.7 on the CVSS 4.0 scale. Authentication is not needed wherever XML from an untrusted source is parsed |
| Affected | libexpat through 2.9.0, which is every release so far |
| Fix | Merged upstream on 23 October 2026 (pull request #1433) and milestoned for **Expat 2.9.1** |
| Exploited | No exploitation has been reported |

**As of 27 October 2026 no Expat release contains the fix.** The script reports every copy at 2.9.0 or older as affected and treats 2.9.1 or newer as fixed, because upstream attached the fix to the 2.9.1 milestone. Distribution packages usually backport fixes without changing the version string; the script reads the owning package's changelog for a mention of the CVE.

## Quick start

1. Download the script. The repository is mirrored on GitHub and Codeberg; pick a base URL.

   ```bash
   # BASE from GitHub:   https://raw.githubusercontent.com/PrivacySafe/security-patches/refs/heads/main
   # BASE from Codeberg: https://codeberg.org/PrivacySafe/security-patches/raw/branch/main
   # curl -fLO "$BASE/expat/expat-check.sh"
   curl -fLO https://raw.githubusercontent.com/PrivacySafe/security-patches/refs/heads/main/expat/expat-check.sh
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

Exit codes: `0` every copy found is fixed (or none found), `1` an affected copy was found, `2` bad arguments.

## How to read the result

- **Every host will show affected until a fixed package ships.** That is accurate, not noise. Use the script to track the position and to find the copies that will need attention.
- **Package-managed copies:** if the changelog does not mention the CVE yet, the script says so. If it does, the script reports a likely backported fix.
- **Interpreters carry their own pyexpat.** A Python built with a bundled expat (a `python.org` build, `pyenv`, or a container image) shows a different version from the system library, which is why the script asks the interpreter directly.
- **Running processes keep the old library in memory** until they restart. After you upgrade, restart the services the script lists; a process shown as "running a replaced libexpat" is already on borrowed time.
- **`deep` finds vendored copies**, which a package update will not touch. Those need an update from whoever ships the program.
- **Run as root** to see every process's mappings.

## Reducing exposure until the fix ships

These are our reasoning and not vendor documented. They limit damage from a hostile document, they do not remove the flaw.

- Cap the size of XML request bodies at the reverse proxy.
- Run services that parse untrusted XML under CPU and memory limits (systemd `CPUQuota` and `MemoryMax`) so a single request cannot starve the host.
- libexpat exposes calls that tune its amplification protection, but the upstream notes do not say that tightening them avoids this particular flaw, so do not rely on that.

## Sources

- [libexpat pull request #1433: precompute entity expanded sizes to detect amplification attacks early](https://github.com/libexpat/libexpat/pull/1433)
- [libexpat release tracker for 2.9.1](https://github.com/libexpat/libexpat/issues/1416)

## Expat know before you run it

- **This is a check, not a fix.** As of 27 October 2026 no Expat release contains the fix for CVE-2026-115506. The script reports every copy at 2.9.0 or older as affected and treats 2.9.1 or newer as fixed, because upstream attached the fix to the 2.9.1 milestone; run it again when 2.9.1 ships.
- **Distribution packages usually backport without changing the version.** The script checks for that before calling a packaged copy affected.
- **It looks in several places.** It finds libexpat shared libraries, reads the version compiled into each, asks installed Python interpreters for `pyexpat.EXPAT_VERSION`, lists running processes that have libexpat mapped (flagging those still running a replaced copy), and can scan directories for programs that carry their own copy.
- **There is no hunt.** The flaw is a denial of service, and no indicators have been published.
- **It also reads running containers.** With no argument and `SCAN_CONTAINERS=1` (the default), a read-only probe inside each running docker and podman container captures the libexpat shared libraries and, by running each Python interpreter's `import pyexpat`, its expat version into a private temporary directory, and this script then runs once per container, in isolation, against that copy, so one container's configuration never changes another's result. Running processes are examined on the host only. The copies are removed on exit. A path shown as `.../docker_NAME/...` is inside the container NAME. It is skipped when you name a binary or directory yourself.

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
