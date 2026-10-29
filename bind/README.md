# ISC BIND 9: CVE-2026-94300 GSS-TSIG memory corruption

Part of the [PrivacySafe Security Patches](../README.md) collection.

<a name="bind-check"></a>

## BIND check

**Script:** [`bind/bind-check.sh`](bind-check.sh)

Replaying a GSS-TSIG signed UDP message can corrupt memory in `named`, the BIND 9 name server. ISC says that, combined with crafted queries to a zone the attacker controls, it can lead to remote code execution, and at the least it can crash `named`. The attack is complex: the attacker must capture a signed message and replay it while the key is still valid.

| | |
|---|---|
| CVE | CVE-2026-94300 (published 21 October 2026, early notification 14 October) |
| Severity | High, CVSS 8.1 |
| Affected | BIND 9.11.0 through 9.18.50, 9.20.0 through 9.20.29, 9.21.0 through 9.21.26, and matching `-S1` Supported Preview builds |
| Fixed | **9.20.30 and 9.21.27** (9.20.30-S1 for the Preview Edition) |
| No fix | **9.18 and older are end of life.** ISC does not ship security fixes for them; move to 9.20. A distribution that still supports 9.18 may backport the fix, and the script looks for that |
| Workaround | ISC lists none |
| Exploited | ISC says it is not aware of any active exploitation |
| Same release | The same BIND releases fix three other denial of service flaws that only the update fixes |

**What decides your exposure.** The vulnerable code is in every build, but the path needs GSS-TSIG, which is used for secure dynamic updates against Kerberos or Active Directory. One analysis says builds with no GSS-TSIG configured do not reach it. ISC's advisory text does not spell out which configuration is required, so the script reports whether GSS-TSIG is configured as a **hint**, never as proof of safety, and says to update either way.

## Quick start

1. Download the script. The repository is mirrored on GitHub and Codeberg; pick a base URL.

   ```bash
   # BASE from GitHub:   https://raw.githubusercontent.com/PrivacySafe/security-patches/refs/heads/main
   # BASE from Codeberg: https://codeberg.org/PrivacySafe/security-patches/raw/branch/main
   # curl -fLO "$BASE/bind/bind-check.sh"
   curl -fLO https://raw.githubusercontent.com/PrivacySafe/security-patches/refs/heads/main/bind/bind-check.sh
   ```

2. Read it before running it, then make it executable.

   ```bash
   less bind-check.sh
   chmod +x bind-check.sh
   ```

3. Check this host. It finds `named` on `PATH`, in the usual locations and from running processes, and reads the configuration file the running process was started with.

   ```bash
   ./bind-check.sh check
   ./bind-check.sh check /opt/bind9/sbin/named
   ```

## Commands

| Command | What it does |
|---|---|
| `check [BINARY ...]` (default) | Reads the version from `named -v`, applies ISC's ranges, reads `named.conf` and every file it includes (following `include` statements, with a loop guard), and searches for GSS-TSIG settings: `tkey-gssapi-keytab`, `tkey-gssapi-credential`, `tkey-domain`, and the `krb5-*` and `ms-*` rules in `update-policy`. It also notes whether the build was compiled with GSSAPI (`--with-gssapi`) |
| `version` | Prints the script version |

Environment: `NAMED_CONF` (space separated files) replaces configuration discovery.

Exit codes: `0` nothing exposed, `1` an affected version is exposed or its configuration could not be read, `2` bad arguments.

## How to read the result

- **Affected version and GSS-TSIG configured:** exposed. Upgrade.
- **Affected version, no GSS-TSIG setting found:** exit `0` with a warning that you should update anyway. A text search can miss a setting generated elsewhere.
- **End-of-life branch (9.18 and older, or the 9.19 development line):** always reported as affected with no upstream fix. If your distribution supports it, watch its security tracker; the script reads the package changelog for a mention of the CVE and treats a mention as a likely backport. At the time of writing, Debian 13 had shipped the fix in `bind9 1:9.20.30-1~deb13u1`, while the 9.18 packages were still shown as vulnerable.
- **Config unreadable:** the script cannot tell, so it treats the host as exposed.
- **Preview Edition (`-S1`) and distribution suffixes** such as `9.20.30-1~deb13u1` or `9.18.39-0ubuntu0.24.04.8-Ubuntu` are read correctly.

## Fixing it

Upgrade to 9.20.30 or 9.21.27, or to a distribution build that carries the fix, then restart `named`. ISC lists no workaround. If you do not use GSS-TSIG, removing those settings is our suggestion rather than ISC's, and it does not replace the update.

## Sources

- [ISC advisory CVE-2026-94300](https://kb.isc.org/docs/cve-2026-94300)
- [BIND 9.20.30 download](https://downloads.isc.org/isc/bind9/9.20.30)

## BIND know before you run it

- **This is a check, not a fix.** Update to 9.20.30 or 9.21.27 (9.20.30-S1 for the Preview Edition). ISC lists no workaround. The 9.18 branch and older are end of life and get no upstream fix; a distribution that still supports 9.18 may backport it, which the script looks for.
- **GSS-TSIG is a hint, not a verdict.** The vulnerable path needs GSS-TSIG (used for secure dynamic updates against Kerberos or Active Directory), but ISC does not spell out which configuration is required. The script reports whether GSS-TSIG is configured and tells you to update either way.
- **It never reloads named.** It finds `named` in `PATH`, the usual locations and running processes, reads the version from `named -v` and reads `named.conf` and its include files.
- **Other flaws ride along.** The same releases fix three denial of service flaws that only the update fixes.
- **It also reads running containers.** With no argument and `SCAN_CONTAINERS=1` (the default), a read-only probe inside each running docker and podman container captures the output of `named -v` and `named -V` and the configuration files (with every `secret "..."` value redacted inside the container before it is copied) into a private temporary directory, and this script then runs once per container, in isolation, against that copy, so one container's configuration never changes another's result. `include` paths are resolved inside the container's copy, not on the host. The copies are removed on exit. A path shown as `.../docker_NAME/...` is inside the container NAME. It is skipped when you name a binary or directory yourself.

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
