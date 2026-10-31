# Apache Tomcat: CVE-2026-103119 and CVE-2026-101356 check

Part of the [PrivacySafe Security Patches](../README.md) collection.

<a name="apache-tomcat-october-2026-check"></a>

## Apache Tomcat October 2026 check

**Script:** [`tomcat/tomcat-oct2026-check.sh`](tomcat-oct2026-check.sh)

Two Tomcat bugs disclosed on 20 October 2026 can hand one user's response, or part of it, to another user. Both are request and response mix-ups, which on a site with logins can mean one person is shown another person's page.

| | CVE-2026-103119 | CVE-2026-101356 |
|---|---|---|
| What | AJP response mix-up. A large non-blocking write can split the response body between the current request and the next request on the same connection (buffer under-read, CWE-127) | HTTP/2 request and response mix-up after an error during asynchronous servlet processing (incorrect object recycling) |
| Affected | 11.0.0-M25 through 11.0.26 | 11.0.22 through 11.0.26, 10.1.55 through 10.1.60, 9.0.118 through 9.0.122 |
| Fixed | 11.0.27 | 11.0.27, 10.1.61, 9.0.123 |
| Needs | The AJP connector in use | HTTP/2 enabled, and asynchronous servlets |
| Rating | Apache rates it Important; CVE trackers list 9.1 Critical (CVSS 3.1) | Apache rates it Important; CVE trackers list 9.1 Critical (CVSS 3.1) |
| Exploited | The CISA SSVC entry says none known, and no public exploit is known to us | None confirmed as of 21 October 2026 |

Both were announced on oss-security by Mark Thomas of the Tomcat team on 20 October 2026. The AJP bug was found by Tuomo Hänninen. The advisory for the HTTP/2 bug does not name a finder.

## Quick start

1. Download the script. The repository is mirrored on GitHub and Codeberg; pick a base URL.

   ```bash
   # BASE from GitHub:   https://raw.githubusercontent.com/PrivacySafe/security-patches/refs/heads/main
   # BASE from Codeberg: https://codeberg.org/PrivacySafe/security-patches/raw/branch/main
   # curl -fLO "$BASE/tomcat/tomcat-oct2026-check.sh"
   curl -fLO https://raw.githubusercontent.com/PrivacySafe/security-patches/refs/heads/main/tomcat/tomcat-oct2026-check.sh
   ```

2. Read it before running it, then make it executable.

   ```bash
   less tomcat-oct2026-check.sh
   chmod +x tomcat-oct2026-check.sh
   ```

3. Check this host. With no arguments the script looks at `CATALINA_HOME`, `CATALINA_BASE`, running Tomcat processes and the usual install paths (`/opt/tomcat*`, `/opt/apache-tomcat*`, `/usr/share/tomcat*`, `/usr/local/tomcat`, `/var/lib/tomcat*`). To check a specific install, pass its directory.

   ```bash
   ./tomcat-oct2026-check.sh check
   ./tomcat-oct2026-check.sh check /srv/tomcat-app1
   ```

## Commands

| Command | What it does |
|---|---|
| `check [CATALINA_HOME ...]` (default) | Finds installs, reads the exact version from `lib/catalina.jar` (`ServerInfo.properties`, falling back to `RELEASE-NOTES`), compares it with both CVEs, then reads `server.xml` (comments removed) to see whether an AJP connector and HTTP/2 (`UpgradeProtocol` with `Http2Protocol`) are switched on |
| `mitigate --ajp \| --http2 [--dry-run] [--restart] [CATALINA_HOME ...]` | **Changes the host (root).** The protective measures below, applied to `server.xml`. With no option it applies `--http2`, whose only effect is that clients fall back to HTTP/1.1; `--ajp` is added on request because anything reaching Tomcat over AJP stops working. `--ajp` comments out every AJP `Connector` (11.x below 11.0.27 only); anything reaching Tomcat over AJP (Apache `mod_proxy_ajp`, `mod_jk`) stops working. `--http2` comments out every HTTP/2 `UpgradeProtocol` (11.0.22 to 11.0.26, 10.1.55 to 10.1.60, 9.0.118 to 9.0.122 only). Elements are commented out, never deleted. `server.xml` is copied first and checked with `xmllint` (or `python3`) before and after; if the result is not well-formed the original is put back at once. Restarts nothing unless you add `--restart` |
| `rollback [--dry-run] [--restart]` | Puts back every file `mitigate` changed |
| `version` | Prints the script version |

Environment: `STATE_DIR` (default `/var/lib/psf-security-patches/tomcat`) holds the backups and manifest.

Exit codes of `check`: `0` nothing exposed, `1` an affected version is exposed or its configuration could not be read, `2` bad arguments.

## How to read the result

- Affected version and the feature is on: exposed. Upgrade and restart.
- Affected version, the feature is off in `server.xml`: the script prints a warning and exits `0`. The flaw is not reachable through that path today, but a config change would reopen it, so upgrade anyway.
- `server.xml` not found: the script cannot decide, so it treats the install as exposed and exits `1`.
- Version string and distribution backports. Debian, Ubuntu, RHEL and others backport fixes without changing the upstream version. For installs owned by a `dpkg` or `rpm` package the script reads the package changelog and reports a mention of either CVE. If the changelog does not mention them yet, it says so. Check your distribution's security tracker.
- Milestones. CVE-2026-103119 is listed from 11.0.0-M25. Older 11.0.0 milestones are development builds, and the script treats every 11.x below 11.0.27 as affected.

## What it cannot see

- Running containers are checked; images that are not running are not. See the container note below. For an image that is not running, compare its tag with the fixed versions.
- Which servlets are asynchronous. For CVE-2026-101356 the script reports HTTP/2 as enabled. It cannot tell from configuration whether your applications use asynchronous servlets, so treat HTTP/2 as exposed.
- Connectors defined outside `server.xml` , for example through embedded Tomcat in a Spring Boot jar. Check those applications' own dependencies.

## Protective measures while you upgrade

`mitigate --ajp` and `mitigate --http2` apply these (see Commands). `xmllint` confirms that the edited `server.xml` is well-formed. Verified on Tomcat 10.1.55 (the Ubuntu package), which is in the HTTP/2 range: with an HTTP/2 `UpgradeProtocol` on the 8080 connector, HTTP/2 worked both by prior knowledge and by upgrade. After `mitigate --http2` and a restart it did not, plain HTTP/1.1 still answered, Tomcat started with the commented element, and `rollback` restored `server.xml` exactly and HTTP/2 with it. `mitigate --ajp` correctly did nothing on 10.1.55, which is outside the AJP range.

These are PrivacySafe's measures from the advisory text, and they reduce exposure without fixing the bug.

- AJP: if you do not need AJP, remove or comment out the AJP `Connector` and proxy over HTTP instead. The bug is in how the response is framed on a shared connection, so it appears not to depend on authentication. Do not treat setting an AJP secret as a mitigation.
- HTTP/2: remove the `UpgradeProtocol` element from the `Connector`, and let the front proxy (Apache `mod_proxy_http`, nginx, HAProxy) speak HTTP/1.1 to Tomcat. Clients can still use HTTP/2 to the proxy.

## Sources

- CVE-2026-103119: [oss-security announcement](https://www.openwall.com/lists/oss-security/2026/10/20/28)
- CVE-2026-101356: [oss-security announcement](https://www.openwall.com/lists/oss-security/2026/10/20/27)

## Before you run it

- The fix. Update to 11.0.27, 10.1.61 or 9.0.123. The script never starts, stops or edits Tomcat.
- It reads the exact version from `lib/catalina.jar` and reads `server.xml` to see whether the AJP connector and HTTP/2 are switched on, since each flaw needs its feature.
- Both flaws can hand one user's response to another. CVE-2026-103119 is AJP on 11.0.x. CVE-2026-101356 is HTTP/2 with asynchronous servlets on 9.0, 10.1 and 11.0.
- There is no hunt. No indicators of exploitation have been published.
- It also checks running docker and podman containers, unless you name a directory or set `SCAN_CONTAINERS=0`. A read-only probe inside each running docker and podman container captures `lib/catalina.jar`, `RELEASE-NOTES` and `conf/server.xml` for each Tomcat home (with every `...Pass...` and `secret` attribute redacted inside the container before it is copied) into a private temporary directory. The script then runs once per container, in isolation, against that copy, so one container's configuration never changes another's result. The AJP and HTTP/2 checks read the container's own `server.xml`. The copies are removed on exit. A path shown as `.../docker_NAME/...` is inside the container NAME. It is skipped when you name a binary or directory yourself.

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
