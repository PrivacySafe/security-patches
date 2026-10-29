# OpenSSL DTLS handshake retransmission read (CVE-2026-84782)

Part of the [PrivacySafe Security Patches](../README.md) collection.

<a name="openssl-check"></a>

## OpenSSL check

**Script:** [`openssl/openssl-check.sh`](openssl-check.sh)

OpenSSL's security release of 29 September 2026 fixed 14 flaws. One is rated High: CVE-2026-84782, "DTLS retransmits handshake messages from a stale buffer offset". When DTLS retransmits a handshake message it can read from the wrong place in a buffer, so a remote peer may receive unintended plaintext heap memory in the handshake data, or the program may crash. CISA scored it 8.2 (confidentiality low, availability high). It was found by Laurent Gaffie of Secorizon, with the fix by Ryan Hooper. The FIPS module is not affected.

| | |
|---|---|
| CVE | CVE-2026-84782 |
| Severity | High, 8.2 |
| Reachable through | DTLS (TLS over UDP) only |
| Affected | 4.0.0 before 4.0.3, 3.6 before 3.6.5, 3.5 before 3.5.9, 3.4 before 3.4.8, 3.0 before 3.0.23, 1.1.1 before 1.1.1zj, 1.0.2 before 1.0.2zs |
| Fixed, public | 4.0.3, 3.6.5, 3.5.9, 3.4.8 |
| Fixed, premium support only | 3.0.23, 1.1.1zj, 1.0.2zs. Public support for 3.0 ended on 7 September 2026. Branches 3.1 to 3.3 are end of life and were not evaluated by OpenSSL |
| Ubuntu | Fixed in openssl 3.5.5-1ubuntu3.6 (26.04), 3.0.13-0ubuntu3.16 (24.04) and 3.0.2-0ubuntu1.30 (22.04). Older releases were still marked "needs evaluation" |

## Who is actually exposed

Software that speaks DTLS: VPN servers such as ocserv, VoIP and WebRTC servers such as Asterisk, FreeSWITCH, Janus and coturn, and IoT endpoints. Ordinary TLS (HTTPS, SMTP, IMAP, databases) does not use the vulnerable code. Node.js and Python's `ssl` module have no DTLS API. A host with an affected OpenSSL and no DTLS service has little practical exposure, but the library should still be updated.

## How the script decides

| Case | Judgement |
|---|---|
| A distribution package whose changelog names CVE-2026-84782 | Fixed: a backport, whatever the version says |
| An Ubuntu package, no changelog entry | Compared with the fixed package versions above. Releases not listed are reported as unconfirmed |
| Another distribution's package, no changelog entry | "Cannot confirm": check your vendor's tracker. The script does not guess from the upstream number, because distributions backport |
| A copy no package owns (a local build) | The upstream version against the table. 3.0, 1.1.1 and 1.0.2 are reported as affected with a premium-only fix; 3.1 to 3.3 as end of life |
| A copy bundled under `/opt`, `/usr/local`, `/srv` or `/home` | The version string inside its `libcrypto`, against the table |
| A development or alpha/beta build of a fixed release itself (`3.6.5-dev`, `4.0.3-alpha2`) | Not judged as the release: it may not carry the fix. Warns, exit `1`. A `-dev` build of a later release (`3.6.6-dev`) is fixed |
| A package version string, or `openssl` output, that the script cannot parse | Reported as unreadable with the versions to check by hand, exit `1`; never as clean |

It also reports running DTLS-capable daemons from a short list, and processes that still hold a replaced OpenSSL in memory, because a library update does not reach a running process until it restarts. LibreSSL is not OpenSSL and is not affected. Node.js's bundled OpenSSL is reported for information.

## Quick start

```bash
curl -fLO https://raw.githubusercontent.com/PrivacySafe/security-patches/refs/heads/main/openssl/openssl-check.sh
less openssl-check.sh
chmod +x openssl-check.sh
./openssl-check.sh check
```

## Commands

| Command | What it does |
|---|---|
| `check` (default) | Judges the system OpenSSL, bundled copies, DTLS daemons and stale processes. Exit `0` nothing exposed, `1` an affected or unconfirmed OpenSSL |
| `version` | Prints the script version |

Env: `OPENSSL_BIN`, `OPENSSL_PKG_VERSION`, `OPENSSL_OS_RELEASE`, `OPENSSL_CHANGELOG`, `OPENSSL_PROC` and `OPENSSL_NODE` override the openssl command, the package version, `/etc/os-release`, a changelog file (plain or `.gz`), `/proc` and the node command. `OPENSSL_NO_PACKAGE=1` treats the installed openssl as not owned by a package.

## Update

Update the OpenSSL package, then restart the services that use it (`needrestart`, or a reboot). For 3.0, 1.1.1 and 1.0.2 without a vendor backport, the public fix does not exist: move to a supported branch (3.4 or later) or use a distribution package that carries the fix.

## Sources

- [OpenSSL vulnerabilities page](https://openssl-library.org/news/vulnerabilities/)
- [Ubuntu: CVE-2026-84782](https://ubuntu.com/security/CVE-2026-84782)
- [The Hacker News: OpenSSL fixes a high-severity DTLS flaw](https://thehackernews.com/2026/09/openssl-fixes-high-severity-dtls-flaw.html)

## OpenSSL know before you run it

- **This is a check, not a fix.** Update the OpenSSL package, then restart the services that use it (`needrestart` or a reboot). Fixed public releases are 4.0.3, 3.6.5, 3.5.9 and 3.4.8; for 3.0, 1.1.1 and 1.0.2 the fix is available only to premium-support customers, and 3.1 to 3.3 are end of life.
- **A distribution build is judged by its package.** Ubuntu's fixed builds (26.04: 3.5.5-1ubuntu3.6, 24.04: 3.0.13-0ubuntu3.16, 22.04: 3.0.2-0ubuntu1.30) and the package changelog naming the CVE come first; the upstream version is used only for a build that is not from a package. For other distributions the script says "cannot confirm".
- **The flaw is only reachable through DTLS.** Ordinary TLS services do not use the vulnerable code, and Node.js has no DTLS API. The script lists the DTLS-capable services it finds running and processes still holding a replaced OpenSSL in memory.
- **It also reads running containers.** With `SCAN_CONTAINERS=1` (the default) it asks each running docker and podman container for its own distribution, package and `openssl version`, and judges it by the container's rules, not the host's. OpenSSL linked statically into a program, inside or outside a container, is not visible; copies bundled under `/opt`, `/usr/local`, `/srv` and `/home` are listed, and whoever ships that software updates them. There is no hunt.

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
