# MySQL security releases

Part of the [PrivacySafe Security Patches](../../README.md) collection.

<a name="client-programs"></a>

## Client programs: CVE-2026-114952, unauthenticated flaw in MySQL's client binaries

**Script:** [`servers/mysql/mysql-client-check.sh`](mysql-client-check.sh)

Oracle published CVE-2026-114952 on 17 November 2026 as part of its November 2026 Critical Security Patch Update: CVSS 3.1 9.1 (critical), network-reachable, no authentication or user interaction needed (CVSS vector `AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N`). CISA's record adds CWE-287, improper authentication. The affected component is "Client programs", the `mysql`, `mysqldump`, `mysqlbinlog`, `mysqlimport`, `mysqlshow` and `mysqladmin` binaries that ship alongside every MySQL Server and MySQL Cluster install, over the MySQL protocol.

Oracle's own advisories, as a matter of long-standing practice, give the component, the protocol, the CVSS score and the affected version ranges, and nothing about the technical root cause. Analysis circulating since publication (not confirmed by Oracle; a plausible read, not an established fact) describes a client-side trust failure during the connection handshake, where a client program accepts a server's authentication outcome and releases data, or a relayable credential, to a server it never actually verified. If that holds, the attacker here is a party controlling or positioned to intercept a MySQL server, not one attacking a listening `mysqld`; the victim is whatever script, pipeline or person runs a MySQL client program.

There is no confirmed configuration change that closes this: the vulnerable code is inside the client binaries themselves, and the only confirmed fix is upgrading those packages. Until then, the behavioral guidance follows from the vulnerability's own shape: don't point MySQL client tools at a server you don't fully control and trust, especially over a network path an attacker could sit on. Backup scripts, CI pipelines and admin tooling running `mysqldump` or `mysqlbinlog` against a remote or third-party-managed endpoint are the exposure this describes, not a locally listening server being attacked.

For hosts stuck on MySQL 8.0 with no official patch to move to at all, `harden` offers one speculative, clearly-labeled exception. Unconfirmed secondary analysis (not published or endorsed by Oracle) guesses the mechanism is a client-side trust failure during authentication, and names the client's cleartext authentication plugin, a real, documented feature (`--enable-cleartext-plugin`, and the `MYSQL_ENABLE_CLEARTEXT_PLUGIN`/`LIBMYSQL_ENABLE_CLEARTEXT_PLUGIN` environment variables, not something invented for this analysis), as one concrete thing that would fit that shape. `check` audits the usual client config files and this shell's environment for it; `harden` comments out any active config-file setting it finds (environment variables in another process or a systemd unit have to be removed by hand; `check` and `harden` both say where they found one set). This is a guess about a guess, not a fix for a confirmed root cause, and it is not a substitute for upgrading once a real patch exists for your line. It exists because for an 8.0 host with nothing official to move to, doing something plausible and honestly labeled beats doing nothing.

Oracle's November 2026 CSPU bulletin's affected-version listing for this release batch runs through MySQL Server/Cluster 8.4.0 to 8.4.13, 9.7.0 to 9.7.4, and 26.10 (26.10.0), plus MySQL Shell and MySQL Workbench 26.10.0. That listing does not cover MySQL Server 8.0.x at all: 8.0 left Oracle's Premier/CPU-eligible support in April 2026 for Sustaining Support, which does not receive new security patches. `check` reports any installed 8.0.x client package as exposed with no confirmed remediation besides moving to 8.4 or later, or a direct conversation with Oracle if you hold Extended Support.

`check` needs no privilege and changes nothing. `harden` and `rollback` change the host and require root, stopping with a clear message (and a `sudo` suggestion) otherwise. Neither offers a `--reload`: unlike a web server or proxy, there's no long-running daemon reading this config, since it's read fresh by each client invocation.

`check` finds installed MySQL client packages (`dpkg` or `rpm`, scoped to Oracle's own MySQL packaging, not MariaDB, which forked long ago and is not named in Oracle's advisory either way) and classifies each one's version. The fixed version for the 8.4, 9.7 and 26.x lines is this script's own inference, not a number Oracle's bulletin states directly: Oracle's practice is to ship the CPU/CSPU fix as the next quarterly release on the same line, so the script treats the release immediately after the last-listed-affected point in each line (8.4.14, 9.7.5, 26.10.1) as fixed. The three `MYSQL_114952_AFFECTED_*`/`MYSQL_114952_FIXED_*` environment variables below let you correct any of these against your own vendor's advisory text without waiting on a script update.

There is deliberately no `hunt` command. Oracle has not published a root cause, and no log signature has been publicly tied to this CVE at the time of writing; a heuristic written without either would be guesswork dressed up as detection.

Verified on `mysql-client` 8.0.46 (Ubuntu 24.04): `check` reports the three installed client packages as the unconfirmed 8.0 case and skips rows that `dpkg-query` lists for packages that were never installed. `harden` comments out an active `enable-cleartext-plugin` line and `rollback` restores the file exactly. An environment variable is reported by name and left for you to remove, since `harden` only edits files.

### Client programs quick start

```sh
curl -O https://codeberg.org/PrivacySafe/security-patches/raw/branch/main/servers/mysql/mysql-client-check.sh
chmod +x mysql-client-check.sh
./mysql-client-check.sh check
```

### Client programs commands

| Command | Changes the system? | What it does |
|---|---|---|
| `check` | no | Finds installed MySQL client packages and classifies each against the affected/fixed ranges; also audits for the cleartext-plugin setting below. Exit 0 clear, 1 exposed/unconfirmed, 2 not found/undetermined |
| `harden [--dry-run]` | yes (unless `--dry-run`) | Speculative, unconfirmed defense-in-depth only (see above): comments out any active `enable-cleartext-plugin` config-file setting it finds. Backs up every file it touches |
| `rollback [--dry-run]` | yes (unless `--dry-run`) | Restores every file `harden` backed up; `--dry-run` lists what it would restore |
| `rules` | no | Prints the explanation above |
| `version` | no | Prints the script's version |

Environment overrides: `MYSQL_114952_AFFECTED_84` / `MYSQL_114952_FIXED_84` (default `8.4.13` / `8.4.14`), `MYSQL_114952_AFFECTED_97` / `MYSQL_114952_FIXED_97` (default `9.7.4` / `9.7.5`), `MYSQL_114952_AFFECTED_26X` / `MYSQL_114952_FIXED_26X` (default `26.10.0` / `26.10.1`).

What this script can't see: MariaDB (out of scope by design; see above), a MySQL client installed from a tarball or a vendor package this script's name list doesn't match (it falls back to checking for a `mysql` binary on `PATH` and reports its version unclassified rather than guessing), and any client installed inside a container image this script wasn't run against directly.

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
