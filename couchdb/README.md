# Apache CouchDB: CVE-2026-86471 admin to operating system commands

Part of the [PrivacySafe Security Patches](../README.md) collection.

<a name="couchdb-check"></a>

## CouchDB check

**Script:** [`couchdb/couchdb-check.sh`](couchdb-check.sh)

An unvalidated runtime configuration value in Apache CouchDB lets a CouchDB **server admin** run arbitrary shell commands as the operating system user that runs CouchDB. It needs admin credentials, so it is a privilege escalation from a CouchDB admin to the host: a stolen or weak admin password, an exposed admin interface, or a compromised application that holds admin credentials. It is not something an anonymous visitor can use alone.

| | |
|---|---|
| CVE | CVE-2026-86471 (published 20 October 2026) |
| Severity | Critical: 9.3 on the CVSS 4.0 scale (privileges required: high) |
| Affected | Apache CouchDB 3.5.2 and earlier, on all platforms |
| Fixed | **3.5.3** |
| Needs | Server-admin credentials |
| Exploited | No exploitation has been reported |
| Same release | 3.5.3 also fixes other CouchDB flaws, including a pre-authentication gzip decompression bomb on `POST /_session`. That one needs no credentials, which is why the bind address matters |

## Quick start

1. Download the script. The repository is mirrored on GitHub and Codeberg; pick a base URL.

   ```bash
   # BASE from GitHub:   https://raw.githubusercontent.com/PrivacySafe/security-patches/refs/heads/main
   # BASE from Codeberg: https://codeberg.org/PrivacySafe/security-patches/raw/branch/main
   # curl -fLO "$BASE/couchdb/couchdb-check.sh"
   curl -fLO https://raw.githubusercontent.com/PrivacySafe/security-patches/refs/heads/main/couchdb/couchdb-check.sh
   ```

2. Read it before running it, then make it executable.

   ```bash
   less couchdb-check.sh
   chmod +x couchdb-check.sh
   ```

3. Check this host. With no arguments it reads the release files, the installed package and asks only `http://127.0.0.1:5984/`. To check other servers, pass their URLs.

   ```bash
   ./couchdb-check.sh check
   ./couchdb-check.sh check http://10.0.0.5:5984/ http://10.0.0.6:5984/
   ```

## Commands

| Command | What it does |
|---|---|
| `check [URL ...]` (default) | Reads the version from `releases/start_erl.data` under `/opt/couchdb`, from the dpkg or rpm package, and from a single unauthenticated `GET /` of each URL (the root document, which reports the version). Reads the ini files for `bind_address`, `require_valid_user` and the number of `[admins]` entries |
| `version` | Prints the script version |

Environment: `COUCHDB_ROOT` (default `/opt/couchdb`) and `COUCHDB_ETC` (space separated, default `/opt/couchdb/etc /etc/couchdb /usr/local/etc/couchdb`) point the script at unusual layouts.

Exit codes: `0` nothing affected, `1` an affected version was found, `2` bad arguments.

## Credentials are never printed

The `[admins]` section holds password hashes or passwords. The script **counts** the entries and never prints a value from that section.

## How to read the result

- Affected version: upgrade to 3.5.3. The script exits `1` for any affected version, because it cannot judge how well your admin credentials are protected.
- `bind_address` is `0.0.0.0` or `::`: CouchDB listens on every interface. The unauthenticated `/_session` flaw fixed in the same release is then reachable by anyone who can connect. The script reads the last value across `default.ini`, `default.d`, `local.ini` and `local.d`, and ignores commented lines.
- `bind_address` is loopback: reported as a good sign, not as a fix.
- Several sources: the release files, the package and each live URL are reported separately. A running server that answers with a different version from the files on disk usually means it was upgraded but not restarted, or the reverse.
- Distribution packages: the script reads the package changelog for a mention of the CVE.
- A server that requires a login for `GET /` simply gives no version. The script says it got no answer.

## Fixing it

Upgrade to CouchDB 3.5.3 or later and restart. Until you can, keep port 5984 off untrusted networks, give admins long unique passwords, and do not let applications hold admin credentials they do not need. Those steps are PrivacySafe's recommendation. After upgrading, rotate any admin password that may have been exposed.

## Sources

- [Apache CouchDB](https://couchdb.apache.org/)
- [CVE record for CVE-2026-86471](https://www.cve.org/CVERecord?id=CVE-2026-86471)

## Before you run it

- The fix. Update to 3.5.3. The same release fixes a pre-authentication gzip decompression bomb on `POST /_session`, which needs no credentials, so whether the node listens beyond localhost matters.
- CVE-2026-86471 needs a server admin. It is a privilege escalation from a CouchDB admin (a stolen or weak password, an exposed admin interface, or an application holding admin credentials) to the host. It is not usable by an anonymous visitor alone.
- Given URLs, it asks each server for its version. With a URL argument it makes one unauthenticated `GET` of the server's root document. With none it asks only `http://127.0.0.1:5984/` and ignores a refusal.
- It never prints an `[admins]` value. Those are password hashes or passwords. It reports only the bind address, `require_valid_user` and how many admin entries exist.
- It also checks running docker and podman containers, unless you name a directory or set `SCAN_CONTAINERS=0`. A read-only probe inside each running docker and podman container captures `releases/start_erl.data` and the `.ini` files (with every value under `[admins]` redacted inside the container before it is copied) into a private temporary directory. The script then runs once per container, in isolation, against that copy, so one container's configuration never changes another's result. A container run reads only those copied files: it does not ask the host package database or a live server. The copies are removed on exit. A path shown as `.../docker_NAME/...` is inside the container NAME. It is skipped when you name a binary or directory yourself.

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
