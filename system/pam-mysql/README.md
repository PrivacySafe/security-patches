# pam-mysql: CVE-2026-124749, accounts with no password let in

Part of the [PrivacySafe Security Patches](../../README.md) collection.

<a name="pam-mysql"></a>

## pam-mysql inverted empty-password check

**Script:** [`system/pam-mysql/pam-mysql-check.sh`](pam-mysql-check.sh)

pam-mysql checks Linux logins against a MySQL or MariaDB table. When a service asks PAM to refuse accounts with no password, which sshd does with its default `PermitEmptyPasswords no`, pam-mysql does the opposite: anyone can log in over SSH, typing any password, as an account whose stored password is NULL (0.8.x) or NULL or empty (the 1.0.0 betas, so the common `NOT NULL DEFAULT ''` column is exposed; PostfixAdmin and Froxlor ship tables like that).

| | |
|---|---|
| CVE | CVE-2026-124749 |
| Severity | 8.1 to 9.8, depending on the setup |
| Affected | Every release (0.8.x and the 1.0.0 betas) when the module is in a login service's PAM stack and a row has no password |
| Fixed | Debian 12 `0.8.2-2+deb12u1` (DLA-4919-1) and Debian 13 `0.8.2-2.1+deb13u1` (DSA-6643-1), 19 November 2026, adding a `nullok` option that is off by default. Not fixed on 21 November: Debian testing and unstable, Ubuntu, Fedora (`pam_mysql`), Gentoo |
| Exploited | No; demonstrated by the researcher, exploit not published |

**Do not set `PermitEmptyPasswords yes` as a fix.** The researcher says that opens a different hole.

## Quick start

1. Download the script. The repository is mirrored on GitHub and Codeberg; pick a base URL.

   ```bash
   # BASE from GitHub:   https://raw.githubusercontent.com/PrivacySafe/security-patches/refs/heads/main
   # BASE from Codeberg: https://codeberg.org/PrivacySafe/security-patches/raw/branch/main
   curl -fLO https://raw.githubusercontent.com/PrivacySafe/security-patches/refs/heads/main/system/pam-mysql/pam-mysql-check.sh
   ```

2. Read it before running it, then make it executable.

   ```bash
   less pam-mysql-check.sh
   chmod +x pam-mysql-check.sh
   ```

3. Check. As root it can read sshd's effective settings and pam-mysql's configuration; `QUERY_DB=1` also counts the rows with no password, with pam-mysql's own read credentials.

   ```bash
   sudo ./pam-mysql-check.sh check
   sudo QUERY_DB=1 ./pam-mysql-check.sh check
   ```

4. Look for past logins by accounts with no stored password.

   ```bash
   sudo QUERY_DB=1 ./pam-mysql-check.sh hunt
   ```

## Commands

| Command | What it does |
|---|---|
| `check` (default) | The PAM services that load `pam_mysql.so`, sshd's `PermitEmptyPasswords` (from `sshd -T` as root), the installed package against Debian's fixed versions, and the table and columns pam-mysql checks (from its PAM arguments or `config_file`). With `QUERY_DB=1`: how many rows have a NULL or empty password (`LIST_USERS=1` lists them). Read-only. Exits `0` if pam-mysql is not in use or is fixed, `1` if it is in use and not fixed, `2` if something could not be read |
| `hunt` | "Accepted password" logins from the auth log and the journal. With `QUERY_DB=1`, a login by an account that has no stored password now is marked as a bypass. Read-only. Exits `0` if nothing is found, `1` for leads, `2` if no log could be read |
| `version` | Prints the script version |

## Until a fixed package exists

Give every row in the login table a password or lock it, then make the password column `NOT NULL` with no empty-string default, so a new row cannot reopen it. With your table and column names:

```sql
SELECT username FROM users WHERE password IS NULL OR password = '';
ALTER TABLE users MODIFY password VARCHAR(255) NOT NULL;   -- after every row has a value
```

A bypass looks like any other password login in sshd's log ("Accepted password for"). The table as it is now may not show what it held at the time; a backup or the binary log does.

## Before you run it

- `QUERY_DB=1` reads pam-mysql's database credentials from its PAM line or `config_file` and passes the password to the client through the environment, not the command line. It runs one `SELECT`; it changes nothing.

Sources: [Debian DSA-6643-1](https://lists.debian.org/debian-security-announce/2026/msg00565.html), [Debian DLA-4919-1](https://lists.debian.org/debian-lts-announce/2026/11/msg00045.html) and the [oss-security report](https://www.openwall.com/lists/oss-security/2026/11/19/7). Status current on 23 November 2026.

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
