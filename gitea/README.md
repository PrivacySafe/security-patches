# Gitea: CVE-2026-109553 SSH certificate principal impersonation

Part of the [PrivacySafe Security Patches](../README.md) collection.

<a name="gitea-check"></a>

## Gitea check

**Script:** [`gitea/gitea-check.sh`](gitea-check.sh)

Gitea resolved the principals of an SSH certificate by searching the content of **all** stored public keys instead of only the keys registered as principals. So a certificate that lists another user's public-key line as a principal authenticated as that user, through both the HTTP signature API and the built-in SSH server.

| | |
|---|---|
| CVE | CVE-2026-109553 (CWE-287, advisory GHSA-vcp6-2qc6-gvq3, published 18 October 2026) |
| Severity | High, CVSS 7.5 |
| Affected | Gitea up to and including 28.1.0 (the advisory confirmed it on 1.27.3) |
| Fixed | **28.2.0** (released 18 October 2026) |
| Only if | The instance **trusts a user certificate authority**: `SSH_TRUSTED_USER_CA_KEYS` is set in `[server]` of `app.ini`. The advisory says instances that do not trust a user CA are not affected |
| Worst case | `SSH_AUTHORIZED_PRINCIPALS_ALLOW=anything`, documented as performing no check on principal text: an ordinary user can register another person's public-key line as their own principal and authenticate as them |
| Otherwise | A holder of a certificate signed by your CA can list a victim's key line as a principal |
| Same release | 28.2.0 fixes eight other flaws that only the update fixes |

Forgejo is a separate project. This tool reads Gitea's version output and does not judge Forgejo.

## Quick start

1. Download the script. The repository is mirrored on GitHub and Codeberg; pick a base URL.

   ```bash
   # BASE from GitHub:   https://raw.githubusercontent.com/PrivacySafe/security-patches/refs/heads/main
   # BASE from Codeberg: https://codeberg.org/PrivacySafe/security-patches/raw/branch/main
   # curl -fLO "$BASE/gitea/gitea-check.sh"
   curl -fLO https://raw.githubusercontent.com/PrivacySafe/security-patches/refs/heads/main/gitea/gitea-check.sh
   ```

2. Read it before running it, then make it executable.

   ```bash
   less gitea-check.sh
   chmod +x gitea-check.sh
   ```

3. Check this host. It finds `gitea` on `PATH`, in the usual locations and from running processes, and reads the `app.ini` the process was started with. Run it as a user who can read `app.ini` (often the `git` user or root). To point it at a specific file, set `GITEA_INI`.

   ```bash
   ./gitea-check.sh check
   GITEA_INI=/etc/gitea/app.ini ./gitea-check.sh check
   ```

   A running container is checked from the host (see the container note below); for an image that is not running, check its tag yourself.

## Commands

| Command | What it does |
|---|---|
| `check [BINARY ...]` (default) | Reads the version from `gitea --version`, applies the rule, then reads `[server]` in `app.ini` for `SSH_TRUSTED_USER_CA_KEYS` and `SSH_AUTHORIZED_PRINCIPALS_ALLOW` (section and key names are matched case-insensitively; commented lines and keys in other sections are ignored) |
| `version` | Prints the script version |

Environment: `GITEA_INI` (space separated files) replaces `app.ini` discovery.

Exit codes: `0` nothing exposed, `1` an affected version that trusts a user CA, or whose configuration could not be read, `2` bad arguments.

## Credentials are never printed

`SSH_TRUSTED_USER_CA_KEYS` holds public keys, which are not secret, but the script still **never prints it** and says only that a CA is set.

## How to read the result

- **Affected version, CA trusted, principals `anything`:** the worst case. Upgrade.
- **Affected version, CA trusted, other principal policy:** still exposed to a holder of a CA-signed certificate. Upgrade.
- **Affected version, no CA trusted:** per the advisory the flaw does not apply, so the script exits `0`, but it still tells you to update because the same release fixes eight other flaws and a CA may be added later.
- **`app.ini` unreadable:** the script cannot tell whether a CA is trusted, so it treats the instance as exposed.
- **Version numbers:** Gitea moved from 1.x to 28.x, so `1.27.3` is older than `28.2.0` and is affected. The comparison is numeric, so `28.10.0` is newer than `28.2.0`.

## Fixing it

Upgrade to Gitea 28.2.0 or later and restart. If you do not need certificate login, emptying `SSH_TRUSTED_USER_CA_KEYS` takes the instance out of the affected configuration; that is our reasoning rather than the vendor's. Afterwards, review recent SSH and API signature logins.

## Sources

- [Gitea 28.2.0 release announcement](https://blog.gitea.com/release-of-28.2.0/)
- [Gitea advisory GHSA-vcp6-2qc6-gvq3](https://github.com/go-gitea/gitea/security/advisories/GHSA-vcp6-2qc6-gvq3)

## Gitea know before you run it

- **This is a check, not a fix.** Update to 28.2.0. The same release fixes eight other flaws that only the update fixes.
- **It only applies to instances that trust a user certificate authority.** That means `SSH_TRUSTED_USER_CA_KEYS` is set in `app.ini`, together with a principals policy that lets someone list another user's key line. An instance that does not trust a user CA is not affected.
- **Forgejo is a separate project.** The script reads Gitea's `--version` output and does not judge Forgejo.
- **It never prints your CA keys.** From `app.ini` it reports whether a user CA is trusted and the principal policy word, and nothing else.
- **It also reads running containers.** With no argument and `SCAN_CONTAINERS=1` (the default), a read-only probe inside each running docker and podman container captures the output of `gitea --version` and a reduced `app.ini` containing only the two `[server]` settings this check reads (`SSH_AUTHORIZED_PRINCIPALS_ALLOW`, and whether `SSH_TRUSTED_USER_CA_KEYS` is set, as a bare `x`) into a private temporary directory, and this script then runs once per container, in isolation, against that copy, so one container's configuration never changes another's result. The CA key, the database password and every other `app.ini` value stay in the container. The copies are removed on exit. A path shown as `.../docker_NAME/...` is inside the container NAME. It is skipped when you name a binary or directory yourself.

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
