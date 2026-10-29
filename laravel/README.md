# Laravel: CVE-2026-114509 TokenGuard authentication bypass

Part of the [PrivacySafe Security Patches](../README.md) collection.

<a name="laravel-tokenguard-check"></a>

## Laravel TokenGuard check

**Script:** [`laravel/laravel-tokenguard-check.sh`](laravel-tokenguard-check.sh)

Laravel's built-in token guard (`'driver' => 'token'`) does not reject a crafted non-string credential. A request such as `{"api_token": [0]}` reaches the database lookup, and on MySQL and MariaDB the lookup can match an unintended existing user. An unauthenticated attacker can then sign in as that user on any route protected by the token guard and take over the account. The reporter, Hristijan Manasijev, described it as a login as an existing victim user.

| | |
|---|---|
| CVE | CVE-2026-114509 (GitHub advisory GHSA-f9x3-7vq9-cph6, published 19 October 2026) |
| Severity | 9.2 Critical (CVSS 4.0) |
| Affected | `laravel/framework` below 12.68.0, and 13.0.0 up to 13.29.0 |
| Fixed | 12.68.0 and 13.29.0, both released 25 August 2026, nearly two months before the advisory. The 11.x branch carries the same `is_string()` check from v11.56.1, although the advisory does not list it |
| No fix | 10.x and 9.x, as reported on 21 October 2026 |
| Needs | A guard that uses the `token` driver, routes that use it, and MySQL or MariaDB |
| Not the target | Apps that authenticate with Laravel Sanctum or Laravel Passport, which register their own guard drivers |
| Exploited | None confirmed, and no public proof of concept confirmed, as of 21 October 2026 |

The fix is two lines: the guard now requires `is_string($token)` before it queries the database.

## Quick start

1. Download the script. The repository is mirrored on GitHub and Codeberg; pick a base URL.

   ```bash
   # BASE from GitHub:   https://raw.githubusercontent.com/PrivacySafe/security-patches/refs/heads/main
   # BASE from Codeberg: https://codeberg.org/PrivacySafe/security-patches/raw/branch/main
   # curl -fLO "$BASE/laravel/laravel-tokenguard-check.sh"
   curl -fLO https://raw.githubusercontent.com/PrivacySafe/security-patches/refs/heads/main/laravel/laravel-tokenguard-check.sh
   ```

2. Read it before running it, then make it executable.

   ```bash
   less laravel-tokenguard-check.sh
   chmod +x laravel-tokenguard-check.sh
   ```

3. Check this host. By default it searches `/var/www /srv /home /opt`; pass directories to narrow it.

   ```bash
   ./laravel-tokenguard-check.sh check
   ./laravel-tokenguard-check.sh check /var/www/myapp
   ```

4. If you cannot upgrade today, print the stopgap middleware.

   ```bash
   ./laravel-tokenguard-check.sh middleware > app/Http/Middleware/RejectNonStringApiToken.php
   ```

## Commands

| Command | What it does |
|---|---|
| `check [DIR ...]` (default) | Finds `composer.lock` files, reads the framework version from `vendor/laravel/framework` when it is installed (it wins over the lock file) and otherwise from `composer.lock`, then reads `config/auth.php` for guards that use the token driver, looks for routes and code that use those guards, and reads `DB_CONNECTION` from `.env` |
| `middleware` | Prints a stopgap PHP middleware to standard output. It changes nothing by itself |
| `version` | Prints the script version |

Exit codes: `0` nothing exposed, `1` an affected project looks exposed or is on a branch with no upstream fix, `2` bad arguments.

## How to read the result

- **Affected version, token guard in use, MySQL or MariaDB:** exposed. Upgrade.
- **Affected version and no token guard:** the vulnerable path is not in use. The script still warns, because custom code could construct a `TokenGuard` directly.
- **Token guard defined but nothing references it:** a warning. This is a text search of `routes`, `app` and `bootstrap`, so a guard selected some other way can be missed.
- **Other database:** the advisory describes the bypass on MySQL and MariaDB. The script prints a warning and still recommends upgrading. A project with an unknown database driver is treated as exposed.
- **9.x and 10.x:** affected with no upstream fix as of 21 October 2026. Check the advisory for a newer position before you rely on this.

Many older skeletons ship an `api` guard with the `token` driver in `config/auth.php` whether or not the app uses it. That is why the script looks for routes that use the guard before calling a project exposed.

## The stopgap middleware

`middleware` prints a class that returns HTTP 401 when `api_token` arrives as an array or any other non-string value in the query string, the form body or a JSON body. Register it as global middleware that runs **before** authentication (`$middleware->prepend(...)` in `bootstrap/app.php` on Laravel 11 and newer, the first entry of `$middleware` in `app/Http/Kernel.php` on older versions). It blocks the crafted input described in the advisory. It is not the fix, and the advisory itself offers no workaround other than upgrading.

## Sources

- [Laravel News: Critical Token Guard Auth Bypass Fixed in Laravel 13.29 and 12.68](https://laravel-news.com/laravel-token-guard-auth-bypass)
- [GitHub advisory GHSA-f9x3-7vq9-cph6](https://github.com/advisories/GHSA-f9x3-7vq9-cph6)

## Laravel know before you run it

- **This is a check, not a fix.** Update `laravel/framework` to 12.68.0, 13.29.0 or, on 11.x, 11.56.1 or later. As of 21 October 2026 the 10.x and 9.x branches were reported to have no fix.
- **It only matters with the built-in token guard.** Apps using Laravel Sanctum or Passport register their own guard drivers and are not the target of this bug. The script reads `composer.lock` and the installed copy, `config/auth.php` for a guard with the token driver, the routes that use it, and the database driver in `.env` (the lookup match needs MySQL or MariaDB).
- **The `middleware` command prints a stopgap to stdout only.** It is for apps that cannot upgrade today, it is the project's, and it is not a substitute for the update.
- **There is no hunt.** No indicators of exploitation have been published.
- **It also reads running containers.** With no directory argument and `SCAN_CONTAINERS=1` (the default), a read-only probe inside each running docker and podman container lists the project files this check needs (lockfiles, `package.json`, route directory names, the few source files that contain `'use server'`, `config/auth.php`, and similar), and only those are copied into a private temporary directory that the normal check then judges like a host directory. `.env` is **never** copied: the probe reads only the one `DB_CONNECTION=` line and writes just that line into a minimal `.env`, so a database password or `APP_KEY` stays in the container. A staged symlink is never kept, paths the container reports are validated, and nothing is run in a container beyond `find`, `grep` and `test`. The copies are removed on exit. A path shown as `.../docker_NAME/PATH` is the PATH inside the container NAME. It is skipped when you name directories yourself.

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
