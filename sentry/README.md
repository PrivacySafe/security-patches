# @sentry/nextjs: CVE-2026-114139 tunnelRoute middleware bypass

Part of the [PrivacySafe Security Patches](../README.md) collection.

<a name="sentry-nextjs-check"></a>

## Sentry for Next.js check

**Script:** [`sentry/sentry-nextjs-check.sh`](sentry-nextjs-check.sh)

The `tunnelRoute` option of the Sentry SDK for Next.js sends browser events to a path on your own server (for example `/monitoring`), where a rewrite forwards them to Sentry. To stop your middleware rejecting those envelope requests, the SDK makes the **webpack** build skip middleware for them. The skip is **wider than the rewrite**: it covers every path under the tunnel path, while the rewrite serves only the exact tunnel path with valid query parameters. A request in that gap reaches your application and your middleware never runs on it. Skipping middleware grants no privileges by itself.

| | |
|---|---|
| CVE | CVE-2026-114139 (CWE-693, advisory GHSA-mchm-gjx6-7h55, published 21 October 2026) |
| Severity | Critical, CVSS 9.1 (v4.0) |
| Affected | `@sentry/nextjs` 9.36.0 up to 9.47.2, 10.0.0-alpha.0 up to 10.75.2, and 11.0.0-alpha.0 up to 11.0.0-rc.1 |
| Fixed | **9.47.2, 10.75.2 and 11.0.0-rc.1** (all three, and the prerelease tags in between, exist on the npm registry) |
| Vendor workaround | Set `tunnelRoute` to a path no route of yours can resolve under, or remove the option |

**Exploitation needs all four of these at once**, which is why this tool judges configuration and not just the version:

1. `tunnelRoute` is set (a string path, or `true`);
2. the app is built with **webpack** (Turbopack builds are not affected);
3. one of your routes resolves under the tunnel path;
4. your middleware is the **only** authorization control for that route.

## Quick start

1. Download the script. The repository is mirrored on GitHub and Codeberg; pick a base URL.

   ```bash
   # BASE from GitHub:   https://raw.githubusercontent.com/PrivacySafe/security-patches/refs/heads/main
   # BASE from Codeberg: https://codeberg.org/PrivacySafe/security-patches/raw/branch/main
   # curl -fLO "$BASE/sentry/sentry-nextjs-check.sh"
   curl -fLO https://raw.githubusercontent.com/PrivacySafe/security-patches/refs/heads/main/sentry/sentry-nextjs-check.sh
   ```

2. Read it before running it, then make it executable.

   ```bash
   less sentry-nextjs-check.sh
   chmod +x sentry-nextjs-check.sh
   ```

3. Check this host. By default it searches `/var/www /srv /opt /home`; pass directories to narrow it.

   ```bash
   ./sentry-nextjs-check.sh check
   ./sentry-nextjs-check.sh check /srv/myapp
   ```

## Commands

| Command | What it does |
|---|---|
| `check [DIR ...]` (default) | Reads the `@sentry/nextjs` version from `package-lock.json`, `npm-shrinkwrap.json`, `yarn.lock` (v1 and Berry), `pnpm-lock.yaml`, `bun.lock` and an installed `node_modules` copy. For an affected version it reads `next.config.*` for `tunnelRoute`, guesses the bundler, and looks for routes that collide with the tunnel path |
| `version` | Prints the script version |

Exit codes: `0` nothing exposed, `1` an affected version with `tunnelRoute` on a webpack build (with a collision, or a path that cannot be checked), or a configuration that could not be read, `2` bad arguments.

## How each condition is judged

- **Condition 1, `tunnelRoute`:** read from `next.config.js`, `.mjs`, `.cjs`, `.ts` or `.mts` (and `sentry.config.*`). A value in a `//` comment, `false`, or an absent option means it is not set, and the tool exits `0` with a reminder to update anyway.
- **Condition 2, webpack or Turbopack (a heuristic):** a `--turbopack` or `--turbo` flag in the `build` script means Turbopack; `--webpack` means webpack; otherwise Next.js 16 or newer is taken to use Turbopack by default, and older versions webpack. If your build is configured some other way, check it yourself.
- **Condition 3, a colliding route:** a directory or file named after the tunnel path in `app/`, `src/app/`, `pages/` or `src/pages/`, or a root catch-all (`[...slug]` or `[[...slug]]`), which matches every path. `tunnelRoute: true` lets the SDK choose the path, so a collision cannot be checked and the tool treats it as exposed. This heuristic cannot see rewrites, redirects, custom servers or routes defined elsewhere, and says so.
- **Condition 4, middleware as the only authorization:** not visible from outside the application. The tool tells you to review it. Do not rely on middleware alone: check access in the route handler or data layer too.
- **Prereleases:** `11.0.0-alpha.*`, `-beta.*` and `-rc.0` are affected; `-rc.1` and `11.0.0` are fixed.

## Fixing it

Upgrade to 9.47.2, 10.75.2 or 11.0.0-rc.1 or newer and rebuild. Until then, follow the vendor's workaround: set `tunnelRoute` to a path no route of yours can resolve under, or remove it.

## Sources

- [Advisory GHSA-mchm-gjx6-7h55](https://github.com/getsentry/sentry-javascript/security/advisories/GHSA-mchm-gjx6-7h55)
- [GitLab advisory database entry for CVE-2026-114139](https://advisories.gitlab.com/npm/@sentry/nextjs/CVE-2026-114139/)

## Sentry SDK for Next.js know before you run it

- **This is a check, not a fix.** Update `@sentry/nextjs` to 9.47.2, 10.75.2 or 11.0.0-rc.1. The vendor's workaround is to set `tunnelRoute` to a path none of your routes can resolve under, or to remove the option.
- **Exploitation needs all four conditions at once.** `tunnelRoute` is set, the app is built with webpack (Turbopack builds are not affected), one of your routes resolves under the tunnel path, and your middleware is the only authorization control for that route. Skipping middleware grants no privileges by itself.
- **Two of the four conditions are heuristics and one cannot be seen.** The script reads `next.config.*` for `tunnelRoute`, guesses the bundler from the build script and the Next.js version, and looks for routes that collide with the tunnel path; those last two are heuristics. Whether your middleware is the only authorization control for a route cannot be seen from outside the application, so review that yourself.
- **There is no hunt.** No indicators of exploitation have been published.
- **It also reads running containers.** With no directory argument and `SCAN_CONTAINERS=1` (the default), a read-only probe inside each running docker and podman container lists the project files this check needs (lockfiles, `package.json`, route directory names, the few source files that contain `'use server'`, `config/auth.php`, and similar), and only those are copied into a private temporary directory that the normal check then judges like a host directory. Only the *names* of the entries under `app`, `src/app`, `pages` and `src/pages` are copied, as empty files, so no application source leaves the container; `next.config.*` is copied because it holds the `tunnelRoute` setting. A staged symlink is never kept, paths the container reports are validated, and nothing is run in a container beyond `find`, `grep` and `test`. The copies are removed on exit. A path shown as `.../docker_NAME/PATH` is the PATH inside the container NAME. It is skipped when you name directories yourself.

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
