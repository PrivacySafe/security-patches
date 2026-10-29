# Next.js: CVE-2026-94482 Server Actions denial of service

Part of the [PrivacySafe Security Patches](../README.md) collection.

<a name="nextjs-server-actions-check"></a>

## Next.js Server Actions check

**Script:** [`nextjs/nextjs-server-actions-check.sh`](nextjs-server-actions-check.sh)

Crafted requests aimed at a Next.js App Router application that has at least one Server Action can cause excessive CPU consumption and block the processing of further requests in the same Node.js process. No authentication is needed.

| | |
|---|---|
| CVE | CVE-2026-94482 (GitHub advisory GHSA-p3m5-59mp-jv5r, CWE-770) |
| Severity | High: 7.5 (CVSS 3), 8.2 (CVSS 4.0) |
| Affected | `next` 13.0.0 up to 15.5.28, and 16.0.0 up to 16.4.1 |
| Fixed | 15.5.28 and 16.4.1 |
| No patched release on its own branch | 13.x and 14.x. Those apps have to move to 15.5.28 or later |
| Not affected | Pages Router applications, and App Router applications with no Server Action |

## Quick start

1. Download the script. The repository is mirrored on GitHub and Codeberg; pick a base URL.

   ```bash
   # BASE from GitHub:   https://raw.githubusercontent.com/PrivacySafe/security-patches/refs/heads/main
   # BASE from Codeberg: https://codeberg.org/PrivacySafe/security-patches/raw/branch/main
   # curl -fLO "$BASE/nextjs/nextjs-server-actions-check.sh"
   curl -fLO https://raw.githubusercontent.com/PrivacySafe/security-patches/refs/heads/main/nextjs/nextjs-server-actions-check.sh
   ```

2. Read it before running it, then make it executable.

   ```bash
   less nextjs-server-actions-check.sh
   chmod +x nextjs-server-actions-check.sh
   ```

3. Check this host. By default it searches `/var/www /srv /opt /home`; pass directories to narrow it.

   ```bash
   ./nextjs-server-actions-check.sh check
   ./nextjs-server-actions-check.sh check /srv/web/storefront
   ```

## Commands

| Command | What it does |
|---|---|
| `check [DIR ...]` (default) | Reads the Next.js version from `package-lock.json`, `npm-shrinkwrap.json`, `yarn.lock` (classic and Berry), `pnpm-lock.yaml` and installed `node_modules/next/package.json` copies. For an affected version it checks whether the project has an `app/` or `src/app/` directory and a Server Action (a `'use server'` directive outside `node_modules` and `.next`, or a `.next/server/server-reference-manifest.json` that lists actions) |
| `version` | Prints the script version |

Exit codes: `0` nothing exposed, `1` an affected project with Server Actions was found, `2` bad arguments.

## How to read the result

- **Affected version with Server Actions:** exposed. Upgrade, rebuild and restart.
- **Affected version, no Server Action found:** a warning and exit `0`. The advisory defines the exposed population as App Router apps with at least one Server Action, so this project is outside it. A source search can miss built-only deployments, so the script also reads the build manifest; if you ship only a build output and no sources, confirm by reading that manifest.
- **Pre-release and canary versions** are compared by their release number, so a canary built before the fix can look fixed.
- **Several versions in one project** (a monorepo, or a nested dependency) are each reported.
- **Packages that merely contain the name** (`next-auth`, `next-intl`) are not matched.

## Fixing it

```bash
npm install next@15.5.28        # 15.x apps
npm install next@16.4.1         # 16.x apps, or: npm install next@latest
```

Then rebuild and restart. A running process keeps the old code loaded.

## Throttling at the proxy while you upgrade

This slows abuse and does not fix the bug. Server Action calls carry a `Next-Action` header, so a reverse proxy can rate limit only those requests and leave ordinary page and asset traffic alone. Whether crafted requests always carry that header is not stated in the advisory, so treat this as a speed bump. For nginx:

```nginx
# in the http block
map $http_next_action $next_action_key {
    default "";
    "~."    $binary_remote_addr;     # only requests that carry a Next-Action header
}
limit_req_zone $next_action_key zone=next_actions:10m rate=10r/s;
limit_req_status 429;

# in the server or location that proxies to Next.js
limit_req zone=next_actions burst=20 nodelay;
```

We checked this on nginx 1.24.0 at a deliberately low rate: requests with a `Next-Action` header got a short burst of 200 responses and then 429, requests without it were never limited, and the limit recovered after a pause. Pick a rate that suits your real traffic. nginx does not limit requests whose key is empty, which is what makes the header-only behaviour work.

## Sources

- [GitHub advisory GHSA-p3m5-59mp-jv5r](https://github.com/advisories/GHSA-p3m5-59mp-jv5r)
- [Tenable plugin 476833 for CVE-2026-94482](https://www.tenable.com/plugins/cloud-security/476833)

## Next.js know before you run it

- **This is a check, not a fix.** Update to 15.5.28 or 16.4.1. Next.js 13.x and 14.x have no patched release on their own branch, so those apps move to 15.5.28 or later.
- **Only some apps are exposed.** Pages Router applications, and App Router applications with no Server Action, are not affected. The script reads the version from `package-lock.json`, `npm-shrinkwrap.json`, `yarn.lock`, `pnpm-lock.yaml` and installed `node_modules/next`, then checks for the App Router and for Server Actions (`"use server"`, or a populated `.next/server/server-reference-manifest.json` for built-only deployments).
- **There is no hunt.** The flaw is a denial of service, and no indicators have been published.
- **It also reads running containers.** With no directory argument and `SCAN_CONTAINERS=1` (the default), a read-only probe inside each running docker and podman container lists the project files this check needs (lockfiles, `package.json`, route directory names, the few source files that contain `'use server'`, `config/auth.php`, and similar), and only those are copied into a private temporary directory that the normal check then judges like a host directory. The App Router and Server Action checks work on the copied lockfile, the build manifest, the existence of `app/` or `src/app/`, and the source files that contain `'use server'`, so a container project is judged by the same rules as a host project. A staged symlink is never kept, paths the container reports are validated, and nothing is run in a container beyond `find`, `grep` and `test`. The copies are removed on exit. A path shown as `.../docker_NAME/PATH` is the PATH inside the container NAME. It is skipped when you name directories yourself.

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
