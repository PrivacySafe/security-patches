# Next.js: Server Actions denial of service, the August to November 2026 security releases, and sharp

Part of the [PrivacySafe Security Patches](../../README.md) collection.

<a name="nextjs-server-actions-check"></a>

## Next.js Server Actions check

**Script:** [`developer/nextjs/nextjs-server-actions-check.sh`](nextjs-server-actions-check.sh)

Crafted requests aimed at a Next.js App Router application that has at least one Server Action can cause excessive CPU consumption and block the processing of further requests in the same Node.js process. No authentication is needed. The script also reports every install that is missing [the November 2026 security release](#the-november-2026-security-release), which fixes seven more flaws in 15.5.29 and 16.4.5, names the critical flaws from [the August and October releases](#earlier-releases-august-and-october-2026) that a version still carries, and checks [the `sharp` image library](#sharp-the-image-library-nextjs-runs) each project pins, because an upgraded Next.js still runs whatever `sharp` the lockfile holds.

| | |
|---|---|
| CVE | CVE-2026-94482 (GitHub advisory GHSA-p3m5-59mp-jv5r, CWE-770) |
| Severity | High: 7.5 (CVSS 3), 8.2 (CVSS 4.0) |
| Affected | `next` 13.0.0 up to 15.5.28, and 16.0.0 up to 16.4.1 |
| Fixed | 15.5.28 and 16.4.1; the November 2026 release needs 15.5.29 and 16.4.5 |
| Move to | 15.5.29 or 16.4.5 or later: 13.x and 14.x apps upgrade to one of them |
| Not affected | Pages Router applications, and App Router applications with no Server Action |

## Quick start

1. Download the script. The repository is mirrored on GitHub and Codeberg; pick a base URL.

   ```bash
   # BASE from GitHub:   https://raw.githubusercontent.com/PrivacySafe/security-patches/refs/heads/main
   # BASE from Codeberg: https://codeberg.org/PrivacySafe/security-patches/raw/branch/main
   # curl -fLO "$BASE/developer/nextjs/nextjs-server-actions-check.sh"
   curl -fLO https://raw.githubusercontent.com/PrivacySafe/security-patches/refs/heads/main/developer/nextjs/nextjs-server-actions-check.sh
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
| `check [DIR ...]` (default) | Reads the Next.js version from `package-lock.json`, `npm-shrinkwrap.json`, `yarn.lock` (classic and Berry), `pnpm-lock.yaml` and installed `node_modules/next/package.json` copies. For an affected version it checks whether the project has an `app/` or `src/app/` directory and a Server Action (a `'use server'` directive outside `node_modules` and `.next`, or a `.next/server/server-reference-manifest.json` that lists actions) Every version is also judged against the November 2026 release, whether or not the app has a Server Action. A lockfile that pins Netlify's adapter `@netlify/plugin-nextjs` before 5.16.6 is reported too. For 16.x projects it also reports Cache Components, `'use cache'` and a configured cache store, and whether the cache needs purging after the upgrade. It names the critical flaws of the August and October releases a version still carries, and reads every `sharp` version in each project's lockfiles and `node_modules` (regular files only; links are not followed), plus `images.dangerouslyAllowSVG` from the config. |
| `version` | Prints the script version |

Exit codes: `0` nothing exposed, `1` an affected project with Server Actions was found, a version is missing the November 2026 release, a project carries `sharp` before 0.35.5, a version could not be parsed, or a release older than 13.0.0 was found, `2` bad usage.


## Earlier releases: August and October 2026

Every version before the November release also misses earlier fixes. Two of them are critical code execution flaws that need no Server Action, so the script names them for each version that still carries them; the update to 15.5.29 or 16.4.5 covers all of them.

| Flaw | Released | What it is | Versions | Script reports |
|---|---|---|---|---|
| GHSA-673q-mjm6-r5xr (no CVE; React upstream GHSA-xqc2-xf4c-x3h3, CVE-2026-126187) | 14 October, 16.4.1 | Unauthenticated code execution in App Router apps with Cache Components when a `use cache` function returns multiple typed arrays. Critical (9.5 under CVSS 4.0 per Next.js, 10 under CVSS 3.1 at GitLab); Next.js says there is no workaround and to upgrade even without such a function | 16.0.0 to 16.4.0 | `CRIT`, exit `1` |
| CVE-2026-96889 (GHSA-2464-fhr4-w9xw) | 14 October, 15.5.28 and 16.4.1 | Code execution through a crafted SVG in image optimization: the librsvg inside `sharp`, on glibc GNU/Linux. Critical (CVSS 9.5); workaround `sharp` 0.35.5 or later | 10.0.0 to 15.5.27, and 16.0.0 to 16.4.0 | `CRIT`, exit `1` |
| CVE-2026-75604 (GHSA-p293-qw3h-jr36) | 25 August, 15.5.24 and 16.3.3 | Path traversal (CWE-22) to code execution in apps using both the Pages Router and the App Router without Cache Components, only where the server uses a Windows filesystem. Critical (9.0); GNU/Linux and macOS are not affected | 13.4.0 to 15.5.23, and 16.0.0 to 16.3.2 | `info`: this collection runs on GNU/Linux |
| GHSA-2xp9-vwfh-vxw4 (libheif GHSA-g89c-p67h-r497) | 25 August, 15.5.24 and 16.3.3 | Code execution through a crafted AVIF image, in the libheif inside `sharp`. These releases turn AVIF optimization off until the fix reaches `sharp` | before 15.5.24, and 16.x before 16.3.3 | `info`, and the `sharp` check below |

The October release also carries the React Server Components fix for CVE-2026-126187 (`react-server-dom-*` 19.0.9, 19.1.10, 19.2.9 and 19.3.1).

## sharp, the image library Next.js runs

Next.js optimizes images through `sharp`, which bundles libvips, librsvg and libheif. A Next.js upgrade pulls in a fixed `sharp` only when nothing holds the old one: a lockfile left in place, an `overrides` or `resolutions` entry, or a separate `sharp` dependency keeps it. The script reads every `sharp` version in each Next.js project, from `package-lock.json`, `npm-shrinkwrap.json`, `yarn.lock`, `pnpm-lock.yaml` and from `node_modules/**/sharp/package.json`, and reports the records each one carries (exit `1`):

| `sharp` before | CVE | Bundled library | What reaches it |
|---|---|---|---|
| 0.35.5 | CVE-2026-114111 (VulnCheck; GHSA-wq5f-xc86-pv6w) | librsvg, the flaw behind CVE-2026-96889 | Crafted SVG; code execution on glibc GNU/Linux |
| 0.35.4 | CVE-2026-114112 (VulnCheck; GHSA-rgj7-g3m4-5g8c) | libheif 1.23.2 fixes it | Crafted AVIF or HEIF; code execution on glibc GNU/Linux |
| 0.35.0 | CVE-2026-114113 (VulnCheck; GHSA-f88m-g3jw-g9cj) | libvips | Crafted GIF, TIFF or VIPS files |

The `sharp` maintainers rate the libheif and librsvg records High under CVSS 4.0 because `sharp` has no network interface of its own; behind a public image endpoint the input is the attacker's. Next.js leaves SVG out of optimization unless `images.dangerouslyAllowSVG` is `true`, so the script reads that setting and says when it is on.

**Fixing it.** `npm install sharp@0.35.5` (or later), or, when `sharp` comes in only through `next`, an `overrides` (npm), `resolutions` (Yarn) or `pnpm.overrides` entry; then reinstall and redeploy, including container images. Until then the `sharp` advisory's workaround stops AVIF and HEIF decoding: `sharp.block({ operation: ["VipsForeignLoadHeif"] })`. A `sharp` built against a system-wide libvips (`SHARP_IGNORE_GLOBAL_LIBVIPS` unset and a global libvips present) uses the distribution's libraries instead of the bundled ones; then the distribution packages are what need the update, and [the libheif check](../../system/heif/README.md#libheif-heifavif-decoder-check) covers libheif.

## The November 2026 security release

On 3 November 2026 Next.js released 15.5.29 (Maintenance LTS) and 16.4.5 (Active LTS), fixing seven more flaws. The script reports every version before them as missing the release, with the CVEs that apply to that version, and exits `1`. Most of the flaws need a particular feature that the script cannot see from the files it reads, so it does not try to rule them out: the release is the fix.

| CVE | Advisory | What it is | Versions |
|---|---|---|---|
| CVE-2026-119790 | GHSA-mfr8-8qww-v76h | Cached data disclosed across root params (such as a tenant or a locale) when the same `use cache` function is also called through `unstable_cache()`. Rated high by Next.js, medium (6.3) in the GitHub advisory | 16.3.0 to 16.4.4 |
| CVE-2026-119351 | GHSA-vc7v-qv4w-wrv8 | Cached content served across root params through nested `use cache` functions | 16.2.0 to 16.4.4 |
| CVE-2026-119349 | GHSA-rhh4-g77r-r9qj | Distinct binary arguments (`Uint8Array`, `Blob`) to a `use cache` function share one cache entry: cross-user disclosure or poisoning | 16.0.0 to 16.4.4 |
| CVE-2026-119350 | GHSA-vvgp-ww4w-46vf | Shared page shell poisoned by an unauthenticated request, with Cache Components, a particular dynamic route shape and Partial Prefetching off; persistent wrong content or 404 responses. Netlify reports it affects its hosted apps too | 16.4.0 to 16.4.4 |
| CVE-2026-119348 | GHSA-pc58-hwjq-p385 | A self-hosted route that returns a fetched response unchanged can send framing that does not match the body; behind a reverse proxy that queues pipelined requests on a shared backend connection, responses reach the wrong clients | before 15.5.29, and 16.0.0 to 16.4.4 |
| CVE-2026-119346 | GHSA-f3mh-rxg3-f5g2 | App Router Edge Route Handlers and Pages Router Edge API routes that set cookies with `NextResponse.cookies.set()` copy them into the `x-middleware-set-cookie` header, where same-origin JavaScript can read `HttpOnly` values; Node.js routes and `cookies().set()` were not affected | 15.0.0 to 15.5.28, and 16.0.0 to 16.4.4 |
| CVE-2026-119347 | GHSA-7qx7-33qx-rqx2 | An image from a permitted source, misclassified as AVIF, bypasses `images.dangerouslyAllowSVG: false` and reaches the SVG decoder; needs a native image backend that can decode SVG | 15.0.0 to 15.5.28, and 16.0.0 to 16.4.4 |

Next.js 13.x and 14.x receive none of these fixes; CVE-2026-119348 reaches back to 12.x. Apps on those lines move to 15.5.29 or 16.4.5.

**Which of the cache flaws apply.** Four of the seven need Cache Components, and since Next.js 16.4 `create-next-app` turns Cache Components (and Partial Prefetching) on for every new project. For each 16.x project the script reads `next.config.*` and, for a built-only copy, `.next/required-server-files.json`, and says whether Cache Components is on, how many files use the `'use cache'` directive, and whether Partial Prefetching is on (the reported route shape for CVE-2026-119350 needs it off). These lines explain the result; they do not change the exit code, because the release is the fix either way.

**After upgrading, clear the cache.** Entries written before the fix can outlive it, and the advisories note that entries written by the nested-cache flaw can ignore tag invalidation and cache lifetimes. With a self-hosted `next start`, plain `'use cache'` keeps entries in memory, so restarting after the upgrade clears them. A configured `cacheHandler` or `cacheHandlers` store (Redis, files, a remote service) keeps them across restarts: purge it. The script says which of the two applies to each project.

**Apps deployed to Netlify.** On Netlify, CVE-2026-119346 also exposes cookies set in Next.js Middleware, and that case is fixed only in Netlify's adapter, `@netlify/plugin-nextjs` 5.16.6: upgrading Next.js alone does not fix it. Netlify installs the adapter itself unless a project pins it, so the script reads `@netlify/plugin-nextjs` from the same lockfiles and reports a pinned version before 5.16.6 (exit `1`). Netlify also reports that three of the seven (CVE-2026-119347, CVE-2026-119790 and CVE-2026-119348) do not affect apps hosted on its platform, because its image CDN, isolated invocations and own response framing replace the affected code; self-hosted apps are affected. A new deploy clears cached entries only in the same deploy context, so branch deploys and Deploy Previews need their own purge. Vercel's hosted platform is outside this script, which checks the copies of Next.js on this host.

## How to read the result

- Affected version with Server Actions: exposed. Upgrade, rebuild and restart.
- Affected version, no Server Action found: a warning for CVE-2026-94482, whose advisory defines the exposed population as App Router apps with at least one Server Action. The version still misses the November release and carries the October critical flaws, so the script exits `1` regardless. A source search can miss built-only deployments, so the script also reads the build manifest; if you ship only a build output and no sources, confirm by reading that manifest.
- `sharp` before 0.35.5 in a project: `CRIT` with the records it carries, exit `1`, whatever the Next.js version.
- Pre-release and canary versions are compared by their release number, so a canary built before the fix can look fixed.
- Several versions in one project (a monorepo, or a nested dependency) are each reported.
- Packages that merely contain the name (`next-auth`, `next-intl`) are not matched.

## Fixing it

```bash
npm install next@15.5.29        # 15.x apps, and 13.x and 14.x apps moving to 15
npm install next@16.4.5         # 16.x apps, or: npm install next@latest
```

Then check `npm ls sharp` shows 0.35.5 or later (see [sharp](#sharp-the-image-library-nextjs-runs)), rebuild and restart. A running process keeps the old code loaded.

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

Checked on nginx 1.24.0 at a deliberately low rate: requests with a `Next-Action` header got a short burst of 200 responses and then 429, requests without it were never limited, and the limit recovered after a pause. Pick a rate that suits your real traffic. nginx does not limit requests whose key is empty, which is what makes the header-only behavior work.

## Sources

- [GitHub advisory GHSA-p3m5-59mp-jv5r](https://github.com/advisories/GHSA-p3m5-59mp-jv5r)
- [Next.js August 2026 Security Release](https://nextjs.org/blog/august-2026-security-release), 25 August 2026: GHSA-2xp9-vwfh-vxw4 and CVE-2026-75604
- [GitLab advisory for CVE-2026-75604](https://advisories.gitlab.com/pkg/npm/next/CVE-2026-75604/): affected 13.4.0 before 15.5.24 and 16.0.0 before 16.3.3, CVSS 9.0, CWE-22
- [Next.js Security Update for Upstream Vulnerabilities](https://nextjs.org/blog/nextjs-security-update-october-14-2026), 14 October 2026: GHSA-673q-mjm6-r5xr, CVE-2026-96889, CVE-2026-94482
- [GHSA-673q-mjm6-r5xr at OSV](https://osv.dev/vulnerability/GHSA-673q-mjm6-r5xr): introduced 16.0.0, fixed 16.4.1
- [CVE-2026-114111 at cve.org](https://www.cve.org/CVERecord?id=CVE-2026-114111), [CVE-2026-114112 at OSV](https://osv.dev/vulnerability/CVE-2026-114112), [CVE-2026-114113 at OSV](https://osv.dev/vulnerability/CVE-2026-114113), and the `sharp` advisory [GHSA-rgj7-g3m4-5g8c](https://github.com/advisories/GHSA-rgj7-g3m4-5g8c)
- [Next.js November 2026 Security Release](https://nextjs.org/blog/november-2026-security-release), 3 November 2026
- [CVE-2026-119348 at OSV](https://osv.dev/vulnerability/CVE-2026-119348), and the other November advisories linked from the release post
- [Next.js 16.4](https://nextjs.org/blog/next-16-4): Cache Components on by default for new apps
- [Netlify changelog: multiple vulnerabilities in Next.js (November 2026)](https://www.netlify.com/changelog/2026-11-03-nextjs-security-vulnerabilities/), 3 November 2026
- [Tenable plugin 476833 for CVE-2026-94482](https://www.tenable.com/plugins/cloud-security/476833)

## Before you run it

- The fix. Update to 15.5.29 or 16.4.5, which carry both the CVE-2026-94482 fix and the November 2026 release. Next.js 13.x and 14.x apps move to one of them.
- Only some apps are exposed. Pages Router applications, and App Router applications with no Server Action, are not affected. The script reads the version from `package-lock.json`, `npm-shrinkwrap.json`, `yarn.lock`, `pnpm-lock.yaml` and installed `node_modules/next`, then checks for the App Router and for Server Actions (`"use server"`, or a populated `.next/server/server-reference-manifest.json` for built-only deployments).
- There is no hunt. The flaw is a denial of service, and no indicators have been published.
- It also checks running docker and podman containers, unless you name a directory or set `SCAN_CONTAINERS=0`. In each running container, a read-only probe lists the project files this check needs: lockfiles, `package.json`, route directory names, the few source files that contain `'use server'`, `config/auth.php` and similar. Only those files are copied into a private temporary folder, and the normal check judges that folder like a host directory. The App Router and Server Action checks work on the copied lockfile, the build manifest, the existence of `app/` or `src/app/`, and the source files that contain `'use server'`, so a container project is judged by the same rules as a host project. A staged symlink is never kept, paths the container reports are validated, and nothing is run in a container beyond `find`, `grep` and `test`. The copies are removed on exit. A path shown as `.../docker_NAME/PATH` is the PATH inside the container NAME. It is skipped when you name directories yourself.

<!-- rhsa:begin (generated by packaging/rhsa/rhsa.py from Red Hat's advisory list: edit placement.json or the data, not this block) -->
## Red Hat advisories

Red Hat's advisory list (security advisories released 2026-04-01 to 2026-11-25) names the CVEs below. A Red Hat build is judged by its RPM release, not by the upstream version number, because Red Hat backports fixes: the advisory names the release that fixes it. A CVE with no advisory in the list has none for that period, which is not the same as not affected. The current state is on [Red Hat's CVE database](https://access.redhat.com/security/security-updates/#/cve).

The only advisory is for a Trusted Artifact Signer container image that bundles the affected code, not for a Next.js or sharp package; `check` reads the project's own lockfiles.

| Advisory | Released | Severity | Package and stream | CVEs on this page |
|---|---|---|---|---|
| [RHSA-2026:98988](https://access.redhat.com/errata/RHSA-2026:98988) | 2026-11-11 | Important | `rhtas/rekor-backfill-redis-rhel9` (container image); `rhtas/certificate-transparency-rhel9` (container image); `rhtas/trillian-database-rhel9` (container image); and 7 more | CVE-2026-94482, CVE-2026-114112, CVE-2026-114113 |

<!-- rhsa:end -->

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
