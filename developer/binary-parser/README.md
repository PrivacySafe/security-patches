# binary-parser: CVE-2026-134814 and CVE-2026-1245 code injection check

Part of the [PrivacySafe Security Patches](../../README.md) collection.

<a name="binary-parser-code-injection-check"></a>

## binary-parser code injection check

**Script:** [`developer/binary-parser/binary-parser-check.sh`](binary-parser-check.sh)

`binary-parser` is an npm library that turns a parser definition into JavaScript and compiles it with the `Function` constructor. Values from the definition were pasted into that generated code without validation. Whoever controls a parser definition can therefore run JavaScript in the Node.js process, with its privileges, the moment the parser is compiled.

The fix is `binary-parser` 2.3.1; the maintainer's advisory was published on 11 November 2026. It is the second fix for the same class of bug: 2.3.0 (released in November 2025, disclosed in January 2026 as CVE-2026-1245) closed field names and encodings, and other options were still open. This tool finds every copy, including nested, bundled and distribution-packaged ones, and points at the source lines where a definition could come from outside.

| | CVE-2026-134814 | CVE-2026-1245 ("ParserPoison") |
|---|---|---|
| What reaches the generated code | The `length` option of `string`, `buffer`, `array`, `wrapped` and `seek`; `lengthInBytes` and `key` of `array`; `tag` of `choice`; `offset` of `pointer`; the alias passed to `namely()` | Field names and the `encoding` parameter |
| Severity | 9.2 Critical (CVSS 4.0, VulnCheck, `AV:N/AC:H/AT:P/PR:N/UI:N/VC:H/VI:H/VA:H`), CWE-94 | 6.5 Medium |
| Affected | Every release before 2.3.1 | Every release before 2.3.0 |
| Fixed | 2.3.1 ([GHSA-xmxc-6c22-m377](https://github.com/keichi/binary-parser/security/advisories/GHSA-xmxc-6c22-m377), 11 November 2026; NVD published 22 November) | 2.3.0 ([GHSA-m39p-34qh-rh3w](https://github.com/advisories/GHSA-m39p-34qh-rh3w), CERT/CC [VU#102648](https://kb.cert.org/vuls/id/102648)) |
| Exploited | None publicly reported as of 23 November 2026 | None publicly reported as of 23 November 2026 |

**Who is at risk.** An application that builds a parser definition from data it does not fully control: a schema loaded from a file or database, a definition sent by a client, a plugin or device profile, a format description in JSON. Parsing untrusted *binary data* with a definition written in the source is not affected. The CVSS vector marks attack complexity high for that reason: the attacker needs a say in the definition.

**Why older systems need a look.** Every 1.x and 2.x release before 2.3.1 is affected, and old projects often pin an exact version or a `~` range that can never reach the fix. A bundler can also carry the parser compiler inside another file with no `package.json` to show its version. The check reads the code itself for that: 2.3.0 added fixed error strings (`Invalid field name:`, `Invalid encoding:`) and 2.3.1 added `Invalid reference:`. A copy whose code carries the 2.3.1 checks reads as fixed whatever its version says, so a copy you patched in place is credited, and one whose `package.json` was edited without the code is not.

## Quick start

1. Download the script. The repository is mirrored on GitHub and Codeberg; pick a base URL.

   ```bash
   # BASE from GitHub:   https://raw.githubusercontent.com/PrivacySafe/security-patches/refs/heads/main
   # BASE from Codeberg: https://codeberg.org/PrivacySafe/security-patches/raw/branch/main
   # curl -fLO "$BASE/developer/binary-parser/binary-parser-check.sh"
   curl -fLO https://raw.githubusercontent.com/PrivacySafe/security-patches/refs/heads/main/developer/binary-parser/binary-parser-check.sh
   ```

2. Read it before running it, then make it executable.

   ```bash
   less binary-parser-check.sh
   chmod +x binary-parser-check.sh
   ```

3. Find every copy. This changes nothing. Run it with `sudo` to read every user's projects and the running containers; point `ROOTS` at your projects if they are not under the defaults.

   ```bash
   sudo ./binary-parser-check.sh check
   ROOTS="/srv/app /home/ci" ./binary-parser-check.sh check
   ```

4. See where your own code builds definitions from variables.

   ```bash
   ./binary-parser-check.sh audit ./src
   ```

## Commands

| Command | What it does |
|---|---|
| `check` (default) | Finds `binary-parser` in `package.json`, `package-lock.json`, `npm-shrinkwrap.json`, `yarn.lock` and `pnpm-lock.yaml`; in installed copies, including nested `node_modules` and the Debian and Ubuntu `node-binary-parser` package under `/usr/share/nodejs`; and in bundled `.js`, `.mjs` and `.cjs` files that carry its parser compiler. Judges each by its version and by the checks its code carries. Changes nothing, root optional. Exits `0` if no affected copy is found, `1` if a copy is affected or can't be confirmed as 2.3.1 or newer, `2` for bad arguments |
| `audit DIR...` | Reads the `.js`, `.mjs`, `.cjs`, `.ts`, `.mts` and `.cts` files under each directory that import `binary-parser`, skipping `node_modules` and `.git`, and lists the lines that take a field name, an `encoding`, a `length`, `lengthInBytes`, `key`, `tag` or `offset`, or a `namely()` alias from a variable or a template instead of writing it in the source. Marks a file that also reads JSON, files or request data. Never runs anything. Exits `0` if nothing is found, `1` if there are lines to review, `2` for a bad argument |
| `version` | Prints the script version. Every command prints it on its first line too |

Environment: `ROOTS` (where `check` looks; default `/home /root /srv /var/www /opt /usr/local /usr/lib/node_modules /usr/share/nodejs /usr/lib/nodejs`), `MAX_DEPTH` (how far it descends, default 9), `BUNDLES` (`0` skips the bundle search, the slowest step) and `SCAN_CONTAINERS` (`0` skips running docker and podman containers).

## What `check` judges

- A resolved version in a lockfile or an installed copy: before 2.3.0 is affected by both CVEs, 2.3.0 by CVE-2026-134814, 2.3.1 and later are fixed. A pre-release of 2.3.1 or a version it can't read is not confirmed fixed and counts as affected.
- A version range in `package.json` says what may be installed, not what is. An exact pin is judged. A range that can never reach 2.3.1 (`~2.2.0`, `1.x`, `^1.4.0`) is reported so the next install does not quietly keep an affected copy. Any other range is left to the lockfile and the installed copy.
- An installed or bundled copy is also judged by its code, as described above.

## What `audit` looks for

A value written in the source as a quoted string, a number or a function is fixed when the code is written. A value read from a variable, an object property or a template with `${...}` may come from outside, and those are the lines it lists. It is a pointer for a reviewer, not a verdict: a variable that holds a constant is harmless, and a definition assembled some other way (a helper that builds parsers in a loop, options passed as one object) is not followed. Read those by hand.

## Before you run it

- The fix is the upgrade. There is no setting that closes this on an affected copy. Until you upgrade, the only defense is to build no parser definition from data anyone else controls.
- It reads files. It never runs `npm`, `node` or the code it finds, and it needs only bash, find, grep, awk and sort.
- It also checks running docker and podman containers, unless you set `ROOTS` or `SCAN_CONTAINERS=0`. A read-only probe copies the `package.json` and lockfiles that mention `binary-parser`, **whole**, and each installed copy's `package.json`, into a private temporary directory, and the script runs once per container in isolation. Bundled copies are not searched inside containers, and the code of an installed copy is not copied out, so a container's copy is judged by its version alone.
- Without root it sees only what this account can read, and says so.

## If you use it

1. Upgrade: `npm install binary-parser@^2.3.1` (or `yarn up binary-parser`, `pnpm update binary-parser`), commit the lockfile, rebuild every bundle that includes it, and redeploy. Rerun `check` until nothing is reported.
2. If a dependency of yours pins an older copy, add an override (`overrides` in npm, `resolutions` in yarn, `pnpm.overrides` in pnpm) to force 2.3.1, test, and ask that project to update.
3. If you cannot upgrade a deployed system yet, stop building parser definitions from outside data there, and accept only definitions from a fixed list you wrote. 2.3.1 itself now rejects expressions such as `"len - 1"` in these options: use a function instead.
4. Where `audit` lists lines, trace each value back. If any part came from a user, a file, a database or the network on an affected version, treat the process as compromised: rotate the secrets it could read and look for files and connections it should not have.

Sources: the [GitHub advisory GHSA-xmxc-6c22-m377](https://github.com/keichi/binary-parser/security/advisories/GHSA-xmxc-6c22-m377), the [NVD record for CVE-2026-134814](https://nvd.nist.gov/vuln/detail/CVE-2026-134814), the [VulnCheck advisory](https://www.vulncheck.com/advisories/binary-parser-before-2.3.1-code-injection-via-string-typed-parser-options), the [CERT/CC note VU#102648](https://kb.cert.org/vuls/id/102648) and [Alma Security's ParserPoison write-up](https://alma.security/blog/parserpoison-from-schema-to-shell-in-binary-parser) for CVE-2026-1245. Version and fix status were current on 23 November 2026.

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
