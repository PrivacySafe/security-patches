# openapi-typescript-codegen: CVE-2026-108551 code injection check

Part of the [PrivacySafe Security Patches](../README.md) collection.

<a name="openapi-typescript-codegen-code-injection-check"></a>

## openapi-typescript-codegen code injection check

**Script:** [`openapi/openapi-codegen-check.sh`](openapi-codegen-check.sh)

A crafted OpenAPI document can turn the TypeScript client that `openapi-typescript-codegen` generates into a code execution path. The generator's Handlebars templates copy strings from the document into single-quoted JavaScript literals in the output without escaping them: path keys, parameter names, request media types, response header names, `servers[0].url` and `info.version`. A single quote in one of those values ends the literal, and what follows runs as code.

| | |
|---|---|
| CVE | CVE-2026-108551 (CWE-94, code injection) |
| Severity | 9.8 Critical (CVSS 3.1, `AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H`), 9.3 Critical (CVSS 4.0) |
| Affected | `openapi-typescript-codegen` 0.31.0 and earlier, which is every release |
| Fixed | Nothing. 0.31.0 is the latest release and is affected; the tracking issue, [#2809](https://github.com/ferdikoomen/openapi-typescript-codegen/issues/2809), was still open on 23 October 2026 |
| Reported on | `main` at commit `d7c2a99`, all HTTP clients the generator supports (fetch, axios, xhr, node, angular) |

**When it runs.** A value in `servers[0].url` or `info.version` runs the moment the generated client is imported, because `core/OpenAPI.ts` is always generated and every generated service file imports it. A value in a request path or parameter name runs each time the affected method is called.

**Who is at risk.** Whoever generates or runs a client from a document someone else can influence: a developer running the generator locally, a CI job that regenerates a client from a remote or third-party specification, or an application that fetches a specification and runs a client built from it. This is a supply-chain and developer-tooling problem, not a bug in a server that listens for requests, even though the CVSS vector says network. The same class of bug has been reported and fixed in other OpenAPI generators, so apply the same discipline to them.

**Public exploit.** As of 23 October no exploit was public and the reporter offered a proof of concept on request; a public proof of concept on GitHub has since been reported. It is not linked here, and this tool contains no exploit logic: it reads files and never imports, compiles or runs generated code.

## Quick start

1. Download the script. The repository is mirrored on GitHub and Codeberg; pick a base URL.

   ```bash
   # BASE from GitHub:   https://raw.githubusercontent.com/PrivacySafe/security-patches/refs/heads/main
   # BASE from Codeberg: https://codeberg.org/PrivacySafe/security-patches/raw/branch/main
   # curl -fLO "$BASE/openapi/openapi-codegen-check.sh"
   curl -fLO https://raw.githubusercontent.com/PrivacySafe/security-patches/refs/heads/main/openapi/openapi-codegen-check.sh
   ```

2. Read it before running it, then make it executable.

   ```bash
   less openapi-codegen-check.sh
   chmod +x openapi-codegen-check.sh
   ```

3. See where the package is used. This changes nothing. Point `ROOTS` at your projects if they are not under the defaults.

   ```bash
   ROOTS="/srv /home/ci" ./openapi-codegen-check.sh check
   ```

4. Check what the generator already produced, before anything imports it.

   ```bash
   ./openapi-codegen-check.sh scan ./src/api ./generated
   ```

## Commands

| Command | What it does |
|---|---|
| `check` (default) | Finds `openapi-typescript-codegen` in `package.json`, `package-lock.json`, `npm-shrinkwrap.json`, `yarn.lock` and `pnpm-lock.yaml`, in installed `node_modules` copies, and in the CI workflows, `Makefile`s, shell scripts and `package.json` scripts that run it, and marks a job whose input is a URL. Changes nothing, root optional. Exits `0` if nothing is found, `1` if the package is in use, `2` if something couldn't be judged |
| `scan DIR...` | Reads generated `.ts`, `.js`, `.mjs` and `.cjs` files under each directory and reports a spec-derived value that is not exactly one well-formed single-quoted literal. Exits `0` if nothing is found, `1` if it found something, `2` for a bad argument |
| `version` | Prints the script version. Every command prints it on its first line too |

Environment: `ROOTS` (where `check` looks; default `/home /root /srv /var/www /opt /usr/local`) and `MAX_DEPTH` (how far it descends, default 9).

## What `check` judges

Every published release is affected and none is fixed, so any version at or below 0.31.0 reads as exposed, whether it comes from a lockfile, an installed copy or a version range in `package.json`. A resolved version newer than 0.31.0 reads as unknown, not safe: look at the tracking issue to see whether a fix has shipped. A job that fetches its specification from a URL is marked, because that is the case where a third party's text becomes code in your build.

## What `scan` looks for

The generator writes each spec-derived value inside one single-quoted literal and nothing else on that line. So `scan` accepts only that shape: an opening quote, characters that are not an unescaped quote, a closing quote, and an optional trailing comma. It does not look for a list of dangerous characters. Code after the closing quote, or a bare quote in the middle of the value, does not fit and is reported, while a properly escaped apostrophe in a path or parameter name does not trigger it. It checks the `url`, `BASE`, `VERSION`, `mediaType` and `responseHeader` entries and quoted property keys, on lines laid out the way the generator lays them out.

It reports a breakout in `BASE`, `VERSION`, `url`, a parameter name or `mediaType`, and does not flag keys and paths that contain escaped apostrophes.

## Know before you run it

- **It is a check, not a fix.** There is no fix to apply. Removing the package, or controlling every document it reads, is the remedy.
- **`scan` is a heuristic on one generator's layout.** A clean result is not proof that output is safe, says nothing about code from another tool, and misses a value placed on a line the generator would not have written. Hand-written code is out of scope.
- **`check` reads files, not running systems.** It does not look inside container images or other machines. Remote build services that run the generator are yours to find.
- **GNU/Linux and a POSIX shell.** It needs bash, find and grep, and nothing from Node.js. It never runs `npm`, `node` or any generated file.
- **It also reads running containers.** With no arguments, `ROOTS` unset and `SCAN_CONTAINERS=1` (the default), a read-only probe inside each running docker and podman container copies the `package.json` and lockfiles that mention `openapi-typescript-codegen`, **whole**, and the installed `node_modules` copy's `package.json`, into a private temporary directory, and the script runs once per container in isolation. Workflows, Makefiles and shell scripts are not read inside containers. Setting `ROOTS` yourself skips the containers.

## If you use it

1. **Stop generating from documents you do not control.** Treat an OpenAPI document as source code: review it, pin it by commit or hash, and fetch it only from a trusted, authenticated place.
2. **Move to a maintained generator.** The upstream tracking issue points to `@hey-api/openapi-ts`. Check what it does with the same values before you rely on it.
3. **Until then, contain the job.** Generate in an ephemeral job with no secrets, a read-only token and restricted network access. Review the generated diff, and do not import freshly generated output in a privileged process before that review.
4. **Run `scan` on what you already have**, in particular output generated from a remote or third-party specification.
5. **If a hit is real,** rotate every secret the generating job or developer machine could reach, rebuild from a clean checkout, check published packages built from that output, and look at outbound traffic from the runner.

Sources: the [tracking issue](https://github.com/ferdikoomen/openapi-typescript-codegen/issues/2809), the [VulnCheck advisory](https://www.vulncheck.com/advisories/openapi-typescript-codegen-through-0.31.0-code-injection-via-handlebars-templates) and the [CVE record](https://www.cve.org/CVERecord?id=CVE-2026-108551). The fix status above was current on 23 October 2026; check the issue before relying on it.

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
