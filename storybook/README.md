# Storybook: CVE-2026-114126 dev server code injection from the local network

Part of the [PrivacySafe Security Patches](../README.md) collection.

<a name="storybook-check"></a>

## Storybook check

**Script:** [`storybook/storybook-check.sh`](storybook-check.sh)

The Storybook dev server exposes its WebSocket authentication token to any client that can load its HTML pages. Any host on the same network can open the Storybook by IP address, obtain the token, and call the WebSocket-backed file-writing and testing features. Weak validation of the "write story" feature lets that code land in story files. If the Storybook **Vitest addon** is installed with an old version of Vitest, the payload can use Vitest's API to write more files or run commands, which can end in code execution with the developer's privileges.

| | |
|---|---|
| CVE | CVE-2026-114126 (advisory GHSA-px85-f4q5-jh77, published 21 October 2026) |
| Severity | High, CVSS 8.7 |
| Affected | `storybook` 8.0.0 up to 8.6.19, 9.0.0 up to 9.1.21, 10.0.0 up to 10.6.2, and 11.0.0-alpha.0 up to 11.0.0-alpha.6 |
| Fixed | **8.6.19, 9.1.21, 10.6.2 and 11.0.0-alpha.6** (all exist on the npm registry). The fixed releases also bind the dev server to `127.0.0.1` by default |
| No upgrade possible | The vendor's advice: do not run an affected dev server |
| Needs | A running dev server reachable from your network. **Affected versions listen on all interfaces by default**, so merely running `storybook dev` on a shared network is the exposure. A built, static Storybook has no dev server and is not reachable this way |
| Also | A second Storybook advisory (a malicious website interacting with the preview of a running dev server) is fixed by the same releases. It is not counted separately here |

## Quick start

1. Download the script. The repository is mirrored on GitHub and Codeberg; pick a base URL.

   ```bash
   # BASE from GitHub:   https://raw.githubusercontent.com/PrivacySafe/security-patches/refs/heads/main
   # BASE from Codeberg: https://codeberg.org/PrivacySafe/security-patches/raw/branch/main
   # curl -fLO "$BASE/storybook/storybook-check.sh"
   curl -fLO https://raw.githubusercontent.com/PrivacySafe/security-patches/refs/heads/main/storybook/storybook-check.sh
   ```

2. Read it before running it, then make it executable.

   ```bash
   less storybook-check.sh
   chmod +x storybook-check.sh
   ```

3. Check this machine. By default it searches `/var/www /srv /opt /home`; pass directories to narrow it. Run it while your dev server is running if you want it to see the listening address.

   ```bash
   ./storybook-check.sh check
   ./storybook-check.sh check ~/projects/ui
   ```

## Commands

| Command | What it does |
|---|---|
| `check [DIR ...]` (default) | Reads the `storybook` version from `package-lock.json`, `npm-shrinkwrap.json`, `yarn.lock` (v1 and Berry), `pnpm-lock.yaml`, `bun.lock` and an installed `node_modules` copy; notes the Vitest addon and any `--host` in the dev script; and checks whether a Storybook dev server is running right now and on which address (default port 6006, or the `-p` of the running process) |
| `version` | Prints the script version |

Exit codes: `0` nothing exposed, `1` an affected version while a dev server is listening beyond loopback or is started with a non-loopback `--host`, `2` bad arguments.

## How to read the result

- **Affected version and a dev server listening beyond loopback right now:** exposed. Stop it, upgrade, and treat any story file you did not write as suspect (this flaw writes code into story files; review recent changes in version control).
- **Affected version, no dev server running:** exit `0` with a warning to update before the next run, because the next `storybook dev` will listen on all interfaces.
- **A script with `--host 0.0.0.0` or another non-loopback address:** exposed by configuration. `--host 127.0.0.1` or `localhost` is not flagged.
- **Fixed version:** fine even while a dev server listens on `0.0.0.0`; the check is on the version, not on the socket.
- **Storybook 7.x and earlier** are outside the advisory's range but unsupported: update anyway.
- **Look-alikes** (`eslint-plugin-storybook`, `@storybook/*`) are different packages and are not matched, in all four lock formats.
- **Prereleases:** `11.0.0-alpha.0` to `alpha.5` are affected; `alpha.6` and later are fixed.

## Fixing it

Upgrade to 8.6.19, 9.1.21, 10.6.2 or 11.0.0-alpha.6 or newer. If you cannot, do not run an affected dev server, or run it only on a network you fully trust.

## Sources

- [Advisory GHSA-px85-f4q5-jh77](https://github.com/storybookjs/storybook/security/advisories/GHSA-px85-f4q5-jh77)
- [GitLab advisory database entry for CVE-2026-114126](https://advisories.gitlab.com/npm/storybook/CVE-2026-114126/)

## Storybook know before you run it

- **This is a check, not a fix.** Update to 8.6.19, 9.1.21, 10.6.2 or 11.0.0-alpha.6. The fixed releases also bind the dev server to `127.0.0.1` by default. If you cannot upgrade, do not run an affected dev server (the vendor's advice).
- **Running `storybook dev` is the exposure.** Affected versions listen on all network interfaces, so a host on the same network can obtain the WebSocket token. A Storybook built and served as static files has no dev server and is not reachable this way.
- **Code execution depends on the Vitest addon.** With the Storybook Vitest addon and an old Vitest, the payload can write more files or run commands as the developer.
- **There is no hunt.** No indicators of exploitation have been published.
- **It also reads running containers.** With no directory argument and `SCAN_CONTAINERS=1` (the default), a read-only probe inside each running docker and podman container lists the project files this check needs (lockfiles, `package.json`, route directory names, the few source files that contain `'use server'`, `config/auth.php`, and similar), and only those are copied into a private temporary directory that the normal check then judges like a host directory. The version comes from the copied lockfile or the installed `node_modules/storybook/package.json`, and the `package.json` scripts are read for an explicit non-loopback `--host`. A dev server that is listening *right now* is probed on the host only. A staged symlink is never kept, paths the container reports are validated, and nothing is run in a container beyond `find`, `grep` and `test`. The copies are removed on exit. A path shown as `.../docker_NAME/PATH` is the PATH inside the container NAME. It is skipped when you name directories yourself.

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
