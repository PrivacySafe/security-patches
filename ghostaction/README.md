# GhostAction: stage-2 stealer on developer machines

Part of the [PrivacySafe Security Patches](../README.md) collection.

<a name="ghostaction-developer-machine-stealer"></a>

## GhostAction Developer-Machine Stealer

**Script:** [`ghostaction/ghostaction-oct2026-check.sh`](ghostaction-oct2026-check.sh)

The GhostAction campaign, which injects credential-stealing GitHub Actions workflows into compromised repositories, added a second stage in October 2026 that persists on a developer's own machine. Across 94 repositories it committed a VS Code `.vscode/tasks.json` with `"runOn": "folderOpen"` and hidden output (seen labelled `eslint-check`), which runs automatically when the folder is opened in VS Code and executes a file named `public/fonts/fa-solid-400.woff2`. That file is named like a normal Font Awesome asset but is not a font: it is a Node.js credential stealer that harvests AWS keys, npm and PyPI tokens, Git logins, Kubernetes credentials, SSH private keys and Anthropic Claude and Google Gemini keys, installs a cron job that runs attacker code every five minutes, and exfiltrates over plain HTTP. A backup Actions workflow runs if the stealer never does. Related phishing uses `my-github[.]com` (and `my-gitlab[.]com`) to complete a GitHub OAuth device flow for `repo`, `workflow` and `read:org` scopes; exfiltration and C2 are at `193.32.204[.]199`.

There is no CVE and no patch. This script is a detector and a containment tool. The detection is deliberately content-based, to avoid false positives: the fake font is flagged by its WOFF2 magic bytes (a real font starts with `wOF2`; the stealer does not), not by its name, which is a legitimate Font Awesome file name; and the malicious workflows are flagged by the C2 they carry, not by their names, which are common (`ci-check.yml`, `audit.yml` and the like). None of this undoes a stolen token: if anything matches, from a **clean device** revoke your GitHub tokens and authorized OAuth apps, change your password, rotate every credential the repositories and workflows could reach, audit the repositories, and warn anyone who cloned them. Keep VS Code workspace trust on, so opening a cloned folder does not run its tasks.

### GhostAction quick start

1. Download the script. The repository is mirrored on GitHub and Codeberg; pick a base URL.

   ```bash
   # BASE from GitHub:   https://raw.githubusercontent.com/PrivacySafe/security-patches/refs/heads/main
   # BASE from Codeberg: https://codeberg.org/PrivacySafe/security-patches/raw/branch/main
   # curl -fLO "$BASE/ghostaction/ghostaction-oct2026-check.sh"
   curl -fLO https://raw.githubusercontent.com/PrivacySafe/security-patches/refs/heads/main/ghostaction/ghostaction-oct2026-check.sh
   ```

2. Read it before running it, then make it executable.

   ```bash
   less ghostaction-oct2026-check.sh
   chmod +x ghostaction-oct2026-check.sh
   ```

3. Scan your repositories (point `SCAN_PATHS` at where they live).

   ```bash
   SCAN_PATHS="$HOME/src $HOME/work" ./ghostaction-oct2026-check.sh check
   ```

4. Hunt the machine for the cron job and network indicators.

   ```bash
   ./ghostaction-oct2026-check.sh hunt
   ```

5. If found, contain the artifacts while you revoke tokens and rotate credentials.

   ```bash
   ./ghostaction-oct2026-check.sh quarantine
   ```

### GhostAction commands

| Command | What it does |
|---|---|
| `check` (default) | Scans the paths for the dropped artifacts: a `.woff2`/`.woff` whose magic bytes are not a real font, a `.vscode/tasks.json` that runs on `folderOpen`, a workflow carrying the C2, npm lifecycle hooks that pipe a download into a shell, and the campaign's domains or IP in files. Read-only. Exits `0` if clean, `1` if indicators are found, `2` if something couldn't be read |
| `hunt` | Read-only, machine-level: cron jobs that fetch and run code, the domains/IP in shell history, git config and logs, and a stealer-style process (Node running a font file). Exits `0` if clean, `1` if it found something |
| `quarantine` | Containment, not a fix. Backs up (for forensics) and removes the confirmed artifacts (a fake font, a `tasks.json` that executes it, a workflow carrying the C2). Needs write access. Your tokens are still stolen: revoke and rotate |
| `version` | Prints the script version. Every command prints it on its first line too |

### GhostAction know before you run it

- **A stolen token is the real damage, and this cannot undo it.** If anything matches, from a clean device revoke GitHub tokens and authorized OAuth apps (Settings then Applications), change your password, and rotate every credential the repositories and workflows could reach: cloud keys, npm and PyPI tokens, SSH and signing keys, Kubernetes and AI provider keys.
- **Detection is content-based to avoid false positives.** `fa-solid-400.woff2` is a real Font Awesome file name and workflow names like `ci-check.yml` are everywhere, so the script judges fonts by their magic bytes and workflows by the C2 they carry, not by name. A folder-open task that only runs a genuine script is listed for review, not auto-removed.
- **Keep VS Code workspace trust on.** The stealer runs only when a folder's tasks are allowed to run on open; workspace trust is what stops a freshly cloned folder from executing them.
- **`quarantine` is containment.** It stops the dropped files running; it does not clean a machine that already ran them or revoke what was stolen.
- **Point `SCAN_PATHS` at your repositories.** It defaults to the current directory and your home, prunes `node_modules`, `.git` and similar, and scans for the artifacts.
- **GNU/Linux only.**

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
