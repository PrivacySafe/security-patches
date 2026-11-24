# iTerm2: a file shown in the terminal can run commands (3.6.1 to 3.7.8)

Part of the [PrivacySafe Security Patches](../../README.md) collection.

<a name="iterm2-kitty"></a>

## iTerm2 terminal-reply command execution (macOS)

**Script:** [`developer/iterm2/iterm2-kitty-check.sh`](iterm2-kitty-check.sh), for macOS (its `scan` also runs on GNU/Linux)

The rest of this collection is for GNU/Linux. iTerm2 is the terminal many administrators use to reach those servers, so this tool checks Macs too.

iTerm2 3.6.1 to 3.7.8 answer a Kitty graphics file-transfer request with an error reply that keeps the control characters from the request. A file that carries such a request, shown with `cat README.md`, makes iTerm2 type the attacker's text into your shell, which runs it, in bash, zsh and fish, on a default install. All you see is a few shell errors.

| | |
|---|---|
| CVE | None assigned as of 23 November 2026 |
| Affected | iTerm2 3.6.1 (when Kitty image file transfer arrived) to 3.7.8; 3.6.11, the newest release for macOS 12, is affected too |
| Fixed | iTerm2 3.7.9, 20 November 2026 (macOS 13 or later). No fixed release for macOS 12.4 to 12.x |
| Exploited | No attacks reported; the researcher (ii4gsp) published a complete exploit |
| Setting | "Disable potentially insecure escape sequences" does not cover it |

## Quick start

1. Download the script. The repository is mirrored on GitHub and Codeberg; pick a base URL.

   ```bash
   # BASE from GitHub:   https://raw.githubusercontent.com/PrivacySafe/security-patches/refs/heads/main
   # BASE from Codeberg: https://codeberg.org/PrivacySafe/security-patches/raw/branch/main
   curl -fLO https://raw.githubusercontent.com/PrivacySafe/security-patches/refs/heads/main/developer/iterm2/iterm2-kitty-check.sh
   ```

2. Read it before running it, then make it executable.

   ```bash
   less iterm2-kitty-check.sh
   chmod +x iterm2-kitty-check.sh
   ```

3. Check this Mac. With `sudo` it also reads every user's `~/Applications`.

   ```bash
   ./iterm2-kitty-check.sh check
   ```

4. Look through files you might show in a terminal (a cloned repository, a downloads folder), on a Mac or a GNU/Linux server:

   ```bash
   ./iterm2-kitty-check.sh scan ~/src/some-repo ~/Downloads
   ```

## Commands

| Command | What it does |
|---|---|
| `check` (default) | Finds every iTerm2 in `/Applications`, each user's `~/Applications`, Homebrew's Caskroom and through Spotlight, reads its version from its `Info.plist` without running it, and says whether this macOS can run the fix. Read-only. Exits `0` if no copy is affected, `1` if one is, `2` if a version could not be read |
| `scan PATH...` | Looks through the files under each path (skipping `.git` folders) for the Kitty graphics escape sequence the attack hides in text (`ESC _ G`), and lists files with other escape sequences that make a terminal answer (APC, DCS, device status and attribute requests) for a look by hand. Read-only. Exits `0` if nothing is found, `1` if files are listed, `2` for a bad argument |
| `version` | Prints the script version |

Environment: `APP_DIRS` (where to look for `iTerm.app`), `SCAN_MAX_SIZE` (largest file `scan` reads, in MB, default 20).

## What to do

1. **iTerm2 > Check for Updates**, to 3.7.9 or later, then quit and reopen iTerm2: a window that is still open runs the old code.
2. On macOS 12 there is no fixed iTerm2. Upgrade macOS if you can, or use Terminal.app for files from others.
3. Until you have updated, read files from others with `less` (which shows escape characters as `^[` instead of sending them to the terminal) or in an editor, not with `cat`, `head` or `tail`.

## Before you run it

- It works with the bash 3.2 that macOS ships and needs nothing that macOS does not include.
- A file that `scan` lists for review is not necessarily hostile: test captures and terminal tools use these sequences. A Kitty graphics command in a README or a text file is not something you should display.

Sources: [iTerm2 downloads and release notes](https://iterm2.com/downloads.html), the researcher's [write-up](https://ii4gsp.github.io/iterm2-rce/), and the fixes [a53b1bc](https://github.com/gnachman/iTerm2/commit/a53b1bc084fe062de44b52d03ccf713c7962ac83) and [2a63835](https://github.com/gnachman/iTerm2/commit/2a63835ca19bbd20b0d051b33c14341b0b708d5b). Status current on 23 November 2026.

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
