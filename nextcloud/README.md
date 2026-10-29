# Nextcloud: Collabora Built-in CODE (CVE-2026-110447)

Part of the [PrivacySafe Security Patches](../README.md) collection.

<a name="nextcloud-collabora-built-in-code-command-injection"></a>

## Nextcloud Collabora Built-in CODE Command Injection

**Script:** [`nextcloud/collabora-code-oct2026-mitigate.sh`](collabora-code-oct2026-mitigate.sh)

[CVE-2026-110447](https://github.com/CollaboraOnline/online/security/advisories/GHSA-g3vx-3m76-fghh) is an unauthenticated OS command injection in Nextcloud's optional "Collabora Online - Built-in CODE Server" app (package `richdocumentscode`), which downloads a copy of Collabora Online Development Edition and runs it on the Nextcloud server itself. The app's `proxy.php` starts that local server when a request arrives and nothing is listening. Before 26.4.303 it built the start command by placing text from the request, including its path, inside a double-quoted bash string, so a request with `$(...)` in its path ran commands as the web server account. It is reachable only while the local CODE server is down (a restart, upgrade or crash), which is exactly when `proxy.php` tries to start it. The flaw has been exploited in the wild since September 2026 to plant PHP web shells under `apps/richdocumentscode/` (files named `shx*.php`), which then search for credential stores and wallets.

The key operational point, from Collabora's advisory: **disabling the app is not enough.** `proxy.php` is a plain PHP file the web server runs directly, outside Nextcloud's code, so it stays reachable whether or not the app is enabled. The fix is to update `richdocumentscode` to 26.4.303 or later, or remove the app. The fixed app requires Nextcloud 30 or later; on Nextcloud 29 and older (end of life), upgrade Nextcloud or remove the app. Standalone Collabora Online servers, and Nextcloud Office (`richdocuments`) without the built-in app, are not affected.

This script does not run the update or removal for you, since that is an app-store or `occ` action an administrator should time. What it does: find affected installs, apply a reversible interim block by neutralizing the exploited `proxy.php`, and hunt for the web shells and request markers the attacks leave behind.

### Nextcloud Collabora quick start

1. Download the script. The repository is mirrored on GitHub and Codeberg; pick a base URL.

   ```bash
   # BASE from GitHub:   https://raw.githubusercontent.com/PrivacySafe/security-patches/refs/heads/main
   # BASE from Codeberg: https://codeberg.org/PrivacySafe/security-patches/raw/branch/main
   # curl -fLO "$BASE/nextcloud/collabora-code-oct2026-mitigate.sh"
   curl -fLO https://raw.githubusercontent.com/PrivacySafe/security-patches/refs/heads/main/nextcloud/collabora-code-oct2026-mitigate.sh
   ```

2. Read it before running it, then make it executable.

   ```bash
   less collabora-code-oct2026-mitigate.sh
   chmod +x collabora-code-oct2026-mitigate.sh
   ```

3. See what's affected. This changes nothing.

   ```bash
   sudo ./collabora-code-oct2026-mitigate.sh check
   ```

4. Apply the interim block if you cannot update or remove the app immediately. It backs up `proxy.php` first and is reversible.

   ```bash
   sudo ./collabora-code-oct2026-mitigate.sh apply
   ```

5. Hunt for web shells and attack markers.

   ```bash
   sudo ./collabora-code-oct2026-mitigate.sh hunt
   ```

### Nextcloud Collabora commands

| Command | What it does |
|---|---|
| `check` (default) | Finds every Nextcloud with the built-in CODE app, and reports the app version (fixed at 26.4.303), the Nextcloud version (the fix needs 30+), and whether `proxy.php` is still live or already neutralized by this script. Read-only, root optional. Exits `0` if nothing is exposed, `1` if a vulnerable app is present, `2` if something couldn't be read |
| `apply` | Neutralizes the exploited `proxy.php` on every vulnerable install, replacing it with a stub that returns HTTP 403 and builds no command. Backs the original up first, is idempotent, and is the one thing this script changes. Needs write access to the app (run as root or the web user). Refuses an already-fixed app unless `--force`. This disables the built-in CODE server until you update or remove the app |
| `restore` | Puts the original `proxy.php` back where `apply` replaced it (the original is vulnerable, so update or remove the app instead) |
| `status` | Shows which installs this script has neutralized |
| `hunt` | Read-only. Scans the app folders for planted web shells (`shx*.php`, a known shell by SHA-256, and any file that runs commands from request input) and the web server access logs for the exploitation markers (`proxy.php` requests with `%2e%2e`, `$(` or `${IFS}`, and the known attacker IPs). Exits `0` if nothing matched, `1` if it found something, `2` if there was no app folder and no readable log (nothing was searched) |
| `version` | Prints the script version. Every command prints it on its first line too |

### Why `apply` edits `proxy.php` rather than disabling the app

Because disabling the app does nothing: the web server serves `proxy.php` directly, outside Nextcloud. Neutralizing that one file closes the exploited path at once, no matter how the app is enabled or which web server is in front, and it is reversible (`restore`) and self-healing (an app update to 26.4.303 replaces the stub with the fixed `proxy.php`). It is an interim step, not the fix: update the app to 26.4.303 or later, or remove it.

### Nextcloud Collabora configuration

| Variable | Default | Purpose |
|---|---|---|
| `NC_PATHS` | `/var/www /srv /opt /usr/share/webapps /var/snap` | Where to look for Nextcloud installs |
| `RICHDOC_FIXED` | `26.4.303` | First fixed app version |
| `NC_MIN_FOR_FIX` | `30` | Nextcloud major the fixed app requires |
| `BACKUP_ROOT` | `/var/backups/collabora-code-oct2026` | Where `apply` backs up `proxy.php` |
| `SCAN_DEPTH` | `8` | How deep the install search goes |
| `HUNT_SINCE` | `2026-09-01` | How far back `hunt` reads the journal |
| `HUNT_LOGS` | *(empty)* | Extra access-log globs for `hunt` |

### Nextcloud Collabora know before you run it

- **The real fix is update or remove, which this script does not do for you.** Update `richdocumentscode` to 26.4.303 or later, or remove the app through Nextcloud. `apply` is an interim, reversible block for the window before you can.
- **Disabling the app does not help.** `proxy.php` runs directly from the web server, so it stays reachable when the app is disabled. This is why `apply` edits that file.
- **`apply` disables the built-in CODE server.** Document editing through the built-in CODE server stops until you update the app (which restores a safe `proxy.php`) or `restore` and then update. The app is for local, non-production use by its own description.
- **Neutralizing `proxy.php` trips Nextcloud's integrity check.** That is expected: the file is intentionally changed. The integrity check is also a useful detector here, since it flags a planted web shell as a new file.
- **If you were already exploited, closing the hole is not enough.** Run `hunt`, delete any `shx*.php` under `apps/richdocumentscode/`, and treat anything the web server account could read as exposed: rotate credentials and check for access to credential stores and wallets.
- **On Nextcloud 29 and older the fixed app cannot be installed.** Upgrade Nextcloud to 30+ or remove the app.
- **GNU/Linux only**, and it finds installs under `NC_PATHS`; point `NC_PATHS` at an install kept elsewhere.
- **Only `--force` is a recognised option.** Any other option is refused with exit `2`, so a mistyped or invented flag (for example `restore --dry-run`) can never turn into a real `apply` or `restore`.

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
