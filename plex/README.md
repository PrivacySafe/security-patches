# Plex Media Server: Plex2Shell chain

Part of the [PrivacySafe Security Patches](../README.md) collection.

<a name="plex-media-server-plex2shell-rce-chain"></a>

## Plex Media Server Plex2Shell RCE Chain

**Script:** [`plex/plex2shell-oct2026-check.sh`](plex2shell-oct2026-check.sh)

"Plex2Shell" chains flaws in Plex Media Server into unauthenticated remote code execution: an SSRF on `/player/timeline` (CVE-2026-96652), admin-token theft via `searchOne` (CVE-2026-96654), a second SSRF on the transcode path (CVE-2026-96655), and a file write into the Codecs directory that drops and runs an ELF shared object (CVE-2026-96656). CVE-2026-96651 was fixed in the same release. Plex fixed all of them in Plex Media Server 1.43.3.10861 (3 August 2026). A public proof-of-concept landed on 16 October 2026 and exploitation began the next day: attackers drop an XMRig miner (seen as `mylovelyminer`, fetched as `x12345`) and a reverse-proxy backdoor (`myawesomeproxy`), with traffic to `proxystream[.]st`.

The fix is to upgrade to 1.43.3.10861 or later, including NAS, Docker and VM installs, and restart, which this script does not do for you. It is read-only. Successful exploitation runs code as the Plex service account, so if this host was internet-exposed and unpatched, treat it as compromised: rebuild from a clean install, rotate the Plex account credentials and server token, and (interim) remove any router port-forwarding to Plex until it is updated. Attackers rotate file names, domains and ports, so a clean hunt is not proof; the version is the reliable signal.

### Plex quick start

1. Download the script. The repository is mirrored on GitHub and Codeberg; pick a base URL.

   ```bash
   # BASE from GitHub:   https://raw.githubusercontent.com/PrivacySafe/security-patches/refs/heads/main
   # BASE from Codeberg: https://codeberg.org/PrivacySafe/security-patches/raw/branch/main
   # curl -fLO "$BASE/plex/plex2shell-oct2026-check.sh"
   curl -fLO https://raw.githubusercontent.com/PrivacySafe/security-patches/refs/heads/main/plex/plex2shell-oct2026-check.sh
   ```

2. Read it before running it, then make it executable.

   ```bash
   less plex2shell-oct2026-check.sh
   chmod +x plex2shell-oct2026-check.sh
   ```

3. Check the Plex version.

   ```bash
   sudo ./plex2shell-oct2026-check.sh check
   ```

4. Hunt the indicators.

   ```bash
   sudo ./plex2shell-oct2026-check.sh hunt
   ```

### Plex commands

| Command | What it does |
|---|---|
| `check` (default) | Reports the Plex Media Server version on the host (from the package or the install) and in running containers, judged against 1.43.3.10861. Read-only, root optional. Exits `0` if fixed or not present, `1` if a vulnerable Plex is present, `2` if a version couldn't be read |
| `hunt` | Read-only. Scans Plex data directories, `/tmp` and scratch dirs for the known payload file names, lists recently changed files in the Codecs directory (where CVE-2026-96656 writes), greps files for the proxyware banner and mining domain, checks for the miner/proxy running, and scans logs for the attacker IPs and mining domain. Exits `0` if clean, `1` if it found something |
| `version` | Prints the script version. Every command prints it on its first line too |

### Plex patch detection

Plex Media Server versions look like `1.43.3.10861-xxxxxxxxx`; the script reads the numeric build (from the `plexmediaserver` package, or a version file in the install, or inside a container) and compares it to 1.43.3.10861. Anything earlier is vulnerable to Plex2Shell. Plex's own auto-update covers only Windows and macOS, so on GNU/Linux, NAS and Docker you upgrade through your package manager, a container pull and recreate, or a manual download, then confirm the running build.

### Plex know before you run it

- **The fix is upgrading; this script only tells you where you stand.** Upgrade to 1.43.3.10861 or later on every install (NAS, Docker and VM included) and restart.
- **An exposed, unpatched server should be treated as compromised.** The chain runs code as the Plex service account. Rebuild from a clean install, rotate the Plex account credentials and server token, and remove port-forwarding to Plex until it is updated.
- **Indicators change.** Attackers rotate file names, domains and ports, so the hunt can miss a renamed payload. A clean hunt is not proof of safety; the version is the reliable signal.
- **The Codecs listing is a review aid, not a verdict.** Plex's own codecs are ELF shared objects too, so the script lists what changed there recently rather than flagging every shared object as malware.
- **Containers carry their own Plex.** Pull a fixed image and recreate the container; a restart alone does not change the build.
- **GNU/Linux only**, and it finds data directories under the scanned paths; point `PLEX_DATA_PATHS` at a library kept elsewhere.

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
