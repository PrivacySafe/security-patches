# LiteLLM: the malicious 1.107.0 release

Part of the [PrivacySafe Security Patches](../README.md) collection.

<a name="litellm-11070-supply-chain-compromise"></a>

## LiteLLM 1.107.0 Supply-Chain Compromise

**Script:** [`litellm/litellm-oct2026-check.sh`](litellm-oct2026-check.sh)

On 21 October 2026 a malicious release of `litellm`, version 1.107.0, was published to PyPI (all seven wheels, plus an sdist with a tampered `pyproject.toml`) and to the project's Docker images (tags `v1.107.0`, `latest`, `main-latest`, `main-stable`), after attacker-controlled GitHub accounts triggered a release. There is [no CVE](https://github.com/BerriAI/litellm/issues/47826) and no patch; the release has been quarantined on PyPI and the images removed. The last clean release is 1.106.2.

Each wheel drops three files into the root of site-packages, beside `litellm/` rather than inside it: `cook.pth` (one line, `import cook`), `cook.py` (a credential stealer that calls itself `privcollect`), and `sitecustomize.py` (an hourly backdoor that fetches and runs attacker code from a GitHub dead drop). Python runs `.pth` files and `sitecustomize.py` at interpreter startup, so the malware runs on every Python start on the host, even if `litellm` is never imported. The stealer targets cloud tokens, developer and private keys, AI-tool credentials, browser data, environment variables, and a LiteLLM proxy's saved credentials, and exfiltrates to `litellm[.]dev`.

There is no safe in-place "clean." If 1.107.0 was installed from a wheel, or a LiteLLM container pulled on 21 October ran, treat the host as **fully compromised**: the stealer already ran. From a clean machine, revoke and rotate every credential the host could reach, rebuild it, and reinstall `litellm` pinned to 1.106.2 by digest. This script finds the compromise, hunts the indicators, and can contain the auto-executing backdoor so it stops running while you rebuild. Containment is not remediation.

### LiteLLM quick start

1. Download the script. The repository is mirrored on GitHub and Codeberg; pick a base URL.

   ```bash
   # BASE from GitHub:   https://raw.githubusercontent.com/PrivacySafe/security-patches/refs/heads/main
   # BASE from Codeberg: https://codeberg.org/PrivacySafe/security-patches/raw/branch/main
   # curl -fLO "$BASE/litellm/litellm-oct2026-check.sh"
   curl -fLO https://raw.githubusercontent.com/PrivacySafe/security-patches/refs/heads/main/litellm/litellm-oct2026-check.sh
   ```

2. Read it before running it, then make it executable.

   ```bash
   less litellm-oct2026-check.sh
   chmod +x litellm-oct2026-check.sh
   ```

3. See whether the compromise is present.

   ```bash
   sudo ./litellm-oct2026-check.sh check
   ```

4. Hunt the indicators (files, `/tmp` markers, network traces in logs).

   ```bash
   sudo ./litellm-oct2026-check.sh hunt
   ```

5. If found, contain the backdoor while you plan the rebuild and credential rotation.

   ```bash
   sudo ./litellm-oct2026-check.sh quarantine
   ```

### LiteLLM commands

| Command | What it does |
|---|---|
| `check` (default) | Finds `litellm` in every Python environment (and running containers) and flags 1.107.0, and reports the dropped malware files (`cook.pth`, `cook.py`, a malicious `sitecustomize.py`) in site-packages and the `/tmp` runtime markers. Read-only. Exits `0` if nothing found, `1` if compromise indicators are present, `2` if something couldn't be read |
| `hunt` | Read-only, deeper: the malware files across every site-packages, the `/tmp` markers (`.pc_once_*`, `remote_code_loader.lock`), and logs for the network indicators (`litellm.dev`, the GitHub dead drop). Exits `0` if clean, `1` if it found something |
| `quarantine` | Containment, not a fix. Backs up (for forensics) and removes `cook.pth` and `cook.py`, and `sitecustomize.py` only when it carries the malware markers, so they stop running at Python start. Needs write access. The host is still compromised: rebuild and rotate credentials |
| `version` | Prints the script version. Every command prints it on its first line too |

### LiteLLM what it looks at

1. **Python environments.** The site-packages directories the active `python3` reports, plus every `site-packages` found under the scanned paths (system, user, venvs, pipx, conda). For each it reads the installed `litellm` version and flags 1.107.0.
2. **Dropped files.** `cook.pth`, `cook.py`, and `sitecustomize.py` in the root of each site-packages. A legitimate `sitecustomize.py` exists in some environments, so it is only treated as malware when it carries the backdoor markers; `cook.pth` and `cook.py` are the attacker's own file names.
3. **Runtime markers.** The `/tmp/.pc_once_*` upload marker and the `/tmp/remote_code_loader.lock` the backdoor daemon holds.
4. **Containers.** Running Docker or Podman containers whose `litellm` is 1.107.0 or that carry `cook.pth`. A container is fixed by rebuilding on a clean 1.106.2 digest, not by a restart.

### LiteLLM know before you run it

- **Treat the host as fully compromised.** This is the important one. The stealer runs on every Python start, so by the time you read this it has run. From a clean machine, revoke and rotate every credential the host could reach: cloud keys, API tokens, SSH and signing keys, browser sessions, and the LiteLLM proxy's own keys and model configuration.
- **`quarantine` is containment, not remediation.** Removing the files stops the backdoor re-running; it does not undo the theft or guarantee the host is clean. Rebuild the host and reinstall `litellm` pinned to 1.106.2 by digest.
- **Only the malware files are touched.** `quarantine` removes `cook.pth` and `cook.py`, and a `sitecustomize.py` only if it carries the markers, so a legitimate `sitecustomize.py` is left alone. Forensic copies go to the backup directory.
- **Containers carry their own copy.** Rebuild any image that pulled 1.107.0 (or the `latest` / `main-*` tags on 21 October) on a clean 1.106.2 digest.
- **GNU/Linux only**, and it finds installs under the scanned paths; point `SCAN_PATHS` at an environment kept elsewhere.

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
