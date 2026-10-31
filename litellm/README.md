# LiteLLM: October 2026

Part of the [PrivacySafe Security Patches](../README.md) collection.

<a name="litellm-11070-supply-chain-compromise"></a>

## LiteLLM 1.107.0 Supply-Chain Compromise

**Script:** [`litellm/litellm-oct2026-check.sh`](litellm-oct2026-check.sh)

On 21 October 2026 a malicious release of `litellm`, version 1.107.0, was published to PyPI (all seven wheels, plus an sdist with a tampered `pyproject.toml`) and to the project's Docker images (tags `v1.107.0`, `latest`, `main-latest`, `main-stable`), after attacker-controlled GitHub accounts triggered a release. This compromise has [no CVE](https://github.com/BerriAI/litellm/issues/47826). The release has been quarantined on PyPI and the images removed. The last clean release is 1.106.2.

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
| `quarantine` | Containment. Backs up (for forensics) and removes `cook.pth` and `cook.py`, and `sitecustomize.py` only when it carries the malware markers, so they stop running at Python start. Needs write access. The host is still compromised: rebuild and rotate credentials |
| `version` | Prints the script version. Every command prints it on its first line too |

### LiteLLM what it looks at

1. Python environments. The site-packages directories the active `python3` reports, plus every `site-packages` found under the scanned paths (system, user, venvs, pipx, conda). For each it reads the installed `litellm` version and flags 1.107.0.
2. Dropped files. `cook.pth`, `cook.py`, and `sitecustomize.py` in the root of each site-packages. A legitimate `sitecustomize.py` exists in some environments, so it is only treated as malware when it carries the backdoor markers. `cook.pth` and `cook.py` are the attacker's own file names.
3. Runtime markers. The `/tmp/.pc_once_*` upload marker and the `/tmp/remote_code_loader.lock` the backdoor daemon holds.
4. Containers. Running Docker or Podman containers whose `litellm` is 1.107.0 or that carry `cook.pth`. A container is fixed by rebuilding on a clean 1.106.2 digest, not by a restart.

## Before you run it

- Treat the host as fully compromised. This is the important one. The stealer runs on every Python start, so by the time you read this it has run. From a clean machine, revoke and rotate every credential the host could reach: cloud keys, API tokens, SSH and signing keys, browser sessions, and the LiteLLM proxy's own keys and model configuration.
- `quarantine` is containment, not remediation. Removing the files stops the backdoor re-running. It does not undo the theft or guarantee the host is clean. Rebuild the host and reinstall `litellm` pinned to 1.106.2 by digest.
- Only the malware files are touched. `quarantine` removes `cook.pth` and `cook.py`, and a `sitecustomize.py` only if it carries the markers, so a legitimate `sitecustomize.py` is left alone. Forensic copies go to the backup directory.
- Containers carry their own copy. Rebuild any image that pulled 1.107.0 (or the `latest` / `main-*` tags on 21 October) on a clean 1.106.2 digest.
- GNU/Linux only , and it finds installs under the scanned paths. Point `SCAN_PATHS` at an environment kept elsewhere.
- A path it could not read is not a clean result. If a scan path exists but cannot be read, `check` exits `2` (when nothing else is found) instead of `0`. A path that does not exist is skipped. Directories inside a readable path that you cannot read are skipped, so run it as root for full coverage.
- It also checks running docker and podman containers, unless you name a directory or set `SCAN_CONTAINERS=0`. A read-only probe in each container finds the `litellm` metadata directories (and the `fastapi` and `uvicorn` ones beside them), proxy configuration files, lock and requirements files that mention litellm, and image tags in compose-style files. It copies only what the check reads into a private temporary folder: a one-line marker for each proxy config (the keys stay in the container), the matched `berriai/litellm:TAG` strings from compose, Helm and `.env` files, and requirements lines with index URLs and credentials dropped. The script then runs once per container in isolation, so one container's proxy config never makes another container's copy look exposed. `/app`, where the official image keeps its configuration, is searched in containers. A path shown as `.../docker_NAME/PATH` is the PATH inside the container NAME.

<a name="litellm-proxy-admin-escalation"></a>

## LiteLLM proxy admin escalation (CVE-2026-114612)

**Script:** [`litellm/litellm-escalation-check.sh`](litellm-escalation-check.sh)

This is a **different problem** from the malicious 1.107.0 release above: a genuine vulnerability in genuine releases. The LiteLLM proxy uses one cryptographic context for two purposes, sealing secrets at rest and minting session tokens. An authenticated user with `internal_user` privileges can request a new API key with a crafted metadata field that holds a forged administrator credential as the "secret". The proxy encrypts it and returns it, and the user replays it as a bearer token to become `proxy_admin`, which reaches arbitrary commands through the MCP stdio endpoint.

| | |
|---|---|
| CVE | CVE-2026-114612 (CWE-269, CWE-345, CWE-441, advisory GHSA-7hp6-4w63-5g45, published 22 October 2026) |
| Severity | Critical, CVSS 3.1 9.9 (an authenticated, low-privilege user) |
| Affected | 1.87.0 up to 1.100.4, 1.101.0 up to 1.101.3, 1.102.0 up to 1.102.2, 1.103.0 up to 1.103.1, and 1.104.0-rc.1 up to 1.104.0-rc.2 |
| Fixed | **1.100.4, 1.101.3, 1.102.2, 1.103.1 and 1.104.0-rc.2** (all on PyPI), and every later release. move 1.87.0 through 1.99.x to 1.100.4 or newer |
| Note | The vendor advisory lists 1.91.0 as the first exploitable version. A third-party reading says 1.87.0 to 1.90.x also need `EXPERIMENTAL_UI_LOGIN`. The tool treats the whole CVE range as affected |
| Needs | **The proxy.** Using litellm only as a Python library (the SDK), with no proxy running, is not exposed. The tool reports which it found evidence of |

**Do not confuse the two.** The last clean release before the malicious one is 1.106.2, which is above every fixed version here. If the new script meets 1.107.0 it says so and points to `litellm-oct2026-check.sh`.

### Quick start

```bash
curl -fLO https://raw.githubusercontent.com/PrivacySafe/security-patches/refs/heads/main/litellm/litellm-escalation-check.sh
less litellm-escalation-check.sh
chmod +x litellm-escalation-check.sh
./litellm-escalation-check.sh check
```

By default it searches `/usr/lib /usr/local/lib /opt /srv /var/lib /etc /home /root`. Pass directories to narrow it. Exit `0` nothing exposed, `1` an affected proxy, a floating image tag or the malicious 1.107.0, `2` bad arguments. It is read-only.

### How it decides

- Installed copies (`litellm-*.dist-info`), **pins** (`requirements*.txt`, `poetry.lock`, `uv.lock`, `pdm.lock`, `Pipfile.lock`) and **container image tags** in compose, Helm, Kubernetes and Dockerfiles (`berriai/litellm` and `berriai/litellm-database`).
- Proxy evidence: `fastapi` and `uvicorn` installed beside litellm, a `litellm[proxy]` extra or those packages in the same pin file, a LiteLLM proxy configuration file (`model_list` or `general_settings`), or any container image (the images are the proxy). An affected version with evidence is exposed. Without it the tool warns and exits `0`, because SDK-only use is not exposed.
- Per release line: a version on one line can be affected while a lower one on another line is fixed (1.100.4 is fixed, but 1.101.0 to 1.101.2 are affected), so each line has its own first fixed release. `1.104.0rc1` is affected and `1.104.0rc2` and the final `1.104.0` are fixed.
- Floating tags such as `main-latest` or `main-stable` do not say which release is running, so the tool says it cannot tell and exits `1`. It does not open running containers.
- Look-alikes such as `litellm_proxy_extras` and `litellm_enterprise` are different packages and are not matched, including when listed first in a lock file.

### Fixing it

Upgrade to 1.100.4, 1.101.3, 1.102.2, 1.103.1 or 1.104.0-rc.2 or newer, on the line you run. Never install 1.107.0. After upgrading, check the proxy's user list for administrators you did not create (PrivacySafe recommendation).

### Sources

- [Advisory GHSA-7hp6-4w63-5g45](https://github.com/BerriAI/litellm/security/advisories/GHSA-7hp6-4w63-5g45)

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
