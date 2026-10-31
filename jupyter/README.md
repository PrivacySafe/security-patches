# Jupyter Server and nbconvert: CVE-2026-114135 and CVE-2026-114140

Part of the [PrivacySafe Security Patches](../README.md) collection.

<a name="jupyter-check"></a>

## Jupyter check

**Script:** [`jupyter/jupyter-check.sh`](jupyter-check.sh)

| | CVE-2026-114135 | CVE-2026-114140 |
|---|---|---|
| Component | **Jupyter Server**, gateway kernel handler | **nbconvert**, `ExtractOutputPreprocessor` |
| What | When `GatewayClient.url` is set, the normal kernel WebSocket handler is replaced by a gateway handler that authenticates the user but never asks the configured Authorizer whether that user may **execute** on kernels. A user the Authorizer denies can still open a kernel channel and send messages to the upstream kernel | The attacker-controlled `filename` in a cell's output metadata is joined to the output directory without checking the result. Converting a **malicious notebook** to markdown, LaTeX, reStructuredText or AsciiDoc writes attacker-controlled data to arbitrary paths the victim can write to |
| Severity | High, CVSS 8.8 | High, CVSS 8.8 (some trackers 9.0) |
| Affected | 2.0.0 up to 2.6.0 | 5.4.0 up to 7.17.2 |
| Fixed | **2.6.0** | **7.17.2** |
| Needs | A gateway configured **and** a restrictive Authorizer. With the default allow-all authorizer nobody is denied, so there is nothing to bypass | The victim converts the notebook (user interaction). Re-running a cell replaces the malicious output metadata; merely converting the supplied notebook does not |
| Residual | In 2.6.0 and later the bypass remains possible if a deployment manually registers the deprecated `jupyter_server.gateway.handlers` module | Only the markdown, LaTeX, rst and asciidoc exporters |

## Quick start

1. Download the script. The repository is mirrored on GitHub and Codeberg; pick a base URL.

   ```bash
   # BASE from GitHub:   https://raw.githubusercontent.com/PrivacySafe/security-patches/refs/heads/main
   # BASE from Codeberg: https://codeberg.org/PrivacySafe/security-patches/raw/branch/main
   # curl -fLO "$BASE/jupyter/jupyter-check.sh"
   curl -fLO https://raw.githubusercontent.com/PrivacySafe/security-patches/refs/heads/main/jupyter/jupyter-check.sh
   ```

2. Read it before running it, then make it executable.

   ```bash
   less jupyter-check.sh
   chmod +x jupyter-check.sh
   ```

3. Check this host. By default it searches `/usr/lib /usr/local/lib /opt /srv /var/www /var/lib /home /root`, plus `/etc/jupyter`, `/usr/local/etc/jupyter` and `~/.jupyter` for configuration. Pass directories to narrow it, such as one virtual environment.

   ```bash
   ./jupyter-check.sh check
   ./jupyter-check.sh check /srv/hub/.venv
   ```

## Commands

| Command | What it does |
|---|---|
| `check [DIR ...]` (default) | Finds installed copies (`jupyter_server-*.dist-info`, `nbconvert-*.dist-info` and egg-info) and declared pins (`requirements*.txt`, `poetry.lock`, `uv.lock`, `pdm.lock`, `Pipfile.lock`). For Jupyter Server it reads `jupyter_server_config.py` and `.json`, `jupyter_config.*` and `jupyter_notebook_config.*` (and `jupyter_server_config.d/*.json`) for `GatewayClient.url` and `authorizer_class`, and reads the arguments of running jupyter processes |
| `version` | Prints the script version |

Exit codes: `0` nothing exposed, `1` an affected nbconvert, or an affected Jupyter Server with a gateway and a custom authorizer, `2` bad arguments.

## How to read the result

- Jupyter Server in range, gateway and custom authorizer both configured: exposed. Upgrade.
- In range, gateway configured, no custom authorizer found: a warning and exit `0`. With the default allow-all authorizer there is nothing to bypass, but check whether an authorizer is set somewhere this tool cannot see.
- In range, no gateway configured: exit `0`: the vulnerable handler is not in use. Update anyway, because a gateway enabled later would activate it.
- No Jupyter configuration file found: the defaults (no gateway) apply, and the tool says it cannot see settings given only on the command line or in `JUPYTER_GATEWAY_URL`. It does read the command-line arguments of running jupyter processes (`--gateway-url`, `--GatewayClient.url`, `--ServerApp.authorizer_class`).
- nbconvert in range: exit `1` on version alone, because a library cannot tell whether you convert untrusted notebooks. It only matters if you do, including through JupyterLab's **Download as** on a shared hub or a notebook-rendering service.
- Look-alikes such as `jupyter-server-terminals` and `jupyter_server_fileid` are different packages and are ignored, including when listed before the real one in a lock file.

## Fixing it

```bash
pip install --upgrade 'jupyter_server>=2.6.0' 'nbconvert>=7.17.2'
```

Until you can: do not convert notebooks from untrusted sources to markdown, LaTeX, reST or AsciiDoc, and run conversions in a throwaway directory as an unprivileged user. Remove `GatewayClient.url` if you do not need a gateway. Those two steps are PrivacySafe's recommendation.

## Sources

- [jupyter_server advisory GHSA-354v-3q48-cv69](https://github.com/jupyter-server/jupyter_server/security/advisories/GHSA-354v-3q48-cv69)
- [nbconvert advisory GHSA-pjvx-prjx-h659](https://github.com/jupyter/nbconvert/security/advisories/GHSA-pjvx-prjx-h659)

## Before you run it

- The fix. Update Jupyter Server to 2.6.0 and nbconvert to 7.17.2.
- CVE-2026-114135 needs two conditions together. A gateway must be configured (`GatewayClient.url`) and a restrictive Authorizer must be in use. With the default `AllowAllAuthorizer` nobody is denied, so there is nothing to bypass. Even in 2.6.0 and later the bypass remains if a deployment manually registers the deprecated `jupyter_server.gateway.handlers` module.
- CVE-2026-114140 needs user interaction. The victim must convert a malicious notebook to markdown, LaTeX, reStructuredText or AsciiDoc.
- There is no hunt. No indicators of exploitation have been published.
- It also checks running docker and podman containers, unless you name a directory or set `SCAN_CONTAINERS=0`. In each running container, a read-only probe finds the installed copies by their `dist-info` and `egg-info` folders, plus the lock and requirements files that mention the package. It copies only those names and files into a private temporary folder, and the normal check judges that folder. Jupyter configuration files found in a container (`jupyter_server_config.*`, `jupyter_config.*`, `jupyter_notebook_config.*`, `jupyter_server_config.d/*.json`) are read together with the host's, as the check always aggregates the configuration it finds, so a gateway or authorizer setting in a container counts toward every copy found. A staged symlink is never kept and the copies are removed on exit. A path shown as `.../docker_NAME/PATH` is the PATH inside the container NAME. It is skipped when you name directories yourself.

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
