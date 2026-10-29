# Pillow 13.0.0: CVE-2026-96639 and CVE-2026-112900 check

Part of the [PrivacySafe Security Patches](../README.md) collection.

<a name="pillow-13-security-release-check"></a>

## Pillow 13.0.0 security release check

**Script:** [`pillow/pillow-oct2026-check.sh`](pillow-oct2026-check.sh)

Pillow is one of the most widely installed imaging libraries for Python: web uploads, thumbnails, document pipelines, machine-learning data loaders. Pillow 13.0.0, announced on oss-security on 21 October 2026, fixes a long list of memory-safety and parsing bugs. This tool covers two of them. The release notes list many more, including JPEG decoder overflows, TIFF encoder overflows and PDF parsing problems, and all of them are fixed by the same upgrade.

| | CVE-2026-96639 | CVE-2026-112900 |
|---|---|---|
| What | Stale native image storage reused after a mode transition. A multi-frame file can keep an allocation made for a narrow frame mode while a later frame of the same size switches to wider RGB or CMYK data, so pixels are written past the allocation | `EpsImagePlugin` passes the caller-supplied filename after `-f` to Ghostscript without making it an absolute path. A name that starts with a hyphen is read as a Ghostscript option, and a name that starts with `@` names an argument file |
| Affected | 11.0.0 up to 13.0.0 | 2.6.0 up to 13.0.0 |
| Fixed | 13.0.0 | 13.0.0 |
| Files | Crafted PSD, MPO, DCX or MIC files | EPS input, or any call that hands Pillow an attacker-chosen filename |
| Impact | Native out-of-bounds writes and crashes. The MPO path can also read out of bounds and, in demonstrated runtime-specific profiles, run commands | Option injection into Ghostscript. Command execution needs the attacker to control the filename and the text file it names; the reported chain works with the default `-dSAFER` |
| Severity | 9.8 Critical | Listed as 9.2 Critical |

## Quick start

1. Download the script. The repository is mirrored on GitHub and Codeberg; pick a base URL.

   ```bash
   # BASE from GitHub:   https://raw.githubusercontent.com/PrivacySafe/security-patches/refs/heads/main
   # BASE from Codeberg: https://codeberg.org/PrivacySafe/security-patches/raw/branch/main
   # curl -fLO "$BASE/pillow/pillow-oct2026-check.sh"
   curl -fLO https://raw.githubusercontent.com/PrivacySafe/security-patches/refs/heads/main/pillow/pillow-oct2026-check.sh
   ```

2. Read it before running it, then make it executable.

   ```bash
   less pillow-oct2026-check.sh
   chmod +x pillow-oct2026-check.sh
   ```

3. Check this host. By default it searches `/usr/lib /usr/local/lib /opt /srv /var/www /var/lib /home /root`; pass directories to narrow it.

   ```bash
   ./pillow-oct2026-check.sh check
   ./pillow-oct2026-check.sh check /srv/myapp/.venv
   ```

## Commands

| Command | What it does |
|---|---|
| `check [DIR ...]` (default) | Finds installed copies from `Pillow-*.dist-info` and `*.egg-info` metadata, and declared pins in `requirements*.txt`, `poetry.lock`, `uv.lock`, `pdm.lock` and `Pipfile.lock`. Compares each version with both CVEs and reports whether Ghostscript (`gs`) is on `PATH` |
| `version` | Prints the script version |

Exit codes: `0` nothing affected, `1` an affected version was found, `2` bad arguments.

## How to read the result

- **Both bugs apply:** the version is in both ranges. If `gs` is installed the script prints a critical line for CVE-2026-112900 as well.
- **Affected by CVE-2026-112900 but no `gs`:** the script prints a warning and says the EPS path is inert on this host. The script still exits `1`, because the same Pillow version is affected by the other fixes in 13.0.0.
- **Lock file pins** describe what would be installed, not what is running. A pin is a pointer to fix, not proof that a server is vulnerable.
- **`pillow-heif` and other packages that merely start with "pillow"** are not matched.
- **Distribution packages.** For copies owned by a `dpkg` or `rpm` package the script reads the package changelog and reports a mention of either CVE, because distributions backport fixes without changing the version string.

## Fixing it

```bash
pip install --upgrade 'Pillow>=13.0.0'
```

Check that your Python version is supported by Pillow 13.x before you pin it. Rebuild container images, and restart long-running workers, because a running process keeps the old library loaded.

If you cannot upgrade yet:

- **CVE-2026-96639:** open untrusted files with an allowlist of formats, for example `Image.open(f, formats=["JPEG", "PNG", "GIF", "WEBP"])`, which keeps PSD, MPO, DCX and MIC out. Pillow's own security guidance recommends this approach.
- **CVE-2026-112900:** reject EPS input, or reject any filename that starts with `-` or `@` before it reaches Pillow, or remove Ghostscript from hosts that do not need it. Pillow's guidance also recommends blocking EPS at the application boundary.
- For both, run image processing in a sandbox without network access and without sensitive mounts.

## Sources

- [oss-security: Pillow 13.0.0 fixes long list of vulnerabilities](https://openwall.com/lists/oss-security/2026/10/21/24)
- [Pillow 13.0.0 release notes](https://github.com/python-pillow/Pillow/blob/main/docs/releasenotes/13.0.0.rst)
- [Pillow security handbook](https://pillow.readthedocs.io/en/stable/handbook/security.html)

## Pillow know before you run it

- **This is a check, not a fix.** Update Pillow to 13.0.0, which fixes both flaws.
- **CVE-2026-112900 needs Ghostscript.** The EPS bug passes a filename to the `gs` binary, so the script reports whether Ghostscript is installed. Command execution needs the attacker to control the filename and the referenced text file.
- **It reads installed metadata and lock files.** It finds Pillow in Python environments (`dist-info` and `egg-info`) and in lock files and compares versions.
- **There is no hunt.** No indicators of exploitation have been published.
- **It also reads running containers.** With no directory argument and `SCAN_CONTAINERS=1` (the default), a read-only probe inside each running docker and podman container finds the installed copies by their `dist-info` and `egg-info` directories and the lock and requirements files that mention the package, and copies only those names and files into a private temporary directory, which the normal check then judges. Whether Ghostscript is installed decides if the EPS flaw (CVE-2026-112900) is reachable, so a copy found in a container is judged by *that container's* `gs`, not the host's. A staged symlink is never kept and the copies are removed on exit. A path shown as `.../docker_NAME/PATH` is the PATH inside the container NAME. It is skipped when you name directories yourself.

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
