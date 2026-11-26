# Pillow 13.0.0: CVE-2026-96639 and CVE-2026-112900 check

Part of the [PrivacySafe Security Patches](../../README.md) collection.

<a name="pillow-13-security-release-check"></a>

## Pillow 13.0.0 security release check

**Script:** [`system/pillow/pillow-oct2026-check.sh`](pillow-oct2026-check.sh)

Pillow is one of the most widely installed imaging libraries for Python: web uploads, thumbnails, document pipelines, machine-learning data loaders. Pillow 13.0.0, announced on oss-security on 21 October 2026, fixes a long list of memory-safety and parsing bugs. This tool covers two of them. The release notes list many more, including JPEG decoder overflows, TIFF encoder overflows and PDF parsing problems, and all of them are fixed by the same upgrade.

| | CVE-2026-96639 | CVE-2026-112900 |
|---|---|---|
| What | Stale native image storage reused after a mode transition. A multi-frame file can keep an allocation made for a narrow frame mode while a later frame of the same size switches to wider RGB or CMYK data, so pixels are written past the allocation | `EpsImagePlugin` passes the caller-supplied filename after `-f` to Ghostscript without making it an absolute path. A name that starts with a hyphen is read as a Ghostscript option, and a name that starts with `@` names an argument file |
| Affected | 11.0.0 up to 13.0.0 | 2.6.0 up to 13.0.0 |
| Fixed | 13.0.0 | 13.0.0 |
| Files | Crafted PSD, MPO, DCX or MIC files | EPS input, or any call that hands Pillow an attacker-chosen filename |
| Impact | Native out-of-bounds writes and crashes. The MPO path can also read out of bounds and, in demonstrated runtime-specific profiles, run commands | Option injection into Ghostscript. Command execution needs the attacker to control the filename and the text file it names; the reported chain works with the default `-dSAFER` |
| Severity | 9.8 Critical | Listed as 9.2 Critical |

## Older and distribution-packaged Pillow

Pillow 13.0.0 fixed far more than the two flaws above, and many of them reach releases much older than 2.6.0. Ubuntu backported 39 of them in [USN-9064-1](https://ubuntu.com/security/notices/USN-9064-1) on 12 November 2026, for every supported release and, through Ubuntu Pro, down to the 14.04 build of Pillow 2.3.0. Three are heap writes that can run code: CVE-2026-112393 (saving compressed TIFF data), CVE-2026-112398 (the FlashPix JPEG tile decoder) and CVE-2026-112403 (the JPEG decoder at a requested draft scale). For that reason the script reports every copy older than 13.0.0, whatever its age, and treats a package changelog that names any of these, or either CVE above, as a sign that the distribution backported the fixes.

[USN-9064-2](https://ubuntu.com/security/notices/USN-9064-2) followed on 16 November: the first update's fix for CVE-2026-112402 broke resizing with the `NEAREST` filter and resizing of mode `1` and `P` images. Install both.

| Ubuntu release | Fixed `python3-pil` (USN-9064-1) |
|---|---|
| 26.10 | 12.3.0-1ubuntu2 |
| 26.04 LTS | 12.1.1-2ubuntu1.5 |
| 24.04 LTS | 10.2.0-1ubuntu1.5 |
| 22.04 LTS | 9.0.1-1ubuntu0.7 |
| 18.04 LTS (Ubuntu Pro) | 5.1.0-1ubuntu0.8+esm3 |
| 16.04 LTS (Ubuntu Pro) | 3.1.2-0ubuntu1.6+esm4 |
| 14.04 LTS (Ubuntu Pro, Legacy add-on) | 2.3.0-1ubuntu3.4+esm6 |

20.04 LTS is in the same notice; take its version from the notice itself. A copy installed with `pip` inside a virtual environment is not touched by any distribution update and needs `pip install --upgrade 'Pillow>=13.0.0'`, or a Python version that 13.x supports.

## Quick start

1. Download the script. The repository is mirrored on GitHub and Codeberg; pick a base URL.

   ```bash
   # BASE from GitHub:   https://raw.githubusercontent.com/PrivacySafe/security-patches/refs/heads/main
   # BASE from Codeberg: https://codeberg.org/PrivacySafe/security-patches/raw/branch/main
   # curl -fLO "$BASE/system/pillow/pillow-oct2026-check.sh"
   curl -fLO https://raw.githubusercontent.com/PrivacySafe/security-patches/refs/heads/main/system/pillow/pillow-oct2026-check.sh
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

Exit codes: `0` nothing affected, `1` an affected version, a version that cannot be parsed, or a copy older than 2.6.0 (outside both CVEs, but not confirmed clear of Pillow's many other fixes) was found, `2` bad arguments.

## How to read the result

- Both bugs apply: the version is in both ranges. If `gs` is installed the script prints a critical line for CVE-2026-112900 as well.
- Affected by CVE-2026-112900 but no `gs`: the script prints a warning and says the EPS path is inert on this host. The script still exits `1`, because the same Pillow version is affected by the other fixes in 13.0.0.
- Lock file pins describe what would be installed, not what is running. A pin points to what to fix. Check the running server for exposure.
- `pillow-heif` and other packages that merely start with "pillow" are not matched.
- Distribution packages. For copies owned by a `dpkg` or `rpm` package the script reads the package changelog and reports a mention of either CVE, because distributions backport fixes without changing the version string.

## Fixing it

```bash
pip install --upgrade 'Pillow>=13.0.0'
```

Check that your Python version is supported by Pillow 13.x before you pin it. Rebuild container images, and restart long-running workers, because a running process keeps the old library loaded.

If you cannot upgrade yet:

- CVE-2026-96639: open untrusted files with an allowlist of formats, for example `Image.open(f, formats=["JPEG", "PNG", "GIF", "WEBP"])`, which keeps PSD, MPO, DCX and MIC out. Pillow's own security guidance recommends this approach.
- CVE-2026-112900: reject EPS input, or reject any filename that starts with `-` or `@` before it reaches Pillow, or remove Ghostscript from hosts that do not need it. Pillow's guidance also recommends blocking EPS at the application boundary.
- For both, run image processing in a sandbox without network access and without sensitive mounts.

## Sources

- [oss-security: Pillow 13.0.0 fixes long list of vulnerabilities](https://openwall.com/lists/oss-security/2026/10/21/24)
- [Pillow 13.0.0 release notes](https://github.com/python-pillow/Pillow/blob/main/docs/releasenotes/13.0.0.rst)
- [Pillow security handbook](https://pillow.readthedocs.io/en/stable/handbook/security.html)

## Before you run it

- The fix. Update Pillow to 13.0.0, which fixes both flaws.
- CVE-2026-112900 needs Ghostscript. The EPS bug passes a filename to the `gs` binary, so the script reports whether Ghostscript is installed. Command execution needs the attacker to control the filename and the referenced text file.
- It reads installed metadata and lock files. It finds Pillow in Python environments (`dist-info` and `egg-info`) and in lock files and compares versions.
- There is no hunt. No indicators of exploitation have been published.
- It also checks running docker and podman containers, unless you name a directory or set `SCAN_CONTAINERS=0`. In each running container, a read-only probe finds the installed copies by their `dist-info` and `egg-info` folders, plus the lock and requirements files that mention the package. It copies only those names and files into a private temporary folder, and the normal check judges that folder. Whether Ghostscript is installed decides if the EPS flaw (CVE-2026-112900) is reachable, so a copy found in a container is judged by *that container's* `gs`, not the host's. A staged symlink is never kept and the copies are removed on exit. A path shown as `.../docker_NAME/PATH` is the PATH inside the container NAME. It is skipped when you name directories yourself.

<!-- rhsa:begin (generated by packaging/rhsa/rhsa.py from Red Hat's advisory list: edit placement.json or the data, not this block) -->
## Red Hat advisories

Red Hat's advisory list (security advisories released 2026-04-01 to 2026-11-25) names the CVEs below. A Red Hat build is judged by its RPM release, not by the upstream version number, because Red Hat backports fixes: the advisory names the release that fixes it. A CVE with no advisory in the list has none for that period, which is not the same as not affected. The current state is on [Red Hat's CVE database](https://access.redhat.com/security/security-updates/#/cve).

| Advisory | Released | Severity | Package and stream | CVEs on this page |
|---|---|---|---|---|
| [RHSA-2026:92861](https://access.redhat.com/errata/RHSA-2026:92861) | 2026-10-29 | Critical | `openvox-agent-8.31.1-1.el9sat` (RHEL 9 (el9sat)); `openvox-server-8.17.0-1.el9sat` (RHEL 9 (el9sat)); `python3.12-django-4.2.30-3.el9pc` (RHEL 9 (el9pc)); and 6 more | CVE-2026-112403 |
| [RHSA-2026:93077](https://access.redhat.com/errata/RHSA-2026:93077) | 2026-10-30 | Critical | `python-pillow-5.1.1-36.el8_10` (RHEL 8.10) | CVE-2026-112900 |
| [RHSA-2026:94702](https://access.redhat.com/errata/RHSA-2026:94702) | 2026-11-03 | Critical | `rhaii/vllm-cpu-rhel9` (container image) | CVE-2026-96639, CVE-2026-112403, CVE-2026-112900 |
| [RHSA-2026:94709](https://access.redhat.com/errata/RHSA-2026:94709) | 2026-11-03 | Critical | `rhaii/vllm-rocm-rhel9` (container image) | CVE-2026-96639, CVE-2026-112403, CVE-2026-112900 |
| [RHSA-2026:94715](https://access.redhat.com/errata/RHSA-2026:94715) | 2026-11-03 | Critical | `rhaii/model-opt-cuda-rhel9` (container image) | CVE-2026-96639, CVE-2026-112403, CVE-2026-112900 |
| [RHSA-2026:94717](https://access.redhat.com/errata/RHSA-2026:94717) | 2026-11-03 | Critical | `rhaii/vllm-spyre-rhel9` (container image) | CVE-2026-96639, CVE-2026-112403, CVE-2026-112900 |
| [RHSA-2026:94721](https://access.redhat.com/errata/RHSA-2026:94721) | 2026-11-03 | Critical | `rhaii/vllm-gaudi-rhel9` (container image) | CVE-2026-96639, CVE-2026-112403, CVE-2026-112900 |
| [RHSA-2026:94738](https://access.redhat.com/errata/RHSA-2026:94738) | 2026-11-03 | Critical | `rhaii/vllm-cuda-rhel9` (container image) | CVE-2026-96639, CVE-2026-112403, CVE-2026-112900 |
| [RHSA-2026:95655](https://access.redhat.com/errata/RHSA-2026:95655) | 2026-11-05 | Critical | `python-django-4.2.30-2.el8pc` (RHEL 8 (el8pc)); `python-brotli-1.2.1-1.el8pc` (RHEL 8 (el8pc)); `python-urllib3-2.8.0-1.el8pc` (RHEL 8 (el8pc)); and 19 more | CVE-2026-112403 |
| [RHSA-2026:95656](https://access.redhat.com/errata/RHSA-2026:95656) | 2026-11-05 | Critical | `python-django-4.2.30-2.el9pc` (RHEL 9 (el9pc)); `python-brotli-1.2.1-1.el9pc` (RHEL 9 (el9pc)); `python-urllib3-2.8.0-1.el9pc` (RHEL 9 (el9pc)); and 5 more | CVE-2026-112403 |
| [RHSA-2026:95657](https://access.redhat.com/errata/RHSA-2026:95657) | 2026-11-05 | Critical | `python3.12-pillow-13.0.0-1.el9pc` (RHEL 9 (el9pc)); `python3.12-gitpython-3.2.1-1.el9pc` (RHEL 9 (el9pc)); `python3.12-urllib3-2.8.0-1.el9pc` (RHEL 9 (el9pc)); and 6 more | CVE-2026-112403 |
| [RHSA-2026:95872](https://access.redhat.com/errata/RHSA-2026:95872) | 2026-11-06 | Critical | `rhoai/odh-cli-rhel9` (container image); `rhoai/odh-ai-gateway-operator-rhel9` (container image); `rhoai/odh-ai-gateway-payload-processing-rhel9` (container image); and 116 more | CVE-2026-96639, CVE-2026-112403 |
| [RHSA-2026:96323](https://access.redhat.com/errata/RHSA-2026:96323) | 2026-11-09 | Critical | `rhelai3/disk-image-cuda-rhel9` (container image) | CVE-2026-96639, CVE-2026-112403, CVE-2026-112900 |
| [RHSA-2026:96333](https://access.redhat.com/errata/RHSA-2026:96333) | 2026-11-09 | Critical | `rhelai3/bootc-cuda-rhel9` (container image); `rhelai3/bootc-aws-cuda-rhel9` (container image); `rhelai3/bootc-azure-cuda-rhel9` (container image); and 3 more | CVE-2026-96639, CVE-2026-112403, CVE-2026-112900 |
| [RHSA-2026:96400](https://access.redhat.com/errata/RHSA-2026:96400) | 2026-11-09 | Critical | `rhaiis/vllm-rocm-rhel9` (container image) | CVE-2026-96639, CVE-2026-112403, CVE-2026-112900 |
| [RHSA-2026:96403](https://access.redhat.com/errata/RHSA-2026:96403) | 2026-11-09 | Critical | `rhaiis/model-opt-cuda-rhel9` (container image) | CVE-2026-96639, CVE-2026-112403, CVE-2026-112900 |
| [RHSA-2026:96406](https://access.redhat.com/errata/RHSA-2026:96406) | 2026-11-09 | Critical | `rhaiis/vllm-cuda-rhel9` (container image) | CVE-2026-96639, CVE-2026-112403, CVE-2026-112900 |
| [RHSA-2026:98109](https://access.redhat.com/errata/RHSA-2026:98109) | 2026-11-11 | Critical | `python-pillow-5.1.1-20.el8_8.2` (RHEL 8.8) | CVE-2026-112900 |
| [RHSA-2026:98111](https://access.redhat.com/errata/RHSA-2026:98111) | 2026-11-11 | Critical | `python-pillow-5.1.1-20.el8_6.2` (RHEL 8.6) | CVE-2026-112900 |
| [RHSA-2026:98120](https://access.redhat.com/errata/RHSA-2026:98120) | 2026-11-11 | Critical | `python-pillow-5.1.1-15.el8_4.3` (RHEL 8.4) | CVE-2026-112900 |
| [RHSA-2026:100634](https://access.redhat.com/errata/RHSA-2026:100634) | 2026-11-19 | Critical | `rhoai/odh-built-in-detector-rhel9` (container image); `rhoai/odh-caikit-nlp-rhel9` (container image); `rhoai/odh-caikit-tgis-serving-rhel9` (container image); and 69 more | CVE-2026-112403 |
| [RHSA-2026:100715](https://access.redhat.com/errata/RHSA-2026:100715) | 2026-11-19 | Important | `ansible-creator-26.11.0-1.el9ap` (RHEL 9 (el9ap)); `ansible-core-2.16.20-1.el9ap` (RHEL 9 (el9ap)); `ansible-dev-tools-26.11.0-1.el9ap` (RHEL 9 (el9ap)); and 39 more | CVE-2026-112403 |
| [RHSA-2026:102223](https://access.redhat.com/errata/RHSA-2026:102223) | 2026-11-23 | Critical | `exploit-intelligence/agent-client-rhel9` (container image); `exploit-intelligence/vulnerability-analysis-rhel9` (container image) | CVE-2026-96639, CVE-2026-112403, CVE-2026-112900 |
| [RHSA-2026:103383](https://access.redhat.com/errata/RHSA-2026:103383) | 2026-11-24 | Critical | `rhoai/odh-autorag-rhel9` (container image); `rhoai/odh-ai-gateway-operator-rhel9` (container image); `rhoai/odh-ai-gateway-payload-processing-rhel9` (container image); and 116 more | CVE-2026-112900 |

- [CVE-2026-112393](https://access.redhat.com/security/cve/CVE-2026-112393): 23 advisories, 2026-10-29 to 2026-11-23; 22 critical, 1 important; by stream, RHEL 8 4, RHEL 8 (el8pc) 1, RHEL 9 (el9ap) 1, RHEL 9 (el9pc) 2, RHEL 9 (el9sat) 1, container image 14; most often `python-pillow` (4), `python-django` (2), `openvox-agent` (1), `rhaii/vllm-cpu-rhel9` (1). All of them: [Red Hat's CVE page](https://access.redhat.com/security/cve/CVE-2026-112393).
- [CVE-2026-112398](https://access.redhat.com/security/cve/CVE-2026-112398): 23 advisories, 2026-10-29 to 2026-11-23; 22 critical, 1 important; by stream, RHEL 8 4, RHEL 8 (el8pc) 1, RHEL 9 (el9ap) 1, RHEL 9 (el9pc) 2, RHEL 9 (el9sat) 1, container image 14; most often `python-pillow` (4), `python-django` (2), `openvox-agent` (1), `rhaii/vllm-cpu-rhel9` (1). All of them: [Red Hat's CVE page](https://access.redhat.com/security/cve/CVE-2026-112398).

<!-- rhsa:end -->

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
