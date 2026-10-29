# Apache Traffic Server: CVE-2026-111813 and CVE-2026-111811 experimental plugins

Part of the [PrivacySafe Security Patches](../README.md) collection.

<a name="trafficserver-check"></a>

## Apache Traffic Server check

**Script:** [`trafficserver/trafficserver-check.sh`](trafficserver-check.sh)

Apache Traffic Server (ATS) is a caching reverse and forward proxy used in front of large sites and CDNs. Its October 2026 security release fixes **15 vulnerabilities**. Two of them are in *experimental plugins* and are the severe ones:

| | CVE-2026-111813 | CVE-2026-111811 |
|---|---|---|
| Plugin | `magick` | `tsmemcache` |
| What | Passes client query strings unfiltered to ImageMagick's `convert` in its **default (unsigned) configuration**, so an unauthenticated client controls `convert`'s arguments: command and argument injection | Exposes the shared proxy cache over the network with **no authentication**: unauthenticated read, write and deletion of the cache |
| Severity | **Critical, CVSS 10.0** | CVSS 9.0 by Apache's rating (Moderate on their scale); some aggregators list 9.4 Critical |
| Needs | The `magick` plugin loaded, and no signing configured | The `tsmemcache` plugin loaded |

| | |
|---|---|
| Affected | 8.0.0 through 8.1.11, 9.0.0 through 9.2.15, 10.0.0 through 10.1.4, and 10.2.0 (the `magick` plugin from 8.0.1) |
| Fixed | **9.2.16, 10.1.5 and 10.2.1**, released 20 October 2026 |
| No fix | **8.x, 9.0, 9.1 and 10.0 are end-of-life branches** that Apache does not patch: move to a fixed branch |
| Same release | Thirteen other flaws (request smuggling, cache poisoning, denial of service) that only the update fixes |

**Both flaws only matter when the plugin is loaded.** The plugins are experimental and not enabled by default. So the tool reads the **configuration** (`plugin.config` and the remap files) for `magick.so` and `tsmemcache.so` rather than looking for files. This matters: on a typical Ubuntu host the only `magick.so` on disk is an *ImageMagick coder*, not the ATS plugin, and a check that merely searched for the file would give a false alarm.

## Quick start

1. Download the script. The repository is mirrored on GitHub and Codeberg; pick a base URL.

   ```bash
   # BASE from GitHub:   https://raw.githubusercontent.com/PrivacySafe/security-patches/refs/heads/main
   # BASE from Codeberg: https://codeberg.org/PrivacySafe/security-patches/raw/branch/main
   # curl -fLO "$BASE/trafficserver/trafficserver-check.sh"
   curl -fLO https://raw.githubusercontent.com/PrivacySafe/security-patches/refs/heads/main/trafficserver/trafficserver-check.sh
   ```

2. Read it before running it, then make it executable.

   ```bash
   less trafficserver-check.sh
   chmod +x trafficserver-check.sh
   ```

3. Check this host. It finds `traffic_server` on `PATH`, in the usual locations and from running processes, and reads the configuration directory (`/etc/trafficserver` and the other usual places). To point it elsewhere, set `ATS_CONFIG_DIR`.

   ```bash
   ./trafficserver-check.sh check
   ATS_CONFIG_DIR=/opt/ts/etc/trafficserver ./trafficserver-check.sh check
   ```

## Commands

| Command | What it does |
|---|---|
| `check [BINARY ...]` (default) | Reads the version from `traffic_server -V`, applies the ranges, checks the owning package's changelog for a backport, and scans `plugin.config`, `remap.config`, `remap.yaml`, `plugin.yaml` and the other `*.config` and `*.yaml` files in the configuration directory for the two plugins. Comments are ignored |
| `version` | Prints the script version |

Environment: `ATS_CONFIG_DIR` (space separated directories) replaces configuration discovery.

Exit codes: `0` nothing exposed, `1` an affected version loads one of the plugins, or its configuration could not be read, `2` bad arguments.

## How to read the result

- **Affected version, plugin loaded:** exposed. The script prints the file and line number. Upgrade, and remove the plugin line until you have.
- **Affected version, neither plugin loaded:** exit `0`: these two flaws are not reachable. The script still warns to update, because the same release fixes thirteen other flaws.
- **End-of-life branch (8.x, 9.0, 9.1, 10.0):** always reported as in the affected range with no upstream fix. With neither plugin loaded it exits `0` but tells you to plan the move.
- **Configuration directory not found or unreadable:** treated as exposed.
- **The plugin name must match exactly.** `libmagick.so`, `notmagick.so` and `xtsmemcache.so` are not the plugins and are not matched; a full path such as `/opt/ts/libexec/trafficserver/magick.so` is.
- **Distribution packages** often backport fixes without changing the version, so the script reads the package changelog for a mention of either CVE.

## Fixing it

Upgrade to 9.2.16, 10.1.5 or 10.2.1, or to a distribution build that carries the fix, and restart Traffic Server. Until then, remove `magick.so` and `tsmemcache.so` from `plugin.config` and the remap files and restart. That is our reasoning, not the vendor's; neither plugin is enabled by default and both are experimental.

## Sources

- [Apache Traffic Server October 2026 CVE release](https://trafficserver.apache.org/security-2026-10.html)
- [Apache announcement: multiple vulnerabilities fixed in 9.2.16, 10.1.5 and 10.2.1](https://lists.apache.org/thread/r95dq29ywcd1f4x30snxlqmb12z4s4kc)

## Apache Traffic Server know before you run it

- **This is a check, not a fix.** Update to 9.2.16, 10.1.5 or 10.2.1. The 8.x, 9.0, 9.1 and 10.0 branches are end of life and not patched: move to a fixed branch.
- **Both severe flaws are in experimental plugins and only matter when the plugin is loaded** (`magick` for CVE-2026-111813, `tsmemcache` for CVE-2026-111811). The script reads the configuration to see whether it is. The October release fixes 15 vulnerabilities in all; only these two are covered, and the other thirteen (request smuggling, cache poisoning, denial of service) are fixed only by the update.
- **It reads the configuration, not the files.** The script looks in `plugin.config` and the remap files for `magick.so` and `tsmemcache.so`, because the plugins are experimental and not enabled by default, and a `magick.so` on disk can just as well be an ImageMagick coder. It also reads the version from `traffic_server -V` and checks the owning package's changelog for a backported fix.
- **There is no hunt.** No indicators of exploitation have been published.
- **It also reads running containers.** With no argument and `SCAN_CONTAINERS=1` (the default), a read-only probe inside each running docker and podman container captures the output of `traffic_server -V` and the configuration files with every line that does not load `magick.so` or `tsmemcache.so` blanked inside the container, so remap tokens and other credentials never leave it while line numbers stay exact. The script then runs once per container in isolation. A path shown as `.../docker_NAME/...` is inside the container NAME.

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
