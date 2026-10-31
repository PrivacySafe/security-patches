# HAProxy: CVE-2026-110353 truncated HTTP/2 PING frame

Part of the [PrivacySafe Security Patches](../README.md) collection.

<a name="haproxy-http2-ping-check"></a>

## HAProxy HTTP/2 PING check

**Script:** [`haproxy/haproxy-check.sh`](haproxy-check.sh)

HAProxy's HTTP/2 code does not treat a truncated PING frame as a short read (CVE-2026-110353). A PING frame cannot be used until it is complete, but its presence still wakes the connection up, so the worker thread never goes back to idle. A remote client with no login can open a connection, keep a partial PING frame pending and hold a thread at 100% CPU for as long as the connection stays open or until `timeout http-request` runs out. The vendor rates the impact as moderate, because it depends on how many of your connections look like this.

| | |
|---|---|
| CVE | CVE-2026-110353 (denial of service in `h2c_handle_ping` in `src/mux_h2.c`), published 22 October 2026 |
| Severity | High 7.5 |
| Affected | 3.1.x (end of life), 3.2.x before 3.2.26, 3.3.x before 3.3.17, 3.4.x before 3.4.7. 3.0 and older are outside this CVE's range |
| Fixed | **3.4.7, 3.3.17 and 3.2.26**, all released 14 October 2026 |
| Vendor workaround | Set `timeout http-request` to a low value such as 1 to 5 seconds. It limits CPU consumption, it does not fix the bug |
| Second flaw | The same releases fix a CPU-exhaustion flaw in the HTTP/1 parser (a chunked request with a chunk-size line longer than the buffer). The vendor does not state its affected range, so this tool does not rule out any HTTP-mode HAProxy because of it |

**The CVE text and the vendor disagree, and this tool follows the vendor.** The CVE description says "3.2 before 3.4.6". HAProxy's own release notes say the short-read handling was fixed in 2.5 but PING was missed. They say it only became a problem in 3.1, when the wake-up logic changed, and that the fixes shipped in 3.4.7, 3.3.17 and 3.2.26. So 3.4.6 is not fixed, whatever the CVE description implies.

## Quick start

1. Download the script. The repository is mirrored on GitHub and Codeberg; pick a base URL.

   ```bash
   # BASE from GitHub:   https://raw.githubusercontent.com/PrivacySafe/security-patches/refs/heads/main
   # BASE from Codeberg: https://codeberg.org/PrivacySafe/security-patches/raw/branch/main
   # curl -fLO "$BASE/haproxy/haproxy-check.sh"
   curl -fLO https://raw.githubusercontent.com/PrivacySafe/security-patches/refs/heads/main/haproxy/haproxy-check.sh
   ```

2. Read it before running it, then make it executable.

   ```bash
   less haproxy-check.sh
   chmod +x haproxy-check.sh
   ```

3. Check this host. The script finds HAProxy on `PATH`, in the usual locations and from running processes, and reads the configuration files the running process was started with. To check a specific binary, pass its path.

   ```bash
   ./haproxy-check.sh check
   ./haproxy-check.sh check /opt/haproxy/sbin/haproxy
   ```

## Commands

| Command | What it does |
|---|---|
| `check [BINARY ...]` (default) | Reads the version from `haproxy -v`, applies the vendor's ranges, checks whether the running processes use a binary that was replaced on disk, and reads the configuration for HTTP/2 reachability and the `timeout http-request` value |
| `mitigate [--timeout N] [--disable-h2-upgrade] [--dry-run] [--reload]` | **Changes the host (root).** Applies the vendor's workaround: adds `timeout http-request 5s` (or `N`, 1 to 60) to every `defaults` section that has no such line, and never changes a value you set. `--disable-h2-upgrade` also adds `option disable-h2-upgrade` (PrivacySafe recommendation). It runs `haproxy -c` before and after, copies every file first, and puts the originals back at once if HAProxy rejects the result. Nothing is reloaded unless you add `--reload` (a graceful reload) |
| `rollback [--dry-run] [--reload]` | Puts back every file `mitigate` changed |
| `version` | Prints the script version |

Environment: `HAPROXY_CFG` (space-separated files or directories) replaces configuration discovery. `STATE_DIR` (default `/var/lib/psf-security-patches/haproxy`) holds the backups and the manifest that `rollback` reads.

Exit codes: `0` nothing exposed, `1` an affected version is exposed, its configuration could not be read, or it is on the unfixable 3.1 branch, `2` bad arguments.

## How HTTP/2 becomes reachable, which decides exposure

- TLS listeners offer HTTP/2 only when the `bind` line has `alpn h2`. `proto h2` on a `bind` line forces HTTP/2.
- Clear-text HTTP listeners accept the HTTP/2 preface by default and upgrade the connection, unless the frontend has `option disable-h2-upgrade`. So a plain `bind :80` in `mode http` is reachable over HTTP/2 even though no configuration line says `h2`. This is easy to miss, and the script does not treat "no explicit h2" as safe.
- `alpn h2` on a backend `server` line is HAProxy talking HTTP/2 to your servers. It does not expose the frontend, and the script ignores it.
- Comments are ignored.
- `mode tcp` only: the HTTP/2 multiplexer is not in use, so the script reports no exposure.

The exposure test is a text search of the configuration, not a parse of the live configuration. If HAProxy is built from many included files or generated at runtime, check `haproxy -c -f` output and the running configuration yourself.

## How to read the result

- Affected and exposed: upgrade to 3.2.26, 3.3.17 or 3.4.7 or later, then reload.
- Affected but no HTTP/2 path found: exit `0`. If `mode http` is in use, the script still says the HTTP/1 flaw fixed in the same releases may be reachable, so upgrade anyway.
- 3.1.x: always exit `1`. The branch is end of life: move to a supported branch.
- Development builds (`3.5-dev`) cannot be judged by version. The script asks you to check that the build includes the "properly handle short reads on PING frames" change.
- Distribution packages backport fixes without changing the version. The script reads the package changelog for a mention of the CVE.
- A reload keeps the old binary running in some setups. If a process runs a binary that was replaced on disk, the script says so.

## Fixing it

Upgrade to 3.2.26, 3.3.17 or 3.4.7 or later and reload. Until then, apply the vendor's workaround for the PING flaw with `./haproxy-check.sh mitigate --dry-run` and then `./haproxy-check.sh mitigate --reload`. It limits CPU use while a partial PING frame is pending. It does **not** fix the bug, and it does not change a `timeout http-request` you already set. If you do not need clear-text HTTP/2, adding `option disable-h2-upgrade` to HTTP frontends and removing `h2` from `alpn` lists takes the multiplexer out of reach. That last step is PrivacySafe's recommendation.

Verified on HAProxy 3.1.0, 3.2.0 and 3.4.0 built from source, each with a clear-text listener. The check flagged each one (3.1 as end of life) and `haproxy -c` accepted both added lines. A half-sent request stayed open for the full six seconds before the change and got a `408` after two seconds with `timeout http-request 2s`. `rollback` restored the file exactly and the old behavior.

## Sources

- [HAProxy 3.4.7 announcement](https://mail-archive.com/haproxy@formilux.org/msg47598.html)
- [HAProxy 3.3.17 announcement](https://www.mail-archive.com/haproxy@formilux.org/msg47605.html)
- [HAProxy: option disable-h2-upgrade](https://git01.mediatek.com/plugins/gitiles/haproxy/+/89aed32bfffb5f6f51bdab3e7bd5efc44a9927a1)

## Before you run it

- The fix. Update to 3.4.7, 3.3.17 or 3.2.26. Branch 3.1 is end of life: move to a supported branch.
- Two sources disagree and the script follows the vendor. The CVE description says "3.2 before 3.4.6", but HAProxy's release notes say the bug was introduced in 3.1 and that 3.4.6 is not fixed. HAProxy 3.0 and older are outside this CVE's range.
- Development builds are not judged. For a 3.5 development build, check the commit yourself.
- The impact is a denial of service. A client holding a partial PING frame can keep a worker thread at full CPU until the connection ends or `timeout http-request` expires. There is no hunt.
- It also checks running docker and podman containers, unless you name a directory or set `SCAN_CONTAINERS=0`. A read-only probe inside each running docker and podman container captures the output of `haproxy -v` and the configuration files (with `password` values and `auth user:pass` credentials redacted inside the container before they are copied) into a private temporary directory. The script then runs once per container, in isolation, against that copy, so one container's configuration never changes another's result. Each container is judged by its own configuration only. The copies are removed on exit. A path shown as `.../docker_NAME/...` is inside the container NAME. It is skipped when you name a binary or directory yourself.

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
