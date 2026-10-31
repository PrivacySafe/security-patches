# Linux kernel: ebtables SNAT (CVE-2026-53266) and the local root quartet

Part of the [PrivacySafe Security Patches](../README.md) collection.

<a name="linux-kernel-check"></a>

## Linux kernel ebtables SNAT check

**Script:** [`linux-kernel/linux-kernel-check.sh`](linux-kernel-check.sh)

CVE-2026-53266 is an out-of-bounds write in the bridge netfilter ebtables SNAT target. CISA added it to its Known Exploited Vulnerabilities catalog on 18 September 2026 with a three-day federal deadline, and Red Hat confirmed exploitation.

| | |
|---|---|
| CVE | CVE-2026-53266 (CWE-787) |
| Severity | 8.8 High (NVD, CVSS 3.1); Red Hat scores it 7.5 |
| Requires | A local user with `CAP_NET_ADMIN` who can reach the ebtables SNAT ARP rewrite path |
| Impact | Memory corruption, a crash, or privilege escalation to root |
| Fixed in the stable kernels | 5.10.259, 5.15.210, 6.1.176, 6.6.143, 6.12.94, 6.18.36, 7.0.13 |
| Vendor backport | End-of-life branches such as 5.4 are fixed by a vendor backport |

## How the flaw works

When an ebtables SNAT rule uses the ARP rewrite option (`--snat-arp`), the target writes the new hardware address into the ARP header of the packet with `skb_store_bits()`. The option exists in both the legacy `ebtables` and the nft-based `ebtables-nft` tool, which describes it as "also change src address in arp msg". The vulnerable code did not first make that range of the socket buffer writable, so the write could land in a fragment backed by memory the kernel did not own at that moment, for example a page imported from a file by `splice`. The fix calls `skb_ensure_writable()` on the range before the write.

## Why the script reads the kernel's origin first

The upstream patch level is visible in the release string only on kernels that follow the stable series (vanilla builds, Arch, Alpine, most custom kernels). Debian carries it in `uname -v`. Ubuntu, RHEL and its derivatives, SUSE and Amazon Linux backport fixes under release strings that do not say which fixes they contain (for example `6.8.0-45-generic` or `5.14.0-503.el9`), so a number taken from them cannot be compared with the table above. A script that did would mark nearly every distribution kernel as vulnerable.

| Origin | How the script judges it |
|---|---|
| Stable series (vanilla, Arch, Alpine, custom) | The upstream version against the table. End-of-life branches are reported as having no upstream fix |
| Debian | The upstream version from `uname -v` against the table, then the changelog for a backport |
| Ubuntu, RHEL family, SUSE, Amazon | The vendor changelog must name CVE-2026-53266. When it does not, the result is a pointer to the vendor's tracker, not a claim that the kernel is vulnerable |

A stable release candidate (`7.0.13-rc1`) comes before the release it leads to and may not carry the fix, so it is judged as the release before it (7.0.12). A mainline candidate of a newer series (`7.1.0-rc3`) is judged by its series.

## Quick start

```bash
curl -fLO https://raw.githubusercontent.com/PrivacySafe/security-patches/refs/heads/main/linux-kernel/linux-kernel-check.sh
less linux-kernel-check.sh
chmod +x linux-kernel-check.sh
./linux-kernel-check.sh check
```

## Commands

| Command | What it does |
|---|---|
| `check` (default) | Reads the running kernel, judges it as above, and reports exposure information. Exit `0` the kernel has the fix or a vendor backport, `1` affected or unconfirmed |
| `version` | Prints the script version |

Env: `KERNEL_CHANGELOG` (a vendor changelog to read, plain or `.gz`), and `KERNEL_RELEASE`, `KERNEL_VERSION_STRING`, `KERNEL_MODULES_FILE` and `KERNEL_PROC_SYS` to override `uname -r`, `uname -v`, `/proc/modules` and `/proc/sys`.

## Exposure information

The script also reports ebtables SNAT rules (and whether any uses `--snat-arp`), whether the `ebt_snat` module is loaded or loadable, and whether unprivileged user namespaces are allowed. Read these carefully: seeing no such rule on the host does **not** make a kernel safe. A local user with `CAP_NET_ADMIN` inside a user namespace may be able to create a rule in their own network namespace. That reading is the project's, so the lines are information and do not change the exit code.

## Update

Install your vendor's fixed kernel and reboot. Upstream fixes are 5.10.259, 5.15.210, 6.1.176, 6.6.143, 6.12.94, 6.18.36 and 7.0.13.

Until you can, PrivacySafe suggests the following. Remove ebtables SNAT rules that use `--snat-arp`. Where `ebt_snat` is not needed, prevent the module from loading. Where unprivileged user namespaces are not needed, disable them. Each of these may affect other software, so apply them with care.

## Sources

- [CISA alert, 18 September 2026](https://www.cisa.gov/news-events/alerts/2026/09/18/cisa-adds-two-known-exploited-vulnerabilities-catalog)
- [The Hacker News: three Linux kernel flaws exploited](https://thehackernews.com/2026/09/cisa-flags-three-linux-kernel.html)
- [Fixed versions and mitigation summary](https://aicybr.com/blog/cisa-kev-linux-kernel-cve-2025-39964-2026-53266-2025-39682)
- [`net/bridge/netfilter/ebt_snat.c` in the Linux kernel](https://github.com/torvalds/linux/blob/master/net/bridge/netfilter/ebt_snat.c)
- [`extensions/libebt_snat.c` in iptables (the `--snat-arp` option)](https://git.netfilter.org/iptables/tree/extensions/libebt_snat.c)

---

## Before you run it

- These are checks, not fixes, and the fix needs a reboot. The checks judge the running kernel. Update to your vendor's fixed kernel and reboot. A container shows the host's kernel, so run them on the host.
- A vendor kernel's number does not show its fixes. Ubuntu, RHEL and its derivatives, SUSE and Amazon Linux backport fixes under release strings that do not say which they carry. For those the script reads the vendor changelog for each CVE and points you to the vendor's tracker when a CVE is absent.
- The quartet is judged flaw by flaw. Each of the four has its own fixed release per branch, so 6.12.105 can have two of the four fixes and not the other two. Branches with no upstream fix (for example 5.4) need a vendor kernel.
- Exposure lines are information, not a verdict. A kernel below its fixed release is affected whatever the module and user-namespace lines show. No ebtables rule does not make the ebtables kernel safe, since a local user with `CAP_NET_ADMIN` in a user namespace may be able to create one.
- The protective measures are PrivacySafe's. The ebtables suggestions are the project's, and the quartet's (disable unprivileged user namespaces, disable unused AH6, TUN, PPPoE and SCTP) are the researcher's from the disclosure. DiagSpill is not stopped by the namespace setting. There is no hunt for either.

---

<a name="linux-kernel-lpe-check"></a>

## Linux kernel local root quartet check

**Script:** [`linux-kernel/linux-kernel-lpe-check.sh`](linux-kernel-lpe-check.sh)

Four local privilege escalation flaws in the Linux kernel were disclosed on the oss-security list on 18 September 2026, after an embargo agreed with the linux-distros list (they were reported to the kernel security team in mid-July). Public proof-of-concept exploits exist for all four. Each takes an unprivileged local user to root on the systems it targets, each can corrupt the host kernel from a container, and the bugs are 10 to 21 years old.

| Name | CVE | Kernel area | Needs | Introduced |
|---|---|---|---|---|
| DirtyAH6 | CVE-2026-80844 | IPsec AH over IPv6 (`ah6`): an out-of-bounds access in `ipv6_rearrange_rthdr()` | Unprivileged user and network namespaces, or `CAP_NET_ADMIN` and `CAP_NET_RAW` over an attacker-controlled network namespace | 2.6.12 |
| TUNderflow | CVE-2026-81000 | TUN/TAP: oversized receive headroom underflows a length and leaves `skb->data` beyond its allocation | Unprivileged user and network namespaces, or `CAP_NET_ADMIN` over one | 4.6 |
| PPPoEject | CVE-2026-68121 | PPPoE: a use after free of the socket-buffer head in `pppoe_sendmsg()` | Unprivileged user and network namespaces, or `CAP_NET_ADMIN` over one | 2.6.12 |
| DiagSpill | CVE-2026-74469 | SCTP: a 16-bit peer transport count wraps to zero and `sctp_diag` copies about 8 MiB past its reply | SCTP and `sctp_diag`; **no user namespace and no capability** | 4.7 |

Two of them can be turned into a remote crash under narrow conditions: DirtyAH6 if the host routes IPv6 and adds an Authentication Header in transport mode, and DiagSpill only with non-default SCTP options (ASCONF with SCTP-AUTH, or `net.sctp.addip_noauth_enable=1`). The researcher showed remote root for DirtyAH6 only in a lab with on-target memory grooming, and sees no path to remote root for DiagSpill.

CVSS scores were not in the sources used for this document, so none is given here. The CVE numbers follow the researcher's own disclosure. A few news write-ups swap the numbers of TUNderflow and PPPoEject.

### Fixed versions

The first stable release of each branch that carries each fix. A branch not in the table (5.11 to 5.14, 5.16 to 6.0, 6.2 to 6.5, 6.7 to 6.11, 6.13 to 6.17, 6.19 to 7.0, and older ones such as 5.4) is affected. The fix there is a vendor kernel or a move to a listed branch.

| Branch | DirtyAH6 | TUNderflow | PPPoEject | DiagSpill |
|---|---|---|---|---|
| 5.10 | 5.10.269 | 5.10.270 | 5.10.265 | 5.10.265 |
| 5.15 | 5.15.220 | 5.15.221 | 5.15.216 | 5.15.216 |
| 6.1 | 6.1.187 | 6.1.188 | 6.1.183 | 6.1.183 |
| 6.6 | 6.6.156 | 6.6.157 | 6.6.148 | 6.6.151 |
| 6.12 | 6.12.108 | 6.12.109 | 6.12.101 | 6.12.103 |
| 6.18 | 6.18.49 | 6.18.50 | 6.18.42 | 6.18.44 |
| 7.1 | 7.1.13 | 7.1.14 | 7.1.6 | 7.1.8 |
| 7.2 | 7.2.3 | 7.2.4 | not affected | not affected |

The first stable releases with **all four** fixes are 5.10.270, 5.15.221, 6.1.188, 6.6.157, 6.12.109, 6.18.50 and 7.2.4. Releases of 7.3 and later carry every fix. The table is why a single "newer than X" rule is wrong here: on 6.12, release 6.12.105 has the PPPoEject and DiagSpill fixes but still lacks the other two.

### How the script judges the kernel

It reads the kernel's origin first, exactly as the ebtables check above does. A kernel that follows the stable series (vanilla, Arch, Alpine, most custom builds) is judged on the upstream version in `uname -r`. Debian's upstream version is read from `uname -v`. A stable release candidate such as `6.12.109-rc1` is judged as the release before it. Ubuntu, RHEL and its derivatives, SUSE and Amazon Linux backport fixes under release strings that do not show which fixes they carry, so a number from them cannot be compared with the table. For those the script looks in the vendor changelog for each CVE, and points you to the vendor's tracker when a CVE is absent. A kernel that is below a fixed release but whose changelog names the CVE is reported as carrying a backport.

Each of the four is judged separately, and the verdict names the ones still open.

### Quick start

```bash
curl -fLO https://raw.githubusercontent.com/PrivacySafe/security-patches/refs/heads/main/linux-kernel/linux-kernel-lpe-check.sh
less linux-kernel-lpe-check.sh
chmod +x linux-kernel-lpe-check.sh
./linux-kernel-lpe-check.sh check
```

| Command | What it does |
|---|---|
| `check` (default) | Judges the running kernel against each of the four flaws. Exit `0` the kernel has all four fixes (or vendor backports), `1` it is affected by at least one or a vendor backport could not be confirmed |
| `version` | Prints the script version |

Env: `KERNEL_CHANGELOG` (a vendor changelog file to read, plain or `.gz`), `KERNEL_RELEASE` and `KERNEL_VERSION_STRING` (override `uname -r` and `uname -v`), `KERNEL_MODULES_FILE`, `KERNEL_PROC_SYS` and `KERNEL_BUILTIN_FILE` (override `/proc/modules`, `/proc/sys` and the module list of the release).

A container shows the host's kernel, so run the script on the host.

### Exposure information

For the flaws still open, the script reports whether the module each one needs is loaded, built in or loadable, and whether unprivileged user namespaces are allowed (`user.max_user_namespaces`, `kernel.unprivileged_userns_clone` and `kernel.apparmor_restrict_unprivileged_userns` are read). That is information for you to weigh, not a verdict: a kernel below its fixed release is affected whatever these show, and a process with the right capabilities, such as a container, does not need a user namespace for the first three. That reading is the project's. AppArmor and SELinux did not block the exploits in the researcher's testing, except for Ubuntu's block on unprivileged user namespaces themselves.

### Mitigation: `mitigate`

`./linux-kernel-lpe-check.sh mitigate --dry-run` shows, and `mitigate` applies, the researcher's protective measures. It acts only when `check` finds the kernel affected (`--force` overrides) and you must choose what to apply, because each measure can break software:

| Option | What it does | What it can break |
|---|---|---|
| `--userns` | Stops unprivileged user namespaces with the mildest switch this kernel has: `kernel.unprivileged_userns_clone=0`, else `kernel.apparmor_restrict_unprivileged_userns=1` (restricts, does not fully block). Applied live and written to a `sysctl.d` file. Only with `--force` does it fall back to `user.max_user_namespaces=0` | Rootless containers (podman, rootless docker), flatpak and browser sandboxes. Does **not** stop DiagSpill, which needs no namespace |
| `--modules LIST` | Blocks later loading of the listed modules (`ah6 tun pppoe sctp sctp_diag ebt_snat`, or `all`) with `blacklist` and `install NAME /bin/false` lines in a `modprobe.d` file. A module that is loaded now is left alone unless `--force` (which still only blocks later loads) | `tun`: OpenVPN, Tailscale, QEMU networking. `sctp`: telecom software. `pppoe`: DSL dial-up. `ah6`: IPsec AH. `ebt_snat`: bridge firewalls |

`rollback` restores the saved sysctl values and removes the files. `STATE_DIR`, `SYSCTL_D` and `MODPROBE_D` can be overridden. These are the researcher's measures, applied by PrivacySafe. A patched kernel and a reboot are the permanent fix. The script has been run against simulated `/proc/sys` and module files and in dry-run mode on a kernel.

### There is no hunt

Proof-of-concept code is public for all four, and no indicators of exploitation were published, so the script has no hunt.

### Update

Move to your vendor's kernel that names these CVEs, or to a stable release from the table, and reboot. Until then, the researcher suggests in the disclosure (PrivacySafe applies this): disable unprivileged user namespaces, which removes the ordinary-user path to the first three but can break rootless containers and some sandboxes, and disable AH6, TUN, PPPoE and SCTP with `sctp_diag` where they are not used. A process with the right capabilities, and DiagSpill, are not stopped by the namespace setting.

### Sources

- [oss-security: A quartet of Linux local root vulns (18 September 2026)](https://www.openwall.com/lists/oss-security/2026/09/18/3)
- [The researcher's write-up](https://heyitsas.im/posts/lpe-quartet/)
- [The Hacker News: public exploits released for the four kernel flaws](https://thehackernews.com/2026/09/public-exploits-released-for-four-linux.html)
- Proof-of-concept repositories: [DirtyAH6](https://github.com/manizada/DirtyAH6), [TUNderflow](https://github.com/manizada/TUNderflow), [PPPoEject](https://github.com/manizada/PPPoEject), [DiagSpill](https://github.com/manizada/DiagSpill)

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
