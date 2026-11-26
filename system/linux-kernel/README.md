# Linux kernel: ebtables SNAT (CVE-2026-53266) and the local root quartet

Part of the [PrivacySafe Security Patches](../../README.md) collection.

<a name="linux-kernel-check"></a>

## Linux kernel ebtables SNAT check

**Script:** [`system/linux-kernel/linux-kernel-check.sh`](linux-kernel-check.sh)

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
curl -fLO https://raw.githubusercontent.com/PrivacySafe/security-patches/refs/heads/main/system/linux-kernel/linux-kernel-check.sh
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

Commands that change the host need root. Run them with `sudo` from an admin account, not from a root login, so the change is recorded against a person. The script stops and prints the exact command if you forget:

```bash
sudo ./linux-kernel-lpe-check.sh mitigate --userns --dry-run
sudo ./linux-kernel-lpe-check.sh mitigate --userns
sudo ./linux-kernel-lpe-check.sh rollback
```

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


<a name="linux-kernel-ireq-opt-check"></a>

## Linux kernel IPv4 TCP use-after-free (CVE-2026-98432)

**Script:** [`system/linux-kernel/linux-kernel-ireq-opt-check.sh`](linux-kernel-ireq-opt-check.sh)

A race in the Linux kernel's IPv4 TCP handshake, published as CVE-2026-98432 on 15 October 2026 and discussed on oss-security from 30 October to 3 November. `tcp_v4_syn_recv_sock()` hands the request socket's IP options to the child socket without copying them. A retransmitted SYN for the same request socket, handled on another CPU, can still be building a SYNACK from those options when the child socket is destroyed, and `inet_sock_destruct()` and `tcp_v4_reqsk_destructor()` free them with a plain `kfree()` instead of `kfree_rcu()`: a use after free in `ip_options_build()`. Request socket migration (`net.ipv4.tcp_migrate_req=1`, or a `BPF_SK_REUSEPORT_SELECT_OR_MIGRATE` program) reaches the same bug.

The attacker is an unauthenticated peer who sends a SYN that carries IPv4 options, such as Record Route or Timestamp, to any listening TCP port. No account and no user interaction are needed, and a firewall that allows the port does not help. The CVE record scores it 9.8 (Critical). Red Hat first scored it 5.9 (Moderate) and now rates it Critical. AWS's bulletin 2026-160-AWS says researchers have demonstrated unauthenticated remote code execution against a host with a Multipath TCP (MPTCP) listener, that a kernel crash or a disclosure of kernel memory are the other outcomes, and that it had no evidence of exploitation when it last updated the bulletin on 2 November. IPv6 is not affected by this flaw, and kernels before 4.4 are not affected.

Independent, public testing since that bulletin has narrowed the practical picture a little, without changing which kernels are affected. The duplicate SYN and the ACK that races it share one 4-tuple, so a host's normal flow affinity (RSS, RPS, `sk_incoming_cpu`) puts both on the same CPU, where softirqs run one at a time: there is no second CPU left to read the options while the first one frees them, unless something (an oversubscribed or virtualised host, a custom RPS setup, request-socket migration) spreads the two packets across CPUs anyway. One report says it could only reproduce a read of the already-freed memory, on kernel 6.12.112 (the release immediately before the fix, 6.12.113), after steering the two packets to different CPUs by hand; it also found that every cloud and ISP network edge it tried, though not an exhaustive survey and not something this script tests, silently dropped packets that carry IP options, which would stop the triggering SYN from arriving at all. Neither point is a fix or something to rely on, and both can differ on another path or a differently tuned host; the same report also could not get code execution outside an MPTCP listener, matching AWS's bulletin.

| | |
|---|---|
| Affected | Every kernel from 4.4 (commit `079096f103fa`) up to the fixed releases below, on IPv4 |
| Needs | Any reachable IPv4 TCP listener and a SYN with IP options. RCE has been shown only against an MPTCP listener; otherwise a crash |
| Fixed upstream in | 5.10.272, 5.15.223, 6.1.190, 6.6.159, 6.12.113, 6.18.56, 7.2.10 and 7.3 |

### Fixed versions

The first stable release of each branch that carries the fix. A branch not in the table (4.4 to 5.9, 5.11 to 5.14, 5.16 to 6.0, 6.2 to 6.5, 6.7 to 6.11, 6.13 to 6.17, 6.19 to 7.1, and older ones such as 4.14, 4.19 and 5.4) is affected and has no upstream fix. The fix there is a vendor kernel or a move to a listed branch.

| Branch | First fixed release |
|---|---|
| 5.10 | 5.10.272 |
| 5.15 | 5.15.223 |
| 6.1 | 6.1.190 |
| 6.6 | 6.6.159 |
| 6.12 | 6.12.113 |
| 6.18 | 6.18.56 |
| 7.2 | 7.2.10 |
| 7.3 and later | every release |

Vendors that backport, as published on 3 November. These states change daily, so open your vendor's page before you act on this list.

| Vendor | State | Kernel and advisory |
|---|---|---|
| Debian | Fixed | 13 trixie `linux` 6.12.113-1 (DSA-6568-1); 12 bookworm `linux` 6.1.190-1 (DLA-4841-1) and `linux-6.12` 6.12.113-1~deb12u1 (DLA-4850-1) |
| Red Hat | Fixed on 1 to 3 November for ten RHEL streams: 8.4, 8.8, 8.10, 9.2, 9.4, 9.6, 9.8, 10, 10.0 and 10.2, rated Critical for most and Important for 9.8, 10 and 10.2; a reboot is needed. RHEL 7 is not affected. | The advisory and the fixed kernel of each stream are in [Red Hat advisories](#red-hat-advisories) below, for example RHEL 8.10 `4.18.0-553.182.1.el8_10` ([RHSA-2026:93414](https://access.redhat.com/errata/RHSA-2026:93414)), 9.8 `5.14.0-687.64.1.el9_8` ([RHSA-2026:93412](https://access.redhat.com/errata/RHSA-2026:93412)) and 10.2 `6.12.0-211.72.1.el10_2` ([RHSA-2026:93413](https://access.redhat.com/errata/RHSA-2026:93413)). The RHEL 8.8 update services stream has the same update as `4.18.0-477.178.1.el8_8`, which also fixes a separate local privilege escalation in `skb_zerocopy` that has no CVE yet |
| AlmaLinux | Fixed in the production repositories on 2 November for 8, 9 and 10 (the testing repository had it from 30 October, ahead of Red Hat). `sudo dnf clean metadata && sudo dnf upgrade`, then reboot | The same kernel versions as Red Hat's: `4.18.0-553.182.1.el8_10`, `5.14.0-687.64.1.el9_8`, `6.12.0-211.72.1.el10_2`, or higher ([AlmaLinux](https://almalinux.org/blog/2026-10-30-cve-2026-98432/)) |
| Rocky Linux | Check its errata. CIQ publishes a mitigation article for Rocky 8, 9 and 10 | |
| Ubuntu | The generic kernel is in the `-proposed` pocket, an opt-in channel; no date for the regular archive. Older releases and the cloud, FIPS and real-time kernels are pending | 22.04 `5.15.0-203.213`, 24.04 `6.8.0-149.149`, 26.04 `7.0.0-43.43`; 26.10 is fixed in `7.3.0-10.10` ([Canonical](https://ubuntu.com/blog/fixes-available-in-proposed-pocket-for-cve-2026-98432)) |
| Amazon Linux | Fixed for Amazon Linux 2 and 2023, including `kernel6.12` and `kernel6.18` | ALAS2-2026-4065 and others, listed in [AWS's bulletin](https://explore.alas.aws.amazon.com/CVE-2026-98432.html) |
| Oracle Linux, SUSE | Fixed for at least some releases | See their advisories |

Canonical's position is that security updates are the only appropriate mitigation and that switching MPTCP off is not enough on its own. Red Hat says the same of its filter below: it reduces exposure and cannot fully prevent it.

### How the script judges the kernel

It reads the kernel's origin first, exactly as the other kernel checks above do. A kernel that follows the stable series (vanilla, Arch, Alpine, most custom builds) is judged on the upstream version in `uname -r`. Debian's upstream version is read from `uname -v`. A stable release candidate such as `6.12.113-rc1` is judged as the release before it. Ubuntu, RHEL and its derivatives, SUSE and Amazon Linux backport fixes under release strings that do not say which fixes they carry, so for them the vendor changelog is the evidence: the script looks in it for `CVE-2026-98432`, and when it is absent it says so and points you to your vendor's tracker instead of guessing.

### Three kinds of evidence, strongest first

The script never pretends a remote probe or a crash-free host proves a kernel is patched; a race this narrow can stay quiet for a long time on a vulnerable kernel. Instead it ranks the *local* evidence it can gather, strongest to weakest, and the strongest available kind wins:

1. **Static disassembly of the running kernel's own code** (`verify`, and folded automatically into `check` when a debug image is present). `inet_sock_destruct()` and `tcp_v4_reqsk_destructor()` are the two functions the fix changed, and the fix is a one-line change in each: `kfree()` becomes `kvfree_call_rcu()`. Reading which shape a destructor actually has, from a debug image whose build-id matches the running kernel, is not a guess about what the kernel probably does; it is what the kernel's own code does. It is also the only leg that can catch a backport that claims the CVE in its changelog but missed (or mis-happened to include only one of the two changed lines of) the actual fix, or a custom-built kernel with no changelog at all.
2. **The vendor changelog naming the CVE** (`check`, when the running kernel is a vendor build such as Ubuntu or RHEL). A real signal, but it is the *maintainer's own record* of what they backported, not a reading of the code; a changelog entry can be wrong, miscopied between branches, or reused for a kernel that packaged only part of a fix.
3. **The upstream version number** (`check`, on a kernel that follows the stable series). The weakest leg: correct when the kernel truly follows the stable series, meaningless on a vendor kernel whose release string does not say which fixes it carries.

A static verdict overrides a weaker one in either direction: it can tell you a kernel that *looks* patched by its version string still has the pre-fix code, or that one that *looks* affected has already been quietly fixed. `check` reports both legs and says so explicitly when they disagree; it never discards the disagreement silently.

### Getting the kernel's debug image, for `verify`

`verify` needs a debug build of the exact kernel that is running, matched by build-id, so it has something to disassemble:

| Distribution | Command |
|---|---|
| Debian, Ubuntu | `apt install linux-image-$(uname -r)-dbgsym`. Ubuntu's debug packages live in the separate [ddebs.ubuntu.com](http://ddebs.ubuntu.com) archive, not the main one; see the Ubuntu wiki's "DebugSymbolPackages" page to enable it first |
| RHEL, AlmaLinux, Rocky Linux, Fedora | `dnf debuginfo-install kernel` (or `kernel-core`) |
| openSUSE, SUSE | `zypper install kernel-debuginfo` |

`verify` looks in `/usr/lib/debug/boot/vmlinux-$(uname -r)`, `/boot/vmlinux-$(uname -r)` and `/usr/lib/debug/lib/modules/$(uname -r)/vmlinux`; pass `--vmlinux PATH` for anything else. Its build-id is compared against `/sys/kernel/notes`, the running kernel's own: a mismatch means the image is not what is actually running, and the script says so rather than reporting a verdict that would not apply.

### Quick start

```bash
curl -fLO https://raw.githubusercontent.com/PrivacySafe/security-patches/refs/heads/main/system/linux-kernel/linux-kernel-ireq-opt-check.sh
less linux-kernel-ireq-opt-check.sh
chmod +x linux-kernel-ireq-opt-check.sh
./linux-kernel-ireq-opt-check.sh check
```

| Command | What it does |
|---|---|
| `check` (default) | Judges the running kernel. Exit `0` the kernel has the fix (or a vendor backport), `1` it is affected or a vendor backport could not be confirmed. Read-only |
| `verify [--vmlinux PATH]` | Static ground truth: disassembles the two destructors the fix changed from the kernel's own debug image and reports which free call each one has. `check` runs this by itself when it finds a matching image; run it on its own for the install-the-debug-package pointer, or to check an image that is not the running kernel's. Exit `0` patched, `1` vulnerable, `2` no usable image, or the two functions disagree. Read-only |
| `hunt` | Reads the kernel log (`dmesg`, the journal's kernel messages, and the rotated `kern.log`, `syslog` and `messages` files under `/var/log`) for the crash side of the flaw: a call trace through `ip_options_build`, `ip_build_and_send_pkt`, `tcp_v4_send_synack`, `tcp_v4_reqsk_destructor` or `inet_sock_destruct`, or a `skb_under_panic`. Exit `0` nothing in the logs that were read, `1` hits, `2` no log could be read or one could not. Read-only |
| `mitigate [--mptcp] [--ip-options] [--modules LIST] [--force] [--dry-run]` | **Changes the host (root).** Reductions, not a fix; see below |
| `rollback [--dry-run]` | Restores the saved sysctl values and removes the files and the packet filter `mitigate` wrote |
| `version` | Prints the script version |

Env: `KERNEL_CHANGELOG` (a vendor changelog file to read, plain or `.gz`), `KERNEL_RELEASE` and `KERNEL_VERSION_STRING` (override `uname -r` and `uname -v`), `KERNEL_VMLINUX_FILE` (a debug image for `verify`, instead of looking in the usual places), `KERNEL_NOTES_FILE` (instead of `/sys/kernel/notes`, for the running kernel's build-id), `KERNEL_MODULES_FILE`, `KERNEL_PROC_SYS` and `KERNEL_BUILTIN_FILE` (override `/proc/modules`, `/proc/sys` and the module list of the release), `KERNEL_LOG_FILES` (the log files `hunt` reads, instead of the defaults), `KERNEL_INSTALLED_RELEASES` (the installed kernel releases, instead of `/lib/modules`), `OS_RELEASE_FILE`, and `STATE_DIR`, `SYSCTL_D` and `MODPROBE_D` for `mitigate` and `rollback`.

A container shows the host's kernel, so run the script on the host.

### Exposure information

While the kernel is affected, `check` reports whether MPTCP is on (`net.mptcp.enabled`) and whether the `mptcp` module is built in, loaded or loadable, how many MPTCP sockets and how many IPv4 TCP listeners that are not on loopback exist, whether `net.ipv4.tcp_migrate_req` is set, and whether a filter that drops TCP packets with IP options is in place. That is information for you to weigh, not a verdict: a kernel below its fixed release is affected whatever these show. Go programs built with Go 1.24 or later listen with MPTCP by default when the kernel allows it, and `GODEBUG=multipathtcp=0` turns that off for one program (under systemd, `Environment=GODEBUG=multipathtcp=0` in a drop-in; merge it into any `GODEBUG` the unit already sets). A `godebug multipathtcp=0` line in the `go.mod` of a program you build does the same, and a program whose `go.mod` declares an older Go keeps MPTCP off. A program that asks for MPTCP in code is not changed by the variable. The kernel default decides the rest: the RHEL family builds ship `net.mptcp.enabled=0` (AlmaLinux says so, and Rocky 9 and 10 report it), Debian and Ubuntu kernels ship 1, so a Go service is an MPTCP listener on Debian and Ubuntu and plain TCP on a stock Rocky host.

#### Finding MPTCP listeners

`ss -M -l -n -p` lists them, and `ss -tlnp` cannot tell an MPTCP listener from a TCP one. `ss -M` reads the `mptcp_diag` module. Where it is not loaded, `ss -M` prints an empty table even with an MPTCP listener running, with no error; Ubuntu cloud and virtual kernels keep the module in `linux-modules-extra-$(uname -r)`, so run `sudo apt install linux-modules-extra-$(uname -r)` and `sudo modprobe mptcp_diag`. `check` therefore also reads the socket count the kernel keeps in `/proc/net/protocols` (the `MPTCP` and `MPTCPv6` rows, which count listening and other sockets) and says so when `ss -M` lists none while that count is above zero. A script that audits a fleet should use both. Do not block `mptcp_diag` to reduce exposure: the flawed code is in IPv4 TCP, and the block only hides MPTCP sockets from `ss -M`.

`net.mptcp.enabled`, `ss` and `/proc/net/protocols` all describe one network namespace. A new namespace starts at 1 whatever the host is set to, so a container with its own namespace is not covered by the host's sysctl and is not shown by the host's `ss`. Look from inside it, or from the host with `sudo nsenter -t "$(docker inspect -f '{{.State.Pid}}' NAME)" -n ss -M -l -n -p`, and turn MPTCP off for it when it starts (`docker run --sysctl net.mptcp.enabled=0`). A container started with `--network=host` shares the host's namespace. In Kubernetes, `net.mptcp.enabled` is not in the safe sysctl set, so a pod that sets it in `securityContext.sysctls` is scheduled but fails to start on a node whose kubelet has not allowed it (`--allowed-unsafe-sysctls`, or `allowedUnsafeSysctls` in the kubelet configuration). A kubelet can also set it for every pod on the node with `defaultPodSysctls`, which needs no allow-list. `net.*` sysctls cannot be set on a pod that uses host networking.

### Mitigation: `mitigate`

`./linux-kernel-ireq-opt-check.sh mitigate --dry-run` shows, and `mitigate` applies, measures that reduce the exposure. They are not a fix. `mitigate` acts only when `check` finds the kernel affected (`--force` overrides) and you must choose what to apply, because each measure can break software:

| Option | What it does | What it can break |
|---|---|---|
| `--mptcp` | Sets `net.mptcp.enabled=0` in this network namespace, applied now and written to a `sysctl.d` file. AWS says turning MPTCP off reduces the conditions for running code on the host but does not resolve the issue, and a crash stays possible | Software that needs MPTCP |
| `--ip-options` | Drops inbound IPv4 TCP packets that carry IP options, with nftables (a table of its own, `psf_ireq_opt`) or, without it, an iptables rule with a `u32` match and a comment. It is scoped to TCP, so the Router Alert option that IGMP uses is untouched. It adds nothing when a filter of this kind is already in place, such as Red Hat's own table in [RHSB-2026-016](https://access.redhat.com/security/vulnerabilities/RHSB-2026-016) (`table inet cve_2026_98432`, input hook, priority -310, `ip protocol tcp ip hdrlength > 5 counter drop`: the same rule), and `rollback` leaves a table it did not add. The rule is not saved: a reboot removes it, which is when the patched kernel should be running. It hooks input, so traffic forwarded to containers, or between containers on the same host, can bypass it, and networks that label packets with CIPSO carry the labels in IP options, so leave the filter off there. AlmaLinux publishes its own version of the table (`table ip cve_2026_98432`, prerouting hook, priority -300), which this script respects in the same way | A few diagnostic tools that send IP options over TCP |
| `--modules LIST` | Blocks later loading of the listed modules (`mptcp`, or `all`, which means `mptcp`). `mptcp_diag` is accepted only by name and with `--force`: it is what `ss -M` reads, so blocking it hides MPTCP sockets and removes no known exposure, see above with `blacklist` and `install NAME /bin/false` lines in a `modprobe.d` file. MPTCP is built into most kernels, and a modprobe rule cannot block what is built in; the script says so and points you to `--mptcp`. A module that is loaded now is left alone unless `--force` | Whatever uses MPTCP diagnostics |

`rollback` restores the saved sysctl values and removes the files and the packet filter. A patched kernel and a reboot are the only complete remedy. The [kernel module blocker](#linux-kernel-module-block) does the module part for any module, with a list and a status command.

### Hunt

The flaw leaves a trace when it goes wrong: a use after free or a `skb_under_panic` in the kernel log. `hunt` looks for it. A hit means the kernel faulted in this code, not that someone attacked it, so read the full trace and what connected just before it. A clean result is not clearance: a successful exploit need not crash the host, and a reboot clears the ring buffer. Run it with `sudo`, because the kernel logs belong to root.

### Update

Move to your vendor's kernel that names this CVE, or to a stable release from the table, and reboot. The script prints the command for the system it runs on and the vendor's page for the CVE. Debian, Ubuntu, Trisquel and their derivatives are the project's default targets; the RPM family is covered as well; SUSE, Arch and Alpine get the command and the vendor page.

| System | Update | Check |
|---|---|---|
| Debian, Ubuntu, Trisquel and derivatives | `sudo apt update && sudo apt full-upgrade`, then reboot. `full-upgrade`, not `upgrade`: a new `linux-image` package arrives as a new dependency, which plain `upgrade` holds back | `apt changelog` of the kernel package names the CVE; `/var/run/reboot-required` says a reboot is pending. [Debian](https://security-tracker.debian.org/tracker/CVE-2026-98432), [Ubuntu](https://ubuntu.com/security/CVE-2026-98432) |
| RHEL, Alma, Rocky, Fedora, CloudLinux, Oracle Linux | `sudo dnf update kernel && sudo reboot` (`yum` on RHEL 7 class systems) | `sudo dnf updateinfo list --cve CVE-2026-98432` shows whether your repositories carry the advisory; `needs-restarting -r` after an update says whether a reboot is still needed. [Red Hat](https://access.redhat.com/security/cve/CVE-2026-98432) |
| Amazon Linux 2 | `sudo yum update kernel && sudo reboot` | [Amazon Linux Security Center](https://explore.alas.aws.amazon.com/CVE-2026-98432.html) |
| Amazon Linux 2023 | `sudo dnf update kernel --releasever=latest && sudo reboot`; on kernel 6.12 use `kernel6.12`, on 6.18 use `kernel6.18`. An instance locked to a release needs 2023.12.20261102 or later (AWS) | The same page |
| SUSE | `sudo zypper refresh && sudo zypper patch`, then reboot | [SUSE](https://www.suse.com/security/cve/CVE-2026-98432.html) |
| Arch, Alpine | `sudo pacman -Syu`, or `sudo apk update && sudo apk upgrade`, then reboot | [Arch](https://security.archlinux.org/CVE-2026-98432), [Alpine](https://security.alpinelinux.org/vuln/CVE-2026-98432) |

`check` also says when a fixed kernel is already installed but not running (the common state after an update without a reboot), and when the package manager already has the fix: the cached `apt list --upgradable` or `dnf updateinfo` data is read, never the network.

On an RPM family system: the `.rpm` release package installs the script under `/opt/psf-security-patches`; `mitigate --ip-options` uses `nft`, which RHEL 8 and later ship, because the `iptables` command there is the nftables front end and has no `u32` match (the script says so and does not try it); and a running `firewalld` keeps its own tables, so the one this adds sits beside them.

`mitigate --mptcp` sets `net.mptcp.enabled=0`: the kernel then refuses to create new MPTCP sockets (`ENOPROTOOPT`). It does not close an MPTCP listener that already exists: that one keeps listening until its service restarts. `check` and `mitigate --mptcp` count the listeners with `ss -M -l` and say so, and `ss -M -l -p` shows which services own them.

If you cannot update yet: switch MPTCP off (`mitigate --mptcp`), drop TCP packets that carry IP options at the edge or on the host (`mitigate --ip-options`; AWS Network Firewall users can use the stateful rule in AWS's bulletin), and keep database and other service ports off the internet. On AWS, the bulletin lists what each service needs from you.

### Sources

- [NVD: CVE-2026-98432](https://nvd.nist.gov/vuln/detail/CVE-2026-98432)
- [AWS security bulletin 2026-160-AWS](https://aws.amazon.com/security/security-bulletins/2026-160-aws/)
- [OpenCVE: CVE-2026-98432](https://app.opencve.io/cve/CVE-2026-98432)
- oss-security: [30 October](http://www.openwall.com/lists/oss-security/2026/10/30/1), [30 October (second)](http://www.openwall.com/lists/oss-security/2026/10/30/6), [31 October](http://www.openwall.com/lists/oss-security/2026/10/31/5) and [3 November](http://www.openwall.com/lists/oss-security/2026/11/03/1)
- [The kernel CVE record](https://git.kernel.org/pub/scm/linux/security/vulns.git/plain/cve/published/2026/CVE-2026-98432.mbox)
- Debian: [DSA-6568-1](https://lists.debian.org/debian-security-announce/2026/msg00482.html), [DLA-4841-1](https://lists.debian.org/debian-lts-announce/2026/10/msg00035.html), [DLA-4850-1](https://lists.debian.org/debian-lts-announce/2026/10/msg00044.html)

<a name="linux-kernel-noisytcp-check"></a>

## NoisyTCP: Linux kernel TCP pre-auth remote crash (CVE-2026-99288, and CVE-2026-99676)

**Script:** [`system/linux-kernel/linux-kernel-noisytcp-check.sh`](linux-kernel-noisytcp-check.sh)

A race in the lockless lookup TCP uses to find an established connection, named NoisyTCP by Hyunwoo Kim, who reported and fixed it. The memory of the socket a lookup found can be freed and reused for a new socket with the same addresses and ports before the lookup takes its reference. The lookup then returns a request socket that a SYN cookie has just rebuilt, with no listener attached, and the receive path dereferences the missing listener: a kernel panic. Anyone who can send TCP packets to a listening port can do it, without an account. Kim crashed Nginx, Apache and SSH in their default setup on virtual machines in 5 seconds to 2 minutes; a quiet physical server with 8 receive queues took about 14 hours. A crash takes down the whole host, containers included.

The race needs packets for the same connection handled at the same time on different CPUs: two or more receive queues on the interface the attacker's packets arrive on, or RPS spreading them across CPUs. Kim also describes a second, much harder path to a use after free; kernel maintainer Eric Dumazet disputed it when the fix was posted, and Red Hat states that the flaw does not allow data alteration or code execution. The researcher's own exploit is not public; an exploit tracker lists third-party proof of concept code, which this project has not examined. No attacks had been reported, and it was not on CISA's list of exploited vulnerabilities, as of 24 November.

| | |
|---|---|
| Affected | Every kernel from 4.4 (commit `079096f103fa`, October 2015) up to the fixed releases below |
| Needs | A reachable TCP listener, SYN cookies on (the usual default), and packets spread across CPUs (two or more receive queues, or RPS) |
| Fixed upstream in | 5.10.275, 5.15.226, 6.1.193, 6.6.163, 6.12.117, 6.18.63 and 7.3.4; mainline `4e2b3ef19e0e` (7.4-rc2) |
| Ratings | CVE record 7.5 (kernel CVE team) and 5.9 (CISA, in the same record); Red Hat Important; Ubuntu High |

### The sibling flaw (CVE-2026-99676)

The same patch series restores the memory ordering of those lockless lookups. A 2019 change (`fb041bb7c0a9`, in 5.5, and a backport of it in 5.4.208) removed that ordering on weakly ordered processors. x86 keeps it in hardware, so the sibling does not apply there; on Arm, POWER, RISC-V and other weakly ordered processors, a kernel fixed for NoisyTCP may still not be fixed for this. A review bot asked for both patches to be backported together for that reason; no maintainer has confirmed that the crash is still reachable without it. It is fixed in 6.12.118, 6.18.64 and 7.3.5 (mainline `5b5d8f351dd9`, 7.4-rc2), and the 5.4, 5.10, 5.15, 6.1 and 6.6 branches have no upstream fix yet. Debian 13 has it in 6.12.118-1 (DSA-6652-1). NVD scores it 9.8, a score that does not reflect that it needs a weakly ordered processor.

### Fixed versions

The first stable release of each branch that carries the NoisyTCP fix. Every other branch from 4.4 on has no upstream fix, 6.19 to 7.2 included (7.2 ended at 7.2.15, two days before the fix). Vendors that maintain such a branch backport it.

| Branch | NoisyTCP (CVE-2026-99288) | Sibling (CVE-2026-99676), weakly ordered processors only |
|---|---|---|
| 5.4 | no fix | no fix (affected from 5.4.208) |
| 5.10 | 5.10.275 | no fix yet |
| 5.15 | 5.15.226 | no fix yet |
| 6.1 | 6.1.193 | no fix yet |
| 6.6 | 6.6.163 | no fix yet |
| 6.12 | 6.12.117 | 6.12.118 |
| 6.18 | 6.18.63 | 6.18.64 |
| 7.3 | 7.3.4 | 7.3.5 |
| 7.4 | 7.4-rc2 and later | 7.4-rc2 and later |

Vendors, as their trackers and advisories stood on 24 November (Red Hat: its list of 25 November). These states change daily, so open your vendor's page before you act on this list.

| Vendor | State | Kernel and advisory |
|---|---|---|
| Debian | Fixed | 12 bookworm `linux` 6.1.192-1 (DLA-4906-1; Debian carried it before upstream 6.1.193) and `linux-6.12` 6.12.117-1~deb12u1; 13 trixie `linux` 6.12.117-1 (DSA-6628-1), and 6.12.118-1 for the sibling (DSA-6652-1) |
| Red Hat | Fixed for RHEL 8.10, 9.9 and 10.3 on 23 November and RHEL 8.8 on 24 November, rated Important. Other update streams (9.8, 10.2 and so on) had no fixed kernel in Red Hat's list of 25 November. RHEL 6 and 7 are not affected | 8.8 `4.18.0-477.181.1.el8_8` (RHSA-2026:102709), 8.10 `4.18.0-553.189.1.el8_10` (RHSA-2026:102218; kernel-rt RHSA-2026:102219), 9.9 `5.14.0-741.26.1.el9_9` (RHSA-2026:102167), 10.3 `6.12.0-264.19.1.el10_3` (RHSA-2026:102168) |
| Ubuntu | Not fixed: every release from 16.04 to 26.10 is listed as vulnerable. Fixes are in progress for the main `linux` package; its other kernels (cloud, HWE, Raspberry Pi and more) have none in progress | In progress: 24.04 `6.8.0-152.152`, 22.04 `5.15.0-205.215`, 26.04 `7.0.0-45.45`, 26.10 `7.3.0-12.13`, 20.04 `5.4.0-248.268`, 18.04 `4.15.0-264.276`, 16.04 `4.4.0-294.328` |
| AlmaLinux, Oracle Linux, CIQ | Fixed for at least some releases | AlmaLinux follows Red Hat's advisories (ALSA-2026:102167 and the others); Oracle Linux UEK ELSA-2026-500630 to 500632 |

A summary that circulated on 24 November listed RHEL 9 `5.14.0-687.67.1.el9_8`, RHEL 10.2 and Ubuntu 24.04 `6.8.0-151.151` among "latest safe versions". None of them carries this fix: the 9.8 and 10.2 streams have no fixed kernel, and Ubuntu's fix is in 152. The script judges those kernels affected.

### How the script judges the kernel

As the other kernel checks in this folder do, it reads the kernel's origin first. A kernel that follows the stable series is compared with the table above, and Debian's patch level is read from `uname -v`, with Debian's own 6.1.192-1 fix taken into account. RHEL itself (an `ID=rhel` system) is compared with the fixed build of its update stream (8.8, 8.10, 9.9 and 10.3), and a stream without a fixed kernel is reported as such. Ubuntu's main kernel is compared with the build Ubuntu named for its fix: below it is affected; at or past it, while Ubuntu still lists the fix as in progress, the script asks you to confirm rather than call it fixed. Every other vendor kernel (the RHEL rebuilds, RHEL's kernel-rt, Ubuntu's cloud kernels, SUSE, Amazon Linux) is judged by its changelog: when it names the CVE, the kernel carries a backport. The sibling is judged only on a weakly ordered processor. A stable release candidate is judged as the release before it, and a 7.4 release candidate by its number (the fixes came in rc2).

### Quick start

```bash
curl -fLO https://raw.githubusercontent.com/PrivacySafe/security-patches/refs/heads/main/system/linux-kernel/linux-kernel-noisytcp-check.sh
less linux-kernel-noisytcp-check.sh
chmod +x linux-kernel-noisytcp-check.sh
./linux-kernel-noisytcp-check.sh check
```

| Command | What it does |
|---|---|
| `check` (default) | Judges the running kernel for NoisyTCP and, on a weakly ordered processor, the sibling. Exit `0` fixed, `1` affected or a fix could not be confirmed. Read-only |
| `hunt` | Reads the kernel logs (`dmesg`, the journal's kernel messages, the rotated `kern.log`, `syslog` and `messages` files) for a NULL pointer dereference or panic whose trace runs through `tcp_v4_rcv`, `tcp_v6_rcv`, the established lookups or the SYN cookie code, and notes crash dumps in `/var/crash` and `/sys/fs/pstore`. A hit is a lead, not proof of an attack; a clean result is not clearance, because a crashed host reboots and loses its ring buffer. Exit `0` nothing found, `1` hits, `2` no log could be read. Read-only |
| `mitigate [--syncookies] [--single-queue IFACE[,IFACE]] [--force] [--dry-run]` | **Changes the host (root).** Stopgaps, not a fix; see below |
| `rollback [--dry-run]` | Restores the saved values and removes the file `mitigate` wrote |
| `version` | Prints the script version |

With `--output jsonl` it writes structured records for [automation](../../automation/README.md), and `psf-run` runs it with the other tools that do. Env: `KERNEL_CHANGELOG` (a vendor changelog file to read, plain or `.gz`), `KERNEL_RELEASE`, `KERNEL_VERSION_STRING` and `KERNEL_ARCH` (override `uname -r`, `-v` and `-m`), `KERNEL_PROC_SYS` and `KERNEL_SYS_NET` (instead of `/proc/sys` and `/sys/class/net`), `KERNEL_LOG_FILES` and `KERNEL_CRASH_DIRS` (for `hunt`), `KERNEL_INSTALLED_RELEASES`, `OS_RELEASE_FILE`, and `STATE_DIR` and `SYSCTL_D` for `mitigate` and `rollback`.

A container shows the host's kernel, so run the script on the host.

What `check` shows, here on an example Debian 12 host with an affected kernel:

[![sudo ./linux-kernel-noisytcp-check.sh check in a terminal: a Debian 12 kernel, upstream 6.1.191, is marked CRIT for NoisyTCP, the sibling flaw does not apply on x86, the exposure lines show SYN cookies on and four receive queues, and the verdict gives the update command](../../automation/examples/screenshots/check-noisytcp.png)](../../automation/examples/screenshots/check-noisytcp.png)

### Exposure information

After the verdict, `check` reports what decides whether the race can be reached here: `net.ipv4.tcp_syncookies`, the receive queues of each interface and whether RPS or RFS spreads packets across CPUs, the TCP listeners that are not on loopback, the processor, and how many other network namespaces exist. That is information to weigh, not a verdict: a kernel below its fixed release is affected whatever it shows. Which interface faces the attacker, and which CPUs its queues are bound to, the script cannot know. Each network namespace has its own `tcp_syncookies`, so a container's value can differ from the host's, and a crash in any container takes the whole host down.

### Mitigation: `mitigate`

Both stopgaps come from the researcher's advisory and Red Hat. They act only when `check` finds the kernel affected (`--force` overrides), `--dry-run` shows everything first, and `rollback` puts the saved values back.

- **`--syncookies`** sets `net.ipv4.tcp_syncookies=0` now and writes `/etc/sysctl.d/99-psf-kernel-noisytcp.conf` so it stays after a reboot; if another file read later sets the value, it says which. It closes the SYN cookie path the crash uses, and it weakens protection against SYN floods. It acts in the host's network namespace only: start each container that has its own namespace with `--sysctl net.ipv4.tcp_syncookies=0` (Docker, Podman), set it under `securityContext.sysctls` in Kubernetes, or set it from inside with `nsenter -t PID -n sysctl -w net.ipv4.tcp_syncookies=0`.
- **`--single-queue IFACE`** cuts the named interfaces (the ones that face the attacker) to one receive channel with `ethtool -L`, and turns RPS and RFS off. Network throughput drops, the link may reset for a moment (an SSH session over that interface can drop), and none of it survives a reboot or a driver reset. Without `ethtool`, the queue count stays and only RPS and RFS change.

Run as root, it writes no file through a link, and it runs `ethtool` only when root owns the program and every folder above it.

### Update

| Distribution | Command |
|---|---|
| Debian | `sudo apt update && sudo apt full-upgrade`, then reboot |
| RHEL 8.8, 8.10, 9.9, 10.3 and rebuilds | `sudo dnf update kernel && sudo reboot`; `sudo dnf updateinfo list --cve CVE-2026-99288` shows whether the repositories have the advisory |
| Ubuntu | Wait for the fix on [Ubuntu's page](https://ubuntu.com/security/CVE-2026-99288), then `sudo apt update && sudo apt full-upgrade` and reboot; use a stopgap until then |

### Sources

- oss-security: [Hyunwoo Kim's NoisyTCP advisory](https://www.openwall.com/lists/oss-security/2026/11/15/2), 15 November; [the 5.15 backport](https://www.openwall.com/lists/oss-security/2026/11/20/3), 20 November
- [The kernel CVE team's announcement of CVE-2026-99288](https://lists.openwall.net/linux-cve-announce/2026/11/10/4), 10 November
- OSV, generated from the CVE records: [CVE-2026-99288](https://osv.dev/vulnerability/CVE-2026-99288) (all seven fixed releases) and [CVE-2026-99676](https://osv.dev/vulnerability/CVE-2026-99676)
- [Red Hat: CVE-2026-99288](https://access.redhat.com/security/cve/cve-2026-99288), and its advisories [RHSA-2026:102167](https://access.redhat.com/errata/RHSA-2026:102167), [RHSA-2026:102168](https://access.redhat.com/errata/RHSA-2026:102168), [RHSA-2026:102218](https://access.redhat.com/errata/RHSA-2026:102218) and [RHSA-2026:102219](https://access.redhat.com/errata/RHSA-2026:102219)
- [Ubuntu: CVE-2026-99288](https://ubuntu.com/security/CVE-2026-99288)
- [Debian security tracker: CVE-2026-99288](https://security-tracker.debian.org/tracker/CVE-2026-99288)

<a name="linux-kernel-module-block"></a>

## Linux kernel module blocker

**Script:** [`system/linux-kernel/linux-kernel-module-block.sh`](linux-kernel-module-block.sh)

Many kernel flaws sit in a module that almost nobody needs and that loads by itself the moment an unprivileged process opens the right socket, or a device appears. Stopping that module from loading removes the attack surface until a patched kernel is running. This script does it the way the kernel documents, for a curated list of modules behind recent flaws or for any name you give it, with a manifest and a rollback, and it tells you when a block cannot work. It is generic: the tools above carry their own copies of this logic for their own modules and keep working when copied on their own.

A block is a file of its own, `/etc/modprobe.d/psf-block-NAME.conf`, with `blacklist NAME`, which stops the alias based autoload, and `install NAME /bin/false`, which also stops an explicit `modprobe NAME`. A hyphen and an underscore are the same thing to the kernel, and the script treats them so.

A bare `blacklist` line, which is what many distributions ship (Ubuntu's own `/etc/modprobe.d/blacklist-*.conf` files, for one), stops only the automatic load by alias. An explicit `modprobe NAME` still loads the module, and so does another module that depends on it. `list` and `check` call that `blacklist`, not blocked, and `block` adds the install rule on top. Rules that already exist anywhere under `modprobe.d` count, wherever they came from.

### Quick start

```bash
curl -fLO https://raw.githubusercontent.com/PrivacySafe/security-patches/refs/heads/main/system/linux-kernel/linux-kernel-module-block.sh
less linux-kernel-module-block.sh
chmod +x linux-kernel-module-block.sh
./linux-kernel-module-block.sh list --present        # what this host has from the list
./linux-kernel-module-block.sh check tun             # what it is, what holds it, how it loads
sudo ./linux-kernel-module-block.sh block sctp --dry-run
sudo ./linux-kernel-module-block.sh block sctp
./linux-kernel-module-block.sh status
```

| Command | What it does |
|---|---|
| `list [--group exploited\|historic\|hardening\|all] [--present] [--list-file FILE]` (default) | The table, with the state of each module on this host: loaded, built in, loadable, absent, blocked (an install rule) or blacklist (the automatic load only). Read-only |
| `check NAME...` | For any module: its state, what holds it, its aliases and how it autoloads, what breaks if it goes, and where it is blocked already. Exit `0` every module named is absent or blocked, `1` at least one is present and can still load. Read-only |
| `block NAME... \| --group G \| --cve ID [--force] [--unload] [--initramfs] [--even-if-absent] [--allow-protected] [--list-file FILE] [--dry-run]` | **Changes the host (root).** Writes the block files and a manifest. `--group` blocks a whole group, `--cve` every module that lists the CVE. Built-in and loaded modules are skipped with the reason |
| `status` | What the script blocked, and whether each block is effective: the file is still there and unchanged, and the module is not loaded. Exit `0` all effective, `1` at least one is not. Read-only |
| `rollback [NAME...] [--force] [--initramfs] [--dry-run]` | **Changes the host (root).** Removes the block files the script wrote, all or the named ones. A file you edited since is kept unless `--force` |
| `version` | Prints the script version |

Env: `STATE_DIR` and `MODPROBE_D` (where the manifest and the block files go), `MODPROBE_DIRS` (the other directories searched for rules that already exist), `KERNEL_RELEASE`, `KERNEL_MODULES_FILE`, `KERNEL_BUILTIN_FILE` (override `uname -r`, `/proc/modules` and the module list of the release), `SYS_MODULE_DIR` and `OS_RELEASE_FILE`.

Commands that change the host need root. Run them with `sudo` from an admin account, not from a root login, so the change is recorded against a person. The script stops and prints the exact command if you forget.

Only one run changes the host at a time: a second `block` or `rollback` waits for the first (`PSF_LOCK_WAIT` seconds, default 30, lock file `STATE_DIR/.lock`) and then stops with exit `2` and says why. Without that, runs started together can overwrite each other's manifest entries and leave blocks that a rollback no longer knows about. The manifest itself is replaced whole through a temporary file, so an interrupted run leaves the old one or the new one. `mitigate` and `rollback` in the two tools above take the same lock.

### The list

Three groups, each labeled for what it is. `list` shows all 43 rows with the CVE, what a block breaks and the state on your host.

| Group | Modules | What it means |
|---|---|---|
| `exploited` | `ah6` (CVE-2026-80844), `tun` (CVE-2026-81000), `pppoe` (CVE-2026-68121), `sctp` and `sctp_diag` (CVE-2026-74469), `ebt_snat` (CVE-2026-53266), `mptcp` (CVE-2026-98432, a reduction, not a fix), `kvm_amd` (CVE-2026-99312; blocking it stops all AMD virtualization, so prefer `linux-kernel-kvm-escape-check.sh mitigate`, which only turns off nested virtualization) | Modules behind flaws that this collection has a tool for. The tools above judge the kernel; this one blocks the module |
| `historic` | `dccp`, `rds`, `rds_tcp`, `tipc`, `n_hdlc`, `bluetooth`, `vsock`, `vmw_vsock_virtio_transport`, `esp6` | Modules behind older, well known local root or remote flaws. `list` shows the CVE ids |
| `hardening` | The rare filesystems `cramfs`, `freevxfs`, `jffs2`, `hfs`, `hfsplus`, `udf`, `squashfs`; `usb_storage` and `uas`; the DMA buses `firewire_core`, `firewire_ohci`, `firewire_sbp2` and `thunderbolt`; the rare protocols `ax25`, `netrom`, `rose`, `appletalk`, `x25`, `atm`, `can`, `nfc` and `ieee802154`; `parport_pc`, `ppdev`, `floppy` and `mptcp_diag`* | Attack surface that almost no system needs, in the style of the CIS benchmarks. No CVE is claimed for these. Blocking them is a policy choice, and each row says what it breaks |

Blocking `sctp` also removes the surface of CVE-2026-64564, a newer SCTP use-after-free in ASCONF handling (present since 4.15) that Xint chained with nginx2root to reach host root out of a Docker container. Its fix merged into mainline on 19 November 2026 and was in no stable kernel release as of 22 November; Docker's default seccomp profile does not block SCTP sockets. See the [nginx2root](../../servers/nginx/README.md#nginx2root) section.

A module marked * is one that detection depends on. `mptcp_diag` is the module `ss -M` reads to list MPTCP sockets, and this collection's own checks use it. The flawed code of CVE-2026-98432 is in IPv4 TCP, not in `mptcp_diag`, so blocking it removes no known exposure and hides the MPTCP listeners you would look for. `block --group` and `block --cve` therefore skip it and say so, and it is blocked only when you name it and add `--force`. A row you add with `--list-file` can carry the same flag as a seventh field, `keep`.

The list is a table in the script and is updated with each release; `--list-file FILE` adds your own rows (`module|group|CVEs|what needs it|what a block breaks|switch for a built-in module`, with the group `custom` allowed). The scripts do not fetch anything.

### What a block cannot do

| Case | What the script does |
|---|---|
| Built into the kernel | No modprobe rule can block it. The script refuses and prints the switch the list knows, for MPTCP `sysctl net.mptcp.enabled=0` (the IPv4 TCP tool above does that) |
| Loaded now | It stays loaded until it is unloaded or the host reboots. The script refuses unless you pass `--force`, which writes the rule anyway; `--unload` then tries `modprobe -r`, which fails while something uses the module. `status` says a block is not effective yet while the module is loaded |
| In the initramfs | A module can load from the initramfs before `modprobe.d` is read. After a block the script prints the command that rebuilds it for this system, and `--initramfs` runs it. It is off by default because a rebuild is slow and can fail on a full `/boot` |
| A module others depend on | Blocking a module also stops the modules that depend on it: `modprobe` runs the `install` rule of the blocked dependency, which fails, so the dependent cannot load. Blocking only the dependent leaves the base module loadable. The list names both modules for a CVE (`sctp` and `sctp_diag`), and `--cve` blocks both |
| Needed to boot or log in | A short protected list is refused: the root filesystems, storage and `nvme`, USB host and input drivers, `virtio`, device mapper and a few more. Only `--force --allow-protected` overrides it. Keep a console or rescue medium at hand |
| Not present | Nothing to block, so nothing is written. `--even-if-absent` writes the rule anyway, so it is there if the module is installed later |

The rebuild command by system: `update-initramfs -u -k all` on Debian, Ubuntu, Trisquel and derivatives, which copies everything in `/etc/modprobe.d` into the image; `dracut -f --regenerate-all -I "/etc/modprobe.d/psf-block-*.conf"` on RHEL, Alma, Rocky, Fedora, Amazon Linux and SUSE, where `-I` is needed because dracut reads `/etc/modprobe.d` only for a host-only image (the usual kind for the running system, but not the generic one) and does not mind when nothing matches, as after a rollback; `mkinitcpio -P` on Arch; `mkinitfs` on Alpine. The same applies after a `rollback`. A new kernel's image is built by your distribution's own hook: a host-only image carries the files, a generic one does not unless dracut is told to include them. A kernel command line option, `module_blacklist=NAME`, is the alternative for a module you cannot get a file in place for; the script does not touch the boot loader.

### Why a block helps

`check` shows how a module loads. Network protocol modules have `net-pf-` aliases: any process, with no privileges, loads one by opening a socket of that family. That is why a block removes a real path for an attacker. Filesystem modules load when something mounts that type, USB modules when a matching device is plugged in.

---

<a name="linux-kernel-kvm-escape-check"></a>

## KVM guest-to-host escape on AMD nested virtualization (CVE-2026-99312)

**Script:** [`system/linux-kernel/linux-kernel-kvm-escape-check.sh`](linux-kernel-kvm-escape-check.sh)

Terra Security (Oren Yomtov) disclosed CVE-2026-99312 on 18 November 2026: a guest VM on an AMD KVM host with nested virtualization on can read and write the host's physical memory, which on a shared host means every other tenant's memory too. Terra demonstrated the read on an ordinary DigitalOcean droplet (the host's own kernel version banner came back first, then about 127 GB of host RAM) and the write on their own server, so as not to disrupt other customers.

The official record (the kernel's own CNA entry, mirrored by NVD and Red Hat) describes the underlying bug as an unconditional MMU-context reset missing when KVM emulates an INIT while a nested guest's paging is off, and scores it as a local denial-of-service: the CVSS vector ends `C:N/I:N/A:H`, no confidentiality or integrity impact, only availability. Terra's own research, independently corroborated, found the same bug chains with a use-after-free in KVM's nested SVM handling (a stale `nCR3` pointer left referencing a recycled page-table page) and an Accessed-bit timing oracle, into the full guest-to-host read and write demonstrated above. Treat the official score as a description of the kernel's own accounting of the bug class, not of what was actually shown against it.

This is a fix landing on top of an older one. In 2022, a different, already-fixed KVM reset flaw was fixed by switching a reset back to the control block of the VM that runs the nested one before anything is freed. CVE-2026-99312 is a flaw that fix itself opened. It is unrelated to three other 2026 KVM guest-to-host escapes found by a different researcher under the names ITScape (arm64), Januscape and Zapscape (x86, both reaching Intel and AMD); this script covers only CVE-2026-99312, and its one AMD-only mitigation should not be confused with those.

**Affected:** nested virtualization on AMD (`kvm_amd`), on any kernel from 6.1 up to, but not including, the fixed releases below. INIT is an unconditional intercept on Intel VMX, so Intel nested virtualization (`kvm_intel`) cannot reach this specific bug. First fixed stable release of each currently maintained branch: `6.12.118`, `6.18.64`, `7.3.5`; first mainline release with the fix: `7.4-rc2` (9 November 2026). The precondition for this flaw came from a November 2022 commit that was itself widely backported at the time, confirmed at least as far back as the (now unsupported) stable branches 5.15.81 and 6.0.11. Nothing confirms that *other* branches below 6.1 that were also receiving backports in November 2022 (5.10 and 5.4, for instance) escaped it; `check` reports those as unknown rather than clear, and says to check that branch's own changelog, rather than assume its age puts it out of scope.

### Quick start

```bash
curl -fLO https://raw.githubusercontent.com/PrivacySafe/security-patches/refs/heads/main/system/linux-kernel/linux-kernel-kvm-escape-check.sh
less linux-kernel-kvm-escape-check.sh
chmod +x linux-kernel-kvm-escape-check.sh
./linux-kernel-kvm-escape-check.sh check
```

If you can't upgrade the kernel yet:

```bash
sudo ./linux-kernel-kvm-escape-check.sh mitigate --dry-run
```

### Commands

| Command | What it does |
|---|---|
| `check` (default) | Read-only. Kernel version against the fixed releases; whether this is an AMD host; `kvm_amd`'s load state and current `nested` parameter. Exit `0` not exposed (patched, not AMD, module absent, or `nested` already off), `1` exposed, `2` something couldn't be read |
| `mitigate [--unload] [--force] [--dry-run]` | **Changes the host (root).** Writes `/etc/modprobe.d/psf-kvm-amd-nested-off.conf` (`options kvm_amd nested=0`). Refuses if `kvm_amd` is currently loaded, unless `--unload` (which itself refuses if any VM is running on it, since `modprobe -r` fails while anything uses the module) or `--force` (writes the file anyway, for the next load) |
| `rollback [--dry-run]` | Removes the modprobe.d file. Does not turn `nested` back on for an already-loaded `kvm_amd`; that needs the same drain this script will not do for you |
| `rules` | Prints the file `mitigate` writes and the manual unload/reload commands |
| `version` | Prints the script version |

The `nested` module parameter is read only when `kvm_amd` loads, so there is no way to flip it on a host where the module is already loaded without unloading it (every VM must already be stopped; `modprobe -r` refuses otherwise) or rebooting. `mitigate --force` writes the file and tells you it only takes effect on the next load, which on most hosts means the next reboot or maintenance window.

`linux-kernel-module-block.sh` also lists `kvm_amd` (`check kvm_amd`, `list --group exploited`), but **blocking it entirely is the wrong tool here**: it would stop all AMD virtualization, nested or not, which is far more than this flaw needs. That tool's own `check` output says so; use `mitigate` above for the targeted fix.

### Sources

- [Terra Security, "CVE-2026-99312: KVM Guest-to-Host Escape", 18 November 2026](https://www.terra.security/blog/kvm-guest-to-host-escape): the disclosure, the DigitalOcean demonstration, the fixed releases and the `kvm_amd nested=0` mitigation.
- The kernel's own CNA record for CVE-2026-99312 (mirrored by NVD and Red Hat): the official description and CVSS vector.
- ITScape, Januscape and Zapscape are separate KVM guest-to-host escapes found by a different researcher; their own write-ups and this script's header note how they differ from CVE-2026-99312.

## Before you run it

- These are checks, not fixes, and the fix needs a reboot. The checks judge the running kernel. Update to your vendor's fixed kernel and reboot. A container shows the host's kernel, so run them on the host.
- A vendor kernel's number does not show its fixes. Ubuntu, RHEL and its derivatives, SUSE and Amazon Linux backport fixes under release strings that do not say which they carry. For those the script reads the vendor changelog for each CVE and points you to the vendor's tracker when a CVE is absent.
- The quartet is judged flaw by flaw. Each of the four has its own fixed release per branch, so 6.12.105 can have two of the four fixes and not the other two. Branches with no upstream fix (for example 5.4) need a vendor kernel.
- Exposure lines are information, not a verdict. A kernel below its fixed release is affected whatever the module and user-namespace lines show. No ebtables rule does not make the ebtables kernel safe, since a local user with `CAP_NET_ADMIN` in a user namespace may be able to create one.
- The protective measures are PrivacySafe's. The ebtables suggestions are the project's, and the quartet's (disable unprivileged user namespaces, disable unused AH6, TUN, PPPoE and SCTP) are the researcher's from the disclosure. DiagSpill is not stopped by the namespace setting. There is no hunt for either.

---

<a name="linux-kernel-lpe-check"></a>

## Linux kernel local root quartet check

**Script:** [`system/linux-kernel/linux-kernel-lpe-check.sh`](linux-kernel-lpe-check.sh)

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
curl -fLO https://raw.githubusercontent.com/PrivacySafe/security-patches/refs/heads/main/system/linux-kernel/linux-kernel-lpe-check.sh
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

`rollback` restores the saved sysctl values and removes the files. `STATE_DIR`, `SYSCTL_D` and `MODPROBE_D` can be overridden. To block modules that are not listed here, or several at once, see the [kernel module blocker](#linux-kernel-module-block). These are the researcher's measures, applied by PrivacySafe. A patched kernel and a reboot are the permanent fix. The script has been run against simulated `/proc/sys` and module files and in dry-run mode on a kernel.

### There is no hunt

Proof-of-concept code is public for all four, and no indicators of exploitation were published, so the script has no hunt.

### Update

Move to your vendor's kernel that names these CVEs, or to a stable release from the table, and reboot. Until then, the researcher suggests in the disclosure (PrivacySafe applies this): disable unprivileged user namespaces, which removes the ordinary-user path to the first three but can break rootless containers and some sandboxes, and disable AH6, TUN, PPPoE and SCTP with `sctp_diag` where they are not used. A process with the right capabilities, and DiagSpill, are not stopped by the namespace setting.

### Sources

- [oss-security: A quartet of Linux local root vulns (18 September 2026)](https://www.openwall.com/lists/oss-security/2026/09/18/3)
- [The researcher's write-up](https://heyitsas.im/posts/lpe-quartet/)
- [The Hacker News: public exploits released for the four kernel flaws](https://thehackernews.com/2026/09/public-exploits-released-for-four-linux.html)
- Proof-of-concept repositories: [DirtyAH6](https://github.com/manizada/DirtyAH6), [TUNderflow](https://github.com/manizada/TUNderflow), [PPPoEject](https://github.com/manizada/PPPoEject), [DiagSpill](https://github.com/manizada/DiagSpill)

<!-- rhsa:begin (generated by packaging/rhsa/rhsa.py from Red Hat's advisory list: edit placement.json or the data, not this block) -->
## Red Hat advisories

Red Hat's advisory list (security advisories released 2026-04-01 to 2026-11-25) names the CVEs below. A Red Hat build is judged by its RPM release, not by the upstream version number, because Red Hat backports fixes: the advisory names the release that fixes it. A CVE with no advisory in the list has none for that period, which is not the same as not affected. The current state is on [Red Hat's CVE database](https://access.redhat.com/security/security-updates/#/cve).

The columns are CVE-2026-NNNNN. The table shows, for each stream, the advisories that name each CVE (the number is the part of RHSA-2026:NNNNN after the colon; `rt` is `kernel-rt`, `kp` is a `kpatch-patch` live patch). A blank cell means no advisory in the list, not that the stream is unaffected. Each advisory is at `https://access.redhat.com/errata/RHSA-2026:NNNNN`.

| Stream | 53266 | 64564 | 68121 | 74469 | 80844 | 81000 | 98432 | 99288 |
|---|---|---|---|---|---|---|---|---|
| RHEL 6 | 73732 |  | 71649 |  | 71649 |  |  |  |
| RHEL 7 | 71657 rt, 71687 | 70290, 70308 rt | 71657 rt, 71687 | 71657 rt, 71687 | 71657 rt, 71687 | 71657 rt, 71687 |  |  |
| RHEL 8 |  |  |  |  |  |  | 95754 |  |
| RHEL 8.4 | 71565 | 69874 | 71565 | 71565 | 71565 | 71565 | 94623 |  |
| RHEL 8.6 | 70797 | 69906 | 71592 | 71592 | 71592 | 71592 | 94996 |  |
| RHEL 8.8 | 71325, 92063 kp | 69837 | 71594, 92063 kp | 71594 | 71594, 92063 kp | 71594, 95601 kp | 100524 kp, 94303 | 102709 |
| RHEL 8.10 | 39082 rt, 39083, 92062 kp | 71016 rt, 71213 | 71329, 71330 rt, 92062 kp | 71213 | 71016 rt, 71213, 92062 kp | 71016 rt, 71213, 95587 kp | 100525 kp, 93414, 93415 rt | 102218, 102219 rt |
| RHEL 9 |  |  |  |  |  |  | 95754 |  |
| RHEL 9.2 | 71601, 71606 rt, 92629 kp | 70482, 70483 rt | 71601, 71606 rt, 92629 kp | 71601, 71606 rt | 71601, 71606 rt, 92629 kp | 71601, 71606 rt, 95600 kp | 100521 kp, 94477, 94558 rt |  |
| RHEL 9.4 | 71569, 91639 kp | 69908 | 71569, 91639 kp | 71569 | 71569, 91639 kp | 71569, 96090 kp | 100523 kp, 94109 |  |
| RHEL 9.6 | 71327, 91638 kp | 70484 | 71631, 91638 kp | 71631 | 71631, 91638 kp | 71631, 96091 kp | 100693 kp, 94438 |  |
| RHEL 9.8 | 36645, 91650 kp | 71232 | 71700, 91650 kp | 71232 | 71232, 91650 kp | 71232, 96093 kp | 100522 kp, 93412 |  |
| RHEL 9.9 |  |  |  |  |  |  |  | 102167 |
| RHEL 10.0 | 71326 | 69089 | 71599 | 71599 | 71599 | 71599 | 94508 |  |
| RHEL 10.2 | 71233, 92061 kp | 71233 | 71602, 92061 kp | 71233 | 71233, 92061 kp | 71233, 99722 kp | 100694 kp, 93413 |  |
| RHEL 10.3 |  |  |  |  |  | 98608 | 98608 | 102168 |
| OpenShift (RHCOS) |  | 11 advisories | 11 advisories | 10 advisories | 12 advisories | 11 advisories | 12 advisories |  |
| RHEL 10 (el10nv) | 72059 |  | 73788 | 73788 | 74974 | 73788 | 93775 |  |

The fixed kernels for CVE-2026-98432 (IPv4 TCP use-after-free), newest first. A kernel is fixed if its release is this one or a later one in the same stream:

| Stream | Advisory | Released | Severity | Kernel |
|---|---|---|---|---|
| RHEL 8.4 | [RHSA-2026:94623](https://access.redhat.com/errata/RHSA-2026:94623) | 2026-11-03 | Critical | `kernel-4.18.0-305.218.1.el8_4` |
| RHEL 8.6 | [RHSA-2026:94996](https://access.redhat.com/errata/RHSA-2026:94996) | 2026-11-04 | Critical | `kernel-4.18.0-372.227.1.el8_6` |
| RHEL 8.8 | [RHSA-2026:94303](https://access.redhat.com/errata/RHSA-2026:94303) | 2026-11-03 | Critical | `kernel-4.18.0-477.178.1.el8_8` |
| RHEL 8.10 | [RHSA-2026:93414](https://access.redhat.com/errata/RHSA-2026:93414) | 2026-11-01 | Critical | `kernel-4.18.0-553.182.1.el8_10` |
| RHEL 9.2 | [RHSA-2026:94477](https://access.redhat.com/errata/RHSA-2026:94477) | 2026-11-03 | Critical | `kernel-5.14.0-284.202.1.el9_2` |
| RHEL 9.4 | [RHSA-2026:94109](https://access.redhat.com/errata/RHSA-2026:94109) | 2026-11-02 | Critical | `kernel-5.14.0-427.161.1.el9_4` |
| RHEL 9.6 | [RHSA-2026:94438](https://access.redhat.com/errata/RHSA-2026:94438) | 2026-11-03 | Critical | `kernel-5.14.0-570.154.1.el9_6` |
| RHEL 9.8 | [RHSA-2026:93412](https://access.redhat.com/errata/RHSA-2026:93412) | 2026-11-01 | Important | `kernel-5.14.0-687.64.1.el9_8` |
| RHEL 10.0 | [RHSA-2026:94508](https://access.redhat.com/errata/RHSA-2026:94508) | 2026-11-03 | Critical | `kernel-6.12.0-55.117.1.el10_0` |
| RHEL 10.2 | [RHSA-2026:93413](https://access.redhat.com/errata/RHSA-2026:93413) | 2026-11-01 | Important | `kernel-6.12.0-211.72.1.el10_2` |
| RHEL 10.3 | [RHSA-2026:98608](https://access.redhat.com/errata/RHSA-2026:98608) | 2026-11-11 | Important | `kernel-6.12.0-264.14.1.el10_3` |
| RHEL 10 (el10nv) | [RHSA-2026:93775](https://access.redhat.com/errata/RHSA-2026:93775) | 2026-11-02 | Important | `kernel-6.12.0-265.31.el10nv` |

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
