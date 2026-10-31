#!/usr/bin/env bash
# SPDX-License-Identifier: CC0-1.0
# =============================================================================
# Linux kernel local root quartet: checker  (v1)
# DirtyAH6 CVE-2026-80844, TUNderflow CVE-2026-81000, PPPoEject CVE-2026-68121,
# DiagSpill CVE-2026-74469
#
# If this software is helpful, consider a donation to our 501c3 nonprofit:
# https://privacysafe.foundation
#
# Four local privilege escalation flaws in the Linux kernel, disclosed on the oss-security list
# on 18 September 2026 by Asim Manizada, after an embargo agreed with the linux-distros list
# (reported to the kernel security team in mid-July). Public proof-of-concept exploits exist.
# Each gives an unprivileged local user code execution as root on the systems it targets, and
# each can corrupt the host kernel from a container. The bugs are 10 to 21 years old.
#
#   CVE-2026-80844  DirtyAH6    IPsec AH over IPv6 (ah6): ipv6_rearrange_rthdr() does not check
#                               that segments_left is within the header, an out-of-bounds
#                               access. Needs unprivileged user and network namespaces, or
#                               CAP_NET_ADMIN and CAP_NET_RAW over an attacker-controlled
#                               network namespace. Remote crash only if the host routes IPv6
#                               and adds an Authentication Header in transport mode.
#   CVE-2026-81000  TUNderflow  TUN/TAP: oversized receive headroom underflows a length and
#                               leaves skb->data beyond its allocation. Needs unprivileged
#                               user and network namespaces, or CAP_NET_ADMIN over one.
#   CVE-2026-68121  PPPoEject   PPPoE: pppoe_sendmsg() keeps a pointer into a socket-buffer
#                               head that dev_hard_header() can free (use after free). Needs
#                               unprivileged user and network namespaces, or CAP_NET_ADMIN.
#   CVE-2026-74469  DiagSpill   SCTP: a 16-bit peer transport count wraps to zero, so sctp_diag
#                               copies about 8 MiB past the end of its Netlink reply. Needs
#                               SCTP and sctp_diag, and NO user namespace or capability.
#                               Remote crash only with non-default SCTP options.
#
#   Affected: DirtyAH6 and PPPoEject since 2.6.12, TUNderflow since 4.6, DiagSpill since 4.7,
#             through the stable releases below. Every release of a branch not listed in the
#             table (5.11 to 5.14, 5.16 to 6.0, 6.2 to 6.5, 6.7 to 6.11, 6.13 to 6.17, 6.19
#             to 7.0, and older ones such as 5.4) is affected and has no upstream fix.
#   First fixed stable release of each branch, per flaw (DirtyAH6 / TUNderflow / PPPoEject /
#   DiagSpill):
#     5.10  269 / 270 / 265 / 265      6.12  108 / 109 / 101 / 103
#     5.15  220 / 221 / 216 / 216      6.18   49 /  50 /  42 /  44
#     6.1   187 / 188 / 183 / 183      7.1    13 /  14 /   6 /   8
#     6.6   156 / 157 / 148 / 151      7.2     3 /   4 / not affected / not affected
#   The first stable releases with all four fixes: 5.10.270, 5.15.221, 6.1.188, 6.6.157,
#   6.12.109, 6.18.50 and 7.2.4.
#
# Why this script reads the kernel's origin first. The upstream patch level is in the release
# string only on kernels that follow the stable series (vanilla, Arch, Alpine, most custom
# builds). Debian puts it in `uname -v`. Ubuntu, RHEL and its derivatives, SUSE and Amazon Linux
# backport fixes under release strings that do not say which fixes they carry, so a number from
# them cannot be compared with the table. For those the vendor changelog is the evidence: the
# script looks in it for each CVE, and points you to the vendor's tracker when it is absent. A kernel that
# is a stable release candidate (-rc) is judged as the release before it.
#
# What the exposure lines mean. They report whether the module each flaw needs is loaded,
# built in or loadable, and whether unprivileged user namespaces are allowed. That is
# information for you to weigh, not a verdict: a kernel below its fixed release is affected
# whatever these show, and a process with the right capabilities, such as a container, does not
# need a user namespace for the first three. That reading is the project's.
#
# A container shows the host's kernel, so run this on the host.
#
# GitHub proof-of-concept repositories exist for all four, so there is no indicator to hunt
# for in logs and this script has no hunt. It is read-only.
#
# Usage:
#   ./linux-kernel-lpe-check.sh [check]
#   check (default)  Exit 0 = the running kernel has all four fixes (or vendor backports),
#                    1 = affected by at least one, or a vendor backport could not be confirmed.
#   mitigate [--userns] [--modules LIST] [--force] [--dry-run]   (root) changes the host.
#                    The researcher's protective measures; a patched kernel is the
#                    permanent fix: they only act when check finds
#                    the kernel affected (--force overrides). Choose what to apply,
#                    because each can break software that depends on it:
#                      --userns        stops unprivileged user namespaces, using the
#                                      mildest switch this kernel has:
#                                      kernel.unprivileged_userns_clone=0, else
#                                      kernel.apparmor_restrict_unprivileged_userns=1
#                                      (restricts, does not fully block). Only with
#                                      --force does it fall back to
#                                      user.max_user_namespaces=0, which stops ALL new
#                                      user namespaces. Breaks rootless containers
#                                      (podman, rootless docker), flatpak and browser
#                                      sandboxes. The change is applied live and
#                                      written to a sysctl.d file. It does not stop
#                                      DiagSpill, which needs no namespace.
#                      --modules LIST  prevents loading of the listed modules, from:
#                                      ah6 tun pppoe sctp sctp_diag ebt_snat (or all).
#                                      "install NAME /bin/false" lines in a modprobe.d
#                                      file. A module that is loaded now is left alone
#                                      (it cannot be unloaded safely here) unless
#                                      --force, which still only blocks later loads.
#                                      tun is used by OpenVPN, Tailscale and QEMU
#                                      networking; sctp by telecom software; pppoe by
#                                      DSL dial-up; ah6 by IPsec AH; ebt_snat by
#                                      bridge firewalls.
#                    --dry-run shows everything and changes nothing. Previous sysctl
#                    values are saved so that rollback can put them back.
#   rollback [--dry-run]   restore the saved sysctl values and remove the files mitigate wrote.
#   version          print the script version.
#
# Env: KERNEL_CHANGELOG   a vendor changelog file to read, plain or .gz
#      STATE_DIR (default /var/lib/psf-security-patches/linux-kernel), SYSCTL_D and
#      MODPROBE_D (default /etc/sysctl.d and /etc/modprobe.d) for mitigate and rollback
#      KERNEL_RELEASE, KERNEL_VERSION_STRING   override uname -r and uname -v
#      KERNEL_MODULES_FILE, KERNEL_PROC_SYS    override /proc/modules and /proc/sys
#      KERNEL_BUILTIN_FILE   override /lib/modules/<release>/modules.builtin
# =============================================================================

# Commands run as "cmd_${CMD}", which shellcheck cannot follow
# shellcheck disable=SC2317,SC2329,SC2034
set -uo pipefail

SCRIPT_NAME="linux-kernel-lpe-check.sh"
SCRIPT_VERSION="1.0.0"
SCRIPT_DATE="2026-10-30"
SELF="$0"
STATE_DIR="${STATE_DIR:-/var/lib/psf-security-patches/linux-kernel}"


# ---------- common helpers (the same block is used in every check script) ----
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; CYAN='\033[0;36m'; NC='\033[0m'
[[ -t 1 ]] || { RED=''; GREEN=''; YELLOW=''; CYAN=''; NC=''; }
info()    { echo -e "${GREEN}[+]${NC} $*"; }
warn()    { echo -e "${YELLOW}[!]${NC} $*"; }
step()    { echo -e "\n${CYAN}=====${NC} $* ${CYAN}=====${NC}"; }
die()     { echo -e "${RED}[-] FATAL:${NC} $*" >&2; exit 2; }
ok()      { echo -e "  ${GREEN}check${NC} $*"; }
bad()     { echo -e "  ${RED}CRIT${NC}  $*"; }
caution() { echo -e "  ${YELLOW}WARN${NC}  $*"; }
inf()     { echo -e "  ${CYAN}info${NC}  $*"; }
have()    { command -v "$1" >/dev/null 2>&1; }

# Version helpers: strip a leading v and any -prerelease or +build suffix, then compare with
# sort -V. A pre-release of the boundary itself (6.3.0-rc2 against 6.3.0) is below it, as in
# semantic versioning, so a pre-release of a fixed release is never reported as the release.
norm_ver() { local v="${1#v}"; v="${v%%[-+]*}"; echo "$v"; }
ver_lt() {
    local a b
    a="$(norm_ver "$1")"; b="$(norm_ver "$2")"
    if [[ "$a" == "$b" ]]; then [[ "${1#v}" =~ ^[0-9][0-9.]*-(alpha|beta|rc|dev|pre) ]]; return; fi
    [[ "$(printf '%s\n%s\n' "$a" "$b" | sort -V | head -n1)" == "$a" ]]
}
ver_ge() { ! ver_lt "$1" "$2"; }
is_semver() { [[ "$(norm_ver "$1")" =~ ^[0-9]+\.[0-9]+(\.[0-9]+)*$ ]]; }

# distro_mentions FILE CVE...
# Distributions often backport a fix without changing the upstream version
# string. This looks at the changelog of the package that owns FILE.
#   return 0: changelog mentions one of the CVE ids (DISTRO_HIT, DISTRO_PKG set)
#   return 1: FILE is package-managed but the changelog does not mention them
#   return 2: FILE is not owned by a dpkg or rpm package
DISTRO_PKG=""; DISTRO_HIT=""
distro_mentions() {
    local f real pkg="" cl="" c id
    f="$1"; shift
    real="$(readlink -f "$f" 2>/dev/null || echo "$f")"
    if have dpkg; then
        pkg="$(dpkg -S "$real" 2>/dev/null | head -n1 | cut -d: -f1)"
        if [[ -n "$pkg" ]]; then
            for c in "/usr/share/doc/${pkg}/changelog.Debian.gz" "/usr/share/doc/${pkg}/changelog.gz"; do
                [[ -r "$c" ]] && cl+="$(zcat "$c" 2>/dev/null)"
            done
        fi
    fi
    if [[ -z "$pkg" ]] && have rpm; then
        pkg="$(rpm -qf "$real" 2>/dev/null | head -n1)"
        [[ "$pkg" == *"not owned"* ]] && pkg=""
        [[ -n "$pkg" ]] && cl="$(rpm -q --changelog "$pkg" 2>/dev/null)"
    fi
    [[ -n "$pkg" ]] || return 2
    DISTRO_PKG="$pkg"
    for id in "$@"; do
        if grep -qF "$id" <<<"$cl"; then DISTRO_HIT="$id"; return 0; fi
    done
    return 1
}

# Print the help text: everything between the first two ===== lines of this file.
print_help() { awk 'f && /^# =+$/ {exit} f {sub(/^# ?/,""); print} /^# =+$/ {f=1}' "$SELF"; }
# ---------- the four flaws ---------------------------------------------------
# One row per flaw: id|name|introduced|first fixed patch release per branch|modules|needs a namespace
# A fixed patch of 0 means the whole branch is not affected.
LPE_ROWS=(
"CVE-2026-80844|DirtyAH6|2.6.12|5.10:269 5.15:220 6.1:187 6.6:156 6.12:108 6.18:49 7.1:13 7.2:3|ah6|yes"
"CVE-2026-81000|TUNderflow|4.6|5.10:270 5.15:221 6.1:188 6.6:157 6.12:109 6.18:50 7.1:14 7.2:4|tun|yes"
"CVE-2026-68121|PPPoEject|2.6.12|5.10:265 5.15:216 6.1:183 6.6:148 6.12:101 6.18:42 7.1:6 7.2:0|pppoe|yes"
"CVE-2026-74469|DiagSpill|4.7|5.10:265 5.15:216 6.1:183 6.6:151 6.12:103 6.18:44 7.1:8 7.2:0|sctp sctp_diag|no"
)
NEWEST_LISTED="7.2"

# prints: fixed | notaffected | affected | eol | unknown        (for an upstream x.y.z)
#   eol = a branch with no upstream fix listed
lpe_status() {   # <introduced> <fixed per branch> <x.y.z>
    local intro="$1" fixes="$2" ver="${3%%-*}" maj min pat line e fx
    [[ "$ver" =~ ^([0-9]+)\.([0-9]+)\.([0-9]+)$ ]] || { echo unknown; return; }
    maj="${BASH_REMATCH[1]}"; min="${BASH_REMATCH[2]}"; pat="${BASH_REMATCH[3]}"
    if ver_lt "$ver" "$intro"; then echo notaffected; return; fi
    line="${maj}.${min}"
    for e in $fixes; do
        if [[ "${e%%:*}" == "$line" ]]; then
            fx="${e#*:}"
            if (( fx == 0 )); then echo notaffected; return; fi
            if (( pat >= fx )); then echo fixed; else echo affected; fi
            return
        fi
    done
    # newer than the newest listed branch: the mainline carries every fix; older branches that
    # are not listed are end of life
    if ver_lt "$NEWEST_LISTED" "$line"; then echo fixed; else echo eol; fi
}

# prints: stable <x.y.z> | debian <x.y.z> | vendor
kernel_origin() {
    local rel="$1" ver="$2" up
    if [[ "$ver" =~ Debian[[:space:]]+([0-9]+\.[0-9]+\.[0-9]+)- ]]; then echo "debian ${BASH_REMATCH[1]}"; return; fi
    if [[ "$ver" == *Ubuntu* ]] \
       || [[ "$rel" =~ \.(el|fc|amzn|azl|oe|ael)[0-9]+ ]] \
       || [[ "$rel" =~ ^[0-9]+\.[0-9]+\.[0-9]+-[0-9]+\.[0-9]+ ]] \
       || [[ "$rel" =~ ^[0-9]+\.[0-9]+\.0-[0-9]+ ]]; then echo vendor; return; fi
    up="${rel%%-*}"
    if [[ "$up" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]]; then echo "stable ${up}"; else echo vendor; fi
}

# does a vendor changelog name this CVE?
changelog_names() {   # <release> <CVE>
    local c pkg rel="$1" cve="$2"
    if [[ -n "${KERNEL_CHANGELOG:-}" && -r "${KERNEL_CHANGELOG}" ]]; then
        if zcat -f "${KERNEL_CHANGELOG}" 2>/dev/null | grep -F "$cve" >/dev/null; then return 0; fi
        return 1
    fi
    if have dpkg; then
        for pkg in $(dpkg -S "/boot/vmlinuz-${rel}" "/lib/modules/${rel}" 2>/dev/null | cut -d: -f1 | sort -u); do
            for c in /usr/share/doc/"${pkg}"/changelog*; do
                [[ -r "$c" ]] || continue
                if zcat -f "$c" 2>/dev/null | grep -F "$cve" >/dev/null; then return 0; fi
            done
        done
    fi
    if have rpm; then
        pkg="$(rpm -qf "/lib/modules/${rel}" 2>/dev/null | head -n1)"
        if [[ -n "$pkg" && "$pkg" != *"not owned"* ]]; then
            if rpm -q --changelog "$pkg" 2>/dev/null | grep -F "$cve" >/dev/null; then return 0; fi
        fi
    fi
    return 1
}

# prints: loaded | builtin | loadable | absent
mod_state() {   # <module> <release>
    local m="$1" rel="$2" mods="${KERNEL_MODULES_FILE:-/proc/modules}" bi="${KERNEL_BUILTIN_FILE:-/lib/modules/$2/modules.builtin}"
    if [[ -r "$mods" ]] && grep -E "^${m} " "$mods" >/dev/null; then echo loaded; return; fi
    if [[ -r "$bi" ]] && grep -E "/${m}\.ko" "$bi" >/dev/null; then echo builtin; return; fi
    if have modinfo && modinfo "$m" >/dev/null 2>&1; then echo loadable; return; fi
    echo absent
}

# prints: disabled | restricted | allowed | unknown
userns_state() {
    local ps="${KERNEL_PROC_SYS:-/proc/sys}" v
    if [[ -r "$ps/user/max_user_namespaces" ]]; then
        v="$(cat "$ps/user/max_user_namespaces" 2>/dev/null)"; [[ "$v" == 0 ]] && { echo disabled; return; }
    fi
    if [[ -r "$ps/kernel/unprivileged_userns_clone" ]]; then
        v="$(cat "$ps/kernel/unprivileged_userns_clone" 2>/dev/null)"; [[ "$v" == 0 ]] && { echo disabled; return; }
    fi
    if [[ -r "$ps/kernel/apparmor_restrict_unprivileged_userns" ]]; then
        v="$(cat "$ps/kernel/apparmor_restrict_unprivileged_userns" 2>/dev/null)"; [[ "$v" == 1 ]] && { echo restricted; return; }
    fi
    if [[ -r "$ps/user/max_user_namespaces" ]]; then echo allowed; else echo unknown; fi
}

cmd_check() {
    local rc=0 rel ver origin kind up row id name intro fixes mods needns st m ms n_bad=0
    local -a affected_ids=()
    rel="${KERNEL_RELEASE:-$(uname -r 2>/dev/null)}"; ver="${KERNEL_VERSION_STRING:-$(uname -v 2>/dev/null)}"
    step "Running kernel"
    [[ -n "$rel" ]] || { caution "uname -r returned nothing: cannot check"; return 1; }
    inf "release: ${rel}"
    origin="$(kernel_origin "$rel" "$ver")"; kind="${origin%% *}"; up=""; [[ "$origin" == *" "* ]] && up="${origin#* }"
    case "$kind" in
        stable) inf "origin: follows the stable series; upstream version ${up}" ;;
        debian) inf "origin: Debian; upstream version ${up} (from uname -v)" ;;
        *)      inf "origin: a vendor kernel that backports fixes; its release string does not show which" ;;
    esac
    # a stable release candidate (6.12.109-rc1) comes before the release it leads to and may not
    # carry the fixes: judge it as the release before it
    if [[ "$kind" == stable && "$rel" =~ -rc[0-9]+ && "$up" =~ ^([0-9]+\.[0-9]+)\.([0-9]+)$ && "${BASH_REMATCH[2]}" -gt 0 ]]; then
        up="${BASH_REMATCH[1]}.$(( BASH_REMATCH[2] - 1 ))"; inf "a release candidate is not the release: judged as the release before it, ${up}"
    fi
    step "The four flaws"
    for row in "${LPE_ROWS[@]}"; do
        IFS='|' read -r id name intro fixes mods needns <<<"$row"
        if [[ -n "$up" ]]; then st="$(lpe_status "$intro" "$fixes" "$up")"; else st=vendor; fi
        case "$st" in
            fixed)       ok "${name} (${id}): upstream ${up} is at or beyond the fixed release of its branch" ;;
            notaffected) ok "${name} (${id}): upstream ${up} is not affected (the bug came in with ${intro}, or this branch never had it)" ;;
            affected|eol|unknown|vendor)
                if changelog_names "$rel" "$id"; then
                    ok "${name} (${id}): the vendor changelog names ${id}: this kernel carries a backport, so its version number understates its state"
                else
                    case "$st" in
                        affected) bad "${name} (${id}): upstream ${up} is below the fixed release of its branch" ;;
                        eol)      bad "${name} (${id}): upstream ${up} is on a branch with no upstream fix listed (end of life): only a vendor backport fixes it" ;;
                        unknown)  caution "${name} (${id}): cannot parse upstream version '${up}', and the vendor changelog does not name ${id}" ;;
                        vendor)   caution "${name} (${id}): The vendor changelog does not name ${id} (or is not readable), and this release string cannot be compared with the upstream table" ;;
                    esac
                    rc=1; n_bad=$((n_bad+1)); affected_ids+=("${id}|${name}|${mods}|${needns}")
                fi ;;
        esac
    done
    if [[ ${#affected_ids[@]} -gt 0 ]]; then
        step "Exposure surface of the flaws still open (information; a kernel below its fixed release is affected whatever this shows)"
        local entry us; us="$(userns_state)"
        for entry in "${affected_ids[@]}"; do
            IFS='|' read -r id name mods needns <<<"$entry"
            local msum=""; for m in $mods; do ms="$(mod_state "$m" "$rel")"; msum+="${m}: ${ms}; "; done
            if [[ "$needns" == yes ]]; then
                inf "${name}: ${msum}needs unprivileged user namespaces (${us}) or the capabilities CAP_NET_ADMIN over a network namespace"
            else
                inf "${name}: ${msum}needs no user namespace and no capability"
            fi
        done
        case "$us" in
            disabled)   inf "unprivileged user namespaces are disabled: that removes the ordinary-user path to DirtyAH6, TUNderflow and PPPoEject; DiagSpill is unaffected by it" ;;
            restricted) inf "unprivileged user namespaces are restricted by AppArmor: that blocks the plain path to the first three; DiagSpill is unaffected by it" ;;
            allowed)    inf "unprivileged user namespaces are allowed" ;;
            *)          inf "could not read the user namespace setting" ;;
        esac
    fi
    step "Verdict"
    if [[ $rc -eq 0 ]]; then info "The running kernel has the fixes for all four flaws (or a vendor backport)."
    else
        warn "The running kernel is affected by ${n_bad} of the four flaws or a fix could not be confirmed. Update to your vendor's fixed kernel and reboot."
        inf "Upstream: the first stable releases with all four fixes are 5.10.270, 5.15.221, 6.1.188, 6.6.157, 6.12.109, 6.18.50 and 7.2.4"
        inf "Until then (the researcher's suggestion in the disclosure, not a vendor's): disable unprivileged user namespaces (it removes the ordinary-user path to the first three; it can break rootless containers and some sandboxes), and disable AH6, TUN, PPPoE and SCTP with sctp_diag where they are not used. A process with the right capabilities, such as a container, and DiagSpill are not stopped by the namespace setting"
    fi
    return "$rc"
}


# ---------- mitigate and rollback --------------------------------------------
LM_MANIFEST=""; LM_DRY=0
lm_note() { [[ "$LM_DRY" -eq 1 ]] || echo "$1" >>"$LM_MANIFEST"; }
lm_valid_mods="ah6 tun pppoe sctp sctp_diag ebt_snat"

lm_sysctl_set() {   # path-under-proc-sys value
    local ps="${KERNEL_PROC_SYS:-/proc/sys}" f old
    f="$ps/$1"; old="$(cat "$f" 2>/dev/null)"
    if [[ "$LM_DRY" -eq 1 ]]; then echo "  would set ${1//\//.}=$2 (now ${old:-unreadable})"; return 0; fi
    if printf '%s\n' "$2" >"$f" 2>/dev/null; then
        lm_note "sysctl|$1|${old}"; ok "set ${1//\//.}=$2 (was ${old:-unknown}), applied now"; return 0
    fi
    bad "could not write ${f}: read-only /proc/sys (a container?) or no permission"; return 1
}

cmd_mitigate() {
    local userns=0 mods="" force=0 rc=0 rel ps m st line keys="" lines="" sd md mf cnt=0 did=0 mt
    local -a want=() mlines=()
    LM_DRY=0
    while [[ $# -gt 0 ]]; do
        case "$1" in
            --userns) userns=1 ;; --force) force=1 ;; --dry-run) LM_DRY=1 ;;
            --modules) shift; mods="${1:-}"; [[ -n "$mods" ]] || die "--modules needs a comma separated list (${lm_valid_mods// /,} or all)" ;;
            *) die "Unknown mitigate option: $1 (--userns --modules LIST --force --dry-run)" ;;
        esac
        shift
    done
    [[ $userns -eq 1 || -n "$mods" ]] || die "mitigate needs --userns and/or --modules LIST, because each measure can break software that depends on it (see --help). Nothing was changed."
    if [[ -n "$mods" ]]; then
        [[ "$mods" == all ]] && mods="${lm_valid_mods// /,}"
        for m in ${mods//,/ }; do
            case " $lm_valid_mods " in *" $m "*) want+=("$m") ;; *) die "not a module this tool knows: ${m} (${lm_valid_mods// /,})" ;; esac
        done
    fi
    [[ $LM_DRY -eq 1 || "${EUID:-$(id -u)}" -eq 0 ]] || die "mitigate changes the host: run it as root, or add --dry-run to see what it would do"
    rel="${KERNEL_RELEASE:-$(uname -r)}"; ps="${KERNEL_PROC_SYS:-/proc/sys}"
    step "Is this kernel affected?"
    if cmd_check >/dev/null 2>&1; then
        if [[ $force -eq 0 ]]; then info "check finds this kernel fixed (or carrying vendor backports): nothing to do (use --force to apply anyway)"; return 0; fi
        caution "check finds this kernel fixed, applying anyway because of --force"
    else bad "check finds kernel ${rel} affected or no vendor backport is confirmed: applying the measures you chose"; fi
    if [[ $LM_DRY -eq 0 ]]; then
        mkdir -p "$STATE_DIR" || die "cannot create ${STATE_DIR}"
        LM_MANIFEST="${STATE_DIR}/manifest.txt"; touch "$LM_MANIFEST"
    else LM_MANIFEST=/dev/null; step "Dry run: nothing will be changed"; fi
    sd="${SYSCTL_D:-/etc/sysctl.d}"; md="${MODPROBE_D:-/etc/modprobe.d}"
    if [[ $userns -eq 1 ]]; then
        step "Unprivileged user namespaces"
        local keypath="" val=""
        if [[ -e "$ps/kernel/unprivileged_userns_clone" ]]; then keypath="kernel/unprivileged_userns_clone"; val=0
        elif [[ -e "$ps/kernel/apparmor_restrict_unprivileged_userns" ]]; then keypath="kernel/apparmor_restrict_unprivileged_userns"; val=1; caution "this switch restricts unprivileged namespaces to AppArmor-allowed programs; it does not block them outright"
        elif [[ -e "$ps/user/max_user_namespaces" ]]; then
            if [[ $force -eq 1 ]]; then keypath="user/max_user_namespaces"; val=0; caution "using user.max_user_namespaces=0: this stops ALL new user namespaces (rootless containers, flatpak, browser sandboxes)"
            else caution "this kernel only has user.max_user_namespaces, which stops ALL user namespaces (rootless containers, flatpak, browser sandboxes): left alone. Add --force to use it."; rc=1; fi
        else caution "no user namespace switch found under ${ps}"; rc=1; fi
        if [[ -n "$keypath" ]]; then
            if lm_sysctl_set "$keypath" "$val"; then
                lines="${keypath//\//.} = ${val}"; did=1
                if [[ $LM_DRY -eq 0 ]]; then
                    mkdir -p "$sd" && { printf '# psf-security-patches: Linux kernel local root quartet protective measure (linux-kernel-lpe-check.sh mitigate). Remove with: rollback\n%s\n' "$lines" >"$sd/99-psf-kernel-lpe.conf" && lm_note "file|$sd/99-psf-kernel-lpe.conf" && ok "persistent across reboots: ${sd}/99-psf-kernel-lpe.conf"; }
                else echo "  would write ${sd}/99-psf-kernel-lpe.conf"; fi
            else rc=1; fi
        fi
    fi
    if [[ ${#want[@]} -gt 0 ]]; then
        step "Module loading"
        for m in "${want[@]}"; do
            st="$(mod_state "$m" "$rel")"
            case "$st" in
                loaded) if [[ $force -eq 1 ]]; then caution "${m}: loaded now; blocking later loads only (it stays loaded until reboot or unload)"; mlines+=("$m")
                        else caution "${m}: loaded and probably in use: left alone (--force blocks later loads only)"; fi ;;
                builtin) inf "${m}: built into the kernel: a modprobe rule cannot block it" ;;
                absent) inf "${m}: not present on this kernel: nothing to block" ;;
                *) mlines+=("$m") ;;
            esac
        done
        if [[ ${#mlines[@]} -gt 0 ]]; then
            mf="$md/psf-kernel-lpe.conf"
            mt="# psf-security-patches: Linux kernel local root quartet protective measure (linux-kernel-lpe-check.sh mitigate). Remove with: rollback"
            for m in "${mlines[@]}"; do mt+=$'\n'"blacklist ${m}"$'\n'"install ${m} /bin/false"; done
            if [[ $LM_DRY -eq 1 ]]; then echo "  would write ${mf}:"; printf '%s\n' "$mt" | sed 's/^/      /'
            else
                mkdir -p "$md" && printf '%s\n' "$mt" >"$mf" && { lm_note "file|${mf}"; ok "loading blocked for: ${mlines[*]} (${mf})"; did=1; }
            fi
        fi
    fi
    step "Result"
    if [[ $LM_DRY -eq 1 ]]; then info "Dry run finished: nothing was changed"
    elif [[ $did -eq 1 ]]; then info "Applied. Backups and manifest: ${STATE_DIR}. Undo with: $0 rollback"
    else info "Nothing was changed"; fi
    inf "These are the researcher's measures, applied by PrivacySafe. The fix is a patched kernel and a reboot."
    return "$rc"
}

cmd_rollback() {
    local line kind rest path old f rc=0 ps="${KERNEL_PROC_SYS:-/proc/sys}"
    LM_DRY=0
    while [[ $# -gt 0 ]]; do
        case "$1" in --dry-run) LM_DRY=1 ;; *) die "Unknown rollback option: $1 (--dry-run)" ;; esac
        shift
    done
    LM_MANIFEST="${STATE_DIR}/manifest.txt"
    [[ -s "$LM_MANIFEST" ]] || { info "Nothing to roll back (no manifest in ${STATE_DIR})"; return 0; }
    [[ $LM_DRY -eq 1 || "${EUID:-$(id -u)}" -eq 0 ]] || die "rollback changes the host: run it as root, or add --dry-run"
    step "Rolling back"
    while IFS= read -r line; do
        kind="${line%%|*}"; rest="${line#*|}"
        case "$kind" in
            sysctl) path="${rest%%|*}"; old="${rest#*|}"
                if [[ -z "$old" ]]; then caution "${path//\//.}: previous value unknown, left alone"; rc=1; continue; fi
                if [[ $LM_DRY -eq 1 ]]; then echo "  would set ${path//\//.}=${old}"; else printf '%s\n' "$old" >"$ps/$path" 2>/dev/null && ok "restored ${path//\//.}=${old}" || { bad "could not write ${path}"; rc=1; }; fi ;;
            file) f="$rest"; if [[ $LM_DRY -eq 1 ]]; then echo "  would remove ${f}"; else rm -f "$f" && ok "removed ${f}"; fi ;;
        esac
    done <"$LM_MANIFEST"
    if [[ $LM_DRY -eq 0 && $rc -eq 0 ]]; then
        mv "$LM_MANIFEST" "${LM_MANIFEST}.rolled-back-$(date +%s)" 2>/dev/null || true
        info "Rolled back. A module that was blocked can load again."
    fi
    return "$rc"
}

main() {
    CMD="${1:-check}"; [[ $# -gt 0 ]] && shift
    case "$CMD" in -V|--version|version) echo "${SCRIPT_NAME} ${SCRIPT_VERSION} (${SCRIPT_DATE})"; exit 0 ;; esac
    case "$CMD" in -h|--help|help) print_help; exit 0 ;; esac
    echo "${SCRIPT_NAME} ${SCRIPT_VERSION} (${SCRIPT_DATE}) - ${CMD} on $(hostname 2>/dev/null || echo '?') at $(date -u +%FT%TZ)"
    echo "DirtyAH6, TUNderflow, PPPoEject and DiagSpill (CVE-2026-80844, -81000, -68121, -74469): Linux kernel local root"
    case "$CMD" in
        check) cmd_check "$@" ;;
        mitigate) cmd_mitigate "$@" ;;
        rollback) cmd_rollback "$@" ;;
        *) die "Unknown command: ${CMD} (check|mitigate|rollback|version)" ;;
    esac
}
main "$@"; exit

# Assisted-by: Claude Sonnet 5.5
