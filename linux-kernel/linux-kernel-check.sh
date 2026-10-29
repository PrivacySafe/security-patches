#!/usr/bin/env bash
# SPDX-License-Identifier: CC0-1.0
# =============================================================================
# Linux kernel ebtables SNAT out-of-bounds write: read-only checker  (v2)
# CVE-2026-53266
#
# If this software is helpful, consider a donation to our 501c3 nonprofit:
# https://privacysafe.foundation
#
# CVE-2026-53266 is an out-of-bounds write in the bridge netfilter ebtables SNAT target.
# When the target rewrites the ARP sender hardware address, it writes into a
# socket-buffer fragment, which can be backed by a page imported from a file, without
# first making that range writable. A local user with CAP_NET_ADMIN who can reach that
# path can cause memory corruption, a crash, or privilege escalation to root.
#
# CISA added it to the Known Exploited Vulnerabilities catalog on 18 September 2026 with
# a three-day federal deadline. CVSS 8.8 (NVD, CVSS 3.1); Red Hat scores it 7.5. CWE-787.
#
#   Fixed in the stable kernels:
#     5.10.259  5.15.210  6.1.176  6.6.143  6.12.94  6.18.36  7.0.13
#   Branches with no upstream fix listed (end of life, for example 5.4): a vendor
#   backport is the only fix.
#
# Why this script reads the kernel's origin first. The upstream patch level is in the
# release string only on kernels that follow the stable series (vanilla, Arch, Alpine,
# most custom builds). Debian puts it in `uname -v`. Ubuntu, RHEL and its derivatives,
# SUSE and Amazon Linux backport fixes under release strings that do not say which
# fixes they carry (for example 6.8.0-45-generic, 5.14.0-503.el9), so a number from
# them cannot be compared with the table above. For those the vendor changelog is the
# evidence: the script looks in it for CVE-2026-53266, and says "cannot confirm" when
# it is absent.
#
# What the exposure lines mean. The CVE needs an ebtables SNAT rule that rewrites the
# ARP sender hardware address (the --snat-arp option). Seeing no such rule on the host
# does NOT make a kernel safe: a local user with CAP_NET_ADMIN inside a user namespace
# may be able to create one in their own network namespace. The script therefore
# reports the rules, whether the ebt_snat module is loaded or loadable, and whether
# unprivileged user namespaces are allowed, as information for you to weigh. That
# reading is the project's, not the vendor's.
#
# This script is read-only.
#
# Usage:
#   ./linux-kernel-check.sh [check]
#   check (default)  Exit 0 = the running kernel has the fix (or a vendor backport),
#                    1 = affected, or the vendor backport could not be confirmed.
#   version          print the script version.
#
# Env: KERNEL_CHANGELOG   a vendor changelog file to read, plain or .gz
#      KERNEL_RELEASE, KERNEL_VERSION_STRING   override uname -r and uname -v
#      KERNEL_MODULES_FILE, KERNEL_PROC_SYS    override /proc/modules and /proc/sys
# =============================================================================

# Commands run as "cmd_${CMD}", which shellcheck cannot follow
# shellcheck disable=SC2317,SC2329,SC2034
set -uo pipefail

SCRIPT_NAME="linux-kernel-check.sh"
SCRIPT_VERSION="2.0.0"
SCRIPT_DATE="2026-10-28"
SELF="$0"

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
# ---------- the fixed stable kernels -----------------------------------------
# prints: fixed | affected | eol | unknown        (for an upstream x.y.z)
#   eol = a branch with no upstream fix listed
kernel_status() {
    local ver="${1%%-*}" maj min pat fixed
    [[ "$ver" =~ ^([0-9]+)\.([0-9]+)\.([0-9]+)$ ]] || { echo unknown; return; }
    maj="${BASH_REMATCH[1]}"; min="${BASH_REMATCH[2]}"; pat="${BASH_REMATCH[3]}"
    case "${maj}.${min}" in
        5.10) fixed=259 ;; 5.15) fixed=210 ;; 6.1) fixed=176 ;; 6.6) fixed=143 ;;
        6.12) fixed=94 ;;  6.18) fixed=36 ;;  7.0) fixed=13 ;;
        *)  # newer than the 7.0 series: the mainline carried the fix (assumed: the 7.0.13
            # backport means the mainline commit is older than that); older, non-listed
            # branches are end of life
            if (( maj > 7 || (maj == 7 && min > 0) )); then echo fixed; else echo eol; fi
            return ;;
    esac
    (( pat >= fixed )) && echo fixed || echo affected
}

# prints: stable <x.y.z> | debian <x.y.z> | vendor
#   debian : uname -v names Debian and its upstream version
#   vendor : Ubuntu; an RPM release marker (.el9, .fc40, .amzn2023 ...); a dotted ABI field
#            (SUSE's 6.4.0-150600.23.14-default); or a placeholder patch level of 0 with an
#            ABI number (6.1.0-28-amd64), none of which show the upstream patch level
#   stable : everything else (vanilla, Arch, Alpine, most custom builds)
kernel_origin() {
    local rel="$1" ver="$2" up
    if [[ "$ver" =~ Debian[[:space:]]+([0-9]+\.[0-9]+\.[0-9]+)- ]]; then echo "debian ${BASH_REMATCH[1]}"; return; fi
    if [[ "$ver" == *Ubuntu* ]] \
       || [[ "$rel" =~ \.(el|fc|amzn|azl|oe|ael)[0-9]+ ]] \
       || [[ "$rel" =~ ^[0-9]+\.[0-9]+\.[0-9]+-[0-9]+\.[0-9]+ ]] \
       || [[ "$rel" =~ ^[0-9]+\.[0-9]+\.0-[0-9]+ ]]; then echo vendor; return; fi
    up="${rel%%-*}"
    [[ "$up" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]] && echo "stable ${up}" || echo vendor
}

# does a vendor changelog name the fix?
changelog_names_fix() {
    local c pkg rel="$1"
    if [[ -n "${KERNEL_CHANGELOG:-}" && -r "${KERNEL_CHANGELOG}" ]]; then
        if zcat -f "${KERNEL_CHANGELOG}" 2>/dev/null | grep -F 'CVE-2026-53266' >/dev/null; then return 0; fi
        return 1
    fi
    if have dpkg; then
        for pkg in $(dpkg -S "/boot/vmlinuz-${rel}" "/lib/modules/${rel}" 2>/dev/null | cut -d: -f1 | sort -u); do
            for c in /usr/share/doc/"${pkg}"/changelog*; do
                [[ -r "$c" ]] || continue
                if zcat -f "$c" 2>/dev/null | grep -F 'CVE-2026-53266' >/dev/null; then return 0; fi
            done
        done
    fi
    if have rpm; then
        pkg="$(rpm -qf "/lib/modules/${rel}" 2>/dev/null | head -n1)"
        if [[ -n "$pkg" && "$pkg" != *"not owned"* ]]; then
            if rpm -q --changelog "$pkg" 2>/dev/null | grep -F 'CVE-2026-53266' >/dev/null; then return 0; fi
        fi
    fi
    return 1
}

cmd_check() {
    local rc=0 rel ver origin kind up st have_log=0
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
    # a stable release candidate (7.0.13-rc1) comes before the release it leads to and may not
    # carry the fix: judge it as the release before it
    if [[ "$kind" == stable && "$rel" =~ -rc[0-9]+ && "$up" =~ ^([0-9]+\.[0-9]+)\.([0-9]+)$ && "${BASH_REMATCH[2]}" -gt 0 ]]; then
        up="${BASH_REMATCH[1]}.$(( BASH_REMATCH[2] - 1 ))"; inf "a release candidate is not the release: judged as the release before it, ${up}"
    fi
    step "Version and vendor changelog"
    if [[ -n "$up" ]]; then
        st="$(kernel_status "$up")"
        case "$st" in
            fixed)    ok "upstream ${up} is at or beyond the fixed release of its branch (CVE-2026-53266)" ;;
            affected) bad "upstream ${up} is below the fixed release of its branch (CVE-2026-53266)"; rc=1 ;;
            eol)      bad "upstream ${up} is on a branch with no upstream fix listed (end of life): only a vendor backport fixes it"; rc=1 ;;
            *)        caution "cannot parse upstream version '${up}'"; rc=1 ;;
        esac
    fi
    if [[ -z "$up" || "$rc" -eq 1 ]]; then
        if changelog_names_fix "$rel"; then
            ok "the vendor changelog names CVE-2026-53266: this kernel carries a backport, so its version number understates its state"
            rc=0
        else
            [[ -z "$up" ]] && { caution "cannot confirm: the vendor changelog does not name CVE-2026-53266 (or is not readable), and this release string cannot be compared with upstream. Check your vendor's security tracker for the kernel package you run"; rc=1; } \
                           || inf "the vendor changelog does not name CVE-2026-53266, so no backport was found"
        fi
    fi
    step "Exposure surface (information; absence of a rule does not make a kernel safe)"
    local rules=""
    if have ebtables; then rules="$(ebtables -t nat -L 2>/dev/null | grep -i 'snat')"; fi
    if [[ -n "$rules" ]]; then
        inf "ebtables SNAT rules present:"; head -n 8 <<<"$rules" | sed 's/^/        /'
        if grep -i -e 'snat-arp' <<<"$rules" >/dev/null; then caution "a rule uses --snat-arp: the ARP rewrite this CVE needs is in use on this host"; fi
    else
        inf "no ebtables SNAT rule seen (ebtables $(have ebtables && echo present || echo not installed))"
    fi
    local mods="${KERNEL_MODULES_FILE:-/proc/modules}"
    if [[ -r "$mods" ]] && grep -E '^ebt_snat ' "$mods" >/dev/null; then inf "module ebt_snat is loaded"
    elif have modinfo && modinfo ebt_snat >/dev/null 2>&1; then inf "module ebt_snat is loadable (not loaded now)"
    else inf "module ebt_snat is not loaded and no module information was found"; fi
    local ps="${KERNEL_PROC_SYS:-/proc/sys}" v
    if [[ -r "$ps/user/max_user_namespaces" ]]; then v="$(cat "$ps/user/max_user_namespaces" 2>/dev/null)"; inf "user.max_user_namespaces = ${v} ($([[ "$v" == 0 ]] && echo 'user namespaces disabled' || echo 'unprivileged user namespaces may be allowed'))"; fi
    if [[ -r "$ps/kernel/unprivileged_userns_clone" ]]; then v="$(cat "$ps/kernel/unprivileged_userns_clone" 2>/dev/null)"; inf "kernel.unprivileged_userns_clone = ${v}"; fi
    step "Verdict"
    if [[ $rc -eq 0 ]]; then info "The running kernel has the fix for CVE-2026-53266."
    else
        warn "The running kernel is affected or its fix could not be confirmed (CVE-2026-53266, CVSS 8.8, CISA KEV). Update to your vendor's fixed kernel and reboot."
        inf "Upstream fixes: 5.10.259, 5.15.210, 6.1.176, 6.6.143, 6.12.94, 6.18.36, 7.0.13"
        inf "Until then (the project's suggestion, not the vendor's): remove ebtables SNAT rules that use --snat-arp; where ebt_snat is not needed, prevent it loading; where unprivileged user namespaces are not needed, disable them"
    fi
    return "$rc"
}

main() {
    CMD="${1:-check}"; [[ $# -gt 0 ]] && shift
    case "$CMD" in -V|--version|version) echo "${SCRIPT_NAME} ${SCRIPT_VERSION} (${SCRIPT_DATE})"; exit 0 ;; esac
    case "$CMD" in -h|--help|help) print_help; exit 0 ;; esac
    echo "${SCRIPT_NAME} ${SCRIPT_VERSION} (${SCRIPT_DATE}) - ${CMD} on $(hostname 2>/dev/null || echo '?') at $(date -u +%FT%TZ)"
    echo "CVE-2026-53266 (Linux kernel ebtables SNAT out-of-bounds write, CISA KEV)"
    case "$CMD" in
        check) cmd_check "$@" ;;
        *) die "Unknown command: ${CMD} (check|version)" ;;
    esac
}
main "$@"; exit

# Assisted-by: Claude Sonnet 5.5
