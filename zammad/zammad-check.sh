#!/usr/bin/env bash
# SPDX-License-Identifier: CC0-1.0
# =============================================================================
# Zammad session hijack and local privilege escalation: read-only checker  (v2)
# CVE-2026-102489 and CVE-2026-102490
#
# If this software is helpful, consider a donation to our 501c3 nonprofit:
# https://privacysafe.foundation
#
# Zammad is an open-source helpdesk and ticket system. The Dutch Institute for
# Vulnerability Disclosure (DIVD) reported that two previously unknown flaws in Zammad
# were used to breach its own instance, with first access on 21 September 2026. CISA
# added both to the Known Exploited Vulnerabilities catalog on 2 October 2026.
#
#   CVE-2026-102489  CVSS 9.4 (CVSS 4.0, CISA)  A session hijack that leads to remote
#                    code execution as the zammad service user. Exploitable on 6.3.0
#                    through 6.5.4. The same code is present in 7.0.0 through 7.1.3 but
#                    is reported as not exploitable there. Zammad says exploitation is
#                    possible only on 6.5 and older and that 7.0 and later are not
#                    affected. 7.2.0 contains hardening for it.
#   CVE-2026-102490  CVSS 8.5 to 9.4 depending on who scores it  A local privilege
#                    escalation from the zammad user to root. DIVD lists 1.5.0 through
#                    7.1.0-alpha. Zammad disputes the report (it says it received no
#                    technical details) and, at the time of the sources used here,
#                    had published no patch for it. It needs code already running as
#                    the zammad user.
#
#   Chained: CVE-2026-102489 gives code as zammad, then CVE-2026-102490 gives root.
#   Zammad's advice is to update to version 7 or take the instance offline.
#
# What this script can and cannot say. It reports the remote chain (CVE-2026-102489)
# from the version. It does NOT claim that any version is fixed for CVE-2026-102490:
# no source confirms a patch.
#
# This script is read-only.
#
# Usage:
#   ./zammad-check.sh [command]
#   check (default)  find Zammad, read its version, report. Exit 0 = the remote chain is
#                    not open, 1 = exposed or unclear.
#   hunt             look for persistence a root compromise would leave: changed
#                    authorized_keys, changed root and zammad crontabs, files owned by root
#                    under the Zammad root, new SUID files. These are leads, not proof of
#                    this campaign. Exit 0 = nothing found, 1 = a lead.
#   version          print the script version.
#
# Env: ZAMMAD_ROOT         the Zammad install directory (default /opt/zammad, /usr/share/zammad)
#      ZAMMAD_HUNT_SINCE   YYYY-MM-DD for the hunt (default 2026-09-21)
#      ZAMMAD_HUNT_HOMES   directories searched for authorized_keys
#                          (default /root /home/zammad /opt/zammad)
#      ZAMMAD_CRON_DIRS    crontab directories (default /var/spool/cron/crontabs /var/spool/cron)
#      SCAN_CONTAINERS=1   (the default) check also reads /opt/zammad/VERSION and
#                          /usr/share/zammad/VERSION inside running docker and podman containers;
#                          0 skips them. The hunt is host-only.
# =============================================================================

# Commands run as "cmd_${CMD}", which shellcheck cannot follow
# shellcheck disable=SC2317,SC2329,SC2034
set -uo pipefail

SCRIPT_NAME="zammad-check.sh"
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
# ---------- version rules ----------------------------------------------------
# prints: chain | old | seven | hardened | prerelease | unknown
#   prerelease a build before a release (7.2.0-pre): not judged as the release
#   chain    6.3.0 to before 7.0.0: the remote session chain is exploitable
#   old      1.5.0 to before 6.3.0: the session flaw does not apply; the local one is reported
#   seven    7.0.0 to before 7.2.0: the session flaw is present but reported not exploitable
#   hardened 7.2.0 or later: hardening for the session flaw; no confirmed fix for the local one
zammad_status() {
    local v; v="$(norm_ver "${1%-pre}")"
    # a pre-release only matters at the 7.2.0 boundary: below it, judge by the version it leads to
    [[ "$1" == *-pre ]] && is_semver "$v" && ver_ge "$v" 7.2.0 && { echo prerelease; return; }
    is_semver "$v" || { echo unknown; return; }
    ver_ge "$v" 7.2.0 && { echo hardened; return; }
    ver_ge "$v" 7.0.0 && { echo seven; return; }
    ver_ge "$v" 6.3.0 && { echo chain; return; }
    ver_ge "$v" 1.5.0 && { echo old; return; }
    echo unknown
}
# Zammad's VERSION file holds just the version (6.5.4); the package version is a fallback
zammad_version_of() {
    local root="$1" v=""
    if [[ -r "$root/VERSION" ]]; then
        v="$(head -n1 "$root/VERSION" 2>/dev/null | grep -oE '[0-9]+\.[0-9]+\.[0-9]+' | head -n1)"
        # a pre-release (7.2.0-pre) is a build before the release, not the release
        head -n1 "$root/VERSION" 2>/dev/null | grep -qiE '^v?[0-9]+\.[0-9]+\.[0-9]+-(pre|alpha|beta|rc)' && [[ -n "$v" ]] && v="${v}-pre"
    fi
    if [[ -z "$v" && -z "${CLABEL[$root]:-}" ]] && have dpkg-query; then v="$(dpkg-query -W -f='${Version}' zammad 2>/dev/null | grep -oE '^[0-9]+\.[0-9]+\.[0-9]+' | head -n1)"; fi
    if [[ -z "$v" && -z "${CLABEL[$root]:-}" ]] && have rpm; then v="$(rpm -q --qf '%{VERSION}' zammad 2>/dev/null | grep -oE '^[0-9]+\.[0-9]+\.[0-9]+' | head -n1)"; fi
    echo "$v"
}
# A Zammad inside a running container: copy its VERSION file into a staging directory so the same
# rules judge it. The package-database fallback is skipped for these, because it describes the host.
ZM_STAGE=""
declare -a CROOTS=()
declare -A CLABEL=()
zammad_container_roots() {
    local rt id name d v s
    [[ "${SCAN_CONTAINERS:-1}" == 1 ]] || return 0
    for rt in docker podman; do
        have "$rt" || continue
        while read -r id name; do
            [[ -n "$id" ]] || continue
            for d in /opt/zammad /usr/share/zammad; do
                v="$("$rt" exec "$id" cat "$d/VERSION" 2>/dev/null | head -n1)" || true
                [[ -n "$v" ]] || continue
                if [[ -z "$ZM_STAGE" ]]; then
                    ZM_STAGE="$(mktemp -d)" || return 0
                    trap 'rm -rf "${ZM_STAGE:-}"' EXIT
                fi
                s="$ZM_STAGE/${rt}_${id}"; mkdir -p "$s"; printf '%s\n' "$v" > "$s/VERSION"
                CROOTS+=("$s"); CLABEL["$s"]="${rt} container ${name:-$id}: ${d}"
                break
            done
        done < <("$rt" ps --format '{{.ID}} {{.Names}}' 2>/dev/null)
    done
}
find_roots() {
    local d
    [[ -n "${ZAMMAD_ROOT:-}" && -d "${ZAMMAD_ROOT}" ]] && echo "${ZAMMAD_ROOT}"
    for d in /opt/zammad /usr/share/zammad; do [[ -d "$d" ]] && echo "$d"; done
}

cmd_check() {
    local rc=0 found=0 ver st root
    step "Looking for Zammad"
    local -a roots=(); local -A seen=()
    while IFS= read -r root; do [[ -n "$root" && -z "${seen[$root]:-}" ]] && { seen[$root]=1; roots+=("$root"); }; done < <(find_roots)
    zammad_container_roots
    for root in "${CROOTS[@]:-}"; do [[ -n "$root" ]] && roots+=("$root"); done
    if [[ ${#roots[@]} -eq 0 ]]; then info "No Zammad installation found on the host or in a running container (set ZAMMAD_ROOT if it is not under /opt/zammad)"; return 0; fi
    for root in "${roots[@]}"; do
        found=$((found+1))
        ver="$(zammad_version_of "$root")"
        step "Zammad ${ver:-unknown} at ${CLABEL[$root]:-$root}"
        [[ -n "$ver" ]] || { caution "could not read a version (looked for ${CLABEL[$root]:-${root}}/VERSION$([[ -n "${CLABEL[$root]:-}" ]] || echo ' and the package database'))"; rc=1; continue; }
        st="$(zammad_status "$ver")"
        case "$st" in
            chain)
                bad "Zammad ${ver} (6.3.0 to 6.5.4 and the 6.x line): CVE-2026-102489, the session hijack that leads to code execution as the zammad user, is exploitable; with CVE-2026-102490 it reaches root"
                inf "update to 7.2.0 or later, or take the instance offline, as Zammad advises"
                rc=1 ;;
            old)
                caution "Zammad ${ver}: CVE-2026-102489 does not apply before 6.3.0, but this release is long unsupported and CVE-2026-102490 (local, disputed) is reported against it: update to 7.2.0 or later"
                rc=1 ;;
            seven)
                caution "Zammad ${ver}: the session flaw is present in the code but reported not exploitable on 7.x, so the remote chain is not open; 7.2.0 adds hardening, update to it"
                inf "CVE-2026-102490 (local privilege escalation) is disputed by the vendor and no patch is confirmed" ;;
            hardened)
                ok "Zammad ${ver} is 7.2.0 or later: it has the hardening for CVE-2026-102489"
                inf "CVE-2026-102490 (local privilege escalation to root, needs code as the zammad user) is disputed by the vendor and no patch was confirmed in the sources used; the host's own hardening is the control for it" ;;
            prerelease) caution "Zammad ${ver} is a pre-release build, not a release: it may not have the hardening. Update to 7.2.0 or later"; rc=1 ;;
            *)  caution "version '${ver}' could not be compared: update to 7.2.0 or later"; rc=1 ;;
        esac
    done
    step "Verdict"
    if [[ $rc -eq 0 ]]; then info "The remote chain is not open on the Zammad found (${found} checked)."
    else
        warn "Zammad exposed or unclear. Advisory: https://zammad.com/en/advisories/cve-2026-102489-cve-2026-102490"
        inf "If an instance on 6.x was reachable after 21 September 2026, treat it as possibly compromised and run: $0 hunt"
    fi
    return "$rc"
}

cmd_hunt() {
    local rc=0 f d root n since="${ZAMMAD_HUNT_SINCE:-2026-09-21}"
    step "Hunting for persistence a root compromise would leave (changes since ${since})"
    inf "these are leads, not proof of this campaign; DIVD published a log check for it (https://csirt.divd.nl/DIVD-2026-00015)"
    # 1. authorized_keys changed
    local homes="${ZAMMAD_HUNT_HOMES:-/root /home/zammad /opt/zammad}"
    # shellcheck disable=SC2086
    for d in $homes; do
        [[ -d "$d" ]] || continue
        while IFS= read -r f; do
            bad "${f} changed since ${since}: confirm with whoever administers this host"; rc=1
        done < <(find "$d" -xdev -maxdepth 3 -type f \( -name authorized_keys -o -name authorized_keys2 \) -newermt "$since" 2>/dev/null)
    done
    # 2. root and zammad crontabs changed
    local cdirs="${ZAMMAD_CRON_DIRS:-/var/spool/cron/crontabs /var/spool/cron}"
    # shellcheck disable=SC2086
    for d in $cdirs; do
        [[ -d "$d" ]] || continue
        for f in "$d/root" "$d/zammad"; do
            [[ -f "$f" ]] || continue
            n="$(find "$f" -newermt "$since" 2>/dev/null | grep -c .)"
            [[ "${n:-0}" -gt 0 ]] && { bad "${f} changed since ${since}: review its entries"; rc=1; }
        done
    done
    # 3. files owned by root under the Zammad root (it runs as the zammad user)
    local -a roots=(); while IFS= read -r root; do roots+=("$root"); done < <(find_roots)
    for root in "${roots[@]:-}"; do
        [[ -n "$root" ]] || continue
        n="$(find "$root" -xdev -maxdepth 6 -user root -type f -newermt "$since" -not -path '*/tmp/*' -not -path '*/log/*' 2>/dev/null | grep -c .)"
        if [[ "${n:-0}" -gt 0 ]]; then
            inf "${n} file(s) under ${root} owned by root and changed since ${since} (a package update does this too; review):"
            find "$root" -xdev -maxdepth 6 -user root -type f -newermt "$since" -not -path '*/tmp/*' -not -path '*/log/*' 2>/dev/null | head -n 8 | sed 's/^/        /'
        fi
    done
    # 4. SUID files created since
    n="$(find /usr /opt /var /tmp /home /root -xdev -type f -perm -4000 -newermt "$since" 2>/dev/null | grep -c .)"
    if [[ "${n:-0}" -gt 0 ]]; then
        inf "${n} SUID file(s) created or changed since ${since} (system updates replace some; review):"
        find /usr /opt /var /tmp /home /root -xdev -type f -perm -4000 -newermt "$since" 2>/dev/null | head -n 8 | sed 's/^/        /'
    fi
    step "Verdict"
    if [[ $rc -eq 0 ]]; then info "No persistence lead found. This is not proof the host was not compromised."
    else warn "Lead(s) found. If a 6.x instance was reachable after 21 September 2026, treat the host as possibly compromised: restore from a backup taken before that date, rotate every credential Zammad could read, and review accounts."; fi
    return "$rc"
}

main() {
    CMD="${1:-check}"; [[ $# -gt 0 ]] && shift
    case "$CMD" in -V|--version|version) echo "${SCRIPT_NAME} ${SCRIPT_VERSION} (${SCRIPT_DATE})"; exit 0 ;; esac
    case "$CMD" in -h|--help|help) print_help; exit 0 ;; esac
    echo "${SCRIPT_NAME} ${SCRIPT_VERSION} (${SCRIPT_DATE}) - ${CMD} on $(hostname 2>/dev/null || echo '?') at $(date -u +%FT%TZ)"
    echo "CVE-2026-102489 and CVE-2026-102490 (Zammad session hijack to code execution, local privilege escalation)"
    case "$CMD" in
        check) cmd_check "$@" ;;
        hunt)  cmd_hunt "$@" ;;
        *) die "Unknown command: ${CMD} (check|hunt|version)" ;;
    esac
}
main "$@"; exit

# Assisted-by: Claude Sonnet 5.5
