#!/usr/bin/env bash
# SPDX-License-Identifier: CC0-1.0
# =============================================================================
# Incus October 2026 host-compromise flaws: read-only checker  (v1)
# CVE-2026-115375 (instance backup path traversal, CVSS 4.0 9.4)
# CVE-2026-115377 (migration stream symlink, CVSS 4.0 9.4)
# CVE-2026-115372 (restricted project mkfs argument injection, 8.5)
#
# If this software is helpful, consider a donation to our 501c3 nonprofit:
# https://privacysafe.foundation
#
# Incus is a system container and virtual machine manager. All three flaws let a client
# the daemon is meant to confine (a user restricted to a project) act as root on the
# HOST. A full administrator is already as powerful as host root, so these matter where
# you have restricted projects, restricted client certificates, or members of the
# unprivileged `incus` unix group, or where an instance can be migrated in from a server
# you do not control.
#
#   CVE-2026-115375  7.0.0 before 7.0.2, and 7.1.0 before 7.5.0. Importing an instance
#                    backup validates the instance and snapshot names but not the names
#                    of the dependent custom volumes in the backup's index.yaml, which
#                    become path segments on the host. Any client allowed to create
#                    instances in a project can make the daemon create root-owned
#                    directories with attacker-controlled content at arbitrary host
#                    paths. 6.x is not affected.
#   CVE-2026-115377  before 6.0.7, 6.1.0 before 7.0.2, and 7.1.0 before 7.5.0. When
#                    receiving an instance or volume by migration (copy, move, refresh,
#                    push or pull) through rsync or an optimized btrfs transfer, a
#                    malicious source can plant a symlink (rootfs pointing at /) and
#                    write through it as root. Any client allowed to create an instance
#                    or custom volume, or any server a target is told to copy or move
#                    from, can exploit it. Optimized ZFS transfers are NOT affected.
#   CVE-2026-115372  7.3.0 before 7.5.0. A user of a restricted project can set
#                    block.create_options through volume update, copy and move
#                    operations and inject arguments into mkfs, which runs as root.
#
#   Fixed: 6.0.7 (the 6.0 LTS, for CVE-2026-115377 only), 7.0.2 (the 7.0 LTS) and
#          7.5.0 (feature release).
#
# The project's own release notes list many other critical project-escape advisories in
# earlier releases this year; moving to a current release fixes those too. Treat a
# restricted project as a security boundary only on a release that has these fixes.
#
# This script is read-only. It reads the version (the daemon's, if it answers, else the
# package's, else the client's), looks in a package changelog for a backport of these
# fixes, and asks the daemon read-only questions: restricted projects, the network
# listener, trusted client certificates, configured remotes, plus the members of the
# unix group `incus`. It never changes anything.
#
# Usage:
#   ./incus-check.sh [command]
#
#   check (default)  Exit 0 = nothing exposed, 1 = an affected version that cannot be
#                    shown to be admin-only, or one that could not be verified.
#   version          print the script version.
#
# Env: INCUS_BIN to name the incus client; INCUS_CHANGELOG to name a changelog file.
# =============================================================================

# Commands run as "cmd_${CMD}", which shellcheck can't follow
# shellcheck disable=SC2317,SC2329,SC2034
set -uo pipefail

SCRIPT_NAME="incus-check.sh"
SCRIPT_VERSION="1.0.0"
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

# ---------- version parsing --------------------------------------------------
# Incus feature releases are "7.4" and LTS point releases "6.0.3". Prints X.Y.Z or empty.
incus_semver() {
    local v="$1"
    v="${v#*:}"                      # drop a Debian epoch such as 1:
    v="${v%%-*}"                     # drop the Debian or RPM revision
    v="${v%%~*}"; v="${v%%+*}"
    [[ "$v" =~ ^([0-9]+)\.([0-9]+)(\.([0-9]+))?$ ]] || { echo ""; return; }
    echo "${BASH_REMATCH[1]}.${BASH_REMATCH[2]}.${BASH_REMATCH[4]:-0}"
}
# Each rule prints "affected" or "ok" for a semver
rule_115375() { local v="$1"; ver_lt "$v" "7.0.0" && { echo ok; return; }; if ver_lt "$v" "7.0.2"; then echo affected; elif ver_lt "$v" "7.1.0"; then echo ok; elif ver_lt "$v" "7.5.0"; then echo affected; else echo ok; fi; }
rule_115377() { local v="$1"; if ver_lt "$v" "6.0.7"; then echo affected; elif ver_lt "$v" "6.1.0"; then echo ok; elif ver_lt "$v" "7.0.2"; then echo affected; elif ver_lt "$v" "7.1.0"; then echo ok; elif ver_lt "$v" "7.5.0"; then echo affected; else echo ok; fi; }
rule_115372() { local v="$1"; ver_lt "$v" "7.3.0" && { echo ok; return; }; ver_lt "$v" "7.5.0" && echo affected || echo ok; }

# ---------- running the client safely ----------------------------------------
trusted_exec() {   # a root user must not run a binary that others can write
    local b="$1" st
    [[ -x "$b" ]] || return 1
    [[ "$(id -u)" != 0 ]] && return 0
    st="$(stat -c '%u %a' "$b" 2>/dev/null)" || return 1
    [[ "${st%% *}" == 0 ]] || return 1
    local mode="${st##* }"; mode="${mode: -3}"
    (( (8#$mode & 8#022) == 0 ))
}
find_client() {
    local c
    for c in "${INCUS_BIN:-}" /usr/bin/incus /opt/incus/bin/incus /usr/local/bin/incus /snap/bin/incus; do
        [[ -n "$c" ]] && trusted_exec "$c" && { echo "$c"; return; }
    done
    return 1
}
q() { timeout 15 "$CLIENT" "$@" 2>/dev/null; }   # a read-only question to the daemon

# ---------- package changelog (a backport can hide behind an old version) -----
backport_in_changelog() {
    local f ids='CVE-2026-(115375|115377|115372)|GHSA-(hpjh-q53p-f27r|579w-c4rw-c8q3|4cph-ccqv-hm3c)'
    for f in "${INCUS_CHANGELOG:-}" /usr/share/doc/incus/changelog.Debian.gz /usr/share/doc/incus-base/changelog.Debian.gz; do
        [[ -n "$f" && -r "$f" ]] || continue
        zcat -f "$f" 2>/dev/null | grep -E "$ids" >/dev/null && return 0
    done
    if have rpm && rpm -q incus >/dev/null 2>&1; then
        rpm -q --changelog incus 2>/dev/null | grep -E "$ids" >/dev/null && return 0
    fi
    return 1
}
package_version() {
    local v=""
    if have dpkg-query; then v="$(dpkg-query -W -f='${Version}' incus 2>/dev/null)"; [[ -z "$v" ]] && v="$(dpkg-query -W -f='${Version}' incus-base 2>/dev/null)"; fi
    if [[ -z "$v" ]] && have rpm; then v="$(rpm -q --qf '%{VERSION}' incus 2>/dev/null)"; [[ "$v" == *"not installed"* ]] && v=""; fi
    echo "$v"
}

# ---------- check ------------------------------------------------------------
cmd_check() {
    local rc=0 CLIENT cli_ver srv_ver pkg_ver sv src p restricted=0 https="" nremotes=0 ntrust=0 nunpriv=0 line name unpriv=0
    step "Looking for Incus"
    CLIENT="$(find_client)" || CLIENT=""
    pkg_ver="$(package_version)"
    if [[ -z "$CLIENT" && -z "$pkg_ver" ]]; then info "No Incus client or package found (searched PATH locations, dpkg and rpm)"; return 0; fi
    cli_ver=""; srv_ver=""
    if [[ -n "$CLIENT" ]]; then
        cli_ver="$(timeout 10 "$CLIENT" --version 2>/dev/null | head -n1)"
        srv_ver="$(timeout 10 "$CLIENT" version 2>/dev/null | sed -n 's/^Server version:[[:space:]]*//p' | head -n1)"
        inf "client: ${CLIENT} ${cli_ver:+(version ${cli_ver})}"
    fi
    [[ -n "$pkg_ver" ]] && inf "package: incus ${pkg_ver}"
    if [[ -n "$srv_ver" && "$srv_ver" != unreachable ]]; then sv="$(incus_semver "$srv_ver")"; src="the daemon (${srv_ver})"
    elif [[ -n "$pkg_ver" ]]; then sv="$(incus_semver "$pkg_ver")"; src="the package (${pkg_ver})"
    else sv="$(incus_semver "$cli_ver")"; src="the client binary (${cli_ver}); the daemon did not answer"; fi
    [[ -n "$sv" ]] || { caution "cannot parse an Incus version (daemon '${srv_ver}', package '${pkg_ver}', client '${cli_ver}')"; return 1; }
    inf "using the version of ${src}"

    local a1 a2 a3; a1="$(rule_115375 "$sv")"; a2="$(rule_115377 "$sv")"; a3="$(rule_115372 "$sv")"
    step "Version ${sv}"
    if [[ "$a1" == ok && "$a2" == ok && "$a3" == ok ]]; then
        ok "Incus ${sv} is outside the affected ranges of CVE-2026-115375, CVE-2026-115377 and CVE-2026-115372 (fixed in 6.0.7, 7.0.2 and 7.5.0)"
        return 0
    fi
    [[ "$a1" == affected ]] && bad "CVE-2026-115375 (instance backup path traversal): ${sv} is affected (fixed in 7.0.2 and 7.5.0)"
    [[ "$a2" == affected ]] && bad "CVE-2026-115377 (migration stream symlink): ${sv} is affected (fixed in 6.0.7, 7.0.2 and 7.5.0)"
    [[ "$a3" == affected ]] && bad "CVE-2026-115372 (restricted project mkfs injection): ${sv} is affected (fixed in 7.5.0)"
    if { [[ -n "$pkg_ver" ]] || [[ -n "${INCUS_CHANGELOG:-}" ]]; } && backport_in_changelog; then
        ok "the package changelog names these fixes: this build appears to carry a backport, so the version number understates its state"
        inf "check that it names all three; this script only looks for any of them"
        return 0
    elif [[ -n "$pkg_ver" || -n "${INCUS_CHANGELOG:-}" ]]; then
        inf "the package changelog does not mention these fixes (no backport found), so a distribution package with an old version number is affected"
    fi

    step "Who can reach the daemon"
    if [[ -z "$CLIENT" ]] || [[ "$srv_ver" == unreachable || -z "$srv_ver" ]]; then
        caution "the daemon did not answer (or no client is installed), so projects, listeners and remotes cannot be read: treating as unverified"
        rc=1
    else
        https="$(q config get core.https_address | head -n1)"
        [[ -n "$https" ]] && inf "network API listening: core.https_address = ${https}" || inf "no network API (core.https_address is empty): clients reach the daemon through the local unix socket"
        while IFS= read -r line; do
            [[ -n "$line" ]] || continue
            name="${line%%,*}"; name="${name% (current)}"
            [[ "$(q project get "$name" restricted | head -n1)" == true ]] && { restricted=$((restricted+1)); inf "restricted project: ${name}"; }
        done < <(q project list -f csv)
        ntrust="$(q config trust list -f csv | grep -c . )"
        [[ "$ntrust" -gt 0 ]] && inf "${ntrust} trusted client certificate(s) in the trust store"
        while IFS= read -r line; do
            [[ -n "$line" ]] || continue
            IFS=',' read -r name url proto _auth public _rest <<<"$line"
            [[ "$proto" == incus && "$url" != unix://* && "$public" == NO ]] && { nremotes=$((nremotes+1)); inf "remote server that could be a migration source: ${name%% *} (${url})"; }
        done < <(q remote list -f csv)
        if have getent; then
            nunpriv="$(getent group incus | awk -F: '{print $4}' | tr ',' '\n' | grep -c .)"
            [[ "$nunpriv" -gt 0 ]] && inf "${nunpriv} member(s) of the unprivileged unix group 'incus' (project-confined local users)"
        fi
        # judge each CVE against who can reach the daemon
        unpriv=0; { [[ $restricted -gt 0 ]] || [[ $nunpriv -gt 0 ]] || { [[ -n "$https" && $ntrust -gt 0 ]]; }; } && unpriv=1
        step "Exposure"
        if [[ "$a1" == affected ]]; then
            if [[ $unpriv -eq 1 ]]; then bad "CVE-2026-115375: restricted or unprivileged clients can create instances, and can make the daemon write as root on the host"; rc=1
            else ok "CVE-2026-115375: no restricted project, unprivileged group member or network client was found, so only full administrators (already host root) can reach it"; caution "upgrade anyway"; fi
        fi
        if [[ "$a2" == affected ]]; then
            if [[ $unpriv -eq 1 || $nremotes -gt 0 ]]; then bad "CVE-2026-115377: unprivileged clients, or a configured remote server acting as a migration source, can write to the host as root"; rc=1
            else ok "CVE-2026-115377: no unprivileged client and no remote migration source was found"; caution "upgrade anyway: copying an instance from a server you do not control would be enough"; fi
        fi
        if [[ "$a3" == affected ]]; then
            if [[ $restricted -gt 0 ]]; then bad "CVE-2026-115372: restricted project(s) exist, and their users can inject arguments into mkfs"; rc=1
            else ok "CVE-2026-115372: no restricted project was found, so there is no restriction to bypass"; caution "upgrade anyway: a restricted project created later would be affected"; fi
        fi
    fi
    step "Verdict"
    if [[ $rc -eq 0 ]]; then
        info "Nothing exposed on this host's current configuration. The affected version still needs the upgrade."
    else
        warn "Exposed or unverifiable Incus found. Upgrade to 7.5.0, or to 7.0.2 (7.0 LTS) or 6.0.7 (6.0 LTS) at the least."
        inf "Interim (ours, not the vendor's): do not treat restricted projects as a security boundary on this release; remove untrusted users from the incus group and the trust store; do not copy or move instances from servers you do not control; ZFS-optimized transfers are not affected by CVE-2026-115377."
        inf "Advisories: https://github.com/lxc/incus/security/advisories/GHSA-hpjh-q53p-f27r, GHSA-579w-c4rw-c8q3 and GHSA-4cph-ccqv-hm3c"
    fi
    return "$rc"
}

# ---------- dispatch ---------------------------------------------------------
main() {
    CMD="${1:-check}"; [[ $# -gt 0 ]] && shift
    case "$CMD" in -V|--version|version) echo "${SCRIPT_NAME} ${SCRIPT_VERSION} (${SCRIPT_DATE})"; exit 0 ;; esac
    case "$CMD" in -h|--help|help) print_help; exit 0 ;; esac
    echo "${SCRIPT_NAME} ${SCRIPT_VERSION} (${SCRIPT_DATE}) - ${CMD} on $(hostname 2>/dev/null || echo '?') at $(date -u +%FT%TZ)"
    echo "CVE-2026-115375, CVE-2026-115377, CVE-2026-115372; fixed in Incus 6.0.7, 7.0.2 and 7.5.0"
    case "$CMD" in
        check) cmd_check "$@" ;;
        *) die "Unknown command: ${CMD} (check|version)" ;;
    esac
}
main "$@"; exit

# Assisted-by: Claude Sonnet 5.5
