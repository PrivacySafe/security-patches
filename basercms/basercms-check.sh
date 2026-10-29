#!/usr/bin/env bash
# SPDX-License-Identifier: CC0-1.0
# =============================================================================
# baserCMS 5 admin SQL injection, path traversal and deserialization: read-only checker  (v1)
# CVE-2026-114621, CVE-2026-114622, CVE-2026-114624
#
# If this software is helpful, consider a donation to our 501c3 nonprofit:
# https://privacysafe.foundation
#
# baserCMS is a website development framework and CMS (PHP, CakePHP based). Its security
# releases 5.3.2 and 5.4.2 of 23 October 2026 fix three flaws rated High:
#
#   CVE-2026-114621  8.8 (v3.1)  SQL injection in the admin panel and the admin API. The list
#                              and detail actions of the Admin and Api/Admin prefixes pass
#                              request query parameters (contain, conditions, fields, finder,
#                              order) straight to the ORM as options, so a logged-in user can
#                              inject SQL and read data such as password hashes.
#                              Affected: 5.0.0 before 5.3.2, and 5.4.0 before 5.4.2.
#   CVE-2026-114622  7.2         Path traversal (CWE-22).
#                              Affected: 5.2.3 before 5.3.2, and 5.4.0 before 5.4.2.
#   CVE-2026-114624  7.2         Deserialization of untrusted data (CWE-502). An administrator,
#                              or an attacker who gets widget-write capability through another
#                              flaw such as chained XSS, can plant an object graph that fires on
#                              unauthenticated page requests. Two gadget chains in the default
#                              dependency set reach proc_open() and run commands as the web
#                              server user. Affected: 5.0.0 before 5.3.2, and 5.4.0 before 5.4.2.
#
#   Fixed: 5.3.2 and 5.4.2. Releases 5.0 to 5.2 are affected and have no fixed release of
#          their own: move to 5.3.2, 5.4.2 or later.
#
# How this script reads a site. The version is the first line of
# plugins/baser-core/VERSION.txt. Each flaw is judged on its own range. The script also reads
# the two things the fix for CVE-2026-114621 adds: the removeOrmStructureFromRequest() method in
# plugins/baser-core/src/Controller/AppController.php, and 'order' in the list of ORM
# structure keys that plugins/baser-core/src/Service/BcQueryParameterTrait.php strips. Both
# present means that fix is there, whatever the version string says; a fixed version whose
# files lack it is a failed update; one of the two is a partial update. Those signatures
# cover CVE-2026-114621 only, so the other two flaws are always judged by version.
#
# No indicators of exploitation have been published for these flaws, so there is no hunt. This
# script is read-only. A plain version file means a clean result cannot prove the site was not
# attacked: after exposure, review administrator accounts and widgets, and rotate passwords.
#
# Usage:
#   ./basercms-check.sh [command] [DIR ...]
#
#   check (default)  scan DIR (default /var/www /srv /opt /home) for baserCMS 5 sites. Exit 0 =
#                    nothing exposed, 1 = an exposed or unverifiable site.
#   version          print the script version.
# Containers: with no directory argument the check also copies the files it reads from running
# docker and podman containers (SCAN_CONTAINERS=1, the default; 0 skips them) and judges them like
# host installs. The copies are temporary: a path shown as .../docker_NAME_PATH is the PATH inside
# the container NAME.
# =============================================================================

# Commands run as "cmd_${CMD}", which shellcheck cannot follow
# shellcheck disable=SC2317,SC2329,SC2034
set -uo pipefail

SCRIPT_NAME="basercms-check.sh"
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
# ---------- reading a site ---------------------------------------------------
# the version string, exactly as VERSION.txt holds it on its first line (5.3.2, or 5.4.2-rc1)
bc_version() {
    local f="$1/plugins/baser-core/VERSION.txt" v
    [[ -r "$f" ]] || return 0
    v="$(head -n1 "$f" 2>/dev/null | tr -d '\r[:space:]')"
    [[ "$v" =~ ^[0-9]+\.[0-9]+\.[0-9]+(-[A-Za-z0-9.]+)?$ ]] && echo "$v"
    return 0
}

# One row per flaw: id|cvss|first affected release|what
BC_CVES=(
"CVE-2026-114621|8.8|5.0.0|SQL injection in the admin panel and admin API (can read password hashes)"
"CVE-2026-114622|7.2|5.2.3|path traversal"
"CVE-2026-114624|7.2|5.0.0|deserialization of untrusted data leading to command execution (needs an administrator or widget-write access)"
)

# bc_state <version> <first affected>  ->  notaffected | affected | nofix | fixed | unknown
#   nofix = affected, and no fixed release exists on this line (5.0 to 5.2)
# A pre-release of a fixed release (5.3.2-rc1) is below it.
bc_state() {
    local raw="$1" intro="$2" maj min pat pre imaj imin ipat
    [[ "$raw" =~ ^([0-9]+)\.([0-9]+)\.([0-9]+)(-.+)?$ ]] || { echo unknown; return; }
    maj="${BASH_REMATCH[1]}"; min="${BASH_REMATCH[2]}"; pat="${BASH_REMATCH[3]}"; pre="${BASH_REMATCH[4]:-}"
    [[ "$intro" =~ ^([0-9]+)\.([0-9]+)\.([0-9]+)$ ]]; imaj="${BASH_REMATCH[1]}"; imin="${BASH_REMATCH[2]}"; ipat="${BASH_REMATCH[3]}"
    (( maj < 5 )) && { echo notaffected; return; }
    (( maj > 5 )) && { echo fixed; return; }
    (( min < imin || (min == imin && pat < ipat) )) && { echo notaffected; return; }
    case "$min" in
        3) if (( pat > 2 || (pat == 2 && ${#pre} == 0) )); then echo fixed; else echo affected; fi ;;
        4) if (( pat > 2 || (pat == 2 && ${#pre} == 0) )); then echo fixed; else echo affected; fi ;;
        0|1|2) echo nofix ;;
        *) echo fixed ;;
    esac
}

# the fixed release for the install's line, for the message
bc_fix_for() { case "$(sed -E 's/^([0-9]+\.[0-9]+).*/\1/' <<<"$1")" in 5.4) echo 5.4.2 ;; 5.3) echo 5.3.2 ;; *) echo "5.3.2 or 5.4.2" ;; esac; }

# the two things the CVE-2026-114621 fix adds. prints: both | one | none | unreadable
bc_signature() {
    local ac="$1/plugins/baser-core/src/Controller/AppController.php" tr="$1/plugins/baser-core/src/Service/BcQueryParameterTrait.php" a=0 b=0
    [[ -r "$ac" && -r "$tr" ]] || { echo unreadable; return; }
    grep -qF 'function removeOrmStructureFromRequest(' "$ac" && a=1
    grep -qE "^[[:space:]]*'order',[[:space:]]*$" "$tr" && b=1
    case "$((a+b))" in 2) echo both ;; 1) echo one ;; *) echo none ;; esac
}

# ---------- check ------------------------------------------------------------
# ---------- running containers -----------------------------------------------
# An install inside a container is not on the host. For each running container, find installs by
# their marker file, copy ONLY the files this check reads into a temporary directory (one per
# install, named after the container and the path inside it, mode 0700, removed on exit), and let
# the normal checks judge it like a host install. Paths the container reports are checked before
# they are used. The check never runs anything in a container beyond "find" and a file copy.
# It runs once, in the main shell (a subshell's exit would delete the copies early).
STAGE=""
declare -a STAGED_DIRS=()
stage_containers() {   # <marker file, relative to the install root> <other relative files the check reads>...
    local marker="$1" rt id name roots r f s; shift
    [[ "${SCAN_CONTAINERS:-1}" == 1 ]] || return 0
    for rt in docker podman; do
        have "$rt" || continue
        while read -r id name; do
            [[ -n "$id" ]] || continue
            roots="$("$rt" exec "$id" sh -c "find /var/www /srv /opt /home /usr/share -maxdepth 8 -path '*/${marker}' -type f 2>/dev/null | head -n 20" 2>/dev/null)" || continue
            while read -r r; do
                [[ "$r" =~ ^/[A-Za-z0-9._/@+-]+$ && "$r" == */"$marker" ]] || continue
                r="${r%/"$marker"}"
                if [[ -z "$STAGE" ]]; then
                    STAGE="$(mktemp -d)" || return 0
                    trap 'rm -rf "${STAGE:-}"' EXIT
                fi
                s="$STAGE/${rt}_${name:-$id}_${r//\//_}"; mkdir -p "$s"
                for f in "$marker" "$@"; do
                    mkdir -p "$s/$(dirname "$f")"
                    "$rt" cp "${id}:${r}/${f}" "$s/$f" >/dev/null 2>&1 || rm -f "$s/$f"
                    [[ -L "$s/$f" ]] && rm -f "$s/$f"
                done
                STAGED_DIRS+=("$s")
            done <<<"$roots"
        done < <("$rt" ps --format '{{.ID}} {{.Names}}' 2>/dev/null)
    done
}

cmd_check() {
    # running containers: stage once, here in the main shell, then pass the staged directories on
    # as ordinary directory arguments
    if [[ $# -eq 0 ]]; then
        stage_containers 'plugins/baser-core/VERSION.txt' 'plugins/baser-core/src/Controller/AppController.php' 'plugins/baser-core/src/Service/BcQueryParameterTrait.php'
        if [[ ${#STAGED_DIRS[@]} -gt 0 ]]; then
            local _d; local -a _a=()
            for _d in /var/www /srv /opt /home; do [[ -d "$_d" ]] && _a+=("$_d"); done
            set -- ${_a[@]:+"${_a[@]}"} "${STAGED_DIRS[@]}"
        fi
    fi
    local -a dirs=() existing=()
    local rc=0 found=0 d vf root ver sig row id cvss intro what st nbad
    if [[ $# -gt 0 ]]; then dirs=("$@"); else dirs=(/var/www /srv /opt /home); fi
    for d in "${dirs[@]}"; do [[ -d "$d" ]] && existing+=("$d"); done
    step "Looking for baserCMS 5 sites"
    if [[ ${#existing[@]} -eq 0 ]]; then info "None of the search directories exist"; return 0; fi
    while IFS= read -r vf; do
        [[ -n "$vf" ]] || continue
        root="$(dirname "$(dirname "$(dirname "$vf")")")"
        found=$((found+1)); ver="$(bc_version "$root")"
        step "baserCMS ${ver:-version unreadable} at ${root}"
        if [[ -z "$ver" ]]; then caution "could not read a version from the first line of ${vf}: affected is 5.0.0 before 5.3.2 and 5.4.0 before 5.4.2"; rc=1; continue; fi
        sig="$(bc_signature "$root")"; nbad=0
        for row in "${BC_CVES[@]}"; do
            IFS='|' read -r id cvss intro what <<<"$row"
            st="$(bc_state "$ver" "$intro")"
            case "$st" in
                fixed|notaffected) continue ;;
                affected) bad "${id} (CVSS ${cvss}): ${what}. Fixed in $(bc_fix_for "$ver")"; nbad=$((nbad+1)); rc=1 ;;
                nofix)    bad "${id} (CVSS ${cvss}): ${what}. No fix for the ${ver%.*} line: move to 5.3.2 or 5.4.2 or later"; nbad=$((nbad+1)); rc=1 ;;
                *)        caution "cannot compare version '${ver}': check it against 5.3.2 and 5.4.2"; nbad=$((nbad+1)); rc=1; break ;;
            esac
        done
        case "$sig" in
            both) [[ $nbad -gt 0 ]] && inf "the files carry the fix for CVE-2026-114621 (a backport, or files copied over an older install), but the version is below the fixed release: the other flaws are judged by version" ;;
            one)  caution "the files have only part of the fix for CVE-2026-114621: a partial or mixed update. Reinstall 5.3.2 or 5.4.2 or later"; rc=1 ;;
            none) if [[ $nbad -eq 0 ]]; then caution "version ${ver} is a fixed release, but the files lack the fix for CVE-2026-114621: they do not match the version. Reinstall baserCMS"; rc=1; fi ;;
        esac
        [[ $nbad -eq 0 && "$sig" != none && "$sig" != one ]] && ok "no flaw in this set applies to baserCMS ${ver}"
    done < <(find "${existing[@]}" -xdev -maxdepth 9 -path '*/plugins/baser-core/VERSION.txt' -type f 2>/dev/null | sort -u)
    step "Verdict"
    if [[ $found -eq 0 ]]; then info "No baserCMS 5 site found under: ${existing[*]}"
    elif [[ $rc -eq 0 ]]; then info "No exposed baserCMS found (${found} checked)"
    else
        warn "Exposed or unverifiable baserCMS found. Update to 5.3.2 or 5.4.2 or later."
        inf "CVE-2026-114621 can read password hashes: after exposure, rotate administrator passwords and review administrator accounts"
        inf "CVE-2026-114624 plants an object graph through widgets: review the widget areas for entries you did not create"
        inf "Interim, ours and not vendor guidance: restrict the admin area (/baser/admin and the admin API) to trusted addresses, and remove accounts you do not need"
        inf "Advisory: https://github.com/baserproject/basercms/security/advisories/GHSA-2w6g-wp3r-26m3"
    fi
    return "$rc"
}

# ---------- dispatch ---------------------------------------------------------
main() {
    CMD="${1:-check}"; [[ $# -gt 0 ]] && shift
    case "$CMD" in -V|--version|version) echo "${SCRIPT_NAME} ${SCRIPT_VERSION} (${SCRIPT_DATE})"; exit 0 ;; esac
    case "$CMD" in -h|--help|help) print_help; exit 0 ;; esac
    echo "${SCRIPT_NAME} ${SCRIPT_VERSION} (${SCRIPT_DATE}) - ${CMD} on $(hostname 2>/dev/null || echo '?') at $(date -u +%FT%TZ)"
    echo "CVE-2026-114621, CVE-2026-114622, CVE-2026-114624; fixed in baserCMS 5.3.2 and 5.4.2"
    case "$CMD" in
        check) cmd_check "$@" ;;
        *) die "Unknown command: ${CMD} (check|version)" ;;
    esac
}
main "$@"; exit

# Assisted-by: Claude Sonnet 5.5
