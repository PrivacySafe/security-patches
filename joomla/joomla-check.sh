#!/usr/bin/env bash
# SPDX-License-Identifier: CC0-1.0
# =============================================================================
# Joomla core, September 2026 security release (16 issues): read-only checker  (v1)
# CVE-2026-90915 and CVE-2026-92222 (High), CVE-2026-92227 (MFA bypass) and others
#
# If this software is helpful, consider a donation to our 501c3 nonprofit:
# https://privacysafe.foundation
#
# Joomla 5.4.9 and 6.1.4, released 29 September 2026, fix 16 core security issues
# (CVE-2026-90906 to CVE-2026-92232). The Joomla Security Strike Team rates two High:
#
#   CVE-2026-90915  Arbitrary directory deletion. The cache purge action (System, Clear
#                   Cache) did not confine the cache group name, so a path traversal in
#                   the file-based cache could delete any directory the web server can
#                   write to. Affects 4.0.0 to 5.4.8 and 6.0.0 to 6.1.3.
#   CVE-2026-92222  Server-side request forgery through URL fields (feed and request URLs)
#                   in several core extensions. Affects 3.0.0 and later; needs a Manager
#                   account or above.
#
# Others in the same release, as named in the advisories: CVE-2026-92227 (a multi-factor
# authentication bypass through remember-me cookies issued too early; needs the password
# first), CVE-2026-90916 (improper access checks in the content history comparison view),
# cross-site scripting in HTMLHelper::link and the link toolbar (CVE-2026-90906,
# CVE-2026-92224), tagged items (CVE-2026-90917) and two InputFilter bypasses
# (CVE-2026-92231, CVE-2026-92232), and access-control fixes in the Joomla API
# (CVE-2026-90913, CVE-2026-92226).
#
#   Affected: Joomla 6.0.0 to 6.1.3, and 4.0.0 to 5.4.8 (the SSRF flaw reaches back to
#             3.0.0, one XSS flaw to 1.5.0).
#   Fixed:    5.4.9 and 6.1.4. There is no fixed release for 3.x or 4.x or for 5.0 to 5.3:
#             those branches are past security support, so the fix is to move to 5.4.9 or
#             later in 5.x, or to 6.1.4 or later.
#
# How this script reads an install. Version.php holds the version as constants
# (MAJOR_VERSION, MINOR_VERSION, PATCH_VERSION). It also reads one file the fix changed,
# libraries/src/Cache/Storage/FileStorage.php: the cache-purge fix adds
# Path::check($dir, $this->_root). That single signature confirms the High cache flaw and
# catches a partial update; it cannot confirm the other fifteen fixes, so the version
# decides.
#
# This script is read-only.
#
# Usage:
#   ./joomla-check.sh [command] [DIR ...]
#   check (default)  find Joomla by libraries/src/Version.php (default /var/www /srv /home
#                    /opt /usr/share). Exit 0 = nothing exposed, 1 = exposed or unclear.
#   version          print the script version.
# Containers: with no directory argument the check also copies the files it reads from running
# docker and podman containers (SCAN_CONTAINERS=1, the default; 0 skips them) and judges them like
# host installs. The copies are temporary: a path shown as .../docker_NAME_PATH is the PATH inside
# the container NAME.
# =============================================================================

# Commands run as "cmd_${CMD}", which shellcheck cannot follow
# shellcheck disable=SC2317,SC2329,SC2034
set -uo pipefail

SCRIPT_NAME="joomla-check.sh"
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
# ---------- reading an install -----------------------------------------------
jm_const() {   # root NAME -> the number in "const NAME = 5;"
    sed -nE "s/^[[:space:]]*(public[[:space:]]+)?const[[:space:]]+$2[[:space:]]*=[[:space:]]*([0-9]+);.*/\\2/p" "$1/libraries/src/Version.php" 2>/dev/null | head -n1
}
# prints: fixed | affected | eol
#   eol = a branch with no fixed release (3.x, 4.x, and 5.0 to 5.3): move to 5.4.9+ or 6.1.4+
joomla_status() {
    local maj="$1" min="$2" pat="$3" v="$1.$2.$3"
    (( maj >= 7 )) && { echo fixed; return; }
    if (( maj == 6 )); then ver_lt "$v" 6.1.4 && echo affected || echo fixed; return; fi
    if (( maj == 5 )); then
        (( min < 4 )) && { echo eol; return; }
        ver_lt "$v" 5.4.9 && echo affected || echo fixed; return
    fi
    echo eol
}
cache_fix_in_source() {
    local f="$1/libraries/src/Cache/Storage/FileStorage.php"
    [[ -r "$f" ]] || { echo "n/a"; return; }
    if grep -F -- 'Path::check($dir, $this->_root)' "$f" >/dev/null; then echo yes; else echo no; fi
}

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
        stage_containers 'libraries/src/Version.php' 'libraries/src/Cache/Storage/FileStorage.php'
        if [[ ${#STAGED_DIRS[@]} -gt 0 ]]; then
            local _d; local -a _a=()
            for _d in /var/www /srv /home /opt /usr/share; do [[ -d "$_d" ]] && _a+=("$_d"); done
            set -- ${_a[@]:+"${_a[@]}"} "${STAGED_DIRS[@]}"
        fi
    fi
    local -a dirs=() existing=() roots=()
    local rc=0 found=0 d f root maj min pat ver st sig
    if [[ $# -gt 0 ]]; then dirs=("$@"); else dirs=(/var/www /srv /home /opt /usr/share); fi
    for d in "${dirs[@]}"; do [[ -d "$d" ]] && existing+=("$d"); done
    step "Looking for Joomla"
    if [[ ${#existing[@]} -eq 0 ]]; then info "None of the search directories exist"; return 0; fi
    while IFS= read -r f; do roots+=("$(dirname "$(dirname "$(dirname "$f")")")"); done < <(find "${existing[@]}" -xdev -maxdepth 8 -path '*/libraries/src/Version.php' -type f 2>/dev/null | sort -u)
    for root in "${roots[@]:-}"; do
        [[ -n "$root" ]] || continue
        found=$((found+1))
        maj="$(jm_const "$root" MAJOR_VERSION)"; min="$(jm_const "$root" MINOR_VERSION)"; pat="$(jm_const "$root" PATCH_VERSION)"
        step "Joomla ${maj:-?}.${min:-?}.${pat:-?} at ${root}"
        if [[ -z "$maj" || -z "$min" || -z "$pat" ]]; then caution "could not read the version constants from libraries/src/Version.php"; rc=1; continue; fi
        ver="${maj}.${min}.${pat}"; st="$(joomla_status "$maj" "$min" "$pat")"; sig="$(cache_fix_in_source "$root")"
        case "$st" in
            fixed)
                if [[ "$sig" == no ]]; then caution "Joomla ${ver} is a fixed release, but FileStorage.php still lacks the cache-purge fix (CVE-2026-90915): the files do not match the version (a partial or failed update)"; rc=1
                else ok "Joomla ${ver} has the September 2026 fixes"; fi ;;
            affected)
                bad "Joomla ${ver} is below the fixed release of its branch: it has the 16 core issues of the September 2026 release, including CVE-2026-90915 (arbitrary directory deletion) and CVE-2026-92222 (SSRF). Update to $([[ $maj -eq 6 ]] && echo 6.1.4 || echo 5.4.9) or later"
                [[ "$sig" == yes ]] && inf "FileStorage.php already carries the cache-purge fix, so this looks like a partial update or a manual patch: the other fixes are still missing"
                rc=1 ;;
            eol)
                bad "Joomla ${ver} is on a branch with no fixed release (3.x, 4.x and 5.0 to 5.3 are past security support): it has these flaws and will not get a fix. Move to 5.4.9 or later, or 6.1.4 or later"
                rc=1 ;;
        esac
    done
    step "Verdict"
    if [[ $found -eq 0 ]]; then info "No Joomla found under: ${existing[*]}"
    elif [[ $rc -eq 0 ]]; then info "No exposed Joomla found (${found} checked)."
    else
        warn "Exposed Joomla found. Update from the Joomla administrator (System, Update, Joomla) or with the update package."
        inf "Until then (the project's suggestion, not Joomla's): most of these need a logged-in account, so limit who holds Manager or higher and restrict the administrator path by address"
        inf "Advisories: https://developer.joomla.org/security-centre.html"
    fi
    return "$rc"
}

main() {
    CMD="${1:-check}"; [[ $# -gt 0 ]] && shift
    case "$CMD" in -V|--version|version) echo "${SCRIPT_NAME} ${SCRIPT_VERSION} (${SCRIPT_DATE})"; exit 0 ;; esac
    case "$CMD" in -h|--help|help) print_help; exit 0 ;; esac
    echo "${SCRIPT_NAME} ${SCRIPT_VERSION} (${SCRIPT_DATE}) - ${CMD} on $(hostname 2>/dev/null || echo '?') at $(date -u +%FT%TZ)"
    echo "Joomla 5.4.9 and 6.1.4 security release (CVE-2026-90915, CVE-2026-92222 and others)"
    case "$CMD" in
        check) cmd_check "$@" ;;
        *) die "Unknown command: ${CMD} (check|version)" ;;
    esac
}
main "$@"; exit

# Assisted-by: Claude Sonnet 5.5
