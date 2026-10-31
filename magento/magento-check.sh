#!/usr/bin/env bash
# SPDX-License-Identifier: CC0-1.0
# =============================================================================
# Magento, Adobe Commerce and Mage-OS email-template RCE (BlockStrap): read-only checker  (v3)
# CVE-2026-103849
#
# If this software is helpful, consider a donation to our 501c3 nonprofit:
# https://privacysafe.foundation
#
# CVE-2026-103849 (BlockStrap) is an unauthenticated remote code execution flaw in the email
# template engine, CVSS 10.0 (CVSS 3.1). It is a second-pass directive injection: a directive
# hidden in a child email template is signed, passes the check, and is processed again by the
# parent template. Adobe's fix is in APSB26-153 (13 October 2026). Researchers found four attack
# paths within a day and expect exploitation; none was confirmed at the time of the sources
# used here.
#
#   Affected: Adobe Commerce 2.4.4 to 2.4.9, Adobe Commerce B2B 1.3.3 to 1.5.3 and Magento
#             Open Source (sources give 2.4.6 or 2.4.7 as the first) to 2.4.9, in builds
#             before APSB26-153. Mage-OS up to and including 3.5.0.
#   Fixed:    Adobe's October 2026 releases (APSB26-153); Mage-OS 3.6.0 (14 October 2026).
#
# What a version number can and cannot show. Adobe ships this fix as an isolated patch, and
# applying it does not change the version string. So for Magento and Adobe Commerce the script
# tells you what to check rather than guessing. It can give a
# firm answer for Mage-OS (the fix arrives as a release) and for a dated release string if your
# build uses one (for example 2.4.9-2026-oct).
#
# No indicators of exploitation have been published for this flaw, so there is no hunt.
#
# This script is read-only.
#
# Usage:
#   ./magento-check.sh [command] [DIR ...]
#   check (default)  find installs by bin/magento (default /var/www /srv /home /opt),
#                    read the distribution and version from composer.lock. Exit 0 = nothing
#                    exposed, 1 = exposed or unconfirmed.
#   version          print the script version.
# Containers: with no directory argument the check also copies the files it reads from running
# docker and podman containers (SCAN_CONTAINERS=1, the default; 0 skips them) and judges them like
# host installs. The copies are temporary: a path shown as .../docker_NAME_PATH is the PATH inside
# the container NAME.
# =============================================================================

# Commands run as "cmd_${CMD}", which shellcheck cannot follow
# shellcheck disable=SC2317,SC2329,SC2034
set -uo pipefail

SCRIPT_NAME="magento-check.sh"
SCRIPT_VERSION="3.0.0"
SCRIPT_DATE="2026-10-30"
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
# prints: <edition>|<version>      edition = mageos | adobe | magento | unknown
# composer.lock names the distribution package and its version
magento_identity() {
    local root="$1" lock="$1/composer.lock" pkg v
    if [[ -r "$lock" ]]; then
        for pkg in mage-os/product-community-edition magento/product-enterprise-edition magento/product-community-edition; do
            v="$(grep -F -A1 "\"name\": \"${pkg}\"" "$lock" 2>/dev/null | sed -nE 's/^[[:space:]]*"version":[[:space:]]*"([^"]+)".*/\1/p' | head -n1)"
            if [[ -n "$v" ]]; then
                case "$pkg" in mage-os/*) echo "mageos|${v}" ;; magento/product-enterprise-edition) echo "adobe|${v}" ;; *) echo "magento|${v}" ;; esac
                return
            fi
        done
    fi
    # a git checkout names itself in composer.json
    if [[ -r "$root/composer.json" ]]; then
        local name; name="$(sed -nE 's/^[[:space:]]*"name":[[:space:]]*"([^"]+)".*/\1/p' "$root/composer.json" | head -n1)"
        v="$(sed -nE 's/^[[:space:]]*"version":[[:space:]]*"([^"]+)".*/\1/p' "$root/composer.json" | head -n1)"
        if [[ -n "$v" ]]; then case "$name" in mage-os/*) echo "mageos|${v}" ;; magento/*) echo "magento|${v}" ;; *) echo "unknown|${v}" ;; esac; return; fi
    fi
    echo "unknown|"
}

# Mage-OS: the fix arrives as a release. prints: affected | fixed | prerelease | unknown
#   affected = below 3.6.0 (3.5.x included);  fixed = 3.6.0 or later
mageos_open() {
    local v; v="$(norm_ver "$1")"
    is_semver "$v" || { echo unknown; return; }
    ver_lt "$v" 3.6.0 && { echo affected; return; }
    # a pre-release of 3.6.0 (3.6.0-beta1, 3.6.0-rc2) comes before the release: it may not carry
    # the fix, and the script does not claim it does
    [[ "$1" =~ -(alpha|beta|rc|dev|pre) && "$v" == 3.6.0 ]] && { echo prerelease; return; }
    echo fixed
}

# a dated release string such as 2.4.9-2026-oct gives the patch month, as YYYYMM; else 0
dated_month() {
    local v="$1" n
    if [[ "$v" =~ -([0-9]{4})-(jan|feb|mar|apr|may|jun|jul|aug|sep|oct|nov|dec)$ ]]; then
        case "${BASH_REMATCH[2]}" in jan)n=01;; feb)n=02;; mar)n=03;; apr)n=04;; may)n=05;; jun)n=06;; jul)n=07;; aug)n=08;; sep)n=09;; oct)n=10;; nov)n=11;; *)n=12;; esac
        echo "${BASH_REMATCH[1]}${n}"
    elif [[ "$v" =~ -([0-9]{4})-([0-9]{2})$ ]]; then echo "${BASH_REMATCH[1]}${BASH_REMATCH[2]}"
    else echo 0; fi
}

find_installs() {
    local -a dirs=() existing=(); local d f
    if [[ $# -gt 0 ]]; then dirs=("$@"); else dirs=(/var/www /srv /home /opt); fi
    for d in "${dirs[@]}"; do [[ -d "$d" ]] && existing+=("$d"); done
    [[ ${#existing[@]} -gt 0 ]] || return 0
    while IFS= read -r f; do echo "$(dirname "$(dirname "$f")")"; done < <(find "${existing[@]}" -xdev -maxdepth 8 -path '*/bin/magento' -type f -not -path '*/vendor/*' 2>/dev/null | sort -u)
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
        stage_containers 'bin/magento' 'composer.lock' 'composer.json'
        if [[ ${#STAGED_DIRS[@]} -gt 0 ]]; then
            local _d; local -a _a=()
            for _d in /var/www /srv /home /opt; do [[ -d "$_d" ]] && _a+=("$_d"); done
            set -- ${_a[@]:+"${_a[@]}"} "${STAGED_DIRS[@]}"
        fi
    fi
    local rc=0 found=0 root id ed ver mo
    step "Looking for Magento, Adobe Commerce or Mage-OS"
    local -a roots=(); while IFS= read -r root; do [[ -n "$root" ]] && roots+=("$root"); done < <(find_installs "$@")
    if [[ ${#roots[@]} -eq 0 ]]; then info "No install found (looked for bin/magento under ${*:-/var/www /srv /home /opt})"; return 0; fi
    for root in "${roots[@]}"; do
        found=$((found+1))
        id="$(magento_identity "$root")"; ed="${id%%|*}"; ver="${id#*|}"
        step "${ed} ${ver:-unknown} at ${root}"
        if [[ -z "$ver" ]]; then caution "could not read the version (looked in composer.lock and composer.json)"; rc=1; continue; fi
        if [[ "$ed" == mageos ]]; then
            case "$(mageos_open "$ver")" in
                affected)   bad "Mage-OS ${ver} is below 3.6.0 and is exposed to BlockStrap (CVE-2026-103849). Update to 3.6.0 or later"; rc=1 ;;
                fixed)      ok "Mage-OS ${ver} carries the BlockStrap fix (3.6.0 or later)" ;;
                prerelease) caution "Mage-OS ${ver} is a pre-release build, not a release: it may not carry the fix. Update to 3.6.0 or later"; rc=1 ;;
                *)          caution "cannot compare Mage-OS version '${ver}': update to 3.6.0 or later"; rc=1 ;;
            esac
            continue
        fi
        mo="$(dated_month "$ver")"
        if [[ "$mo" != 0 ]]; then
            if (( mo < 202610 )); then bad "${ver}: built before the October 2026 fix for BlockStrap (CVE-2026-103849, APSB26-153)"; rc=1
            else ok "${ver}: built in or after October 2026, which carries the BlockStrap fix"; fi
            continue
        fi
        caution "${ver}: confirm the patch. Adobe ships this fix as an isolated patch, and a patch does not change the version string. Confirm with your patch tooling that the APSB26-153 fix for CVE-2026-103849 is applied, or move to the October 2026 release"
        rc=1
    done
    step "Verdict"
    if [[ $rc -eq 0 ]]; then info "No exposed install found (${found} checked)."
    else
        warn "Exposed or unconfirmed install found. Apply APSB26-153 (or move to Mage-OS 3.6.0)."
        inf "Adobe documents no workaround, and no indicators of exploitation have been published, so there is no hunt: after exposure, review your email templates for directives you did not add"
        inf "Advisory: Adobe security bulletin APSB26-153"
    fi
    return "$rc"
}

main() {
    CMD="${1:-check}"; [[ $# -gt 0 ]] && shift
    case "$CMD" in -V|--version|version) echo "${SCRIPT_NAME} ${SCRIPT_VERSION} (${SCRIPT_DATE})"; exit 0 ;; esac
    case "$CMD" in -h|--help|help) print_help; exit 0 ;; esac
    echo "${SCRIPT_NAME} ${SCRIPT_VERSION} (${SCRIPT_DATE}) - ${CMD} on $(hostname 2>/dev/null || echo '?') at $(date -u +%FT%TZ)"
    echo "CVE-2026-103849 (BlockStrap): Magento, Adobe Commerce and Mage-OS email template RCE"
    case "$CMD" in
        check) cmd_check "$@" ;;
        *) die "Unknown command: ${CMD} (check|version)" ;;
    esac
}
main "$@"; exit

# Assisted-by: Claude Sonnet 5.5
