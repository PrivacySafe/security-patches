#!/usr/bin/env bash
# SPDX-License-Identifier: CC0-1.0
# =============================================================================
# Drupal Webform remote code execution: read-only checker  (v1)
# CVE-2026-96355 (SA-CONTRIB-2026-175)
#
# If this software is helpful, consider a donation to our 501c3 nonprofit:
# https://privacysafe.foundation
#
# The Drupal Webform module does not sufficiently exclude certain format
# templates from token replacement. An attacker can submit data that is then
# evaluated as template code when a submission is rendered. Depending on site
# configuration and enabled modules this can mean information disclosure,
# stored cross-site scripting or remote code execution. Drupal Security Team
# rating: Critical, 18/25.
#
#   Affected: Webform before 6.2.12, and 6.3.0 before 6.3.1
#   Fixed:    6.2.12 on the 6.2.x branch, 6.3.1 on the 6.3.x branch
#   Condition (from the advisory): an affected webform must define a custom
#   multiple-value item format that includes submission-value tokens. Some
#   impacts also depend on other enabled modules. Drupal core is not affected.
#
# Webform is among the most widely installed Drupal modules and sits on public
# pages. The same releases close 19 other Webform advisories published on the
# same day (numbered between SA-CONTRIB-2026-154 and 174).
#
# This script is read-only. It reads the Webform version from composer.lock and
# from the module's own webform.info.yml, and scans exported configuration for
# webforms that use a custom multiple-value format.
#
# Usage:
#   ./drupal-webform-check.sh [command] [DIR ...]
#
#   check (default)  scan DIR (default /var/www /srv /opt /home) for Webform.
#                    Exit 0 = nothing affected, 1 = an affected version found.
#   version          print the script version.
#
# Configuration stored only in the database is not visible to a file scan. To
# list webforms with a custom multiple-value format from the live site, run in
# the Drupal root:
#   drush config:list --prefix=webform.webform. --format=list | while read -r c; do
#     drush config:get "$c" elements 2>/dev/null | grep -E "format_items.*custom" >/dev/null && echo "$c"; done
# Containers: with no directory argument the check also copies the files it reads from running
# docker and podman containers (SCAN_CONTAINERS=1, the default; 0 skips them) and judges them like
# host installs. The copies are temporary: a path shown as .../docker_NAME_PATH is the PATH inside
# the container NAME.
# =============================================================================

# Commands run as "cmd_${CMD}", which shellcheck can't follow
# shellcheck disable=SC2317,SC2329,SC2034
set -uo pipefail

SCRIPT_NAME="drupal-webform-check.sh"
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

# ---------- version rule -----------------------------------------------------
# affected: below 6.2.12, or 6.3.0 up to (not including) 6.3.1. A 6.3.0
# pre-release such as 6.3.0-rc2 is the same branch and counts as affected.
webform_affected() {
    ver_lt "$1" "6.2.12" && return 0
    ver_ge "$1" "6.3.0" && ver_lt "$1" "6.3.1" && return 0
    return 1
}

lock_pkg_version() {   # composer.lock package -> version
    awk -v pkg="\"name\": \"$2\"" 'index($0,pkg){f=1;next} f && /"version":/{gsub(/[",]/,"",$2); print $2; exit}' "$1"
}

info_yml_version() {   # webform.info.yml -> version
    sed -n "s/^version:[[:space:]]*['\"]\{0,1\}\([^'\"]*\)['\"]\{0,1\}[[:space:]]*\$/\1/p" "$1" | head -n1
}

report() {   # label version
    local label="$1" ver="$2"
    if [[ "$ver" == dev-* || "$ver" == *x-dev || "$ver" == *.x ]]; then
        caution "${label}: development version '${ver}', check the exact commit against 6.2.12 / 6.3.1"; return 0
    fi
    if ! is_semver "$ver" || [[ "$ver" == 8.x-* || "$ver" == 7.x-* ]]; then
        caution "${label}: version '${ver}' is not in the 6.x scheme; check drupal.org/sa-contrib-2026-175 manually"; return 0
    fi
    if webform_affected "$ver"; then
        bad "${label}: Webform ${ver} is affected by CVE-2026-96355 (fixed in 6.2.12 / 6.3.1)"
        return 1
    fi
    ok "${label}: Webform ${ver} is fixed (6.2.12+ on 6.2.x, 6.3.1+ on 6.3.x)"
    return 0
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
        stage_containers 'webform/webform.info.yml'
        if [[ ${#STAGED_DIRS[@]} -gt 0 ]]; then
            local _d; local -a _a=()
            for _d in /var/www /srv /opt /home; do [[ -d "$_d" ]] && _a+=("$_d"); done
            set -- ${_a[@]:+"${_a[@]}"} "${STAGED_DIRS[@]}"
        fi
    fi
    local -a dirs=() existing=()
    local rc=0 found=0 d f v root hits fc
    if [[ $# -gt 0 ]]; then dirs=("$@"); else dirs=(/var/www /srv /opt /home); fi
    for d in "${dirs[@]}"; do [[ -d "$d" ]] && existing+=("$d"); done
    step "Looking for the Drupal Webform module"
    if [[ ${#existing[@]} -eq 0 ]]; then info "None of the search directories exist"; return 0; fi

    step "composer.lock"
    while IFS= read -r f; do
        [[ -n "$f" ]] || continue
        v="$(lock_pkg_version "$f" drupal/webform)"
        [[ -n "$v" ]] || continue
        found=$((found+1))
        report "$f" "$v" || rc=1
    done < <(find "${existing[@]}" -maxdepth 7 \( -name node_modules -o -name vendor -o -name contrib \) -prune \
                -o -name composer.lock -type f -print 2>/dev/null | sort -u)

    step "Installed module copies (webform.info.yml)"
    while IFS= read -r f; do
        [[ -n "$f" ]] || continue
        v="$(info_yml_version "$f")"
        [[ -n "$v" ]] || { caution "${f}: no version line (a git checkout or a dev copy)"; continue; }
        found=$((found+1))
        report "$f" "$v" || rc=1
    done < <(find "${existing[@]}" -maxdepth 9 -path '*/webform/webform.info.yml' -type f 2>/dev/null | sort -u)

    step "Exported configuration: webforms with a custom multiple-value format (heuristic)"
    hits=0
    while IFS= read -r f; do
        [[ -n "$f" ]] || continue
        fc="$(grep -cE "format_items'?:[[:space:]]*'?custom" "$f" 2>/dev/null)"
        if [[ "${fc:-0}" -gt 0 ]]; then
            hits=$((hits+1))
            caution "$(basename "$f"): ${fc} element(s) use a custom multiple-value format; check whether they contain submission-value tokens"
        fi
    done < <(find "${existing[@]}" -maxdepth 9 -name 'webform.webform.*.yml' -type f 2>/dev/null | sort -u)
    [[ $hits -eq 0 ]] && inf "no exported webform config with a custom multiple-value format (database-only config is not visible here)"
    root="${existing[0]}"; : "$root"

    step "Verdict"
    if [[ $found -eq 0 ]]; then
        info "No Webform module found under: ${existing[*]}"
    elif [[ $rc -eq 0 ]]; then
        info "No affected Webform found (${found} copy checked)"
    else
        warn "Affected Webform found. Update: composer require 'drupal/webform:^6.2.12' (or ^6.3.1), then run drush updb and drush cr."
        inf "Until then, remove custom multiple-value item formats that include submission-value tokens from your webforms (the advisory names this as the required condition)."
        inf "Advisory: https://www.drupal.org/sa-contrib-2026-175"
    fi
    return "$rc"
}

# ---------- dispatch ---------------------------------------------------------
main() {
    CMD="${1:-check}"; [[ $# -gt 0 ]] && shift
    case "$CMD" in -V|--version|version) echo "${SCRIPT_NAME} ${SCRIPT_VERSION} (${SCRIPT_DATE})"; exit 0 ;; esac
    case "$CMD" in -h|--help|help) print_help; exit 0 ;; esac
    echo "${SCRIPT_NAME} ${SCRIPT_VERSION} (${SCRIPT_DATE}) - ${CMD} on $(hostname 2>/dev/null || echo '?') at $(date -u +%FT%TZ)"
    echo "CVE-2026-96355; fixed in Webform 6.2.12 and 6.3.1"
    case "$CMD" in
        check) cmd_check "$@" ;;
        *) die "Unknown command: ${CMD} (check|version)" ;;
    esac
}
main "$@"; exit

# Assisted-by: Claude Sonnet 5.5
