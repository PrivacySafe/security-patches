#!/usr/bin/env bash
# SPDX-License-Identifier: CC0-1.0
# =============================================================================
# Craft CMS Twig create() blocklist bypass: read-only checker  (v1)
# CVE-2026-112777 (GHSA-w643-x88w-6wcm)
#
# If this software is helpful, consider a donation to our 501c3 nonprofit:
# https://privacysafe.foundation
#
# Craft CMS restricts which classes the Twig create() function may instantiate
# with a blocklist. The class-name checks are case-sensitive while PHP class
# resolution is not, so a differently capitalized class name slips past the
# blocklist. The result is remote code execution, or reading secrets such as
# the .env file, for someone who can get Twig to render attacker-controlled
# template content. CVSS 8.7 (v4.0), 7.2 (v3.1). It is an authenticated flaw:
# it needs template-execution rights, so the realistic attackers are a
# compromised or malicious control panel account, or any setup that lets
# untrusted users supply template code. A GitHub proof of concept has been
# reported by one CVE aggregator and is not linked here.
#
#   Affected: Craft CMS 4.x from 4.0.0 before 4.18.8, and 5.x from 5.0.0 before 5.11.0
#   Fixed:    4.18.8 and 5.11.0
#
# The same two releases fix several related Twig sandbox and behavior-injection
# flaws, so updating covers more than this one issue.
#
# This script is read-only. It reads the Craft version from the installed
# vendor/craftcms/cms (and from composer.lock), and from config/general.php it
# reports whether allowAdminChanges is off and whether the Twig sandbox is on.
#
# Usage:
#   ./craftcms-check.sh [command] [DIR ...]
#
#   check (default)  scan DIR (default /var/www /srv /home /opt) for Craft
#                    projects. Exit 0 = nothing affected, 1 = an affected
#                    version was found.
#   version          print the script version.
# Containers: with no directory argument the check also copies the files it reads from running
# docker and podman containers (SCAN_CONTAINERS=1, the default; 0 skips them) and judges them like
# host installs. The copies are temporary: a path shown as .../docker_NAME_PATH is the PATH inside
# the container NAME.
# =============================================================================

# Commands run as "cmd_${CMD}", which shellcheck can't follow
# shellcheck disable=SC2317,SC2329,SC2034
set -uo pipefail

SCRIPT_NAME="craftcms-check.sh"
SCRIPT_VERSION="1.0.0"
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

# ---------- helpers ----------------------------------------------------------
# prints fixed | vulnerable | eol | unknown
craft_status() {
    local v; v="$(norm_ver "$1")"
    is_semver "$v" || { echo unknown; return; }
    case "${v%%.*}" in
        4) ver_lt "$v" "4.18.8" && echo vulnerable || echo fixed ;;
        5) ver_lt "$v" "5.11.0" && echo vulnerable || echo fixed ;;
        0|1|2|3) echo eol ;;
        *) echo unknown ;;
    esac
}

lock_pkg_version() {   # composer.lock package -> version
    awk -v pkg="\"name\": \"$2\"" 'index($0,pkg){f=1;next} f && /"version":/{gsub(/[",]/,"",$2); print $2; exit}' "$1"
}

installed_version() {  # project dir -> version from vendor/craftcms/cms
    local f="$1/vendor/craftcms/cms/src/config/app.php"
    [[ -r "$f" ]] && sed -n "s/^[[:space:]]*'version'[[:space:]]*=>[[:space:]]*'\([^']*\)'.*/\1/p" "$f" | head -n1
    return 0
}

# report a boolean-ish Craft general setting: prints "true", "false" or nothing
general_setting() {    # config/general.php setting-name
    local f="$1" name="$2" v
    [[ -r "$f" ]] || return 0
    v="$(sed -E 's#//.*$##' "$f" | grep -iE "(['\"]${name}['\"][[:space:]]*=>|->${name}\\()" | head -n1)"
    [[ -n "$v" ]] || return 0
    if grep -qiE 'false' <<<"$v"; then echo false
    elif grep -qiE 'true' <<<"$v"; then echo true
    else echo set; fi
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
        stage_containers 'vendor/craftcms/cms/src/config/app.php' 'composer.lock' 'config/general.php'
        if [[ ${#STAGED_DIRS[@]} -gt 0 ]]; then
            local _d; local -a _a=()
            for _d in /var/www /srv /home /opt; do [[ -d "$_d" ]] && _a+=("$_d"); done
            set -- ${_a[@]:+"${_a[@]}"} "${STAGED_DIRS[@]}"
        fi
    fi
    local -a dirs=() existing=() locks=()
    local rc=0 found=0 d lock dir lv iv ver st gen aac sbx
    if [[ $# -gt 0 ]]; then dirs=("$@"); else dirs=(/var/www /srv /home /opt); fi
    for d in "${dirs[@]}"; do [[ -d "$d" ]] && existing+=("$d"); done
    step "Looking for Craft CMS projects"
    if [[ ${#existing[@]} -eq 0 ]]; then info "None of the search directories exist"; return 0; fi
    while IFS= read -r lock; do [[ -n "$lock" ]] && locks+=("$lock"); done < <(
        find "${existing[@]}" -maxdepth 7 \( -name node_modules -o -name vendor \) -prune \
             -o -name composer.lock -type f -print 2>/dev/null | sort -u)
    for lock in "${locks[@]:-}"; do
        [[ -n "$lock" ]] || continue
        lv="$(lock_pkg_version "$lock" craftcms/cms)"
        dir="$(dirname "$lock")"
        iv="$(installed_version "$dir")"
        [[ -z "$lv" && -z "$iv" ]] && continue
        found=$((found+1))
        ver="${iv:-$lv}"
        step "Craft CMS ${ver} in ${dir}"
        [[ -n "$lv" && -n "$iv" && "$(norm_ver "$lv")" != "$(norm_ver "$iv")" ]] \
            && inf "composer.lock says ${lv}, vendor/ has ${iv}; using the installed copy"
        st="$(craft_status "$ver")"
        case "$st" in
            fixed)   ok "Craft CMS ${ver} has the fix (4.18.8+ on 4.x, 5.11.0+ on 5.x)"; continue ;;
            eol)     caution "Craft ${ver} is an end-of-life major version. The advisory covers 4.x and 5.x, so this copy is not described by it; move to a supported version."; continue ;;
            unknown) caution "cannot compare version '${ver}' (a 6.x pre-release, a dev checkout or an unusual string): check the advisory GHSA-w643-x88w-6wcm"; continue ;;
            vulnerable) bad "Craft CMS ${ver} is affected by CVE-2026-112777 (fixed in 4.18.8 / 5.11.0)"; rc=1 ;;
        esac
        gen="${dir}/config/general.php"
        if [[ -r "$gen" ]]; then
            aac="$(general_setting "$gen" allowAdminChanges)"
            sbx="$(general_setting "$gen" enableTwigSandbox)"
            case "$aac" in
                false) ok "allowAdminChanges is false: production configuration changes through the control panel are off" ;;
                true)  caution "allowAdminChanges is true: anyone with an admin account can change configuration that feeds Twig; turn it off in production" ;;
                *)     caution "allowAdminChanges is not set in config/general.php: Craft's default allows admin changes; turn it off in production" ;;
            esac
            case "$sbx" in
                true)  inf "enableTwigSandbox is on" ;;
                false) caution "enableTwigSandbox is off" ;;
                *)     inf "enableTwigSandbox is not set in config/general.php" ;;
            esac
        else
            inf "config/general.php not readable: allowAdminChanges and the sandbox setting were not checked"
        fi
    done
    step "Verdict"
    if [[ $found -eq 0 ]]; then
        info "No Craft CMS project found under: ${existing[*]}"
    elif [[ $rc -eq 0 ]]; then
        info "No affected Craft CMS found (${found} checked)"
    else
        warn "Affected Craft CMS found. Update: composer update craftcms/cms  (4.18.8+ or 5.11.0+), then run php craft up."
        inf "Meanwhile: review who holds admin or template-related permissions in the control panel, remove accounts you do not recognize, and set allowAdminChanges to false in production."
        inf "Those measures narrow who can reach the flaw; they are PrivacySafe's recommendation and work alongside the update."
        inf "Advisory: https://github.com/craftcms/cms/security/advisories/GHSA-w643-x88w-6wcm"
    fi
    return "$rc"
}

# ---------- dispatch ---------------------------------------------------------
main() {
    CMD="${1:-check}"; [[ $# -gt 0 ]] && shift
    case "$CMD" in -V|--version|version) echo "${SCRIPT_NAME} ${SCRIPT_VERSION} (${SCRIPT_DATE})"; exit 0 ;; esac
    case "$CMD" in -h|--help|help) print_help; exit 0 ;; esac
    echo "${SCRIPT_NAME} ${SCRIPT_VERSION} (${SCRIPT_DATE}) - ${CMD} on $(hostname 2>/dev/null || echo '?') at $(date -u +%FT%TZ)"
    echo "CVE-2026-112777; fixed in Craft CMS 4.18.8 and 5.11.0"
    case "$CMD" in
        check) cmd_check "$@" ;;
        *) die "Unknown command: ${CMD} (check|version)" ;;
    esac
}
main "$@"; exit

# Assisted-by: Claude Sonnet 5.5
