#!/usr/bin/env bash
# SPDX-License-Identifier: CC0-1.0
# =============================================================================
# Drupal core Field UI and Entity List remote code execution: checker with mitigation  (v2)
# CVE-2026-108097 (SA-CORE-2026-014) and CVE-2026-108099 (SA-CONTRIB-2026-218)
#
# If this software is helpful, consider a donation to our 501c3 nonprofit:
# https://privacysafe.foundation
#
# The Field UI module in Drupal core does not properly validate PHP callbacks
# while it renders its tables. Drupal rates it Critical, 19/25. Drupal core
# alone is not directly exploitable: the callbacks have to be reachable from
# data an attacker controls, and that happens through contributed modules or
# custom code. At least one such path needs no authentication, which is why the
# Drupal Security Team announced it in advance (PSA-2026-10-12) and called for
# emergency patching. A research write-up with laboratory artifacts has been
# published; at disclosure no public exploit for real sites existed.
#
#   Affected: Drupal core 8.9.0 up to 10.6.19, 11.0.0 up to 11.3.19,
#             11.4.0 up to 11.4.10, and Drupal 12 before 12.0.0-beta2
#   Fixed:    10.6.19, 11.3.19, 11.4.10 (released 14 October 2026), and
#             12.0.0-beta2 for Drupal 12
#   Move to:  a supported branch. 10.5.x and earlier, 11.2.x and earlier, 9.x and
#             8.9.x are end of life
#   Workaround published by Drupal: uninstall the core Field UI module. It covers
#             only this advisory. The same release fixes two other core issues
#             that only the update fixes.
#
# CVE-2026-108099 is the same story for the contributed Entity List module
# (project entity_list), which builds lists of entities without Views. Versions
# before 3.0.10 have a critical remote code execution flaw (Drupal rating 19/25).
# It is not directly exploitable by itself, but multiple serious exploit paths exist
# with other contributed modules, at least one needs no authentication, and custom
# code may expose it. Fixed: Entity List 3.0.10 (14 October 2026). UPDATING DRUPAL
# CORE DOES NOT REPLACE THE MODULE: it needs its own update. The script checks it on
# every site it finds, whatever the core version is.
#
# "check" is read-only; "mitigate" and "rollback" are the only commands that change
# anything. "check" finds Drupal sites from core/lib/Drupal.php (and
# composer.lock), applies the version rules, reads exported configuration
# (core.extension.yml) to see whether Field UI is enabled, and flags the
# contributed Entity List module and compares its version with 3.0.10 (read from
# its info.yml, or from composer.lock when the info file carries no version).
#
# Usage:
#   ./drupal-core-check.sh [command] [DIR ...]
#
#   check (default)  scan DIR (default /var/www /srv /opt /home). Exit 0 = nothing
#                    exposed, 1 = an affected site is exposed, unverifiable, or on
#                    an end-of-life branch that cannot be patched.
#   mitigate [--dir DIR] [--dry-run] [--force]   (root) changes the host. Drupal's own
#                    published workaround for CVE-2026-108097: uninstalls the Field UI
#                    module with drush (pm:uninstall field_ui) on every site whose core is
#                    affected and where the LIVE site (not only exported configuration)
#                    still has it enabled. drush runs as the owner of the site, never as
#                    root, and is looked up in the project's vendor/bin, then PATH. The
#                    field management screens are unavailable until you reinstall Field UI.
#                    It covers this advisory only: the same release fixes two other core
#                    issues, so update core as well. --force uninstalls on a core that is
#                    not in the affected range.
#   rollback [--dry-run]   reinstall Field UI (pm:install field_ui) on the sites mitigate changed.
#   version          print the script version.
#
# Configuration kept only in the database is not visible to a file scan. On a
# live site, run in the Drupal root:
#   drush pm:list --status=enabled --type=module --format=list | grep -x field_ui
# Containers: with no directory argument the check also copies the files it reads from running
# docker and podman containers (SCAN_CONTAINERS=1, the default; 0 skips them) and judges them like
# host installs. The copies are temporary: a path shown as .../docker_NAME_PATH is the PATH inside
# the container NAME.
# =============================================================================

# Commands run as "cmd_${CMD}", which shellcheck can't follow
# shellcheck disable=SC2317,SC2329,SC2034
set -uo pipefail

SCRIPT_NAME="drupal-core-check.sh"
SCRIPT_VERSION="2.0.0"
SCRIPT_DATE="2026-10-30"
SELF="$0"
STATE_DIR="${STATE_DIR:-/var/lib/psf-security-patches/drupal}"

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
# prints: vulnerable | eol | fixed | dev | old | out
dcore_status() {
    local raw="$1" n major minor
    [[ "$raw" == *-dev || "$raw" == *.x-dev || "$raw" == dev-* ]] && { echo dev; return; }
    n="$(norm_ver "$raw")"
    is_semver "$n" || { echo dev; return; }
    major="${n%%.*}"; minor="${n#*.}"; minor="${minor%%.*}"
    case "$major" in
        7|6|5|4|3|2|1|0) echo out ;;
        8) ver_ge "$n" "8.9.0" && echo eol || echo old ;;
        9) echo eol ;;
        10)
            if (( minor >= 7 )); then echo fixed
            elif (( minor == 6 )); then ver_lt "$n" "10.6.19" && echo vulnerable || echo fixed
            else echo eol; fi ;;
        11)
            if (( minor >= 5 )); then echo fixed
            elif (( minor == 4 )); then ver_lt "$n" "11.4.10" && echo vulnerable || echo fixed
            elif (( minor == 3 )); then ver_lt "$n" "11.3.19" && echo vulnerable || echo fixed
            else echo eol; fi ;;
        12)
            # 12.0.0 alpha and beta1 are affected; beta2 and later are fixed
            if [[ "$raw" =~ ^12\.0\.0-(alpha|beta1$|beta1[^0-9]) ]]; then echo vulnerable; else echo fixed; fi ;;
        *) echo fixed ;;
    esac
}

core_version_from_source() {   # path to core/lib/Drupal.php
    sed -n "s/^[[:space:]]*const VERSION = '\([^']*\)'.*/\1/p" "$1" | head -n1
}

lock_pkg_version() {
    awk -v pkg="\"name\": \"$2\"" 'index($0,pkg){f=1;next} f && /"version":/{gsub(/[",]/,"",$2); print $2; exit}' "$1"
}

# field_ui state from exported configuration: prints enabled | disabled | unknown
field_ui_state() {   # project root
    local root="$1" f found=0
    while IFS= read -r f; do
        [[ -n "$f" ]] || continue
        found=1
        if grep -qE '^[[:space:]]+field_ui:[[:space:]]*[0-9]+' "$f"; then echo enabled; return; fi
    done < <(find "$root" -maxdepth 8 -name core.extension.yml -type f \
                -not -path '*/vendor/*' -not -path '*/core/*' -not -path '*/tests/*' -not -path '*/node_modules/*' 2>/dev/null)
    if [[ $found -eq 1 ]]; then echo disabled; else echo unknown; fi
}

# Entity List (CVE-2026-108099): its own version rule, independent of the core version
entity_list_check() {   # project root -> returns 1 when it needs action
    local root="$1" info path v lockv
    info="$(find "$root" -maxdepth 8 -path '*/entity_list/entity_list.info.yml' -type f -not -path '*/tests/*' 2>/dev/null | head -n1)"
    [[ -n "$info" ]] || return 0
    path="$(dirname "$info")"
    v="$(sed -n "s/^version:[[:space:]]*['\"]\{0,1\}\([^'\"]*\)['\"]\{0,1\}.*/\1/p" "$info" | head -n1)"
    v="${v#8.x-}"
    if [[ -z "$v" && -r "${root}/composer.lock" ]]; then
        lockv="$(lock_pkg_version "${root}/composer.lock" drupal/entity_list)"; v="${lockv#v}"; v="${v#8.x-}"
    fi
    if [[ -z "$v" ]]; then
        caution "Entity List is installed at ${path} but its version could not be read: check it (composer show drupal/entity_list). Anything before 3.0.10 has CVE-2026-108099, a critical remote code execution flaw that updating core does not fix."
        return 1
    fi
    if [[ "$v" == *dev* ]]; then
        caution "Entity List ${v} (a development version) at ${path}: confirm it includes the 3.0.10 fix for CVE-2026-108099"
        return 1
    fi
    if ver_lt "$(norm_ver "$v")" "3.0.10"; then
        bad "the contributed Entity List module ${v} at ${path} is affected by CVE-2026-108099 (SA-CONTRIB-2026-218, fixed in 3.0.10): critical remote code execution with at least one unauthenticated exploit path via other contributed modules. Updating core does NOT fix it."
        return 1
    fi
    ok "Entity List ${v} has the fix (3.0.10 or newer)"
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
        stage_containers 'core/lib/Drupal.php' 'composer.lock'
        if [[ ${#STAGED_DIRS[@]} -gt 0 ]]; then
            local _d; local -a _a=()
            for _d in /var/www /srv /opt /home; do [[ -d "$_d" ]] && _a+=("$_d"); done
            set -- ${_a[@]:+"${_a[@]}"} "${STAGED_DIRS[@]}"
        fi
    fi
    local -a dirs=() existing=()
    local rc=0 found=0 d f root ver lockver lock st fu el
    if [[ $# -gt 0 ]]; then dirs=("$@"); else dirs=(/var/www /srv /opt /home); fi
    for d in "${dirs[@]}"; do [[ -d "$d" ]] && existing+=("$d"); done
    step "Looking for Drupal sites"
    if [[ ${#existing[@]} -eq 0 ]]; then info "None of the search directories exist"; return 0; fi
    while IFS= read -r f; do
        [[ -n "$f" ]] || continue
        found=$((found+1))
        ver="$(core_version_from_source "$f")"
        # core/lib/Drupal.php -> docroot is two levels up; the project root may be one more
        root="$(dirname "$(dirname "$(dirname "$f")")")"
        [[ "$(basename "$root")" == "web" || "$(basename "$root")" == "docroot" ]] && root="$(dirname "$root")"
        lockver=""; lock="${root}/composer.lock"
        [[ -r "$lock" ]] && lockver="$(lock_pkg_version "$lock" drupal/core)"
        step "Drupal ${ver:-?} at ${root}"
        entity_list_check "$root" || rc=1
        if [[ -z "$ver" ]]; then caution "version not found in ${f}"; continue; fi
        [[ -n "$lockver" && "$(norm_ver "$lockver")" != "$(norm_ver "$ver")" ]] \
            && inf "composer.lock says drupal/core ${lockver}; the installed core says ${ver}; using the installed copy"
        st="$(dcore_status "$ver")"
        case "$st" in
            fixed) ok "Drupal core ${ver} has the fix (10.6.19, 11.3.19, 11.4.10 or 12.0.0-beta2 or newer)"; continue ;;
            out)   caution "Drupal ${ver} is outside the affected range of this advisory (it is end of life; Drupal 7 has its own long-term-support fix path)"; continue ;;
            old)   caution "Drupal ${ver} is older than 8.9.0, which the advisory does not describe; it is end of life regardless"; continue ;;
            dev)   caution "development or unparseable version '${ver}': check the exact commit against the advisory"; continue ;;
            eol)   bad "Drupal core ${ver} is affected by CVE-2026-108097 and its branch is end of life: it will not be patched, move to 10.6.19, 11.3.19 or 11.4.10"; rc=1 ;;
            vulnerable) bad "Drupal core ${ver} is affected by CVE-2026-108097 (fixed in 10.6.19, 11.3.19, 11.4.10, 12.0.0-beta2)" ;;
        esac
        fu="$(field_ui_state "$root")"
        case "$fu" in
            enabled)  bad "the Field UI module is ENABLED in exported configuration: the vulnerable code is present"; [[ "$st" == vulnerable ]] && rc=1 ;;
            disabled)
                ok "Field UI is not enabled in exported configuration: Drupal's published workaround is in effect for this advisory"
                caution "update anyway: the same release fixes two other core issues that the workaround does not cover" ;;
            *)
                caution "no exported core.extension.yml found, so Field UI status is unknown (configuration may live only in the database): treating as exposed"
                inf "check on the live site: drush pm:list --status=enabled --type=module --format=list | grep -x field_ui"
                [[ "$st" == vulnerable ]] && rc=1 ;;
        esac
    done < <(find "${existing[@]}" -maxdepth 7 -path '*/core/lib/Drupal.php' -type f \
                -not -path '*/vendor/*' -not -path '*/node_modules/*' 2>/dev/null | sort -u)
    step "Verdict"
    if [[ $found -eq 0 ]]; then
        info "No Drupal site found under: ${existing[*]}"
    elif [[ $rc -eq 0 ]]; then
        info "No exposed Drupal found (${found} checked)"
    else
        warn "Exposed Drupal found. Update core (and Entity List to 3.0.10 or later if it is installed): composer update 'drupal/core-*' --with-all-dependencies, then drush updb and drush cr."
        inf "If you cannot update today, uninstall Field UI (Drupal's published workaround for this advisory only): drush pm:uninstall field_ui"
        inf "Then review contributed and custom code that passes request data into render arrays or field configuration."
        inf "Advisory: https://www.drupal.org/sa-core-2026-014"
    fi
    return "$rc"
}

# ---------- dispatch ---------------------------------------------------------

# ---------- mitigate and rollback --------------------------------------------
DR_MANIFEST=""; DR_DRY=0
dr_runner() {   # path of runuser, which usually lives in /usr/sbin and may not be on PATH
    local c
    for c in "$(command -v runuser 2>/dev/null || true)" /usr/sbin/runuser /sbin/runuser /usr/bin/runuser; do
        [[ -n "$c" && -x "$c" ]] && { echo "$c"; return 0; }
    done
    return 1
}
dr_drush() {   # owner docroot drushbin args...  (runs as the owner of the site, never as root, so no root-owned cache files appear)
    local owner="$1" docroot="$2" bin="$3" ru; shift 3
    if [[ "${EUID:-$(id -u)}" -eq 0 && -n "$owner" && "$owner" != root ]]; then
        ru="$(dr_runner)" || { echo "cannot run drush as ${owner}: runuser not found" >&2; return 126; }
        "$ru" -u "$owner" -- "$bin" --root="$docroot" "$@"
    else "$bin" --root="$docroot" "$@"; fi
}
dr_field_ui_enabled() { grep -qx field_ui <<<"$(dr_drush "$1" "$2" "$3" pm:list --status=enabled --type=module --format=list 2>/dev/null)"; }

cmd_mitigate() {
    local force=0 rc=0 f ver st root docroot owner bin did=0 found=0 d
    local -a dirs=() existing=()
    DR_DRY=0
    while [[ $# -gt 0 ]]; do
        case "$1" in
            --dry-run) DR_DRY=1 ;; --force) force=1 ;;
            --dir) shift; [[ -n "${1:-}" ]] || die "--dir needs a directory"; dirs+=("$1") ;;
            *) die "Unknown mitigate option: $1 (--dir DIR --dry-run --force)" ;;
        esac
        shift
    done
    [[ $DR_DRY -eq 1 || "${EUID:-$(id -u)}" -eq 0 || -n "${DR_ALLOW_NONROOT:-}" ]] || die "mitigate changes the host: run it as root, or add --dry-run to see what it would do"
    [[ ${#dirs[@]} -gt 0 ]] || dirs=(/var/www /srv /opt /home)
    for d in "${dirs[@]}"; do [[ -d "$d" ]] && existing+=("$d"); done
    step "Looking for affected Drupal sites"
    if [[ ${#existing[@]} -eq 0 ]]; then info "None of the search directories exist"; return 0; fi
    if [[ $DR_DRY -eq 0 ]]; then
        mkdir -p "$STATE_DIR" || die "cannot create ${STATE_DIR}"
        DR_MANIFEST="${STATE_DIR}/manifest.txt"; touch "$DR_MANIFEST"
    else DR_MANIFEST=/dev/null; step "Dry run: nothing will be changed"; fi
    while IFS= read -r f; do
        [[ -n "$f" ]] || continue
        found=$((found+1))
        ver="$(core_version_from_source "$f")"
        docroot="$(dirname "$(dirname "$(dirname "$f")")")"; root="$docroot"
        [[ "$(basename "$root")" == "web" || "$(basename "$root")" == "docroot" ]] && root="$(dirname "$root")"
        step "Drupal ${ver:-?} at ${root}"
        st="$(dcore_status "${ver:-x}")"
        case "$st" in
            vulnerable|eol) bad "core ${ver} is affected by CVE-2026-108097" ;;
            *) if [[ $force -eq 0 ]]; then ok "core ${ver:-unknown} is not in the affected range: left alone (use --force to uninstall Field UI anyway)"; continue; fi
               caution "core ${ver:-unknown} is not affected, applying anyway because of --force" ;;
        esac
        bin=""
        if [[ -x "${root}/vendor/bin/drush" ]]; then bin="${root}/vendor/bin/drush"
        elif [[ -x "${docroot}/../vendor/bin/drush" ]]; then bin="${docroot}/../vendor/bin/drush"
        elif have drush; then bin="$(command -v drush)"; fi
        if [[ -z "$bin" ]]; then caution "no drush found (looked in ${root}/vendor/bin and PATH): uninstall Field UI by hand with  drush pm:uninstall field_ui"; rc=1; continue; fi
        owner="$(stat -c %U "$docroot" 2>/dev/null)"
        if [[ "${EUID:-$(id -u)}" -eq 0 && -n "$owner" && "$owner" != root ]] && ! dr_runner >/dev/null; then
            caution "cannot run drush as ${owner} (runuser not found) and it will not be run as root on that site: uninstall Field UI by hand with  drush pm:uninstall field_ui"; rc=1; continue
        fi
        if ! dr_drush "$owner" "$docroot" "$bin" status --field=bootstrap >/dev/null 2>&1 && [[ "${DR_SKIP_BOOTSTRAP:-0}" -ne 1 ]]; then
            caution "drush cannot bootstrap this site as ${owner:-the current user}: left alone (check the database settings, then retry)"; rc=1; continue
        fi
        if ! dr_field_ui_enabled "$owner" "$docroot" "$bin"; then ok "Field UI is not enabled on the live site: Drupal's workaround is already in effect"; continue; fi
        if [[ $DR_DRY -eq 1 ]]; then echo "  would run (as ${owner:-current user}): ${bin} --root=${docroot} pm:uninstall field_ui -y"; continue; fi
        if dr_drush "$owner" "$docroot" "$bin" pm:uninstall field_ui -y >/dev/null 2>&1 && ! dr_field_ui_enabled "$owner" "$docroot" "$bin"; then
            ok "Field UI uninstalled (Drupal's published workaround); the live site no longer lists it"
            echo "drupal|${docroot}|${bin}|${owner}" >>"$DR_MANIFEST"; did=1
        else bad "drush did not uninstall Field UI: check the site by hand"; rc=1; fi
    done < <(find "${existing[@]}" -maxdepth 7 -path '*/core/lib/Drupal.php' -type f -not -path '*/vendor/*' -not -path '*/node_modules/*' 2>/dev/null | sort -u)
    step "Result"
    [[ $found -gt 0 ]] || info "No Drupal site found under: ${existing[*]}"
    if [[ $DR_DRY -eq 1 ]]; then info "Dry run finished: nothing was changed"
    elif [[ $did -eq 1 ]]; then info "Field UI is uninstalled. The field management screens are gone until you update core and reinstall it. Undo with: $0 rollback"
    else info "Nothing was changed"; fi
    inf "Drupal's own workaround covers this advisory only: the same release fixes two other core issues. Update core: composer update 'drupal/core-*' --with-all-dependencies, then drush updb and drush cr."
    return "$rc"
}

cmd_rollback() {
    local line rest docroot bin owner rc=0
    DR_DRY=0
    while [[ $# -gt 0 ]]; do
        case "$1" in --dry-run) DR_DRY=1 ;; *) die "Unknown rollback option: $1 (--dry-run)" ;; esac
        shift
    done
    DR_MANIFEST="${STATE_DIR}/manifest.txt"
    [[ -s "$DR_MANIFEST" ]] || { info "Nothing to roll back (no manifest in ${STATE_DIR})"; return 0; }
    [[ $DR_DRY -eq 1 || "${EUID:-$(id -u)}" -eq 0 || -n "${DR_ALLOW_NONROOT:-}" ]] || die "rollback changes the host: run it as root, or add --dry-run"
    step "Rolling back"
    while IFS= read -r line; do
        [[ "$line" == drupal\|* ]] || continue
        rest="${line#drupal|}"; docroot="${rest%%|*}"; rest="${rest#*|}"; bin="${rest%%|*}"; owner="${rest#*|}"
        if [[ $DR_DRY -eq 1 ]]; then echo "  would run (as ${owner:-current user}): ${bin} --root=${docroot} pm:install field_ui -y"; continue; fi
        if dr_drush "$owner" "$docroot" "$bin" pm:install field_ui -y >/dev/null 2>&1 && dr_field_ui_enabled "$owner" "$docroot" "$bin"; then ok "Field UI reinstalled on ${docroot}"
        else bad "could not reinstall Field UI on ${docroot}: run  drush pm:install field_ui  by hand"; rc=1; fi
    done <"$DR_MANIFEST"
    if [[ $DR_DRY -eq 0 && $rc -eq 0 ]]; then
        mv "$DR_MANIFEST" "${DR_MANIFEST}.rolled-back-$(date +%s)" 2>/dev/null || true
        info "Rolled back."
    fi
    return "$rc"
}

main() {
    CMD="${1:-check}"; [[ $# -gt 0 ]] && shift
    case "$CMD" in -V|--version|version) echo "${SCRIPT_NAME} ${SCRIPT_VERSION} (${SCRIPT_DATE})"; exit 0 ;; esac
    case "$CMD" in -h|--help|help) print_help; exit 0 ;; esac
    echo "${SCRIPT_NAME} ${SCRIPT_VERSION} (${SCRIPT_DATE}) - ${CMD} on $(hostname 2>/dev/null || echo '?') at $(date -u +%FT%TZ)"
    echo "CVE-2026-108097; fixed in Drupal 10.6.19, 11.3.19, 11.4.10 and 12.0.0-beta2"
    case "$CMD" in
        check) cmd_check "$@" ;;
        mitigate) cmd_mitigate "$@" ;;
        rollback) cmd_rollback "$@" ;;
        *) die "Unknown command: ${CMD} (check|mitigate|rollback|version)" ;;
    esac
}
main "$@"; exit

# Assisted-by: Claude Sonnet 5.5
