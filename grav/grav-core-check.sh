#!/usr/bin/env bash
# SPDX-License-Identifier: CC0-1.0
# =============================================================================
# Grav CMS core allowlist bypass through Flex form overrides: read-only checker  (v1)
# CVE-2026-116019
#
# If this software is helpful, consider a donation to our 501c3 nonprofit:
# https://privacysafe.foundation
#
# Grav 2.0.15 before 2.2.13 lets a user who may edit pages run arbitrary public static
# methods. Grav marks the dynamic directives in a blueprint (the data-*@ fields that name a
# PHP method to call) as trusted only where the blueprint file itself defines them, and
# checks the ones that arrive from page frontmatter against an allowlist. The merge that
# combines the two could relocate a directive away from the path it was checked at: the
# vendor deepMerge() honours the unset-name@ merge action as well as replace-name@, and it
# renumbers an integer key the base does not have. A relocated directive was then trusted as
# if the blueprint file had defined it, so the allowlist was skipped. A page editor can embed
# crafted fields in the Flex form overrides of a page's frontmatter and call methods such as
# Folder::delete or Utils::download, which deletes directories, overwrites files, or reads
# files outside the page tree. CVSS 8.8 (v3.1), 8.7 (v4.0). No exploitation was reported at
# the time of the sources used. Found through a GitHub security advisory
# (GHSA-47gg-mh38-9rr7), published 24 October 2026.
#
#   Affected: Grav 2.0.15 up to and including 2.2.12
#   Fixed:    2.2.13 (24 October 2026)
#
# How this script reads a site. The version is the GRAV_VERSION constant in
# system/defines.php. The script also reads system/src/Grav/Common/Data/Blueprint.php for
# the two things the fix adds: the dynamicOf() helper that compares the directives before and
# after the merge, and the extension of the stripping from replace-name@ to unset-name@. Both
# present means the fix is there, whatever the version string says; neither present on a
# version in the affected range means exposed; one of the two is a partial patch.
#
# This script is read-only. "hunt" also looks in the site's pages for what an attack needs:
# a relocation merge action (unset-name@, replace-name@) or a static method call in page
# frontmatter. Those are leads, not proof: a relocation directive together with a static
# method call in the same page is a strong lead, either one alone is only listed for review.
# A clean hunt is not proof that no page was edited maliciously.
#
# Usage:
#   ./grav-core-check.sh [command] [DIR ...]
#
#   check (default)  scan DIR (default /var/www /srv /opt /home) for Grav sites. Exit 0 =
#                    nothing exposed, 1 = an exposed or unverifiable site.
#   hunt             check, then look in the pages for the indicators above. Exit 0 =
#                    nothing found, 1 = an exposed site or a strong lead.
#   version          print the script version.
# Containers: with no directory argument the check also copies the files it reads from running
# docker and podman containers (SCAN_CONTAINERS=1, the default; 0 skips them) and judges them like
# host installs. The copies are temporary: a path shown as .../docker_NAME_PATH is the PATH inside
# the container NAME.
# =============================================================================

# Commands run as "cmd_${CMD}", which shellcheck cannot follow
# shellcheck disable=SC2317,SC2329,SC2034
set -uo pipefail

SCRIPT_NAME="grav-core-check.sh"
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
# the version string, exactly as defines.php holds it (2.2.12, or 2.2.13-rc.1)
grav_version() {
    local f="$1/system/defines.php"
    [[ -r "$f" ]] || return 0
    sed -nE "s/^[[:space:]]*define\([[:space:]]*['\"]GRAV_VERSION['\"][[:space:]]*,[[:space:]]*['\"]([^'\"]+)['\"].*/\1/p" "$f" | head -n1 | tr -d '\r'
}

# version status. prints: notaffected | vulnerable | fixed | prerelease | unknown
#   prerelease = a pre-release of the fixed release itself (2.2.13-rc.1): not judged as the release
grav_status() {
    local raw="$1" v; v="$(norm_ver "$raw")"
    is_semver "$v" || { echo unknown; return; }
    ver_lt "$v" 2.0.15 && { echo notaffected; return; }
    ver_lt "$v" 2.2.13 && { echo vulnerable; return; }
    [[ "$raw" =~ -(alpha|beta|rc|dev|pre) && "$v" == 2.2.13 ]] && { echo prerelease; return; }
    echo fixed
}

# the two things the fix adds to Blueprint.php. prints: both | one | none | unreadable
blueprint_signature() {
    local f="$1/system/src/Grav/Common/Data/Blueprint.php" a=0 b=0
    [[ -r "$f" ]] || { echo unreadable; return; }
    grep -qF 'function dynamicOf(' "$f" && a=1
    grep -qF "['replace', 'unset']" "$f" && b=1
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
        stage_containers 'system/defines.php' 'system/src/Grav/Common/Data/Blueprint.php'
        if [[ ${#STAGED_DIRS[@]} -gt 0 ]]; then
            local _d; local -a _a=()
            for _d in /var/www /srv /opt /home; do [[ -d "$_d" ]] && _a+=("$_d"); done
            set -- ${_a[@]:+"${_a[@]}"} "${STAGED_DIRS[@]}"
        fi
    fi
    local -a dirs=() existing=()
    local rc=0 found=0 d df root ver st sig
    if [[ $# -gt 0 ]]; then dirs=("$@"); else dirs=(/var/www /srv /opt /home); fi
    for d in "${dirs[@]}"; do [[ -d "$d" ]] && existing+=("$d"); done
    step "Looking for Grav sites"
    SITES=()
    if [[ ${#existing[@]} -eq 0 ]]; then info "None of the search directories exist"; return 0; fi
    while IFS= read -r df; do
        [[ -n "$df" ]] || continue
        grep -qF 'GRAV_VERSION' "$df" 2>/dev/null || continue
        root="$(dirname "$(dirname "$df")")"
        found=$((found+1)); SITES+=("$root")
        ver="$(grav_version "$root")"
        step "Grav ${ver:-version unreadable} at ${root}"
        if [[ -z "$ver" ]]; then caution "could not read GRAV_VERSION from ${df}: affected is 2.0.15 up to 2.2.12, fixed is 2.2.13"; rc=1; continue; fi
        st="$(grav_status "$ver")"; sig="$(blueprint_signature "$root")"
        case "$sig" in
            both)
                ok "Blueprint.php carries the fix (the dynamicOf() comparison and the unset-name@ stripping)"
                [[ "$st" == vulnerable ]] && inf "the version string ${ver} is older than 2.2.13, but the files carry the fix: a backport, or files copied over an older install" ;;
            one)
                caution "Blueprint.php has only part of the fix (one of dynamicOf() and the unset-name@ stripping): a partial or mixed update. Reinstall 2.2.13 or later"; rc=1 ;;
            none)
                case "$st" in
                    vulnerable|prerelease) bad "Grav ${ver} is affected by CVE-2026-116019 (fixed in 2.2.13): a page editor can run arbitrary public static methods"
                        inf "update now (bin/gpm selfupgrade), then run: $0 hunt"; rc=1 ;;
                    fixed)       caution "version ${ver} is 2.2.13 or later, but Blueprint.php lacks the fix: the files do not match the version. Reinstall Grav"; rc=1 ;;
                    notaffected) ok "Grav ${ver} is older than 2.0.15, the start of the affected range. It is far out of date, so update it anyway" ;;
                    *)           caution "cannot compare version '${ver}': check it against 2.2.13"; rc=1 ;;
                esac ;;
            unreadable)
                case "$st" in
                    fixed)       ok "Grav ${ver} is 2.2.13 or later (Blueprint.php could not be read to confirm)" ;;
                    notaffected) ok "Grav ${ver} is older than 2.0.15, the start of the affected range. It is far out of date, so update it anyway" ;;
                    vulnerable)  bad "Grav ${ver} is affected by CVE-2026-116019 (fixed in 2.2.13): a page editor can run arbitrary public static methods"; inf "update now (bin/gpm selfupgrade), then run: $0 hunt"; rc=1 ;;
                    prerelease)  caution "Grav ${ver} is a pre-release of 2.2.13, not the release, and Blueprint.php could not be read to confirm the fix. Update to 2.2.13 or later"; rc=1 ;;
                    *)           caution "cannot compare version '${ver}': check it against 2.2.13"; rc=1 ;;
                esac ;;
        esac
    done < <(find "${existing[@]}" -xdev -maxdepth 9 -path '*/system/defines.php' -type f 2>/dev/null | sort -u)
    step "Verdict"
    if [[ $found -eq 0 ]]; then info "No Grav site found under: ${existing[*]}"
    elif [[ $rc -eq 0 ]]; then info "No exposed Grav found (${found} checked)"
    else
        warn "Exposed or unverifiable Grav found. Update to 2.2.13 or later."
        inf "Exposure needs an account that can edit pages (or a form that accepts page frontmatter). Interim, ours and not vendor guidance: restrict who can edit pages and who has Admin access until you update"
        inf "Advisory: https://github.com/getgrav/grav/security/advisories/GHSA-47gg-mh38-9rr7"
    fi
    return "$rc"
}

# ---------- hunt -------------------------------------------------------------
hunt_site() {   # site root; returns 1 on a strong lead
    local root="$1" rc=0 f has_reloc has_call n_reloc=0 n_call=0 strong="" rl="" cl=""
    step "Hunting in ${root}"
    if [[ ! -d "$root/user/pages" ]]; then inf "no user/pages directory to search"; return 0; fi
    while IFS= read -r f; do
        [[ -n "$f" ]] || continue
        has_reloc=0; has_call=0
        grep -qE '(unset|replace)-name@' "$f" 2>/dev/null && has_reloc=1
        grep -qE '(Folder|Utils|Filesystem)(\\\\|\\)?[A-Za-z]*::[A-Za-z_]+' "$f" 2>/dev/null && has_call=1
        [[ $has_reloc -eq 1 ]] && { n_reloc=$((n_reloc+1)); rl+="${f}"$'\n'; }
        [[ $has_call -eq 1 ]] && { n_call=$((n_call+1)); cl+="${f}"$'\n'; }
        [[ $has_reloc -eq 1 && $has_call -eq 1 ]] && strong+="${f}"$'\n'
    done < <(find "$root/user/pages" -type f \( -name '*.md' -o -name '*.yaml' -o -name '*.yml' \) 2>/dev/null | head -n5000)
    if [[ -n "$strong" ]]; then
        bad "page(s) with a relocation merge action (unset-name@ or replace-name@) AND a static method call in the same file: a strong lead"
        grep -v '^$' <<<"$strong" | sed 's/^/        /' | head -n10; rc=1
    fi
    if [[ $n_reloc -gt 0 && -z "$strong" ]]; then
        caution "${n_reloc} page file(s) use a relocation merge action (unset-name@ or replace-name@), which pages do not normally need:"
        grep -v '^$' <<<"$rl" | sed 's/^/        /' | head -n10
    fi
    if [[ $n_call -gt 0 && -z "$strong" ]]; then
        caution "${n_call} page file(s) mention a static method call (Folder::, Utils::); on a documentation site this can be harmless. Review who wrote them:"
        grep -v '^$' <<<"$cl" | sed 's/^/        /' | head -n10
    fi
    [[ $n_reloc -eq 0 && $n_call -eq 0 ]] && ok "no page frontmatter uses a relocation merge action or a static method call"
    return "$rc"
}

cmd_hunt() {
    local rc=0 site
    cmd_check "$@" || rc=1
    for site in "${SITES[@]:-}"; do
        [[ -n "$site" ]] || continue
        hunt_site "$site" || rc=1
    done
    step "Verdict"
    if [[ $rc -eq 0 ]]; then info "No exposed site and no strong lead found. This is not proof that no page was edited maliciously."
    else
        warn "An exposed site or a strong lead was found."
        inf "Review recent edits to pages and Flex form overrides, check for deleted directories and changed files outside the page tree, and review who can edit pages."
    fi
    return "$rc"
}

# ---------- dispatch ---------------------------------------------------------
main() {
    CMD="${1:-check}"; [[ $# -gt 0 ]] && shift
    case "$CMD" in -V|--version|version) echo "${SCRIPT_NAME} ${SCRIPT_VERSION} (${SCRIPT_DATE})"; exit 0 ;; esac
    case "$CMD" in -h|--help|help) print_help; exit 0 ;; esac
    echo "${SCRIPT_NAME} ${SCRIPT_VERSION} (${SCRIPT_DATE}) - ${CMD} on $(hostname 2>/dev/null || echo '?') at $(date -u +%FT%TZ)"
    echo "CVE-2026-116019; fixed in Grav 2.2.13"
    case "$CMD" in
        check|hunt) "cmd_${CMD}" "$@" ;;
        *) die "Unknown command: ${CMD} (check|hunt|version)" ;;
    esac
}
main "$@"; exit

# Assisted-by: Claude Sonnet 5.5
