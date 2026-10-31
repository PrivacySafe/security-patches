#!/usr/bin/env bash
# SPDX-License-Identifier: CC0-1.0
# =============================================================================
# Next.js Server Actions denial of service: read-only checker  (v1)
# CVE-2026-94482
#
# If this software is helpful, consider a donation to our 501c3 nonprofit:
# https://privacysafe.foundation
#
# Crafted requests aimed at a Next.js App Router application that has at least
# one Server Action can cause excessive CPU consumption and block the processing
# of further requests in the same Node.js process. CVSS 8.2 (v4.0), 7.5 (v3).
# No authentication is needed.
#
#   Affected: next 13.0.0 up to 15.5.28, and 16.0.0 up to 16.4.1
#   Fixed:    15.5.28 and 16.4.1
#   Not affected: Pages Router applications, and App Router applications that
#   have no Server Action.
#
# Next.js 13.x and 14.x apps move to 15.5.28 or later.
#
# This script is read-only. It reads the Next.js version from package-lock.json,
# npm-shrinkwrap.json, yarn.lock, pnpm-lock.yaml and from installed
# node_modules/next copies, then checks the project for the App Router and for
# Server Actions ("use server" directives, or a populated
# .next/server/server-reference-manifest.json for built-only deployments).
#
# Usage:
#   ./nextjs-server-actions-check.sh [command] [DIR ...]
#
#   check (default)  scan DIR (default /var/www /srv /opt /home).
#                    Exit 0 = nothing exposed, 1 = an affected project with
#                    Server Actions was found.
#   version          print the script version.
# Containers: with no directory argument the check also reads the project files it needs from
# running docker and podman containers (SCAN_CONTAINERS=1, the default; 0 skips them), through a
# read-only probe, and judges them like host projects. The copies are temporary: a path shown as
# .../docker_NAME/PATH is the PATH inside the container NAME.
# =============================================================================

# Commands run as "cmd_${CMD}", which shellcheck can't follow
# shellcheck disable=SC2317,SC2329,SC2034
set -uo pipefail

SCRIPT_NAME="nextjs-server-actions-check.sh"
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

# ---------- version rule -----------------------------------------------------
# affected: 13.0.0 up to 15.5.28, and 16.0.0 up to 16.4.1
next_affected() {
    local v; v="$(norm_ver "$1")"
    is_semver "$v" || return 1
    ver_lt "$v" "13.0.0" && return 1
    if (( ${v%%.*} >= 16 )); then ver_lt "$v" "16.4.1"; else ver_lt "$v" "15.5.28"; fi
}

# ---------- lock file parsers (each prints every Next.js version it finds) ---
versions_npm_lock() {
    awk '
        /node_modules\/next": *\{/ {f=1; next}
        /^    "next": *\{/ {f=1; next}
        f && /"version":/ { v=$2; gsub(/[",]/,"",v); print v; f=0 }
    ' "$1" | sort -u
}
versions_yarn_lock() {
    awk '
        /^"?next@/ {f=1; next}
        f && /^[[:space:]]+version:?[[:space:]]/ { v=$2; gsub(/"/,"",v); print v; f=0 }
        /^[^ #]/ && !/^"?next@/ {f=0}
    ' "$1" | sort -u
}
versions_pnpm_lock() {
    grep -oE "^[[:space:]]+'?/?next@[0-9]+\.[0-9]+\.[0-9]+[^:(' ]*" "$1" 2>/dev/null \
        | sed -E "s/.*next@//" | sort -u
}
version_installed() {   # node_modules/next/package.json
    grep -q '"name": *"next"' "$1" 2>/dev/null || return 0
    sed -n 's/^[[:space:]]*"version":[[:space:]]*"\([^"]*\)".*/\1/p' "$1" | head -n1
}

declare -A ACT_CACHE=()
ACT_EVIDENCE=""
server_actions_present() {   # project dir -> 0 if the App Router and a Server Action are present
    local dir="$1" manifest f app=0
    if [[ -n "${ACT_CACHE[$dir]:-}" ]]; then
        [[ "${ACT_CACHE[$dir]}" == yes* ]] && { ACT_EVIDENCE="${ACT_CACHE[$dir]#yes }"; return 0; }
        return 1
    fi
    [[ -d "$dir/app" || -d "$dir/src/app" ]] && app=1
    manifest="$dir/.next/server/server-reference-manifest.json"
    if [[ -r "$manifest" ]] && ! { grep -q '"node": *{}' "$manifest" && grep -q '"edge": *{}' "$manifest"; }; then
        ACT_CACHE[$dir]="yes built manifest lists server actions"
        ACT_EVIDENCE="built manifest lists server actions"; return 0
    fi
    if [[ $app -eq 1 ]]; then
        f="$(grep -rlE "^[[:space:]]*['\"]use server['\"]" \
              --include='*.ts' --include='*.tsx' --include='*.js' --include='*.jsx' --include='*.mjs' \
              --exclude-dir=node_modules --exclude-dir=.next --exclude-dir=.git "$dir" 2>/dev/null | head -n2 | tr '\n' ' ')"
        f="${f% }"
        if [[ -n "$f" ]]; then
            ACT_CACHE[$dir]="yes 'use server' in ${f}"
            ACT_EVIDENCE="'use server' in ${f}"; return 0
        fi
        ACT_CACHE[$dir]="no App Router without any 'use server' directive"
    else
        ACT_CACHE[$dir]="no no app/ directory (Pages Router)"
    fi
    return 1
}

# ---------- check ------------------------------------------------------------
# ---------- running containers -----------------------------------------------
# A project inside a container is not on the host. For each running container, a small read-only
# probe (find, grep, test; nothing is modified or started) lists what this check needs, and those
# are copied into a private temporary directory (mode 0700, removed on exit) that the normal
# checks then judge like a host directory. Each probe line is one of:
#   F <path>          copy this file
#   D <path>          create this directory (its existence is what the check looks at)
#   E <path>          create an empty file (only its name matters, no content leaves the container)
#   L <path> <text>   write one short sanitized line of text (used so .env itself is never copied)
# Paths the container reports are validated before use, a symlink is never kept (docker cp copies the
# link itself, and the check would then read whatever it points to on the host), and the number of
# copied files is capped. It runs once, in the main shell (a subshell's exit would delete the copies).
STAGE=""
declare -a STAGED_DIRS=()
stage_probe() {   # <probe script, run with sh -s inside each running container>
    local probe="$1" rt id name out kind p rest s nf
    [[ "${SCAN_CONTAINERS:-1}" == 1 ]] || return 0
    for rt in docker podman; do
        command -v "$rt" >/dev/null 2>&1 || continue
        while read -r id name; do
            [[ -n "$id" ]] || continue
            out="$(printf '%s\n' "$probe" | "$rt" exec -i "$id" sh -s 2>/dev/null | head -n 6000)" || continue
            [[ -n "$out" ]] || continue
            s=""; nf=0
            while read -r kind p rest; do
                [[ "$p" =~ ^/[]A-Za-z0-9._/@+[-]+$ && "$p" != */../* && "$p" != */.. ]] || continue   # no ".." path component
                if [[ -z "$s" ]]; then
                    if [[ -z "$STAGE" ]]; then STAGE="$(mktemp -d)" || return 0; trap 'rm -rf "${STAGE:-}"' EXIT; fi
                    s="$STAGE/${rt}_${name:-$id}"; mkdir -p "$s"
                fi
                case "$kind" in
                    F) nf=$((nf + 1)); [[ $nf -le 400 ]] || continue
                       mkdir -p "$s$(dirname "$p")"
                       "$rt" cp "${id}:${p}" "$s$p" >/dev/null 2>&1 || rm -f "$s$p"
                       [[ -L "$s$p" ]] && rm -f "$s$p" ;;
                    D) mkdir -p "$s$p" ;;
                    E) mkdir -p "$s$(dirname "$p")"; : > "$s$p" ;;
                    L) [[ "$rest" =~ ^[A-Za-z0-9_=.,:/@-]{0,120}$ ]] || continue
                       mkdir -p "$s$(dirname "$p")"; printf '%s\n' "$rest" > "$s$p" ;;
                esac
            done <<<"$out"
            [[ -z "$s" ]] || STAGED_DIRS+=("$s")
        done < <("$rt" ps --format '{{.ID}} {{.Names}}' 2>/dev/null)
    done
}

NEXT_PROBE="$(cat <<'EOS'
R="/var/www /srv /opt /home"
find $R -maxdepth 7 \( -name node_modules -o -name .next -o -name .git \) -prune -o \( -name package-lock.json -o -name npm-shrinkwrap.json -o -name yarn.lock -o -name pnpm-lock.yaml \) -type f -print 2>/dev/null | head -n 30 | while read -r l; do
  d=${l%/*}
  echo "F $l"
  [ -f "$d/.next/server/server-reference-manifest.json" ] && echo "F $d/.next/server/server-reference-manifest.json"
  [ -d "$d/app" ] && echo "D $d/app"
  [ -d "$d/src/app" ] && echo "D $d/src/app"
  find "$d" \( -name node_modules -o -name .next -o -name .git \) -prune -o -type f \( -name "*.ts" -o -name "*.tsx" -o -name "*.js" -o -name "*.jsx" -o -name "*.mjs" \) -print 2>/dev/null | head -n 5000 | xargs -r grep -lE "^[[:space:]]*['\"]use server['\"]" 2>/dev/null | head -n 5 | while read -r f; do echo "F $f"; done
done
find $R -maxdepth 9 -path "*/node_modules/next/package.json" -type f 2>/dev/null | head -n 30 | while read -r l; do echo "F $l"; done
exit 0
EOS
)"

cmd_check() {
    # running containers: stage once, here in the main shell, then pass the staged directories on
    # as ordinary directory arguments
    if [[ $# -eq 0 ]]; then
        stage_probe "$NEXT_PROBE"
        if [[ ${#STAGED_DIRS[@]} -gt 0 ]]; then
            local _d; local -a _a=()
            for _d in /var/www /srv /opt /home; do [[ -d "$_d" ]] && _a+=("$_d"); done
            set -- ${_a[@]:+"${_a[@]}"} "${STAGED_DIRS[@]}"
        fi
    fi
    local -a dirs=() existing=()
    local rc=0 found=0 d f v dir kind
    if [[ $# -gt 0 ]]; then dirs=("$@"); else dirs=(/var/www /srv /opt /home); fi
    for d in "${dirs[@]}"; do [[ -d "$d" ]] && existing+=("$d"); done
    step "Looking for Next.js"
    if [[ ${#existing[@]} -eq 0 ]]; then info "None of the search directories exist"; return 0; fi

    local -a hits=()   # "project|source|version"
    while IFS= read -r f; do
        [[ -n "$f" ]] || continue
        dir="$(dirname "$f")"
        case "$(basename "$f")" in
            package-lock.json|npm-shrinkwrap.json) kind=npm ;;
            yarn.lock) kind=yarn ;;
            pnpm-lock.yaml) kind=pnpm ;;
            *) continue ;;
        esac
        while IFS= read -r v; do [[ -n "$v" ]] && hits+=("${dir}|${f}|${v}"); done < <("versions_${kind}_lock" "$f")
    done < <(find "${existing[@]}" -maxdepth 7 \( -name node_modules -o -name .next -o -name .git \) -prune \
                -o \( -name package-lock.json -o -name npm-shrinkwrap.json -o -name yarn.lock -o -name pnpm-lock.yaml \) -type f -print 2>/dev/null | sort -u)
    while IFS= read -r f; do
        [[ -n "$f" ]] || continue
        v="$(version_installed "$f")"
        [[ -n "$v" ]] || continue
        dir="${f%/node_modules/next/package.json}"
        hits+=("${dir}|${f}|${v}")
    done < <(find "${existing[@]}" -maxdepth 9 -name .git -prune -o -path '*/node_modules/next/package.json' -type f -print 2>/dev/null | sort -u)

    local h seen=""
    for h in "${hits[@]:-}"; do
        [[ -n "$h" ]] || continue
        IFS='|' read -r dir f v <<<"$h"
        [[ "$seen" == *"|${dir}|${v}|"* ]] && continue
        seen+="|${dir}|${v}|"
        found=$((found+1))
        step "next ${v} in ${dir}"
        inf "source: ${f}"
        if ! is_semver "$v"; then caution "cannot parse version '${v}'"; continue; fi
        if ! next_affected "$v"; then
            if ver_lt "$v" "13.0.0"; then ok "next ${v} is older than 13.0.0 and outside the affected range of CVE-2026-94482"
            else ok "next ${v} has the fix (15.5.28+ on 15.x, 16.4.1+ on 16.x)"; fi
            continue
        fi
        bad "next ${v} is affected by CVE-2026-94482"
        [[ "${v%%.*}" -le 14 ]] && inf "13.x and 14.x move to 15.5.28 or later"
        if server_actions_present "$dir"; then
            bad "this project uses Server Actions (${ACT_EVIDENCE}): exposed"
            rc=1
        else
            caution "no Server Action found (${ACT_CACHE[$dir]#no }): not exposed by the advisory's definition, but source checks can miss built-only apps"
        fi
    done

    step "Verdict"
    if [[ $found -eq 0 ]]; then
        info "No Next.js found under: ${existing[*]}"
    elif [[ $rc -eq 0 ]]; then
        info "No exposed Next.js project found (${found} version checked)"
    else
        warn "Exposed Next.js found. Upgrade: npm install next@15.5.28  (or next@16.4.1 or later), rebuild and restart."
        inf "Reduce exposure meanwhile at the reverse proxy: rate limit requests that carry a Next-Action header. This slows abuse, it does not fix the bug."
        inf "Advisory: GHSA-p3m5-59mp-jv5r"
    fi
    return "$rc"
}

# ---------- dispatch ---------------------------------------------------------
main() {
    CMD="${1:-check}"; [[ $# -gt 0 ]] && shift
    case "$CMD" in -V|--version|version) echo "${SCRIPT_NAME} ${SCRIPT_VERSION} (${SCRIPT_DATE})"; exit 0 ;; esac
    case "$CMD" in -h|--help|help) print_help; exit 0 ;; esac
    echo "${SCRIPT_NAME} ${SCRIPT_VERSION} (${SCRIPT_DATE}) - ${CMD} on $(hostname 2>/dev/null || echo '?') at $(date -u +%FT%TZ)"
    echo "CVE-2026-94482; fixed in Next.js 15.5.28 and 16.4.1"
    case "$CMD" in
        check) cmd_check "$@" ;;
        *) die "Unknown command: ${CMD} (check|version)" ;;
    esac
}
main "$@"; exit

# Assisted-by: Claude Sonnet 5.5
