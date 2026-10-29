#!/usr/bin/env bash
# SPDX-License-Identifier: CC0-1.0
# =============================================================================
# Storybook dev server code injection from the local network: read-only checker  (v1)
# CVE-2026-114126 (GHSA-px85-f4q5-jh77)
#
# If this software is helpful, consider a donation to our 501c3 nonprofit:
# https://privacysafe.foundation
#
# The Storybook dev server exposes its WebSocket authentication token to any client
# that can load its HTML pages. Any host on the same network can open the Storybook
# by IP address, obtain the token, and call the WebSocket-backed file-writing and
# testing features. Weak validation of the "write story" feature lets that code land
# in story files. If the Storybook Vitest addon is installed with an old version of
# Vitest, the payload can use Vitest's API to write more files or run commands, which
# can end in code execution with the developer's privileges. CVSS 8.7.
#
#   Affected: storybook 8.0.0 up to 8.6.19, 9.0.0 up to 9.1.21, 10.0.0 up to 10.6.2,
#             and 11.0.0-alpha.0 up to 11.0.0-alpha.6
#   Fixed:    8.6.19, 9.1.21, 10.6.2, 11.0.0-alpha.6 (all exist on the npm registry)
#             The fixed releases also bind the dev server to 127.0.0.1 by default.
#   If you cannot upgrade: do not run an affected dev server (the vendor's advice).
#
# Affected versions listen on ALL network interfaces by default, so simply running
# "storybook dev" on a shared network is the exposure. A Storybook that is built and
# served as static files has no dev server and is not reachable this way.
#
# A second Storybook advisory (a malicious website interacting with the preview of a
# running dev server) is fixed by the same releases; it is not counted separately here.
#
# This script is read-only. It finds the storybook package in package-lock.json,
# npm-shrinkwrap.json, yarn.lock, pnpm-lock.yaml, bun.lock and installed
# node_modules, notes whether the Vitest addon is present and whether a project's
# scripts bind the dev server to a host, and checks whether a Storybook dev server is
# running right now and listening beyond loopback.
#
# Usage:
#   ./storybook-check.sh [command] [DIR ...]
#
#   check (default)  scan DIR (default /var/www /srv /opt /home). Exit 0 = nothing
#                    exposed, 1 = an affected version while a dev server is running
#                    beyond loopback or started with --host.
#   version          print the script version.
# Containers: with no directory argument the check also reads the project files it needs from
# running docker and podman containers (SCAN_CONTAINERS=1, the default; 0 skips them), through a
# read-only probe, and judges them like host projects. The copies are temporary: a path shown as
# .../docker_NAME/PATH is the PATH inside the container NAME.
# =============================================================================

# Commands run as "cmd_${CMD}", which shellcheck can't follow
# shellcheck disable=SC2317,SC2329,SC2034
set -uo pipefail

SCRIPT_NAME="storybook-check.sh"
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
# prints: vulnerable | fixed | notaffected | unknown
sb_status() {
    local raw="${1#v}" maj min pat pre n
    [[ "$raw" =~ ^([0-9]+)\.([0-9]+)\.([0-9]+)(-([0-9A-Za-z.]+))?$ ]] || { echo unknown; return; }
    maj="${BASH_REMATCH[1]}"; min="${BASH_REMATCH[2]}"; pat="${BASH_REMATCH[3]}"; pre="${BASH_REMATCH[5]:-}"
    (( maj < 8 )) && { echo notaffected; return; }
    # a pre-release of a fixed release (8.6.19-rc.1) comes BEFORE it, so it does not have the fix
    if [[ -n "$pre" ]] && { (( maj == 8 && min == 6 && pat == 19 )) || (( maj == 9 && min == 1 && pat == 21 )) || (( maj == 10 && min == 6 && pat == 2 )); }; then echo vulnerable; return; fi
    (( maj == 8 )) && { (( min < 6 || (min == 6 && pat < 19) )) && echo vulnerable || echo fixed; return; }
    (( maj == 9 )) && { (( min < 1 || (min == 1 && pat < 21) )) && echo vulnerable || echo fixed; return; }
    (( maj == 10 )) && { (( min < 6 || (min == 6 && pat < 2) )) && echo vulnerable || echo fixed; return; }
    if (( maj == 11 )) && (( min == 0 )) && (( pat == 0 )) && [[ "$pre" == alpha.* ]]; then
        n="${pre#alpha.}"; [[ "$n" =~ ^[0-9]+$ ]] || { echo unknown; return; }
        (( n < 6 )) && echo vulnerable || echo fixed; return
    fi
    echo fixed
}

# ---------- lock file parsers (each prints every storybook version found) -----
versions_npm_lock() {
    awk '
        /node_modules\/storybook": *\{/ {f=1; next}
        /^    "storybook": *\{/ {f=1; next}
        f && /"version":/ { v=$2; gsub(/[",]/,"",v); print v; f=0 }
    ' "$1" | sort -u
}
versions_yarn_lock() {
    awk '
        /^"?storybook@/ {f=1; next}
        f && /^[[:space:]]+version:?[[:space:]]/ { v=$2; gsub(/"/,"",v); print v; f=0 }
        /^[^ #]/ && !/^"?storybook@/ {f=0}
    ' "$1" | sort -u
}
versions_at_lock() {   # pnpm-lock.yaml and bun.lock; the boundary stops eslint-plugin-storybook and @storybook/* matching
    grep -oE '(^|[^A-Za-z0-9_@.-])storybook@[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.]+)?' "$1" 2>/dev/null | sed -E 's/.*storybook@//' | sort -u
}
version_installed() {
    grep -q '"name"[[:space:]]*:[[:space:]]*"storybook"' "$1" 2>/dev/null || return 0
    grep -oE '"version"[[:space:]]*:[[:space:]]*"[^"]+"' "$1" | head -n1 | sed -E 's/.*:[[:space:]]*"([^"]+)"/\1/'
}

# ---------- runtime: is a dev server running, and where is it listening? -----
DEV_RUNNING=0; DEV_EXPOSED=0; DEV_NOTES=""
probe_dev_server() {
    DEV_RUNNING=0; DEV_EXPOSED=0; DEV_NOTES=""
    local procs port line addr
    have ps || return 0
    procs="$(ps -eo args= 2>/dev/null | grep -E 'storybook([[:space:]/]|.*)dev|start-storybook|storybook/(bin|dist)/' | grep -v grep)"
    [[ -n "$procs" ]] && DEV_RUNNING=1
    # the default port is 6006; also take a -p/--port from the process arguments
    port="$(grep -oE -- '(-p|--port)[ =][0-9]+' <<<"$procs" | head -n1 | grep -oE '[0-9]+')"
    port="${port:-6006}"
    if have ss; then
        while read -r line; do
            addr="$(awk '{print $4}' <<<"$line")"
            [[ "$addr" == *":${port}" ]] || continue
            DEV_RUNNING=1
            case "$addr" in
                127.0.0.1:*|"[::1]:"*|localhost:*) DEV_NOTES+="  listening on ${addr} (loopback only)"$'\n' ;;
                *) DEV_EXPOSED=1; DEV_NOTES+="  listening on ${addr} (reachable from the network)"$'\n' ;;
            esac
        done < <(ss -H -ltn 2>/dev/null)
    else
        DEV_NOTES+="  ss is not available: the listening address could not be checked"$'\n'
    fi
    return 0
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

STORYBOOK_PROBE="$(cat <<'EOS'
R="/var/www /srv /opt /home"
slice() {
  d=$1
  for f in package.json package-lock.json npm-shrinkwrap.json yarn.lock pnpm-lock.yaml bun.lock node_modules/storybook/package.json; do
    [ -f "$d/$f" ] && echo "F $d/$f"
  done
}
{ find $R -maxdepth 8 \( -name node_modules -o -name .git \) -prune -o \( -name package-lock.json -o -name npm-shrinkwrap.json -o -name yarn.lock -o -name pnpm-lock.yaml -o -name bun.lock \) -type f -print 2>/dev/null | sed "s#/[^/]*\$##"
  find $R -maxdepth 9 -path "*/node_modules/storybook/package.json" -type f 2>/dev/null | sed "s#/node_modules/storybook/package.json\$##"
} | sort -u | head -n 30 | while read -r d; do slice "$d"; done
exit 0
EOS
)"

cmd_check() {
    # running containers: stage once, here in the main shell, then pass the staged directories on
    # as ordinary directory arguments
    if [[ $# -eq 0 ]]; then
        stage_probe "$STORYBOOK_PROBE"
        if [[ ${#STAGED_DIRS[@]} -gt 0 ]]; then
            local _d; local -a _a=()
            for _d in /var/www /srv /opt /home; do [[ -d "$_d" ]] && _a+=("$_d"); done
            set -- ${_a[@]:+"${_a[@]}"} "${STAGED_DIRS[@]}"
        fi
    fi
    local -a dirs=() existing=() hits=()
    local rc=0 found=0 d f base proj ver kind st line script
    if [[ $# -gt 0 ]]; then dirs=("$@"); else dirs=(/var/www /srv /opt /home); fi
    for d in "${dirs[@]}"; do [[ -d "$d" ]] && existing+=("$d"); done
    step "Looking for Storybook"
    if [[ ${#existing[@]} -eq 0 ]]; then info "None of the search directories exist"; return 0; fi
    probe_dev_server
    if [[ $DEV_RUNNING -eq 1 ]]; then
        inf "a Storybook dev server is running on this host"
        [[ -n "$DEV_NOTES" ]] && grep -v '^$' <<<"$DEV_NOTES" | sed 's/^/        /'
    else
        inf "no running Storybook dev server was seen"
    fi
    declare -A seen=()
    while IFS= read -r f; do
        [[ -n "$f" ]] || continue
        base="$(basename "$f")"
        case "$base" in
            package.json) proj="$(dirname "$(dirname "$(dirname "$f")")")" ; kind=installed ;;
            package-lock.json|npm-shrinkwrap.json) proj="$(dirname "$f")"; kind=npm ;;
            yarn.lock) proj="$(dirname "$f")"; kind=yarn ;;
            pnpm-lock.yaml|bun.lock) proj="$(dirname "$f")"; kind=atlock ;;
            *) continue ;;
        esac
        local -a vers=()
        case "$kind" in
            npm) mapfile -t vers < <(versions_npm_lock "$f") ;;
            yarn) mapfile -t vers < <(versions_yarn_lock "$f") ;;
            atlock) mapfile -t vers < <(versions_at_lock "$f") ;;
            installed) mapfile -t vers < <(version_installed "$f") ;;
        esac
        for ver in "${vers[@]:-}"; do [[ -n "$ver" ]] && hits+=("${proj}"$'\t'"${ver}"$'\t'"${base}"); done
    done < <(find "${existing[@]}" -xdev -maxdepth 8 \( -name node_modules -prune \) -o \
                \( -name package-lock.json -o -name npm-shrinkwrap.json -o -name yarn.lock -o -name pnpm-lock.yaml -o -name bun.lock \) -type f -print 2>/dev/null
             find "${existing[@]}" -xdev -maxdepth 9 -path '*/node_modules/storybook/package.json' -type f -print 2>/dev/null)
    for line in "${hits[@]:-}"; do
        [[ -n "$line" ]] || continue
        IFS=$'\t' read -r proj ver base <<<"$line"
        [[ -n "${seen[${proj}|${ver}]:-}" ]] && continue
        seen["${proj}|${ver}"]=1
        found=$((found+1))
        step "storybook ${ver} in ${proj} (from ${base})"
        st="$(sb_status "$ver")"
        case "$st" in
            fixed)       ok "${ver} has the fix (8.6.19, 9.1.21, 10.6.2 or 11.0.0-alpha.6 or newer), and binds the dev server to 127.0.0.1 by default"; continue ;;
            notaffected) ok "${ver} is older than 8.0.0, outside the advisory's range (7.x and earlier are unsupported: update anyway)"; continue ;;
            unknown)     caution "cannot compare version '${ver}': check it against 8.6.19, 9.1.21, 10.6.2 and 11.0.0-alpha.6"; rc=1; continue ;;
            vulnerable)  bad "storybook ${ver} is affected by CVE-2026-114126 (fixed in 8.6.19, 9.1.21, 10.6.2, 11.0.0-alpha.6)" ;;
        esac
        if [[ -r "$proj/package.json" ]] && grep -q '@storybook/addon-vitest' "$proj/package.json"; then
            caution "the Vitest addon (@storybook/addon-vitest) is installed: with an old Vitest the payload can run commands, not just write story files"
        fi
        script="$(grep -oE '"[A-Za-z:_-]*"[[:space:]]*:[[:space:]]*"[^"]*storybook[[:space:]]+dev[^"]*"' "$proj/package.json" 2>/dev/null | head -n3)"
        if [[ -n "$script" ]] && grep -qE -- '(--host|-h)[ =]+(0\.0\.0\.0|::|[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+)' <<<"$script" && ! grep -qE -- '(--host|-h)[ =]+(127\.0\.0\.1|localhost)' <<<"$script"; then
            bad "a package.json script starts the dev server with an explicit non-loopback --host: it is reachable from the network"
            rc=1
        fi
    done
    step "Verdict"
    if [[ $found -eq 0 ]]; then
        info "No storybook found under: ${existing[*]}"
        return 0
    fi
    # an affected version plus a dev server listening beyond loopback right now is the exposure
    local any_vuln=0
    for line in "${hits[@]:-}"; do
        [[ -n "$line" ]] || continue
        IFS=$'\t' read -r proj ver base <<<"$line"
        [[ "$(sb_status "$ver")" == vulnerable ]] && any_vuln=1
    done
    if [[ $any_vuln -eq 1 && $DEV_EXPOSED -eq 1 ]]; then
        bad "an affected Storybook is installed AND a Storybook dev server is listening beyond loopback right now"
        rc=1
    elif [[ $any_vuln -eq 1 && $rc -eq 0 ]]; then
        caution "an affected Storybook is installed, but no dev server is running beyond loopback right now. Affected versions listen on ALL interfaces whenever 'storybook dev' runs, so update before the next run."
    fi
    if [[ $rc -eq 0 ]]; then
        info "No exposed Storybook found (${found} checked)."
    else
        warn "Exposed Storybook found. Upgrade to 8.6.19, 9.1.21, 10.6.2 or 11.0.0-alpha.6 (or newer)."
        inf "If you cannot upgrade, do not run an affected dev server (the vendor's advice). Stop it, or run it only on a network you fully trust."
        inf "Treat any story file you did not write as suspect: this flaw writes code into story files. Review recent changes in version control."
        inf "Advisory: https://github.com/storybookjs/storybook/security/advisories/GHSA-px85-f4q5-jh77"
    fi
    return "$rc"
}

# ---------- dispatch ---------------------------------------------------------
main() {
    CMD="${1:-check}"; [[ $# -gt 0 ]] && shift
    case "$CMD" in -V|--version|version) echo "${SCRIPT_NAME} ${SCRIPT_VERSION} (${SCRIPT_DATE})"; exit 0 ;; esac
    case "$CMD" in -h|--help|help) print_help; exit 0 ;; esac
    echo "${SCRIPT_NAME} ${SCRIPT_VERSION} (${SCRIPT_DATE}) - ${CMD} on $(hostname 2>/dev/null || echo '?') at $(date -u +%FT%TZ)"
    echo "CVE-2026-114126; fixed in storybook 8.6.19, 9.1.21, 10.6.2 and 11.0.0-alpha.6"
    case "$CMD" in
        check) cmd_check "$@" ;;
        *) die "Unknown command: ${CMD} (check|version)" ;;
    esac
}
main "$@"; exit

# Assisted-by: Claude Sonnet 5.5
