#!/usr/bin/env bash
# SPDX-License-Identifier: CC0-1.0
# =============================================================================
# libexpat billion laughs detection delay: read-only checker  (v1)
# CVE-2026-115506
#
# If this software is helpful, consider a donation to our 501c3 nonprofit:
# https://privacysafe.foundation
#
# libexpat is the XML parser inside Python (pyexpat), Apache httpd, many PHP and
# Perl builds, Subversion, Mercurial, D-Bus, fontconfig, Firefox and a very long
# list of other programs. Its protection against "billion laughs" entity
# amplification works by tracking how much a parse expands. In
# accountingDiffTolerated() in xmlparse.c that check detects the amplification
# too late, so a moderately sized crafted XML document can still make the parser
# consume a large amount of CPU and memory before the protection stops it. The
# result is denial of service. Rated High (CVSS 7.5 v3; the CVE list shows 8.7 on
# the v4 scale). No authentication is needed wherever a service parses XML from
# an untrusted source. Reported through Google; the upstream issue is #1160.
#
#   Affected: libexpat through 2.9.0, that is every release so far
#   Fix:      merged upstream on 23 October 2026 (pull request #1433) and
#             milestoned for Expat 2.9.1
#
# As of 27 October 2026 no Expat release contains the fix. The script reports
# every copy at 2.9.0 or older as affected and treats 2.9.1 or newer as fixed,
# because upstream attached the fix to the 2.9.1 milestone. Distribution
# packages usually backport fixes without changing the version, which the
# script checks for.
#
# This script is read-only. It finds libexpat shared libraries, reads the version
# string compiled into each, asks installed Python interpreters for
# pyexpat.EXPAT_VERSION, lists running processes that have libexpat mapped
# (and flags those still running a replaced copy), and can scan directories for
# programs that carry their own copy.
#
# Usage:
#   ./expat-check.sh [command] [DIR ...]
#
#   check (default)  system libraries, Python interpreters and running processes.
#                    Exit 0 = every copy found is fixed, 1 = an affected copy found.
#   deep [DIR ...]   also scan DIR (default /usr/local /opt /srv /var/www /home)
#                    for executables and libraries that embed their own expat,
#                    such as vendored or statically linked copies.
#   version          print the script version.
#
# EXPAT_LIB_DIRS (space separated) replaces the default library search directories.
# EXPAT_PY_DIRS (space separated) replaces the directories searched for Python interpreters.
# Containers: with no argument the check also looks in running docker and podman containers
# (SCAN_CONTAINERS=1, the default; 0 skips them). A read-only probe captures the daemon's version
# output and its configuration (secrets are redacted inside the container before anything is
# copied) into a private temporary directory, and this script then runs once per container, in
# isolation, against that copy. Paths shown as .../docker_NAME/... are inside the container NAME.
# =============================================================================

# Commands run as "cmd_${CMD}", which shellcheck can't follow
# shellcheck disable=SC2317,SC2329,SC2034
set -uo pipefail

SCRIPT_NAME="expat-check.sh"
SCRIPT_VERSION="1.0.0"
SCRIPT_DATE="2026-10-28"
SELF="$0"
FIXED_VERSION="2.9.1"

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
expat_affected() { ver_lt "$1" "$FIXED_VERSION"; }

lib_version() {   # file -> version compiled into XML_ExpatVersion(), or nothing
    grep -a -o -m1 'expat_[0-9]\+\.[0-9]\+\.[0-9]\+' "$1" 2>/dev/null | head -n1 | sed 's/^expat_//'
}

AFFECTED=0; CHECKED=0
report() {   # label version [file for the distribution check]
    local label="$1" ver="$2" probe="${3:-}"
    CHECKED=$((CHECKED+1))
    if ! is_semver "$ver"; then caution "${label}: cannot parse version '${ver}'"; return 0; fi
    if ! expat_affected "$ver"; then
        ok "${label}: expat ${ver} is ${FIXED_VERSION} or newer"; return 0
    fi
    if [[ -n "$probe" ]]; then
        if distro_mentions "$probe" CVE-2026-115506; then
            ok "${label}: expat ${ver}, and package ${DISTRO_PKG} changelog mentions ${DISTRO_HIT}: a backported fix is likely"
            return 0
        elif [[ $? -eq 1 ]]; then
            bad "${label}: expat ${ver} is affected; package ${DISTRO_PKG} does not mention the CVE yet"
            AFFECTED=$((AFFECTED+1)); return 0
        fi
    fi
    bad "${label}: expat ${ver} is affected (2.9.0 and older)"
    AFFECTED=$((AFFECTED+1))
    return 0
}

list_libs() {   # prints resolved, de-duplicated libexpat files
    local d
    # EXPAT_LIB_DIRS overrides the search directories (for testing or unusual layouts)
    for d in ${EXPAT_LIB_DIRS:-/lib /lib64 /usr/lib /usr/lib64 /usr/local/lib /usr/local/lib64 /opt}; do
        [[ -d "$d" ]] && find "$d" -maxdepth 6 \( -name 'libexpat.so*' -o -name 'libexpatw.so*' -o -name 'libexpat-*.so*' \) \( -type f -o -type l \) 2>/dev/null
    done | while read -r f; do readlink -f "$f"; done | sort -u
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
#   L <path> <text>   write one short sanitized line of text
#   B <path> <base64> write a decoded blob (size-capped): captured command output, or a configuration
#                     file with its secrets already redacted INSIDE the container
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
                [[ "$p" =~ ^/[]A-Za-z0-9._/@+[-]+$ && "$p" != *..* ]] || continue
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
                    B) [[ ${#rest} -le 200000 && "$rest" != *[!A-Za-z0-9+/=]* ]] || continue
                       mkdir -p "$s$(dirname "$p")"
                       printf '%s' "$rest" | base64 -d > "$s$p" 2>/dev/null || rm -f "$s$p" ;;
                esac
            done <<<"$out"
            [[ -z "$s" ]] || STAGED_DIRS+=("$s")
        done < <("$rt" ps --format '{{.ID}} {{.Names}}' 2>/dev/null)
    done
}

EXPAT_PROBE="$(cat <<'EOS'
find /lib /lib64 /usr/lib /usr/lib64 /usr/local/lib /usr/local/lib64 /opt -maxdepth 6 \( -name "libexpat.so*" -o -name "libexpatw.so*" -o -name "libexpat-*.so*" \) -type f -size -4096k 2>/dev/null | head -n 20 | while read -r l; do echo "F $l"; done
for p in /usr/bin/python3 /usr/local/bin/python3 /usr/bin/python /usr/local/bin/python; do
  [ -x "$p" ] || continue
  v=$("$p" -c 'import pyexpat; print(pyexpat.EXPAT_VERSION)' 2>/dev/null | head -n 1)
  [ -n "$v" ] && echo "B /py/${p##*/} $(printf '%s\n' "$v" | base64 | tr -d '\n')"
done
exit 0
EOS
)"

container_run() {   # <staged directory> : libexpat in one container, judged by this script run in isolation
    local s="$1" out rc f v n
    [[ -d "$s/py" || -n "$(find "$s" -name 'libexpat*' -type f 2>/dev/null | head -n1)" ]] || return 0
    mkdir -p "$s/pyx"
    for f in "$s"/py/*; do
        [[ -f "$f" ]] || continue
        v="$(head -n1 "$f" | tr -cd 'A-Za-z0-9_.-')"; n="$(basename "$f")"
        [[ -n "$v" ]] && { printf '#!/bin/sh\necho "%s"\n' "$v" > "$s/pyx/$n"; chmod 755 "$s/pyx/$n"; }
    done
    step "libexpat in a container (${s##*/})"
    out="$(SCAN_CONTAINERS=0 EXPAT_NO_PROCS=1 EXPAT_PY_DIRS="$s/pyx" EXPAT_LIB_DIRS="$s/lib $s/lib64 $s/usr/lib $s/usr/lib64 $s/usr/local/lib $s/usr/local/lib64 $s/opt" bash "$SELF" check  2>&1)"; rc=$?
    tail -n +3 <<<"$out"
    return "$rc"
}

# shellcheck disable=SC2120
cmd_check() {
    local rc=0 crc=0 _s
    if [[ $# -eq 0 && "${SCAN_CONTAINERS:-1}" == 1 ]]; then
        stage_probe "$EXPAT_PROBE"
        for _s in ${STAGED_DIRS[@]:+"${STAGED_DIRS[@]}"}; do
            container_run "$_s" || crc=1
        done
    fi
    cmd_check_host "$@" || rc=$?
    if [[ $crc -eq 1 && $rc -eq 0 ]]; then rc=1; fi
    return "$rc"
}

cmd_check_host() {
    local f v p out pid comm line stale n=0
    step "System libraries"
    while IFS= read -r f; do
        [[ -n "$f" && -f "$f" ]] || continue
        v="$(lib_version "$f")"
        [[ -n "$v" ]] || { inf "${f}: no version string found"; continue; }
        n=$((n+1))
        report "$f" "$v" "$f"
    done < <(list_libs)
    [[ $n -eq 0 ]] && inf "no libexpat shared library found in the standard library directories"

    step "Python interpreters (pyexpat)"
    local -a pys=()
    local d
    # EXPAT_PY_DIRS overrides where interpreters are looked for (default: PATH, /usr/bin, /usr/local/bin)
    for d in ${EXPAT_PY_DIRS:-$(echo "$PATH" | tr ':' ' ') /usr/bin /usr/local/bin}; do
        shopt -s nullglob
        for p in "$d"/python3 "$d"/python3.[0-9]* "$d"/python; do
            # interpreters only: python, python3, python3.12 (not python3.12-config and friends)
            [[ "$(basename "$p")" =~ ^python3?(\.[0-9]+)?$ && -x "$p" && ! -d "$p" ]] || continue
            [[ "$(basename "$(readlink -f "$p")")" =~ ^python[0-9.]*$ ]] && pys+=("$(readlink -f "$p")")
        done
        shopt -u nullglob
    done
    local seen="" any=0
    for p in "${pys[@]:-}"; do
        [[ -n "$p" && "$seen" != *"|${p}|"* ]] || continue
        seen+="|${p}|"
        v="$(timeout 10 "$p" -c 'import pyexpat; print(pyexpat.EXPAT_VERSION)' 2>/dev/null | sed 's/^expat_//')"
        [[ -n "$v" ]] || continue
        any=1; report "${p} (pyexpat)" "$v" "$p"
    done
    [[ $any -eq 0 ]] && inf "no Python interpreter with pyexpat found"

    step "Running processes that have libexpat loaded"
    out=""; stale=0
    if [[ -n "${EXPAT_NO_PROCS:-}" ]]; then inf "running processes are not examined for a copy staged from a container"; fi
    while read -r f; do
        [[ -n "$f" ]] || continue
        pid="${f#/proc/}"; pid="${pid%%/*}"
        comm="$(cat "/proc/${pid}/comm" 2>/dev/null)"
        line="$(grep -m1 'libexpat' "$f" 2>/dev/null)"
        if grep -q 'libexpat.*(deleted)' "$f" 2>/dev/null; then
            out+="  ${pid} ${comm} (running a replaced libexpat: restart it after upgrading)"$'\n'; stale=$((stale+1))
        else
            out+="  ${pid} ${comm}"$'\n'
        fi
        : "$line"
    done < <(if [[ -z "${EXPAT_NO_PROCS:-}" ]]; then grep -l 'libexpat' /proc/[0-9]*/maps 2>/dev/null | head -n200; fi)
    if [[ -n "$out" ]]; then
        inf "processes with libexpat mapped (restart them after you upgrade the library):"
        sed 's/^/        /' <<<"$out" | head -n25
        [[ $stale -gt 0 ]] && caution "${stale} process(es) are still running a library that was replaced on disk"
    else
        inf "no readable process has libexpat mapped (run as root to see all processes)"
    fi

    step "Verdict"
    if [[ $CHECKED -eq 0 ]]; then
        info "No expat copy found by the standard checks (try: $0 deep)"
    elif [[ $AFFECTED -eq 0 ]]; then
        info "No affected copy found (${CHECKED} checked)"
    else
        warn "${AFFECTED} affected copy(ies) of ${CHECKED} checked. Upstream planned Expat ${FIXED_VERSION} for 26 October 2026."
        inf "Install your distribution's expat or libexpat update as soon as it ships, then restart the processes listed above."
        inf "Until then, reduce exposure (not vendor documented): cap the size of XML bodies at the proxy, and run services that parse untrusted XML under CPU and memory limits (systemd CPUQuota and MemoryMax) so one request cannot starve the host."
        inf "libexpat exposes tuning calls for its amplification protection, but the upstream notes do not say that tightening them avoids this flaw, so do not rely on that."
        inf "Upstream: https://github.com/libexpat/libexpat/pull/1433 and issue #1160"
    fi
    [[ $AFFECTED -eq 0 ]]
}

cmd_deep() {
    local -a dirs=() existing=()
    local d f v n=0
    if [[ $# -gt 0 ]]; then dirs=("$@"); else dirs=(/usr/local /opt /srv /var/www /home); fi
    for d in "${dirs[@]}"; do [[ -d "$d" ]] && existing+=("$d"); done
    cmd_check
    local rc=$?
    step "Programs and libraries that embed their own expat"
    if [[ ${#existing[@]} -eq 0 ]]; then inf "none of the search directories exist"; return "$rc"; fi
    AFFECTED=0; CHECKED=0
    while IFS= read -r f; do
        [[ -n "$f" ]] || continue
        v="$(lib_version "$f")"
        [[ -n "$v" ]] || continue
        n=$((n+1)); report "$f" "$v" "$f"
    done < <(find "${existing[@]}" -xdev -type f -size -200M \( -perm -u+x -o -name '*.so*' \) \
               -exec grep -laE 'expat_[0-9]+\.[0-9]+\.[0-9]+' {} + 2>/dev/null | head -n300)
    [[ $n -eq 0 ]] && inf "no embedded copy found in: ${existing[*]}"
    [[ $AFFECTED -gt 0 ]] && rc=1
    return "$rc"
}

# ---------- dispatch ---------------------------------------------------------
main() {
    CMD="${1:-check}"; [[ $# -gt 0 ]] && shift
    case "$CMD" in -V|--version|version) echo "${SCRIPT_NAME} ${SCRIPT_VERSION} (${SCRIPT_DATE})"; exit 0 ;; esac
    case "$CMD" in -h|--help|help) print_help; exit 0 ;; esac
    echo "${SCRIPT_NAME} ${SCRIPT_VERSION} (${SCRIPT_DATE}) - ${CMD} on $(hostname 2>/dev/null || echo '?') at $(date -u +%FT%TZ)"
    echo "CVE-2026-115506; affects libexpat through 2.9.0, fix planned for 2.9.1"
    case "$CMD" in
        check|deep) "cmd_${CMD}" "$@" ;;
        *) die "Unknown command: ${CMD} (check|deep|version)" ;;
    esac
}
main "$@"; exit

# Assisted-by: Claude Sonnet 5.5
