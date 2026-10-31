#!/usr/bin/env bash
# SPDX-License-Identifier: CC0-1.0
# =============================================================================
# curl HTTP/2 upload use-after-free, October 2026: read-only checker  (v1)
# CVE-2026-92392
#
# If this software is helpful, consider a donation to our 501c3 nonprofit:
# https://privacysafe.foundation
#
# A use-after-free in libcurl's HTTP/2 upload handling lets a malicious server
# that receives an upload corrupt the client's memory, and the reporter turned
# it into code execution on the uploading machine. The attack runs from the
# server side: the client uploads roughly 135KB over HTTP/2 to an attacker's
# HTTPS server (certificate must validate), the server stalls and resets the
# stream, and curl reuses a freed handle. Taking over a client needs exact
# knowledge of its build and heap, so curl expects most attempts to end in a
# crash and rates the flaw High, not Critical. Because libcurl is linked by
# many other programs, the exposure is not limited to the curl command.
#
# Affected: curl and libcurl 8.12.0 through 8.22.0. Not present before 8.12.0.
# Fixed upstream in 8.23.0, with branch backports 8.14.3, 8.16.2 and 8.20.2.
# Distributions backport the fix into their own builds under older numbers
# (Debian 13 trixie: 8.14.1-2+deb13u7, DSA-6558-1; Debian 12 is not affected).
#
# This is read-only: it finds what needs updating and judges each against the
# fixes. It changes nothing. The fix is to update curl/libcurl and restart the
# programs that use it. Where you cannot update, curl's advice is to
# avoid HTTP/2: the command's --http1.1 option, or CURLOPT_HTTP_VERSION set to
# CURL_HTTP_VERSION_1_1 in an application (a request, since an existing
# connection may be reused). A libcurl built without HTTP/2 cannot reach the
# path at all.
#
# Usage:
#   ./curl-oct2026-check.sh [command]
#
#   check (default)  every curl command and libcurl on the host, and libcurl
#                    inside running containers, with whether each carries the
#                    fix and whether the build supports HTTP/2. Root optional.
#                    Exit 0 = nothing exposed, 1 = a vulnerable curl/libcurl is
#                    present, 2 = something couldn't be read.
#   hunt             read-only: the journal and logs for process crashes that
#                    look like this bug: curl segfaults, use-after-free aborts,
#                    programs killed by a crash signal. A failed attack is most
#                    likely a crash, so a crash on an outbound HTTP/2 upload is
#                    the signal. Exit 0 = clean, 1 = findings.
#   version          print the script version.
#
# Env overrides:
#   FIXED_BUILDS="8.14.1-2+deb13u7 8.5.0-2ubuntu10.6"
#                                     extra distro curl/libcurl builds known to
#                                     carry the fix, space-separated full
#                                     versions. Checked alongside a built-in
#                                     list (Debian 13's 8.14.1-2+deb13u7),
#                                     which a value here does not replace.
#   CURL_SEGMENTS="8.12.0:8.14.3 8.15.0:8.16.2 8.17.0:8.20.2 8.21.0:8.23.0"
#                                     "<introduced>:<fixed>" per maintained
#                                     branch; the fix for a version is the one
#                                     whose introduced bound is highest at or
#                                     below it
#   CURL_INTRODUCED=8.12.0            below this the flaw is not present
#   SCAN_CONTAINERS=1                 1 = read libcurl inside running containers
#                                     (default 1; 0 to skip)
#   HUNT_SINCE="2026-10-01"           how far back hunt reads the journal
#   HUNT_LOGS="/srv/app/log/*.log"    extra log globs for hunt
# =============================================================================

# Commands run as "cmd_${CMD}", which shellcheck can't follow
# shellcheck disable=SC2317,SC2329
set -euo pipefail

# ---------- config -----------------------------------------------------------
CVE="CVE-2026-92392"
CURL_INTRODUCED="${CURL_INTRODUCED:-8.12.0}"
CURL_FIXED_MAIN="8.23.0"
CURL_SEGMENTS="${CURL_SEGMENTS:-8.12.0:8.14.3 8.15.0:8.16.2 8.17.0:8.20.2 8.21.0:8.23.0}"
FIXED_BUILDS="${FIXED_BUILDS:-}"
# Distro builds known to carry the fix under an older-looking upstream number.
# Checked alongside any user FIXED_BUILDS. Debian 13 (trixie): 8.14.1-2+deb13u7
# (DSA-6558-1). Debian 12 (bookworm) does not carry the vulnerable code.
FIXED_BUILDS_KNOWN="8.14.1-2+deb13u7"
CHANGELOG_MARKERS=(CVE-2026-92392 DSA-6558-1)
SCAN_CONTAINERS="${SCAN_CONTAINERS:-1}"
HUNT_SINCE="${HUNT_SINCE:-2026-10-01}"
HUNT_LOGS="${HUNT_LOGS:-}"
SCRIPT_NAME="curl-oct2026-check.sh"
SCRIPT_VERSION="1.0.0"
SCRIPT_DATE="2026-10-30"
SELF="$0"
UPSTREAM="https://curl.se/docs/CVE-2026-92392.html"

# ---------- output -----------------------------------------------------------
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; CYAN='\033[0;36m'; NC='\033[0m'
[[ -t 1 ]] || { RED=''; GREEN=''; YELLOW=''; CYAN=''; NC=''; }
info()    { echo -e "${GREEN}[+]${NC} $*"; }
warn()    { echo -e "${YELLOW}[!]${NC} $*"; }
step()    { echo -e "\n${CYAN}=====${NC} $* ${CYAN}=====${NC}"; }
die()     { echo -e "${RED}[-] FATAL:${NC} $*" >&2; exit 2; }
ok()      { echo -e "  ${GREEN}✓${NC} $*"; }
bad()     { echo -e "  ${RED}✗${NC} $*"; }
inf()     { echo -e "  • $*"; }
caution() { echo -e "  ${YELLOW}!${NC} $*"; }

have() { command -v "$1" >/dev/null 2>&1; }
ver_ge() { [[ "$(printf '%s\n%s\n' "$2" "$1" | sort -V | head -1)" == "$2" ]]; }
state_word() { case "$1" in 0) echo -e "${GREEN}fixed${NC}" ;; 1) echo -e "${RED}vulnerable${NC}" ;; *) echo -e "${YELLOW}unknown${NC}" ;; esac; }

# ---------- version judgment ------------------------------------------------
# The fix for a given upstream version is the one whose "introduced" bound is
# the highest at or below it: 8.12.0-8.14.2 -> 8.14.3, 8.15.0-8.16.1 -> 8.16.2,
# 8.17.0-8.20.1 -> 8.20.2, 8.21.0-8.22.x -> 8.23.0.
curl_segment_fix() {   # <X.Y.Z> -> fixed version for its branch
    local v="$1" seg lo fx best=""
    for seg in $CURL_SEGMENTS; do
        lo="${seg%%:*}"; fx="${seg#*:}"
        ver_ge "$v" "$lo" && best="$fx"
    done
    echo "$best"
}

curl_upstream_state() {   # <X.Y.Z[-DEV]> -> rc|why  (rc 0 fixed or not-affected, 1 vuln, 2 unknown)
    local v="$1" fx dev=""
    [[ -n "$v" ]] || { echo "2|version unreadable"; return; }
    # a development build (8.20.2-DEV) is made after the previous release and before 8.20.2 ships
    [[ "$v" == *-DEV ]] && { dev=1; v="${v%-DEV}"; }
    if ! ver_ge "$v" "$CURL_INTRODUCED"; then
        echo "0|${v} predates the flaw (introduced in ${CURL_INTRODUCED}); not affected"; return
    fi
    fx="$(curl_segment_fix "$v")"
    [[ -n "$fx" ]] || fx="$CURL_FIXED_MAIN"
    if [[ -n "$dev" && "$v" == "$fx" ]]; then
        echo "2|${v}-DEV is a development build made before ${fx} was released: it may or may not carry the fix. Use the ${fx} release"
    elif ver_ge "$v" "$fx"; then echo "0|${v} >= ${fx}"
    else echo "1|${v} < ${fx} (affected ${CURL_INTRODUCED} through 8.22.0; fix for this branch is ${fx}, or move to ${CURL_FIXED_MAIN})"; fi
}

owner_pkg() { have dpkg-query || return 0; dpkg -S "$(readlink -f "$1")" 2>/dev/null | head -1 | cut -d: -f1 || true; }

# Upstream X.Y.Z out of a dpkg version like 2:8.14.1-2+deb13u7 -> 8.14.1
dpkg_upstream() { local f="${1#*:}"; f="${f%%-*}"; grep -oE '^[0-9]+\.[0-9]+\.[0-9]+' <<<"$f" || true; }

# A distro package can carry the fix under an older upstream number, so judge a
# dpkg-owned curl/libcurl on its package build first, then on the branch fix.
curl_pkg_state() {   # <X.Y.Z> <path> -> rc|why
    local v="$1" p="${2:-}" pkg full f m cl rc why
    if [[ -n "$p" ]]; then
        pkg="$(owner_pkg "$p")"
        if [[ -n "$pkg" ]]; then
            full="$(dpkg-query -W -f='${Version}' "$pkg" 2>/dev/null || true)"
            [[ -n "$v" ]] || v="$(dpkg_upstream "$full")"
            for f in $FIXED_BUILDS_KNOWN $FIXED_BUILDS; do
                if [[ -n "$full" ]] && dpkg --compare-versions "$full" ge "$f" 2>/dev/null \
                   && [[ "${f%%[-+~]*}" == "${full%%[-+~]*}" ]]; then
                    echo "0|${pkg} ${full} >= fixed build ${f}"; return
                fi
            done
            cl="/usr/share/doc/${pkg}/changelog.Debian.gz"
            if [[ -f "$cl" && "$(zcat "$cl" 2>/dev/null | head -1)" == *"(${full})"* ]]; then
                for m in "${CHANGELOG_MARKERS[@]}"; do
                    if zgrep -q "$m" "$cl" 2>/dev/null; then echo "0|${pkg} ${full}: changelog lists ${m}"; return; fi
                done
            fi
            IFS='|' read -r rc why <<<"$(curl_upstream_state "$v")"
            case $rc in
                0) echo "0|${pkg} ${full} (${why})" ;;
                1) echo "1|${pkg} ${full} (upstream ${why}). A backport may exist under this number: check the distro advisory, then add it to FIXED_BUILDS" ;;
                *) echo "2|${pkg} ${full} (version unreadable)" ;;
            esac
            return
        fi
    fi
    curl_upstream_state "$v"   # self-built or bundled
}

# ---------- discovery --------------------------------------------------------
curl_binaries() {
    { type -a -P curl 2>/dev/null || true
      shopt -s nullglob
      local c
      for c in /usr/bin/curl /usr/local/bin/curl /opt/*/bin/curl /snap/*/current/usr/bin/curl; do echo "$c"; done
      shopt -u nullglob
    } | while read -r c; do [[ -x "$c" ]] && readlink -f "$c"; done | sort -u
}

find_libcurl() {   # resolved libcurl.so paths
    {
        shopt -s nullglob
        local c
        for c in /usr/lib/*/libcurl.so* /usr/lib/libcurl.so* /usr/lib64/libcurl.so* \
                 /usr/local/lib/*/libcurl.so* /usr/local/lib/libcurl.so* /lib/*/libcurl.so* \
                 /opt/*/lib/libcurl.so* /opt/*/*/lib/libcurl.so*; do echo "$c"; done
        shopt -u nullglob
        have ldconfig && ldconfig -p 2>/dev/null | grep -oE '/[^ ]*libcurl\.so[^ ]*' || true
    } | while read -r c; do [[ -e "$c" ]] && readlink -f "$c"; done | sort -u
}

# libcurl's soname is fixed (libcurl.so.4), so the version is not in the file
# name. Read the "libcurl/X.Y.Z" string the library carries for curl_version().
lib_embedded_version() { grep -aoE 'libcurl/[0-9]+\.[0-9]+\.[0-9]+(-DEV)?' "$1" 2>/dev/null | head -1 | cut -d/ -f2 || true; }

# Does this libcurl bring in HTTP/2 (nghttp2)? Informational only.
lib_has_http2() {
    local p="$1"
    { have ldd && ldd "$p" 2>/dev/null | grep 'libnghttp2' >/dev/null; } && return 0
    grep -aq 'nghttp2' "$p" 2>/dev/null && return 0
    return 1
}

# ---------- containers -------------------------------------------------------
container_libcurl() {   # "runtime|ref|version"
    [[ "$SCAN_CONTAINERS" == 1 ]] || return 0
    local rt id name v
    for rt in docker podman; do
        have "$rt" || continue
        "$rt" ps --format '{{.ID}} {{.Names}}' 2>/dev/null | while read -r id name; do
            [[ -n "$id" ]] || continue
            v="$("$rt" exec "$id" sh -c 'for p in /usr/lib/*/libcurl.so* /usr/lib/libcurl.so* /usr/local/lib/libcurl.so* /lib/*/libcurl.so*; do [ -e "$p" ] && { v=$(grep -aoE "libcurl/[0-9]+\.[0-9]+\.[0-9]+" "$p" 2>/dev/null | head -1); [ -n "$v" ] && { echo "${v#libcurl/}"; break; }; }; done' 2>/dev/null | head -1 || true)"
            [[ -n "$v" && "$v" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]] && echo "${rt}|${name:-$id}|${v}"
        done
    done
}

# ---------- check ------------------------------------------------------------
cmd_check() {
    local rc=0 exposed=0 unknownz=0 st how

    step "curl command on the host"
    local b out cli lib h2 any=0
    while read -r b; do
        [[ -n "$b" ]] || continue
        any=1
        out="$("$b" --version 2>/dev/null || true)"
        cli="$(grep -oE '^curl [0-9]+\.[0-9]+\.[0-9]+(-DEV)?' <<<"$out" | head -1 | awk '{print $2}' || true)"
        lib="$(grep -oE 'libcurl/[0-9]+\.[0-9]+\.[0-9]+(-DEV)?' <<<"$out" | head -1 | cut -d/ -f2 || true)"
        if grep -qiw 'HTTP2' <<<"$out"; then h2="HTTP/2 supported"; else h2="no HTTP/2 in this build, upload path unreachable"; fi
        IFS='|' read -r st how <<<"$(curl_pkg_state "$lib" "$b")"
        local label="${b} (curl ${cli:-?}, libcurl ${lib:-?})"
        case $st in
            0) ok "${label}  $(state_word 0)  (${how})" ;;
            1) if grep -qiw 'HTTP2' <<<"$out"; then bad "${label}  $(state_word 1)  (${how}); ${h2}"; exposed=1
               else caution "${label}  $(state_word 1) by version, but ${h2}; update anyway (${how})"; fi ;;
            *) caution "${label}  $(state_word 2)  (${how})"; unknownz=1 ;;
        esac
    done < <(curl_binaries)
    [[ $any -eq 1 ]] || inf "no curl command found on PATH or the usual locations"

    step "libcurl on the host"
    local p v h2note any2=0
    while read -r p; do
        [[ -n "$p" ]] || continue
        any2=1
        v=""
        [[ -n "$(owner_pkg "$p")" ]] || v="$(lib_embedded_version "$p")"
        if lib_has_http2 "$p"; then h2note="links nghttp2 (HTTP/2 capable)"; else h2note="no nghttp2 linkage seen (HTTP/2 may be unavailable)"; fi
        IFS='|' read -r st how <<<"$(curl_pkg_state "$v" "$p")"
        case $st in
            0) ok "${p}  $(state_word 0)  (${how})" ;;
            1) bad "${p}  $(state_word 1)  (${how}); ${h2note}"; exposed=1 ;;
            *) caution "${p}  $(state_word 2)  (${how}); ${h2note}"; unknownz=1 ;;
        esac
    done < <(find_libcurl)
    if [[ $any2 -eq 0 ]]; then inf "no libcurl shared object found on the host"
    else inf "libcurl is linked by many programs (git, package managers, language runtimes); update it and restart what uses it"; fi

    step "libcurl inside running containers"
    if [[ "$SCAN_CONTAINERS" != 1 ]]; then inf "container scan disabled (SCAN_CONTAINERS=0)"
    elif ! have docker && ! have podman; then inf "no docker or podman CLI"
    else
        local rt ref cv any_c=0
        while IFS='|' read -r rt ref cv; do
            [[ -n "$ref" ]] || continue
            any_c=1
            IFS='|' read -r st how <<<"$(curl_upstream_state "$cv")"
            case $st in
                0) ok "${rt} ${ref}  libcurl ${cv}  $(state_word 0)  (${how})" ;;
                1) bad "${rt} ${ref}  libcurl ${cv}  $(state_word 1)  (${how}); rebuild the image, a restart won't change the library"; exposed=1 ;;
                *) caution "${rt} ${ref}  libcurl ${cv}  $(state_word 2)  (${how})"; unknownz=1 ;;
            esac
        done < <(container_libcurl)
        [[ $any_c -eq 1 ]] || inf "no running container exposes a readable libcurl (or no permission to exec in them)"
    fi

    step "Verdict"
    [[ $exposed -eq 1 ]] && rc=1
    [[ $rc -eq 0 && $unknownz -eq 1 ]] && rc=2
    case $rc in
        0) info "No vulnerable curl/libcurl found where this could read one" ;;
        1) warn "A vulnerable curl/libcurl is present. Update to 8.23.0 (or the 8.14.3 / 8.16.2 / 8.20.2 branch build, or your distribution's fixed build), rebuild anything that bundles it, and restart the programs that use it. Until then, avoid HTTP/2 for uploads (curl --http1.1, or CURLOPT_HTTP_VERSION = CURL_HTTP_VERSION_1_1). Advisory: ${UPSTREAM}" ;;
        *) warn "Some builds couldn't be judged. For a dpkg build, confirm against the distro advisory and add it to FIXED_BUILDS. Rerun as root to read more" ;;
    esac
    return "$rc"
}

# ---------- hunt -------------------------------------------------------------
cmd_hunt() {
    step "Hunting for curl/libcurl crashes since ${HUNT_SINCE}"
    local jr; jr="$(mktemp)"
    # shellcheck disable=SC2064
    trap "rm -f '$jr'" RETURN
    if have journalctl; then journalctl --since "$HUNT_SINCE" --no-pager -o short-iso 2>/dev/null >"$jr" || true; fi
    local -a files=()
    [[ -s "$jr" ]] && files+=("$jr")
    local g f
    shopt -s nullglob
    # shellcheck disable=SC2086
    for g in /var/log/syslog /var/log/syslog.1 /var/log/kern.log /var/log/kern.log.1 /var/log/messages \
             /srv/*/log/*.log /var/www/*/log/*.log $HUNT_LOGS; do
        for f in $g; do [[ -r "$f" && -f "$f" ]] && files+=("$f"); done
    done
    shopt -u nullglob
    [[ ${#files[@]} -gt 0 ]] || { warn "No readable journal or logs (try as root, or set HUNT_LOGS)"; return 0; }
    inf "reading ${#files[@]} source(s)"

    local found=0 name re c n
    local -a checks=(
        "curl process crash or protection fault|curl\[[0-9]+\]: segfault|curl.*(general protection|trap invalid opcode)|segfault.* in libcurl"
        "libcurl frames in a crash/backtrace|(libcurl\.so|curl_multi_|Curl_|nghttp2_)"
        "use-after-free or heap corruption abort|(use-after-free|double free or corruption|free\(\): invalid (pointer|size)|malloc\(\): (corrupted|unaligned)|corrupted size vs\. prev_size)"
        "service killed by SIGSEGV/SIGABRT/SIGBUS|code=dumped, status=(11/SEGV|6/ABRT|7/BUS)"
    )
    for c in "${checks[@]}"; do
        name="${c%%|*}"; re="${c#*|}"
        n="$( { grep -hcE "$re" "${files[@]}" 2>/dev/null || true; } | awk '{s+=$1} END{print s+0}')"
        if [[ "${n:-0}" -gt 0 ]]; then
            found=1
            caution "${name}: ${n}"
            { grep -hE "$re" "${files[@]}" 2>/dev/null || true; } | tail -3 | cut -c1-220 | sed 's/^/      /'
        else
            ok "${name}: none"
        fi
    done
    echo
    echo "  A hit tells you where to look: plenty of things segfault, and the libcurl-frame"
    echo "  pattern is broad. A crash in a program that was uploading over HTTP/2 to an"
    echo "  outside server, on a vulnerable build, is worth treating as an incident: check"
    echo "  what that process could reach (secrets, tokens, credentials) and rotate them."
    return "$found"
}

# ---------- dispatch ---------------------------------------------------------
main() {
CMD="${1:-check}"; [[ $# -gt 0 ]] && shift
case "$CMD" in -V|--version|version) echo "${SCRIPT_NAME} ${SCRIPT_VERSION} (${SCRIPT_DATE})"; exit 0 ;; esac
case "$CMD" in -h|--help) awk 'f && /^# =+$/ {exit} f {sub(/^# ?/, ""); print} /^# =+$/ {f=1}' "$SELF"; exit 0 ;; esac
[[ $# -eq 0 ]] || die "Unknown option: $1"
echo "${SCRIPT_NAME} ${SCRIPT_VERSION} (${SCRIPT_DATE}) - ${CMD} on $(hostname 2>/dev/null || echo '?') at $(date -u +%FT%TZ)"
echo "${CVE}; advisory: ${UPSTREAM}"
case "$CMD" in
    check|hunt) "cmd_${CMD}" ;;
    *) die "Unknown command: $CMD (check|hunt|version)" ;;
esac
}
main "$@"; exit

# Assisted-by: Claude Opus 5.5
