#!/usr/bin/env bash
# SPDX-License-Identifier: CC0-1.0
# =============================================================================
# HAProxy truncated HTTP/2 PING frame denial of service: read-only checker  (v1)
# CVE-2026-110353
#
# If this software is helpful, consider a donation to our 501c3 nonprofit:
# https://privacysafe.foundation
#
# HAProxy's HTTP/2 multiplexer did not treat a truncated PING frame as a short
# read. A PING frame cannot be consumed until it is complete, but its presence
# was enough to wake the connection up, so the worker thread never went back to
# idle. A remote, unauthenticated client that opens a connection and keeps a
# partial PING frame pending can hold a thread at 100% CPU for as long as the
# connection stays open (or until "timeout http-request" expires, when one is
# set). The impact is moderate and grows with the share of such connections
# among all concurrent connections.
#
# AFFECTED RANGE: read this part carefully, because two sources disagree.
#   The CVE description says "3.2 before 3.4.6". HAProxy's own release notes say
#   the bug was introduced in 3.1 (the short-read handling was fixed in 2.5 but
#   PING was missed, and it only became a problem in 3.1 when the wake-up logic
#   changed), and that the fixes shipped on 14 October 2026 in 3.4.7, 3.3.17 and
#   3.2.26. 3.4.6 is therefore NOT fixed. This script follows the vendor:
#     3.1.x       affected, branch is end of life, no fix: move to a supported branch
#     3.2.x       affected before 3.2.26
#     3.3.x       affected before 3.3.17
#     3.4.x       affected before 3.4.7
#     3.0 and older   outside this CVE's range (the vendor says 3.1 introduced it)
#     3.5-dev     development builds: check the commit yourself
#   The same releases fix a second CPU-exhaustion flaw in the HTTP/1 parser (a
#   chunked request with a chunk-size line longer than the buffer). The vendor
#   does not state its affected range in the release notes, so this script does
#   not rule any HTTP-mode HAProxy out because of it.
#
# Vendor workaround (documented for the PING flaw): setting "timeout http-request"
# to a low value such as 1 to 5 seconds limits the CPU consumption.
#
# HTTP/2 reachability, which decides exposure: TLS listeners offer HTTP/2 only
# when the bind line has "alpn h2". Clear-text HTTP listeners accept the HTTP/2
# connection preface by default and upgrade the connection, unless the frontend
# has "option disable-h2-upgrade". "proto h2" on a bind line forces HTTP/2.
#
# This script is read-only. It finds HAProxy binaries (PATH, usual locations and
# running processes), reads the version from "haproxy -v", reads the
# configuration files the running process was started with (or the defaults) and
# reports HTTP/2 reachability and the http-request timeout. It never reloads or
# restarts HAProxy.
#
# Usage:
#   ./haproxy-check.sh [command] [PATH-TO-haproxy ...]
#
#   check (default)  Exit 0 = nothing exposed, 1 = an affected version is
#                    exposed or its configuration could not be read.
#   version          print the script version.
#
# HAPROXY_CFG (space separated files or directories) replaces configuration discovery.
# Containers: with no argument the check also looks in running docker and podman containers
# (SCAN_CONTAINERS=1, the default; 0 skips them). A read-only probe captures the daemon's version
# output and its configuration (secrets are redacted inside the container before anything is
# copied) into a private temporary directory, and this script then runs once per container, in
# isolation, against that copy. Paths shown as .../docker_NAME/... are inside the container NAME.
# =============================================================================

# Commands run as "cmd_${CMD}", which shellcheck can't follow
# shellcheck disable=SC2317,SC2329,SC2034
set -uo pipefail

SCRIPT_NAME="haproxy-check.sh"
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
# prints: vulnerable | fixed | eol | notaffected | dev | unknown
haproxy_status() {
    local raw="$1" n major minor
    [[ "$raw" == *-dev* ]] && { echo dev; return; }
    n="$(norm_ver "$raw")"
    is_semver "$n" || { echo unknown; return; }
    major="${n%%.*}"; minor="${n#*.}"; minor="${minor%%.*}"
    if (( major > 3 )); then echo fixed; return; fi
    if (( major < 3 )); then echo notaffected; return; fi
    case "$minor" in
        0) echo notaffected ;;
        1) echo eol ;;
        2) ver_lt "$n" "3.2.26" && echo vulnerable || echo fixed ;;
        3) ver_lt "$n" "3.3.17" && echo vulnerable || echo fixed ;;
        4) ver_lt "$n" "3.4.7"  && echo vulnerable || echo fixed ;;
        *) echo fixed ;;
    esac
}

# ---------- discovery --------------------------------------------------------
bin_version() {   # binary -> raw version string such as 3.4.6-abcdef
    "$1" -v 2>/dev/null | head -n1 | sed -n 's/^HA-\{0,1\}[Pp]roxy version \([^ ]*\).*/\1/p'
}

discover_bins() {
    local -a out=()
    local b pid exe
    for b in "$(command -v haproxy 2>/dev/null)" /usr/sbin/haproxy /usr/local/sbin/haproxy /usr/bin/haproxy /usr/local/bin/haproxy; do
        [[ -n "$b" && -x "$b" ]] && out+=("$(readlink -f "$b")")
    done
    shopt -s nullglob
    for b in /opt/haproxy*/sbin/haproxy /opt/haproxy*/bin/haproxy /opt/*/sbin/haproxy; do
        [[ -x "$b" ]] && out+=("$(readlink -f "$b")")
    done
    shopt -u nullglob
    if have ps; then
        while read -r pid; do
            exe="$(readlink "/proc/${pid}/exe" 2>/dev/null)"
            [[ -n "$exe" && "$exe" != *"(deleted)" && -x "$exe" ]] && out+=("$exe")
        done < <(ps -eo pid=,comm= 2>/dev/null | awk '$2=="haproxy"{print $1}')
    fi
    [[ ${#out[@]} -gt 0 ]] || return 0
    printf '%s\n' "${out[@]}" | awk 'NF && !seen[$0]++'
}

RUNNING_STALE=""
running_pids() { ps -eo pid=,comm= 2>/dev/null | awk '$2=="haproxy"{print $1}'; }

config_files() {   # -> readable configuration files, from the running process or defaults
    local -a paths=()
    local f p
    if have ps; then
        while read -r p; do paths+=("$p"); done < <(ps -eo args= 2>/dev/null | grep -E '(^|/)haproxy( |$)' \
            | grep -oE -- '-f[[:space:]]+[^[:space:]]+' | sed -E 's/^-f[[:space:]]+//')
    fi
    # HAPROXY_CFG (space separated files or directories) overrides discovery
    [[ -z "${HAPROXY_CFG:-}" ]] || read -r -a paths <<<"$HAPROXY_CFG"
    [[ ${#paths[@]} -gt 0 ]] || paths=(/etc/haproxy/haproxy.cfg /etc/haproxy/conf.d /usr/local/etc/haproxy/haproxy.cfg)
    for p in "${paths[@]}"; do
        if [[ -d "$p" ]]; then
            for f in "$p"/*.cfg; do [[ -r "$f" ]] && echo "$f"; done
        elif [[ -r "$p" ]]; then echo "$p"; fi
    done | awk '!s[$0]++'
}

timeout_seconds() {   # "5s" "2m" "1500" (milliseconds by default) -> seconds
    local v="$1" n u
    n="${v//[!0-9]/}"; u="${v//[0-9]/}"
    [[ -n "$n" ]] || { echo ""; return; }
    case "$u" in
        us) echo 0 ;; ms|'') echo $(( n / 1000 )) ;; s) echo "$n" ;; m) echo $(( n * 60 )) ;; h) echo $(( n * 3600 )) ;; d) echo $(( n * 86400 )) ;;
        *) echo "" ;;
    esac
}

H2_EXPLICIT=0; H2_UPGRADE_OFF=0; HTTP_MODE=0; CLEAR_BIND=0; HTTP_REQ_TIMEOUT=""
analyze_config() {   # file -> sets the globals above
    local f="$1" body t
    body="$(sed -E 's/[[:space:]]*#.*$//' "$f")"
    grep -qE '^[[:space:]]*bind[[:space:]].*(alpn[[:space:]]+[^[:space:]]*h2|proto[[:space:]]+h2)' <<<"$body" && H2_EXPLICIT=1
    grep -qE '^[[:space:]]*option[[:space:]]+disable-h2-upgrade' <<<"$body" && H2_UPGRADE_OFF=1
    grep -qE '^[[:space:]]*mode[[:space:]]+http' <<<"$body" && HTTP_MODE=1
    awk '/^[ \t]*bind[ \t]/ && !/[ \t]ssl([ \t]|$)/ {f=1} END{exit f?0:1}' <<<"$body" && CLEAR_BIND=1
    t="$(sed -nE 's/^[[:space:]]*timeout[[:space:]]+http-request[[:space:]]+([0-9]+[a-z]*).*/\1/p' <<<"$body" | tail -n1)"
    [[ -n "$t" ]] && HTTP_REQ_TIMEOUT="$t"
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

HAPROXY_PROBE="$(cat <<'EOS'
n=""
for c in /usr/sbin/haproxy /usr/local/sbin/haproxy /usr/bin/haproxy /usr/local/bin/haproxy; do [ -x "$c" ] && { n=$c; break; }; done
[ -n "$n" ] || exit 0
echo "B /.out_v $("$n" -v 2>/dev/null | head -n 1 | base64 | tr -d '\n')"
red() { sed -E 's/(password[[:space:]]+)[^[:space:]]+/\1REDACTED/g; s/(auth[[:space:]]+[^:[:space:]]+:)[^[:space:]]+/\1REDACTED/g' "$1" | base64 | tr -d '\n'; }
for p in /etc/haproxy/haproxy.cfg /usr/local/etc/haproxy/haproxy.cfg; do [ -f "$p" ] && echo "B $p $(red "$p")"; done
find /etc/haproxy/conf.d -maxdepth 1 -type f -name "*.cfg" -size -512k 2>/dev/null | head -n 40 | while read -r p; do echo "B $p $(red "$p")"; done
exit 0
EOS
)"

container_run() {   # <staged directory> : HAProxy in one container, judged by this script run in isolation
    local s="$1" out rc
    [[ -s "$s/.out_v" ]] || return 0
    printf '#!/bin/sh\ncase "$1" in\n  -v) cat "%s/.out_v" ;;\nesac\n' "$s" > "$s/haproxy"; chmod 755 "$s/haproxy"
    step "HAProxy in a container (${s##*/})"
    out="$(SCAN_CONTAINERS=0 HAPROXY_CFG="$s/etc/haproxy/haproxy.cfg $s/etc/haproxy/conf.d $s/usr/local/etc/haproxy/haproxy.cfg" bash "$SELF" check "$s/haproxy" 2>&1)"; rc=$?
    tail -n +3 <<<"$out"
    return "$rc"
}

cmd_check() {
    local rc=0 crc=0 _s
    if [[ $# -eq 0 && "${SCAN_CONTAINERS:-1}" == 1 ]]; then
        stage_probe "$HAPROXY_PROBE"
        for _s in ${STAGED_DIRS[@]:+"${STAGED_DIRS[@]}"}; do
            container_run "$_s" || crc=1
        done
    fi
    cmd_check_host "$@" || rc=$?
    if [[ $crc -eq 1 && $rc -eq 0 ]]; then rc=1; fi
    return "$rc"
}

cmd_check_host() {
    local -a bins=()
    local rc=0 found=0 b raw st pid exe stale=0 f read_any h2exposed rt
    if [[ $# -gt 0 ]]; then bins=("$@")
    else while IFS= read -r b; do [[ -n "$b" ]] && bins+=("$b"); done < <(discover_bins); fi
    step "Looking for HAProxy"
    if [[ ${#bins[@]} -eq 0 ]]; then info "No HAProxy found on this host"; return 0; fi
    for b in "${bins[@]}"; do
        [[ -x "$b" ]] || { caution "${b}: not an executable file"; continue; }
        raw="$(bin_version "$b")"
        [[ -n "$raw" ]] || { caution "${b}: could not read a version from -v"; continue; }
        found=$((found+1))
        step "HAProxy ${raw} at ${b}"
        st="$(haproxy_status "$raw")"
        case "$st" in
            notaffected) ok "HAProxy ${raw} is older than 3.1, outside the range of CVE-2026-110353 (the vendor says 3.1 introduced it)"; continue ;;
            fixed)       ok "HAProxy ${raw} has the fix (3.2.26, 3.3.17, 3.4.7 or newer)" ;;
            dev)         caution "HAProxy ${raw} is a 3.5 development build: check that it includes the fix 'properly handle short reads on PING frames'"; continue ;;
            unknown)     caution "cannot parse version '${raw}'"; continue ;;
            eol)         bad "HAProxy ${raw} is on 3.1, which is affected, end of life and has no fix: move to 3.2.26, 3.3.17 or 3.4.7 or newer"; rc=1 ;;
            vulnerable)  bad "HAProxy ${raw} is affected by CVE-2026-110353 (fixed in 3.2.26, 3.3.17 and 3.4.7)" ;;
        esac
        # running processes: are they on the fixed binary?
        while read -r pid; do
            [[ -n "$pid" ]] || continue
            exe="$(readlink "/proc/${pid}/exe" 2>/dev/null)"
            if [[ "$exe" == *"(deleted)" ]]; then stale=$((stale+1)); fi
        done < <(running_pids)
        [[ $stale -gt 0 ]] && caution "${stale} running HAProxy process(es) use a binary that was replaced on disk: reload or restart to run the new one"
        [[ "$st" == "fixed" ]] && continue
        if distro_mentions "$b" CVE-2026-110353; then
            ok "package ${DISTRO_PKG} changelog mentions ${DISTRO_HIT}: the distribution may have backported the fix"
            continue
        elif [[ $? -eq 1 ]]; then
            inf "package ${DISTRO_PKG} owns this binary and its changelog does not mention the CVE yet"
        fi
        # configuration
        H2_EXPLICIT=0; H2_UPGRADE_OFF=0; HTTP_MODE=0; CLEAR_BIND=0; HTTP_REQ_TIMEOUT=""; read_any=0
        while IFS= read -r f; do
            [[ -n "$f" ]] || continue
            read_any=1; analyze_config "$f"; inf "read ${f}"
        done < <(config_files)
        if [[ $read_any -eq 0 ]]; then
            caution "no readable HAProxy configuration found: exposure cannot be decided, treating as exposed"
            rc=1; continue
        fi
        h2exposed=0
        if [[ $H2_EXPLICIT -eq 1 ]]; then
            bad "HTTP/2 is explicitly enabled on a bind line (alpn h2 or proto h2): exposed to CVE-2026-110353"; h2exposed=1
        elif [[ $HTTP_MODE -eq 1 && $CLEAR_BIND -eq 1 && $H2_UPGRADE_OFF -eq 0 ]]; then
            bad "a clear-text HTTP listener accepts the HTTP/2 preface by default (no 'option disable-h2-upgrade'): exposed to CVE-2026-110353"; h2exposed=1
        elif [[ $HTTP_MODE -eq 1 ]]; then
            ok "no HTTP/2 path found: no 'alpn h2' or 'proto h2', and no clear-text HTTP listener without 'option disable-h2-upgrade' (heuristic)"
        else
            ok "no 'mode http' found in the configuration: the HTTP/2 multiplexer is not in use"
        fi
        rt="$(timeout_seconds "$HTTP_REQ_TIMEOUT")"
        if [[ -z "$HTTP_REQ_TIMEOUT" ]]; then
            caution "no 'timeout http-request' set: nothing bounds how long a partial frame can pin a thread (vendor workaround: 1 to 5 seconds)"
        elif [[ -n "$rt" && "$rt" -le 5 ]]; then
            ok "timeout http-request is ${HTTP_REQ_TIMEOUT}: the vendor's workaround for the PING flaw is in place (this limits CPU use, it is not the fix)"
        else
            caution "timeout http-request is ${HTTP_REQ_TIMEOUT}: the vendor's workaround suggests 1 to 5 seconds"
        fi
        if [[ $h2exposed -eq 1 || $HTTP_MODE -eq 1 ]]; then
            [[ $h2exposed -eq 1 ]] && rc=1
            [[ $h2exposed -eq 0 ]] && inf "HTTP mode is in use, so the HTTP/1 chunk-size flaw fixed in the same releases is still reachable: update anyway"
        fi
    done
    step "Verdict"
    if [[ $found -eq 0 ]]; then
        info "No HAProxy version could be read"
    elif [[ $rc -eq 0 ]]; then
        info "No exposed HAProxy found (${found} checked)"
    else
        warn "Exposed or unverifiable HAProxy found. Upgrade to 3.2.26, 3.3.17 or 3.4.7 (or newer), then reload."
        inf "Interim, vendor documented for the PING flaw: set 'timeout http-request' to 1-5s in the defaults or frontend. It limits CPU consumption and does not fix the bug."
        inf "Interim, ours: if you do not need clear-text HTTP/2, add 'option disable-h2-upgrade' to HTTP frontends and drop 'h2' from alpn lists."
        inf "Release notes: https://www.mail-archive.com/haproxy@formilux.org/msg47598.html (3.4.7)"
    fi
    return "$rc"
}

# ---------- dispatch ---------------------------------------------------------
main() {
    CMD="${1:-check}"; [[ $# -gt 0 ]] && shift
    case "$CMD" in -V|--version|version) echo "${SCRIPT_NAME} ${SCRIPT_VERSION} (${SCRIPT_DATE})"; exit 0 ;; esac
    case "$CMD" in -h|--help|help) print_help; exit 0 ;; esac
    echo "${SCRIPT_NAME} ${SCRIPT_VERSION} (${SCRIPT_DATE}) - ${CMD} on $(hostname 2>/dev/null || echo '?') at $(date -u +%FT%TZ)"
    echo "CVE-2026-110353; fixed in HAProxy 3.4.7, 3.3.17 and 3.2.26"
    case "$CMD" in
        check) cmd_check "$@" ;;
        *) die "Unknown command: ${CMD} (check|version)" ;;
    esac
}
main "$@"; exit

# Assisted-by: Claude Sonnet 5.5
