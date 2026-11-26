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
SCRIPT_VERSION="1.1.0"
SCRIPT_DATE="2026-11-25"
SELF="$0"
UPSTREAM="https://curl.se/docs/CVE-2026-92392.html"

# ---------- output -----------------------------------------------------------
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; CYAN='\033[0;36m'; NC='\033[0m'
[[ -t 1 ]] || { RED=''; GREEN=''; YELLOW=''; CYAN=''; NC=''; }

# A binary this script found may belong to someone else (under /home, or an /opt folder an
# application account owns). Running it as root would run their code as root. So, as root, a binary
# runs as root only when root owns it, nobody else can write it, and every folder above it is root's
# and not writable by others (a sticky folder such as /tmp counts as safe: others cannot replace root's
# entries in it). Otherwise it runs as its owner, or not at all.
fb_safe_to_exec() {   # <binary>
    local f d m
    f="$(readlink -f "$1" 2>/dev/null)" || return 1
    [[ -f "$f" && -x "$f" ]] || return 1
    [[ "$(stat -c %u "$f" 2>/dev/null)" == 0 ]] || return 1
    m="$(stat -c %a "$f" 2>/dev/null)" || return 1; [[ $(( 8#$m & 8#022 )) -eq 0 ]] || return 1
    d="$(dirname "$f")"
    while :; do
        [[ "$(stat -c %u "$d" 2>/dev/null)" == 0 ]] || return 1
        m="$(stat -c %a "$d" 2>/dev/null)" || return 1
        [[ $(( 8#$m & 8#022 )) -eq 0 || $(( 8#$m & 8#1000 )) -ne 0 ]] || return 1
        [[ "$d" == / ]] && break
        d="$(dirname "$d")"
    done
}
run_found() {   # <binary> <args...>: run a binary this script found, as root only when that is safe
    local b="$1" o; shift
    if [[ "${EUID:-$(id -u)}" -ne 0 ]] || fb_safe_to_exec "$b"; then timeout "${RUN_FOUND_TIMEOUT:-20}" "$b" "$@"; return; fi
    o="$(stat -Lc %U "$b" 2>/dev/null)"
    [[ -n "$o" && "$o" != root && "$o" != UNKNOWN ]] || return 1
    command -v runuser >/dev/null 2>&1 || return 1
    timeout "${RUN_FOUND_TIMEOUT:-20}" runuser -u "$o" -- "$b" "$@"
}

info()    { echo -e "${GREEN}[+]${NC} $*"; }
warn()    { echo -e "${YELLOW}[!]${NC} $*"; }
step()    { echo -e "\n${CYAN}=====${NC} $* ${CYAN}=====${NC}"; }
die()     { echo -e "${RED}[-] FATAL:${NC} $*" >&2; exit 2; }
ok()      { echo -e "  ${GREEN}✓${NC} $*"; }
bad()     { echo -e "  ${RED}✗${NC} $*"; }
inf()     { echo -e "  • $*"; }
caution() { echo -e "  ${YELLOW}!${NC} $*"; }

# ---------- structured output and read-only mode (the same block in every script) ----------
# Generated from automation/output-block.bash by automation/psf-output.py; edit it there.
# --output jsonl (or PSF_OUTPUT=jsonl) writes JSON Lines, one record per line, when the script ends:
# a start record, an event for each finding, a text record for any other line, and a verdict.
# The format is described in automation/README.md. --output text, the default, changes nothing.
# NO_COLOR (https://no-color.org): set to anything, no color codes in the text output, for screen readers and logs.
if [[ -n "${NO_COLOR:-}" ]]; then
    for _psf_v in RED GREEN YELLOW CYAN NC BLUE BLU YEL RST GRN BOLD DIM; do [[ -n "${!_psf_v+x}" ]] && printf -v "$_psf_v" '%s' ''; done; unset _psf_v
fi
# PSF_READ_ONLY=1 refuses every command that changes the host, before it starts.
_PSF_FMT="${PSF_OUTPUT:-text}"; _psf_a=()
while (($#)); do
    case "$1" in
        --output) [[ $# -ge 2 ]] || { echo "--output needs a format: text or jsonl" >&2; exit 2; }; _PSF_FMT="$2"; shift 2 ;;
        --output=*) _PSF_FMT="${1#--output=}"; shift ;;
        *) _psf_a+=("$1"); shift ;;
    esac
done
set -- "${_psf_a[@]+"${_psf_a[@]}"}"; unset _psf_a
case "$_PSF_FMT" in text|jsonl) ;; *) echo "--output: unknown format '$_PSF_FMT' (text or jsonl; psf-report renders Markdown, HTML and PDF)" >&2; exit 2 ;; esac
_PSF_CMD=""; for _psf_x in "$@"; do [[ "$_psf_x" == -* ]] || { _PSF_CMD="$_psf_x"; break; }; done; unset _psf_x

# A command that changes the host is refused in read-only mode, whatever else it is asked to do.
psf_refuse_change() {
    [[ "${PSF_READ_ONLY:-0}" == 1 ]] || return 0
    local m="read-only mode (PSF_READ_ONLY=1): ${1:-this change} refused; nothing was changed"
    if [[ "$_PSF_FMT" == jsonl ]]; then PSF_KIND="" _psf_ev error "$m"; else echo "$m" >&2; fi
    exit 2
}

# A check that found nothing to examine says so; only the jsonl verdict records it.
psf_not_applicable() { [[ "$_PSF_FMT" == jsonl ]] && _psf_rec applicable "" "$*"; return 0; }

if [[ "$_PSF_FMT" == jsonl ]]; then
    for _psf_v in RED GREEN YELLOW CYAN NC BLUE BLU YEL RST GRN BOLD DIM; do [[ -n "${!_psf_v+x}" ]] && printf -v "$_psf_v" '%s' ''; done; unset _psf_v   # the colors this script set
    _PSF_SELF="${BASH_SOURCE[0]}"; _PSF_TOOL="${SCRIPT_NAME:-${_PSF_SELF##*/}}"; _PSF_TOOL="${_PSF_TOOL%.sh}"
    _PSF_HOST="$(cat /proc/sys/kernel/hostname 2>/dev/null || uname -n 2>/dev/null || echo unknown)"
    _PSF_MAIN_PID="$BASHPID"; _PSF_T0="${EPOCHREALTIME:-$(date +%s)}"; _PSF_EXIT_CMD=""
    _PSF_RUN="${_PSF_HOST}-${_PSF_TOOL}-$(date -u +%Y%m%dT%H%M%SZ 2>/dev/null)-$$"
    _psf_d="$(cd "$(dirname "$_PSF_SELF")" 2>/dev/null && pwd)"; _psf_c="${_psf_d%/*}"; _psf_c="${_psf_c##*/}"
    case "$_psf_c" in
        servers|system|runtimes|web-apps|developer|threats) _PSF_FIX="https://privacysafe.app/docs/security-patches/${_psf_c}/${_psf_d##*/}/" ;;
        *) _PSF_FIX="https://privacysafe.app/docs/security-patches/" ;;
    esac; unset _psf_d _psf_c

    _psf_s() {   # a JSON string: escapes, newlines kept, color codes and other control characters dropped
        local s="$1"
        while [[ "$s" =~ $'\e'\[[0-9\;]*[A-Za-z] ]]; do s="${s/"${BASH_REMATCH[0]}"/}"; done
        s="${s//\\/\\\\}"; s="${s//\"/\\\"}"; s="${s//$'\n'/\\n}"; s="${s//$'\r'/}"; s="${s//$'\t'/\\t}"
        s="${s//[$'\001'-$'\037']/}"
        printf '"%s"' "$s"
    }
    # A record this block writes carries a secret marker, made fresh for each run and kept in this shell only.
    # At exit only marked lines are records; any other line, even one that looks like a record (a file name
    # with a newline in it, a log line the script prints), stays text, so output cannot forge a record.
    _PSF_MARK=""; read -r _PSF_MARK </proc/sys/kernel/random/uuid 2>/dev/null || _PSF_MARK="${RANDOM}${RANDOM}${RANDOM}${RANDOM}$$"
    _PSF_MARK=$'\036'"psf-${_PSF_MARK}"$'\036'
    _psf_rec() {   # type level message [more JSON fields]: one marked record on stdout
        local type="$1" level="$2" msg="$3" ts tsms ems cves="" rest extra="${4:-}" c er="${EPOCHREALTIME:-}"
        # one reading of the clock, written three ways: ts to the second (as records always had it), ts_ms to the
        # millisecond (as the joint event logging guide prefers), both RFC 3339 in UTC, and ts_epoch_ms, the same
        # instant as whole milliseconds since 1970 for tools that want a number. EPOCHREALTIME (bash 5) can use a
        # decimal comma; without it the time is whole seconds and the milliseconds are 000.
        if [[ "$er" =~ ^([0-9]+)[.,]([0-9]{3}) ]]; then
            TZ=UTC printf -v ts '%(%Y-%m-%dT%H:%M:%S)TZ' "${BASH_REMATCH[1]}"; tsms="${ts%Z}.${BASH_REMATCH[2]}Z"
            ems="${BASH_REMATCH[1]}${BASH_REMATCH[2]}"
        else
            TZ=UTC printf -v ts '%(%Y-%m-%dT%H:%M:%S)TZ' -1; tsms="${ts%Z}.000Z"
            printf -v ems '%(%s)T' -1; ems="${ems}000"
        fi
        rest="$msg"
        while [[ "$rest" =~ (CVE-[0-9]{4}-[0-9]{4,}) ]]; do
            c="${BASH_REMATCH[1]}"; [[ ",$cves," == *",\"$c\","* ]] || cves="${cves:+$cves,}\"$c\""; rest="${rest#*"$c"}"
        done
        local kind="${PSF_KIND:-}"
        [[ -z "$kind" && "$_PSF_CMD" == hunt && "$level" =~ ^(crit|warn)$ ]] && kind=indicator
        [[ -n "$kind" && "$level" =~ ^(crit|warn)$ ]] && extra+=",\"kind\":$(_psf_s "$kind")"
        [[ -n "${PSF_CODE:-}" ]] && extra+=",\"code\":$(_psf_s "$PSF_CODE")"
        [[ -n "${PSF_PATH:-}" ]] && extra+=",\"path\":$(_psf_s "$PSF_PATH")"
        [[ "$level" =~ ^(crit|warn)$ ]] && extra+=",\"fix\":$(_psf_s "${PSF_FIX:-$_PSF_FIX}")"
        printf '%s{"schema":1,"type":"%s","run":%s,"tool":%s,"version":%s,"host":%s,"command":%s,"ts":"%s","ts_ms":"%s","ts_epoch_ms":%s%s,"msg":%s,"cve":[%s]%s}\n' \
            "$_PSF_MARK" "$type" "$(_psf_s "$_PSF_RUN")" "$(_psf_s "$_PSF_TOOL")" "$(_psf_s "${SCRIPT_VERSION:-}")" "$(_psf_s "$_PSF_HOST")" \
            "$(_psf_s "$_PSF_CMD")" "$ts" "$tsms" "$ems" "${level:+,\"level\":\"$level\"}" "$(_psf_s "$msg")" "$cves" "$extra"
    }
    _psf_ev() { local level="$1" m; shift; printf -v m '%b' "$*"; m="${m#"${m%%[![:space:]]*}"}"; m="${m%"${m##*[![:space:]]}"}"; _psf_rec event "$level" "$m"; }

    # the helpers this script defined above now write records
    declare -F ok      >/dev/null && ok()      { _psf_ev ok "$*"; }
    declare -F pass    >/dev/null && pass()    { _psf_ev ok "$*"; }
    declare -F info    >/dev/null && info()    { _psf_ev info "$*"; }
    declare -F inf     >/dev/null && inf()     { _psf_ev info "$*"; }
    declare -F inf_hunt >/dev/null && inf_hunt() { _psf_ev info "$*"; }
    declare -F note    >/dev/null && note()    { _psf_ev info "$*"; }
    declare -F tip     >/dev/null && tip()     { _psf_ev info "$*"; }
    declare -F warn    >/dev/null && warn()    { _psf_ev warn "$*"; }
    declare -F caution >/dev/null && caution() { _psf_ev warn "$*"; }
    declare -F bad     >/dev/null && bad()     { _psf_ev crit "$*"; }
    declare -F fail    >/dev/null && fail()    { _psf_ev crit "$*"; }
    declare -F step    >/dev/null && step()    { local m; printf -v m '%b' "$*"; m="${m//$'\n'/}"; _psf_rec section "" "${m#"${m%%[![:space:]]*}"}"; }
    declare -F section >/dev/null && section() { local m; printf -v m '%b' "$*"; m="${m//$'\n'/}"; _psf_rec section "" "${m#"${m%%[![:space:]]*}"}"; }
    die() { _psf_ev error "$*"; exit 2; }

    # Everything the script prints goes to a private file; at exit it becomes records, and a verdict closes the run.
    # As root it is always /tmp (root's, sticky): a TMPDIR another account can write would let it swap the file.
    _PSF_TMPD="${TMPDIR:-/tmp}"; [[ $EUID -eq 0 ]] && _PSF_TMPD=/tmp
    _PSF_TMP="$(mktemp "$_PSF_TMPD/psf-output.XXXXXXXXXX")" || { echo "--output jsonl: cannot make a temporary file" >&2; exit 2; }
    exec {_PSF_OUT}>&1 {_PSF_ERR}>&2
    exec {_PSF_RD}<"$_PSF_TMP"        # read back at exit through this handle
    exec >>"$_PSF_TMP" 2>&1
    rm -f "$_PSF_TMP"                 # nameless from here on: nothing is left in /tmp, even when the run is killed
    _psf_rec start "" "$_PSF_TOOL ${SCRIPT_VERSION:-} ${_PSF_CMD:-(no command)}" \
        ",\"script_date\":$(_psf_s "${SCRIPT_DATE:-}"),\"euid\":${EUID},\"read_only\":$([[ "${PSF_READ_ONLY:-0}" == 1 ]] && echo true || echo false)"
    _psf_finish() {
        local rc="$1" line crit=0 warn=0 ok=0 info=0 err=0 text=0 app=null result t1 dur seq=0
        exec 1>&"$_PSF_OUT" 2>&"$_PSF_ERR"
        _psf_out() { local r="${1#"$_PSF_MARK"}"; seq=$((seq + 1)); printf '{"schema":1,"seq":%d,%s\n' "$seq" "${r#\{\"schema\":1,}"; }   # numbered in output order
        local fd="$_PSF_RD"
        while IFS= read -r line <&"$fd" || [[ -n "$line" ]]; do
            if [[ "$line" == "$_PSF_MARK"'{"schema":1,'* ]]; then
                case "$line" in
                    *'"type":"applicable"'*) app=false ;;
                    *'"level":"crit"'*) crit=$((crit + 1)) ;;
                    *'"level":"warn"'*) warn=$((warn + 1)) ;;
                    *'"level":"ok"'*) ok=$((ok + 1)) ;;
                    *'"level":"info"'*) info=$((info + 1)) ;;
                    *'"level":"error"'*) err=$((err + 1)) ;;
                esac
                _psf_out "$line"
            else
                line="${line//$'\036'/}"
                while [[ "$line" =~ $'\e'\[[0-9\;]*[A-Za-z] ]]; do line="${line/"${BASH_REMATCH[0]}"/}"; done
                line="${line#"${line%%[![:space:]]*}"}"; line="${line%"${line##*[![:space:]]}"}"
                [[ -n "$line" ]] || continue
                text=$((text + 1)); _psf_out "$(_psf_rec text "" "$line")"
            fi
        done
        exec {fd}<&-
        case "$rc" in 0) result=clean ;; 1) result=findings ;; *) result=undecided ;; esac
        [[ "$app" == null && $((crit + warn + ok)) -gt 0 ]] && app=true
        t1="${EPOCHREALTIME:-$(date +%s)}"; dur="$(awk -v a="$_PSF_T0" -v b="$t1" 'BEGIN { printf "%.2f", b - a }' 2>/dev/null || echo 0)"
        _psf_out "$(_psf_rec verdict "" "$result" ",\"result\":\"$result\",\"exit\":$rc,\"applicable\":$app,\"duration_s\":$dur,\"counts\":{\"crit\":$crit,\"warn\":$warn,\"ok\":$ok,\"info\":$info,\"error\":$err,\"text\":$text}")"
    }
    _psf_on_exit() {
        local rc=$?
        if [[ -n "$_PSF_EXIT_CMD" ]]; then eval "$_PSF_EXIT_CMD"; fi
        [[ "$BASHPID" == "$_PSF_MAIN_PID" ]] && _psf_finish "$rc"
        exit "$rc"
    }
    # the script's own EXIT traps still run, before the verdict is written
    trap() {
        local action has_exit=0 s rest=()
        # shellcheck disable=SC2064   # the script's own trap arguments, passed on unchanged
        case "${1:-}" in ""|-p|-l) builtin trap "$@"; return ;; esac
        action="$1"; shift
        for s in "$@"; do if [[ "$s" == EXIT || "$s" == 0 ]]; then has_exit=1; else rest+=("$s"); fi; done
        if ((has_exit)); then
            if [[ "$action" == - ]]; then _PSF_EXIT_CMD=""; else _PSF_EXIT_CMD="$action"; fi
            builtin trap _psf_on_exit EXIT
        fi
        # shellcheck disable=SC2064   # the action string the script wrote, passed on as it was given
        ((${#rest[@]})) && builtin trap "$action" "${rest[@]}"
        return 0
    }
    builtin trap _psf_on_exit EXIT
fi
case "$_PSF_CMD" in
    mitigate|rollback|harden|fix|apply|restore|remove|uninstall|install|enable|disable|quarantine|purge|revert|undo)
        psf_refuse_change "$_PSF_CMD" ;;
esac
# ---------- end of structured output and read-only mode ----------

have() { command -v "$1" >/dev/null 2>&1; }
is_root() { [[ "${EUID:-$(id -u)}" -eq 0 ]]; }
SELF_CMD="$(printf '%q ' "$0" "$@")"; SELF_CMD="${SELF_CMD% }"
# limited_view WHAT: a hunt run without root sees only what this account can read. Say so where a reader
# would otherwise take "none" for a clean result. Says nothing when running as root. Always returns 0,
# so it is safe under set -e.
limited_view() {
    is_root && return 0
    if command -v sudo >/dev/null 2>&1; then caution "not running as root: ${1:-files and logs} that belong to other users or to system services may not be readable, so a clean result covers only what this account can see. Run it with sudo: sudo ${SELF_CMD}"
    else caution "not running as root: ${1:-files and logs} that belong to other users or to system services may not be readable, so a clean result covers only what this account can see. Run it as root."; fi
}
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
        out="$(run_found "$b" --version 2>/dev/null || true)"
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
    limited_view
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
