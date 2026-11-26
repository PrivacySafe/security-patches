#!/usr/bin/env bash
# SPDX-License-Identifier: CC0-1.0
# =============================================================================
# Node.js October 2026 mitigation  (v1)
# CVE-2026-111497 (Brotli decoder out-of-bounds write, RCE) and the nine other
# CVEs fixed in Node.js 22.23.4 / 24.22.1 / 26.12.1 on 21 Oct 2026
#
# If this software is helpful, consider a donation to our 501c3 nonprofit:
# https://privacysafe.foundation
#
# Usage:
#   ./node-oct2026-mitigate.sh [command] [--unit NAME]... [--force]
#
#   check (default)  read-only report: every Node runtime on the host (PATH,
#                    nvm, n, fnm, volta, asdf, /opt, running processes,
#                    container images), whether each is fixed, which running
#                    processes still need a restart or a guard. Root optional
#                    (root sees every process). Exit 0 = nothing exposed,
#                    1 = unfixed runtime in use, 2 = something couldn't be read.
#   scan             read-only: find application code and dependencies that
#                    decode Brotli, Node single executable applications (SEAs)
#                    and startup snapshots that must be rebuilt
#                    (CVE-2026-106074). Exit 0 = none, 1 = findings.
#   guard --unit U   load brotli-guard.cjs into systemd unit U through a
#                    drop-in that adds --require to NODE_OPTIONS, restart it,
#                    and prove the guard is live. Rolls back if U won't start.
#   unguard --unit U remove that drop-in and restart U.
#   status           guarded units, their runtime, and what the guard blocked.
#   hunt             read-only: scan the journal and logs for Node crashes
#                    (segfaults, V8 fatal errors, Brotli decoder frames) and
#                    guard events. Exit 0 = clean, 1 = findings.
#
#   --unit NAME      systemd unit for guard/unguard (repeatable; .service
#                    is added if missing)
#   --force          guard: install even if the guard's self-test fails on
#                    the unit's runtime, or the runtime is already fixed
#
# This script never executes a Node binary as root unless root owns it and
# nobody else can write it. Versions are read from the binary's contents, so
# a binary planted in a user's ~/.nvm or inside a container is never run with
# root's privileges.
#
# Env overrides:
#   NODE_FIXED_22=22.23.4 NODE_FIXED_24=24.22.1 NODE_FIXED_26=26.12.1
#                                      first fixed release per line
#   FIXED_BUILDS="20.19.2+dfsg-1+deb13u2"  distro builds known to carry the
#                                      fix (Debian/Ubuntu backport to an
#                                      upstream-EOL line)
#   SCAN_PATHS="/srv /opt /var/www /home /usr/local/lib /usr/lib/node_modules"
#   SCAN_DEPTH=8                       how deep scan descends
#   GUARD_DST=/usr/local/lib/privacysafe/brotli-guard.cjs
#   HUNT_SINCE="2026-10-14"            how far back hunt reads the journal
#   GUARD_SRC=./brotli-guard.cjs       the guard file to install (default: the copy
#                                      next to this script)
#      PSF_LOCK_WAIT    seconds a run that changes the host waits for another one that is already
#                       changing it (default 30), then stops with exit 2; the lock is STATE_DIR/.lock
# =============================================================================

# Commands run as "cmd_${CMD}", which shellcheck can't follow
# shellcheck disable=SC2317,SC2329
set -euo pipefail

# ---------- config -----------------------------------------------------------
CVES=(CVE-2026-111497 CVE-2026-105482 CVE-2026-105483 CVE-2026-106069 CVE-2026-105481
      CVE-2026-106072 CVE-2026-106074 CVE-2026-106070 CVE-2026-106071 CVE-2026-106073)
KEY_CVE="CVE-2026-111497"
declare -A FIXED_DEFAULT=([22]=22.23.4 [24]=24.22.1 [26]=26.12.1)
fixed_for() { local n="NODE_FIXED_$1"; echo "${!n:-${FIXED_DEFAULT[$1]:-}}"; }
FIXED_BUILDS="${FIXED_BUILDS:-}"
SCAN_PATHS="${SCAN_PATHS:-/srv /opt /var/www /home /usr/local/lib /usr/lib/node_modules}"
SCAN_DEPTH="${SCAN_DEPTH:-8}"
HUNT_SINCE="${HUNT_SINCE:-2026-10-14}"
SCRIPT_NAME="node-oct2026-mitigate.sh"
SCRIPT_VERSION="1.1.0"
SCRIPT_DATE="2026-11-25"
SELF="$0"
SELF_DIR="$(cd "$(dirname "$0")" && pwd)"
GUARD_SRC="${GUARD_SRC:-${SELF_DIR}/brotli-guard.cjs}"
GUARD_DST="${GUARD_DST:-/usr/local/lib/privacysafe/brotli-guard.cjs}"
DROPIN_NAME="50-privacysafe-brotli-guard.conf"
MARKER="# managed-by: privacysafe node-oct2026-mitigate"
SEA_FUSE="NODE_SEA_FUSE_fce680ab2cc467b6e072b8b5df1996b2:1"

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
# need_root WHAT [HOW]: stop unless root, and name the sudo command to run instead. HOW ends the
# message (default: offer --dry-run); pass "" for a command that has no dry run.
need_root() {
    local how="${2-, or add --dry-run to see what it would do}" msg
    if is_root; then root_note; return 0; fi
    if command -v sudo >/dev/null 2>&1; then msg="${1}: run it as root, for example: sudo ${SELF_CMD}${how}"
    else msg="${1}: run it as root (sudo is not installed here)${how}"; fi
    die "$msg"
}
# root_note: one line, never a stop, for someone logged in as the root account itself while sudo is
# available. Shown once, only on a terminal, not under sudo or in a container. PSF_NO_ROOT_NOTE=1 hides it.
ROOT_NOTED=0
root_note() {
    [[ $ROOT_NOTED -eq 0 ]] || return 0
    ROOT_NOTED=1
    [[ -z "${PSF_NO_ROOT_NOTE:-}" && -z "${SUDO_USER:-}" && -t 2 && ! -f /.dockerenv ]] || return 0
    command -v sudo >/dev/null 2>&1 && [[ "$(logname 2>/dev/null || true)" == root ]] || return 0
    echo "[!] You are logged in as the root account. Prefer a named admin account and sudo, which records who made the change (PSF_NO_ROOT_NOTE=1 hides this note)." >&2
}
# limited_view WHAT: a hunt run without root sees only what this account can read. Say so where a reader
# would otherwise take "none" for a clean result. Says nothing when running as root. Always returns 0,
# so it is safe under set -e.
limited_view() {
    is_root && return 0
    if command -v sudo >/dev/null 2>&1; then caution "not running as root: ${1:-files and logs} that belong to other users or to system services may not be readable, so a clean result covers only what this account can see. Run it with sudo: sudo ${SELF_CMD}"
    else caution "not running as root: ${1:-files and logs} that belong to other users or to system services may not be readable, so a clean result covers only what this account can see. Run it as root."; fi
}
have_systemd() { [[ -d /run/systemd/system ]] && have systemctl; }

# ---------- versions ---------------------------------------------------------
ver_ge() { [[ "$(printf '%s\n%s\n' "$2" "$1" | sort -V | head -1)" == "$2" ]]; }

# Release builds embed their own version in the headers/source URLs
# ("node-v24.22.0-headers.tar.gz"). Reading it costs a grep and runs nothing.
static_version() {
    local v
    v="$(grep -aoE -m1 'node-v[0-9]+\.[0-9]+\.[0-9]+' "$1" 2>/dev/null | head -1 || true)"
    if [[ -n "$v" ]]; then echo "${v#node-}"; fi
}

# Executing is the fallback, and only for a binary root could trust anyway.
safe_to_exec() {
    local f="$1" d
    [[ -x "$f" ]] || return 1
    [[ "$(stat -Lc %u "$f" 2>/dev/null)" == 0 ]] || return 1
    [[ $(( 8#$(stat -Lc %a "$f") & 8#022 )) -eq 0 ]] || return 1
    d="$(dirname "$(readlink -f "$f")")"
    while [[ "$d" != / ]]; do
        [[ "$(stat -c %u "$d")" == 0 && $(( 8#$(stat -c %a "$d") & 8#022 )) -eq 0 ]] || return 1
        d="$(dirname "$d")"
    done
}

node_version() {   # <binary> -> vX.Y.Z or empty
    local v; v="$(static_version "$1")"
    if [[ -z "$v" ]] && { ! is_root || safe_to_exec "$1"; }; then
        v="$(timeout 5 "$1" --version 2>/dev/null | head -1 || true)"
    fi
    # status 0 even when nothing matched: callers read this in "$(...)" under set -e, and an
    # unreadable runtime must be reported as unknown, not end the whole check
    # keep a pre-release suffix (v24.22.1-pre, -rc.0, -nightly...): patch_state needs to see it
    if [[ "$v" =~ ^v[0-9]+\.[0-9]+\.[0-9]+(-[A-Za-z0-9.+~]+)? ]]; then echo "${BASH_REMATCH[0]}"; fi
}

# "<rc>|<explanation>": rc 0 = fixed, 1 = not fixed, 2 = unknown
patch_state() {   # <vX.Y.Z> [binary path]
    local v="${1#v}" bin="${2:-}" major fixed pkg full cl vb pre=""
    [[ -n "$v" ]] || { echo "2|version unreadable"; return; }
    # a pre-release (24.22.1-pre, -rc.0, -nightly...) is a build made before that release
    vb="${v%%[-+~]*}"
    [[ "$v" =~ ^[0-9]+\.[0-9]+\.[0-9]+[-+~._]?(pre|rc|alpha|beta|dev|nightly|canary|snapshot|preview) ]] && pre=1
    major="${v%%.*}"; fixed="$(fixed_for "$major")"

    # A distro package can carry the fix under the old upstream version, so a
    # dpkg-owned binary is judged on its package first.
    if [[ -n "$bin" ]] && have dpkg-query; then
        pkg="$(dpkg -S "$(readlink -f "$bin")" 2>/dev/null | head -1 | cut -d: -f1 || true)"
        if [[ -n "$pkg" ]]; then
            full="$(dpkg-query -W -f='${Version}' "$pkg" 2>/dev/null || true)"
            local f
            for f in $FIXED_BUILDS; do
                if [[ -n "$full" ]] && dpkg --compare-versions "$full" ge "$f" 2>/dev/null \
                   && [[ "${f%%[-+~]*}" == "${full%%[-+~]*}" ]]; then
                    echo "0|${pkg} ${full} >= fixed build ${f}"; return
                fi
            done
            # Debian splits the runtime into nodejs + libnodeNNN; either changelog counts
            shopt -s nullglob
            for cl in "/usr/share/doc/${pkg}/changelog.Debian.gz" /usr/share/doc/libnode[0-9]*/changelog.Debian.gz; do
                [[ -f "$cl" ]] || continue
                # Only trust a changelog whose newest entry is the installed build
                [[ "$(zcat "$cl" 2>/dev/null | head -1)" == *"(${full})"* ]] || continue
                if zgrep -q "$KEY_CVE" "$cl"; then shopt -u nullglob; echo "0|${pkg} ${full}: changelog lists ${KEY_CVE}"; return; fi
            done
            shopt -u nullglob
        fi
    fi
    if [[ -n "$fixed" ]]; then
        if ver_ge "$vb" "$fixed"; then
            if [[ -n "$pre" && "$vb" == "$fixed" ]]; then echo "2|v${v} is a pre-release build made before ${fixed} was released: it may not carry the fix"
            else echo "0|v${v} >= ${fixed}"; fi
        else echo "1|v${v} < ${fixed}"; fi
        return
    fi
    if [[ -n "${pkg:-}" ]]; then
        echo "1|v${v} (${pkg} ${full}): Node ${major} is end-of-life upstream and the package changelog doesn't list ${KEY_CVE}"
    else
        echo "1|v${v}: Node ${major} is end-of-life upstream. Move to 22.23.4, 24.22.1 or 26.12.1"
    fi
}

state_word() { case "$1" in 0) echo -e "${GREEN}fixed${NC}" ;; 1) echo -e "${RED}NOT fixed${NC}" ;; *) echo -e "${YELLOW}unknown${NC}" ;; esac; }

# ---------- discovery --------------------------------------------------------
# Installed runtimes: PATH, the usual system prefixes, and per-user version
# managers. Prints one resolved path per line.
find_runtimes() {
    local c
    {
        type -a -P node nodejs 2>/dev/null || true
        shopt -s nullglob
        for c in /usr/bin/node /usr/bin/nodejs /usr/local/bin/node /opt/*/bin/node /opt/*/*/bin/node \
                 /usr/local/n/versions/node/*/bin/node /snap/node/current/bin/node \
                 /root/.nvm/versions/node/*/bin/node /home/*/.nvm/versions/node/*/bin/node \
                 /root/.volta/tools/image/node/*/bin/node /home/*/.volta/tools/image/node/*/bin/node \
                 /root/.local/share/fnm/node-versions/*/installation/bin/node \
                 /home/*/.local/share/fnm/node-versions/*/installation/bin/node \
                 /home/*/.fnm/node-versions/*/installation/bin/node \
                 /root/.asdf/installs/nodejs/*/bin/node /home/*/.asdf/installs/nodejs/*/bin/node \
                 /home/*/.local/share/mise/installs/node/*/bin/node; do
            echo "$c"
        done
        shopt -u nullglob
    } | while read -r c; do [[ -x "$c" ]] && readlink -f "$c"; done | sort -u
}

# Running Node processes: "pid|exe|user|unit|guarded|snapshot"
find_procs() {
    local p pid exe base user unit guarded snap env cmd
    for p in /proc/[0-9]*; do
        pid="${p#/proc/}"
        exe="$(readlink "$p/exe" 2>/dev/null)" || continue
        base="$(basename "${exe% (deleted)}")"
        [[ "$base" == node* ]] || continue
        # node, nodejs, node22... or a renamed copy that carries a Node version
        # string (node_exporter and friends don't)
        [[ "$base" =~ ^(node|nodejs)[0-9.]*$ ]] || [[ -n "$(static_version "$p/exe")" ]] || continue
        user="$(stat -c %U "$p" 2>/dev/null || echo '?')"
        unit="$(grep -oE '[^/]+\.(service|scope)' "$p/cgroup" 2>/dev/null | tail -1 || true)"
        env="$(tr '\0' '\n' < "$p/environ" 2>/dev/null | grep -E '^NODE_OPTIONS=' || true)"
        cmd="$(tr '\0' ' ' < "$p/cmdline" 2>/dev/null || true)"
        guarded=0; [[ "$env$cmd" == *brotli-guard* ]] && guarded=1
        snap=0;    [[ "$cmd" == *--snapshot-blob* || "$cmd" == *--build-snapshot* ]] && snap=1
        echo "${pid}|${exe}|${user}|${unit}|${guarded}|${snap}"
    done
}

# Container images that declare NODE_VERSION (the official node images and
# most images built on them). Read from image metadata; nothing is started.
find_images() {
    local rt img env
    for rt in docker podman; do
        have "$rt" || continue
        "$rt" image ls --format '{{.Repository}}:{{.Tag}}' >/dev/null 2>&1 || continue
        "$rt" image ls --format '{{.Repository}}:{{.Tag}}' 2>/dev/null | grep -v '<none>' | sort -u | while read -r img; do
            env="$("$rt" image inspect --format '{{range .Config.Env}}{{println .}}{{end}}' "$img" 2>/dev/null \
                   | sed -n 's/^NODE_VERSION=//p' | head -1)"
            [[ -n "$env" ]] && echo "${rt}|${img}|v${env#v}"
        done
    done
}

# ---------- check ------------------------------------------------------------
cmd_check() {
    local rc_all=0 bin v ps how n
    step "Node.js runtimes on disk"
    is_root || caution "not root: other users' version managers and processes may be hidden"
    local found=0 disk_bad=0
    while read -r bin; do
        [[ -n "$bin" ]] || continue
        found=1
        v="$(node_version "$bin")"
        IFS='|' read -r ps how <<<"$(patch_state "$v" "$bin")"
        if [[ -z "$v" ]]; then
            caution "${bin}: version unreadable (not executed: owner $(stat -Lc %U "$bin"))"
            [[ $rc_all -eq 0 ]] && rc_all=2
            continue
        fi
        if [[ $ps -eq 0 ]]; then ok "${bin}  ${v}  $(state_word 0)  (${how})"
        else
            bad "${bin}  ${v}  $(state_word "$ps")  (${how})"; disk_bad=$((disk_bad + 1))
            # a version that cannot be judged (a pre-release at the fix version) is exit 2, as for an unreadable one
            if [[ "$ps" -eq 2 && $rc_all -eq 0 ]]; then rc_all=2; fi
        fi
    done < <(find_runtimes)
    [[ $found -eq 1 ]] || inf "no Node.js runtime found in the usual places"

    step "Running Node.js processes"
    local pid exe user unit guarded snap vers stale running=0 exposed=0
    while IFS='|' read -r pid exe user unit guarded snap; do
        [[ -n "$pid" ]] || continue
        running=1
        vers="$(node_version "/proc/${pid}/exe")"
        IFS='|' read -r ps how <<<"$(patch_state "$vers" "${exe% (deleted)}")"
        stale=""; [[ "$exe" == *"(deleted)" ]] && stale=" binary replaced on disk since start"
        local where="pid ${pid} (${user}${unit:+, ${unit}})"
        if [[ $ps -eq 0 && -z "$stale" ]]; then
            ok "${where}  ${vers}  $(state_word 0)"
        elif [[ $ps -eq 0 ]]; then
            caution "${where}  ${vers}  fixed, but${stale}: restart it to run the new code"
        elif [[ $guarded -eq 1 ]]; then
            caution "${where}  ${vers:-?}  $(state_word "$ps"), brotli-guard loaded${stale:+;${stale}}"
        else
            bad "${where}  ${vers:-?}  $(state_word "$ps"), no guard${stale:+,${stale}}"
            exposed=1
            if [[ "$unit" == *.service ]]; then
                echo "      fix: upgrade Node, then restart ${unit}. Until then: sudo ${SELF} guard --unit ${unit}"
            else
                echo "      fix: upgrade Node and restart it. Until then: start it with --require=${GUARD_DST}"
            fi
        fi
        [[ $snap -eq 1 ]] && caution "    pid ${pid} uses a startup snapshot: rebuild it with the fixed Node (CVE-2026-106074)"
    done < <(find_procs)
    [[ $running -eq 1 ]] || inf "no running Node.js processes"
    [[ $exposed -eq 1 ]] && rc_all=1

    step "Container images"
    local rt img iv any=0
    if ! have docker && ! have podman; then
        inf "no docker or podman CLI"
    else
        while IFS='|' read -r rt img iv; do
            [[ -n "$img" ]] || continue
            any=1
            IFS='|' read -r ps how <<<"$(patch_state "$iv")"
            if [[ $ps -eq 0 ]]; then ok "${rt} ${img}  ${iv}  $(state_word 0)"
            else bad "${rt} ${img}  ${iv}  $(state_word "$ps"): rebuild on a fixed base image (node:22.23.4 / 24.22.1 / 26.12.1 or later)"; fi
        done < <(find_images)
        [[ $any -eq 1 ]] || inf "no images declaring NODE_VERSION (or no permission to list images). Images that install Node another way aren't detected"
    fi

    step "Other places Node hides"
    inf "Electron apps bundle their own Node: update them through their vendor"
    inf "Single executable applications and startup snapshots: run '${SELF} scan'"
    inf "The fixed releases also update Node's bundled CA store (eMudhra): see system/pki/emudhra-mitigate.sh"

    step "Verdict"
    n=${#CVES[@]}
    case $rc_all in
        0) info "Nothing running is exposed to the ${n} CVEs fixed on 21 Oct 2026"
           [[ $disk_bad -eq 0 ]] || warn "...but ${disk_bad} installed runtime(s) are unfixed. Upgrade them before something starts them" ;;
        1) warn "Unfixed Node is running without a guard. Upgrade first; guard what you can't upgrade today" ;;
        *) warn "Some versions couldn't be read; rerun as root" ;;
    esac
    return "$rc_all"
}

# ---------- scan -------------------------------------------------------------
existing_scan_paths() { local p; for p in $SCAN_PATHS; do [[ -d "$p" ]] && echo "$p"; done; }

cmd_scan() {
    local findings=0
    mapfile -t roots < <(existing_scan_paths)
    [[ ${#roots[@]} -gt 0 ]] || { warn "None of SCAN_PATHS exist: $SCAN_PATHS"; return 0; }

    step "Code that decodes Brotli (CVE-2026-111497 reachability)"
    echo "  Every fetch() on an unfixed runtime is reachable; this finds the other paths."
    local hits
    hits="$(find "${roots[@]}" -maxdepth "$SCAN_DEPTH" -type f \
              \( -name '*.js' -o -name '*.cjs' -o -name '*.mjs' -o -name '*.ts' \) \
              ! -name '*.d.ts' ! -path '*/.git/*' -size -5M -print0 2>/dev/null \
            | xargs -0 -r grep -lE '\b(createBrotliDecompress|brotliDecompress(Sync)?|BrotliDecompress)\b' 2>/dev/null || true)"
    if [[ -z "$hits" ]]; then
        ok "no direct use of the Brotli decoder found under ${roots[*]}"
    else
        findings=1
        # Group by application: own code vs. the dependency that does it
        awk '
            {
                f = $0
                if (match(f, /\/node_modules\//)) {
                    n = split(f, a, "/node_modules/")
                    app = a[1]; rest = a[n]
                    split(rest, b, "/")
                    pkg = (substr(b[1],1,1) == "@") ? b[1] "/" b[2] : b[1]
                    if (!seen[app SUBSEP pkg]++) deps[app] = deps[app] (deps[app] ? ", " : "") pkg
                    apps[app] = 1
                } else {
                    own[f] = 1
                }
            }
            END {
                for (ap in apps) printf "  ! app %s\n      dependencies that decode Brotli: %s\n", ap, deps[ap]
                for (f in own) printf "  ! own code: %s\n", f
            }' <<<"$hits"
        echo "      These decode attacker-controlled bytes if they handle request bodies or fetched"
        echo "      responses. brotli-guard makes them fail safely until Node is upgraded."
    fi

    step "Single executable applications (CVE-2026-106074)"
    local sea seav ps how any=0
    while IFS= read -r -d '' sea; do
        grep -qaF "$SEA_FUSE" "$sea" 2>/dev/null || continue
        any=1; findings=1
        seav="$(static_version "$sea")"
        IFS='|' read -r ps how <<<"$(patch_state "$seav")"
        caution "${sea}  built on ${seav:-unknown Node}  $(state_word "$ps")"
        echo "      Rebuild it with a fixed Node. Its crypto.randomUUID()/randomInt() output may repeat"
        echo "      across runs: rotate any IDs or tokens it generated if they need to be unguessable."
    done < <(find "${roots[@]}" -maxdepth "$SCAN_DEPTH" -type f -perm -u+x -size +20M -print0 2>/dev/null)
    [[ $any -eq 1 ]] || ok "no SEA binaries found"

    step "Startup snapshots (CVE-2026-106074)"
    local snaps=""
    if [[ -d /etc/systemd/system ]]; then
        snaps="$(grep -rlE -- '--(snapshot-blob|build-snapshot)' /etc/systemd/system /lib/systemd/system 2>/dev/null || true)"
    fi
    local pid exe user unit guarded snap
    while IFS='|' read -r pid exe user unit guarded snap; do
        [[ "$snap" == 1 ]] && snaps+=$'\n'"pid ${pid} (${unit})"
    done < <(find_procs)
    snaps="$(sed '/^$/d' <<<"$snaps")"
    if [[ -n "$snaps" ]]; then
        findings=1
        while read -r s; do caution "$s uses --snapshot-blob/--build-snapshot: rebuild the blob with a fixed Node"; done <<<"$snaps"
    else
        ok "no startup snapshots in units or running processes"
    fi
    return "$findings"
}

# ---------- guard ------------------------------------------------------------
need_root_systemd() {
    need_root "$CMD changes the host" ""
    have_systemd || die "$CMD needs systemd. Without it, add --require=${GUARD_DST} to NODE_OPTIONS in the service's own startup script"
}

unit_name() { [[ "$1" == *.* ]] && echo "$1" || echo "$1.service"; }
dropin_path() { echo "/etc/systemd/system/$1.d/${DROPIN_NAME}"; }
main_pid() { systemctl show -p MainPID --value "$1" 2>/dev/null || echo 0; }

# systemd's Environment= as one value per line, quotes resolved
unit_env() {
    systemctl show -p Environment --value "$1" 2>/dev/null | xargs -r -n1 printf '%s\n' 2>/dev/null || true
}

# Escape a value for Environment="..." in a unit file
unit_quote() { local s="$1"; s="${s//\\/\\\\}"; s="${s//\"/\\\"}"; s="${s//%/%%}"; printf '%s' "$s"; }

unit_node_bin() {   # best guess at the node binary the unit runs
    local pid exe c
    pid="$(main_pid "$1")"
    if [[ "$pid" != 0 ]]; then
        exe="$(readlink "/proc/${pid}/exe" 2>/dev/null || true)"
        [[ "$(basename "${exe% (deleted)}")" =~ ^node ]] && { echo "${exe% (deleted)}"; return; }
        # a wrapper (npm, pm2, sh): look at its children
        for c in $(pgrep -P "$pid" 2>/dev/null); do
            exe="$(readlink "/proc/${c}/exe" 2>/dev/null || true)"
            [[ "$(basename "${exe% (deleted)}")" =~ ^node ]] && { echo "${exe% (deleted)}"; return; }
        done
    fi
    exe="$(systemctl show -p ExecStart --value "$1" 2>/dev/null | grep -oE 'path=[^ ;]+' | head -1 | cut -d= -f2)"
    [[ "$(basename "$exe")" =~ ^node ]] && { echo "$exe"; return; }
    command -v node 2>/dev/null || true
}

guard_live() {   # <unit> <since> : guard announced itself, or a process carries it
    local u="$1" since="$2" pid c
    journalctl -u "$u" --since "$since" --no-pager -o cat 2>/dev/null | grep -F '[brotli-guard] active' >/dev/null && return 0
    journalctl -u "$u" --since "$since" --no-pager -o cat 2>/dev/null | grep -F '[brotli-guard] Node' >/dev/null && return 0
    pid="$(main_pid "$u")"
    for c in "$pid" $(pgrep -P "$pid" 2>/dev/null); do
        [[ "$c" != 0 ]] || continue
        tr '\0' '\n' < "/proc/${c}/environ" 2>/dev/null | grep -E '^NODE_OPTIONS=.*brotli-guard' >/dev/null && return 0
    done
    return 1
}

wait_active() {   # <unit> : active and not restart-looping for ~5s
    local u="$1" i n0 n1
    n0="$(systemctl show -p NRestarts --value "$u" 2>/dev/null || echo 0)"
    for i in $(seq 1 20); do
        systemctl is-active --quiet "$u" && break
        sleep 1
        [[ $i -eq 20 ]] && return 1
    done
    sleep 5
    n1="$(systemctl show -p NRestarts --value "$u" 2>/dev/null || echo 0)"
    systemctl is-active --quiet "$u" && [[ "${n1:-0}" == "${n0:-0}" ]]
}

install_guard_file() {
    [[ -f "$GUARD_SRC" ]] || die "brotli-guard.cjs not found next to this script (${GUARD_SRC}). Download it from the same place."
    if [[ -f "$GUARD_DST" ]] && cmp -s "$GUARD_SRC" "$GUARD_DST"; then
        info "Guard already installed: $GUARD_DST"
    else
        install -d -m 0755 -o root -g root "$(dirname "$GUARD_DST")"
        install -m 0644 -o root -g root "$GUARD_SRC" "$GUARD_DST"
        info "Installed $GUARD_DST ($(sha256sum "$GUARD_DST" | cut -c1-16)...)"
    fi
}

guard_one() {
    local u="$1" dp node_bin v ps how uu existing="" e f since
    systemctl cat "$u" >/dev/null 2>&1 || die "unit $u not found"
    dp="$(dropin_path "$u")"
    step "guard $u"

    node_bin="$(unit_node_bin "$u")"
    v=""; [[ -z "$node_bin" ]] || v="$(node_version "$node_bin")"
    IFS='|' read -r ps how <<<"$(patch_state "$v" "$node_bin")"
    info "Runtime: ${node_bin:-unknown} ${v:-?} ($(state_word "$ps"): ${how})"
    if [[ $ps -eq 0 && -z "$FORCE" ]]; then
        info "Already fixed - no guard needed. Restart $u if it predates the upgrade. (--force to guard anyway)"
        return 0
    fi

    # EnvironmentFile= wins over Environment=, so a NODE_OPTIONS there would
    # silently discard ours. Don't pretend to have guarded it.
    for f in $(systemctl show -p EnvironmentFiles --value "$u" 2>/dev/null | grep -oE '^/[^ ]+|[[:space:]]/[^ ]+' | tr -d ' '); do
        if [[ -f "$f" ]] && grep -qE '^[[:space:]]*(export[[:space:]]+)?NODE_OPTIONS=' "$f"; then
            die "$f (an EnvironmentFile of $u) sets NODE_OPTIONS, which would override this drop-in. Add --require=${GUARD_DST} to NODE_OPTIONS in that file and restart $u yourself."
        fi
    done

    install_guard_file

    # Self-test on the unit's own runtime, as the unit's user, before touching it
    uu="$(systemctl show -p User --value "$u" 2>/dev/null)"; uu="${uu:-root}"
    if [[ -n "$node_bin" && -x "$node_bin" ]] && id "$uu" >/dev/null 2>&1; then
        if [[ "$uu" == root ]] && ! safe_to_exec "$node_bin"; then
            caution "Not running the self-test: $node_bin isn't root-owned, and $u runs as root (that is worth fixing on its own)"
        else
            local out; out="$(mktemp)"
            if timeout 30 runuser -u "$uu" -- env -u NODE_OPTIONS "$node_bin" "$GUARD_DST" --self-test >"$out" 2>&1; then
                info "Guard self-test passed on ${v} as ${uu}"
                rm -f "$out"
            else
                sed 's/^/      /' "$out"; rm -f "$out"
                [[ -n "$FORCE" ]] || die "Guard self-test failed on $node_bin. Not installing (--force to install anyway)"
                warn "--force: installing despite the failed self-test"
            fi
        fi
    fi

    while IFS= read -r e; do
        [[ "$e" == NODE_OPTIONS=* ]] && existing="${e#NODE_OPTIONS=}"
    done < <(unit_env "$u")
    if [[ -f "$dp" ]] && grep -qF "$MARKER" "$dp"; then
        # our own earlier drop-in: rebuild from what's underneath it
        existing="${existing//--require=${GUARD_DST}/}"
        existing="$(sed -E 's/[[:space:]]+/ /g; s/^ //; s/ $//' <<<"$existing")"
    elif [[ "$existing" == *brotli-guard* ]]; then
        info "$u already loads a brotli-guard through NODE_OPTIONS; leaving it"
        return 0
    fi
    local want="${existing:+${existing} }--require=${GUARD_DST}"

    mkdir -p "$(dirname "$dp")"
    local prev=""; [[ -f "$dp" ]] && prev="$(cat "$dp")"
    printf '%s\n' "$MARKER" \
        "# Guard for ${KEY_CVE}, written by ${SCRIPT_NAME} ${SCRIPT_VERSION}." \
        "# Remove with: ${SELF} unguard --unit ${u}" \
        "[Service]" \
        "Environment=\"NODE_OPTIONS=$(unit_quote "$want")\"" > "$dp"
    systemctl daemon-reload
    info "Wrote $dp"

    # Don't start a service the admin had stopped
    if ! systemctl is-active --quiet "$u"; then
        info "$u isn't running; the guard loads the next time it starts"
        return 0
    fi
    since="$(date '+%Y-%m-%d %H:%M:%S')"
    systemctl restart "$u" || true
    if ! wait_active "$u"; then
        warn "$u didn't come up cleanly with the guard - rolling back"
        journalctl -u "$u" --since "$since" --no-pager -n 15 2>/dev/null | sed 's/^/      /' || true
        if [[ -n "$prev" ]]; then printf '%s\n' "$prev" > "$dp"; else rm -f "$dp"; fi
        systemctl daemon-reload; systemctl restart "$u" || true
        if wait_active "$u"; then die "Rolled back; $u is running without the guard"; fi
        die "Rolled back, but $u still isn't healthy: journalctl -xeu $u"
    fi
    if guard_live "$u" "$since"; then
        info "$u is running with brotli-guard"
    else
        warn "$u is up, but the guard didn't announce itself and no process carries it."
        echo "      The service may reset NODE_OPTIONS (a wrapper script, pm2, docker). Check: journalctl -u $u | grep brotli-guard"
    fi
    echo "  Watch for blocked callers: ${SELF} status   (each one names the code that tried to decode Brotli)"
}

unguard_one() {
    local u="$1" dp since
    dp="$(dropin_path "$u")"
    step "unguard $u"
    if [[ ! -f "$dp" ]]; then info "No guard drop-in for $u"; return 0; fi
    grep -qF "$MARKER" "$dp" || die "$dp wasn't written by this script; leaving it"
    rm -f "$dp"; rmdir --ignore-fail-on-non-empty "$(dirname "$dp")" 2>/dev/null || true
    systemctl daemon-reload
    since="$(date '+%Y-%m-%d %H:%M:%S')"
    systemctl restart "$u" || true
    wait_active "$u" || die "$u isn't healthy after removing the guard: journalctl -xeu $u"
    if guard_live "$u" "$since"; then warn "$u still loads a guard (NODE_OPTIONS set elsewhere)"
    else info "Guard removed from $u"; fi
    local others; others="$(find /etc/systemd/system -name "$DROPIN_NAME" 2>/dev/null | head -1)"
    [[ -n "$others" ]] || inf "No other unit uses $GUARD_DST; you can delete it"
}

cmd_guard()   { need_root_systemd; [[ ${#UNITS[@]} -gt 0 ]] || die "guard needs --unit NAME"; local u; for u in "${UNITS[@]}"; do guard_one "$(unit_name "$u")"; done; }
cmd_unguard() { need_root_systemd; [[ ${#UNITS[@]} -gt 0 ]] || die "unguard needs --unit NAME"; local u; for u in "${UNITS[@]}"; do unguard_one "$(unit_name "$u")"; done; }

# ---------- status -----------------------------------------------------------
cmd_status() {
    step "Guarded units"
    local dp u node_bin v ps how n any=0
    shopt -s nullglob
    for dp in /etc/systemd/system/*.d/"$DROPIN_NAME"; do
        any=1
        u="$(basename "$(dirname "$dp")")"; u="${u%.d}"
        node_bin="$(unit_node_bin "$u")"; v=""; [[ -z "$node_bin" ]] || v="$(node_version "$node_bin")"
        IFS='|' read -r ps how <<<"$(patch_state "$v" "$node_bin")"
        n="$(journalctl -u "$u" --since "-7d" --no-pager -o cat 2>/dev/null | grep -cF '[brotli-guard] blocked' || true)"
        echo -e "  ${u}: $(systemctl is-active "$u" 2>/dev/null || true), Node ${v:-?} $(state_word "$ps"), ${n:-0} blocked call site(s) in 7 days"
        journalctl -u "$u" --since "-7d" --no-pager -o cat 2>/dev/null | grep -F '[brotli-guard] blocked' | sort | uniq -c | sort -rn | head -5 | sed 's/^/      /' || true
        [[ $ps -eq 0 ]] && echo "      runtime is fixed: ${SELF} unguard --unit ${u}"
    done
    shopt -u nullglob
    [[ $any -eq 1 ]] || inf "no units guarded by this script"
    if [[ -f "$GUARD_DST" ]]; then
        inf "guard file: $GUARD_DST v$(grep -oE "GUARD_VERSION = '[^']+'" "$GUARD_DST" | cut -d"'" -f2)"
        if [[ -f "$GUARD_SRC" ]] && ! cmp -s "$GUARD_SRC" "$GUARD_DST"; then caution "differs from ${GUARD_SRC}; rerun guard to update it"; fi
    fi
}

# ---------- hunt -------------------------------------------------------------
cmd_hunt() {
    step "Hunting for Node.js crashes and guard events since ${HUNT_SINCE}"
    limited_view
    local tmp; tmp="$(mktemp)"; trap 'rm -f "${tmp:-}"; trap - RETURN' RETURN
    if have journalctl; then journalctl --since "$HUNT_SINCE" --no-pager -o short-iso 2>/dev/null >>"$tmp" || true; fi
    local f
    shopt -s nullglob
    for f in /var/log/syslog /var/log/syslog.1 /var/log/kern.log /var/log/kern.log.1 /var/log/messages \
             /root/.pm2/logs/*.log /home/*/.pm2/logs/*.log; do
        [[ -r "$f" ]] && cat "$f" >>"$tmp"
    done
    shopt -u nullglob
    [[ -s "$tmp" ]] || { warn "No readable journal or logs (try as root)"; return 0; }

    local found=0 name re c
    local -a checks=(
        "kernel: node segfault/GPF|(node|nodejs|MainThread)\[[0-9]+\]: (segfault at|general protection|trap invalid opcode)"
        "V8 fatal error|FATAL ERROR: |Fatal error in .*v8|Check failed: "
        "Brotli decoder in a crash or backtrace|BrotliDecoder(DecompressStream|Decompress|State)|brotli/c/dec/"
        "unit killed by SIGSEGV/SIGABRT (any service; check which run Node)|code=dumped, status=(11/SEGV|6/ABRT|7/BUS)"
        "brotli-guard blocked a decode|\[brotli-guard\] blocked|ERR_BROTLI_GUARD_BLOCKED"
    )
    for c in "${checks[@]}"; do
        name="${c%%|*}"; re="${c#*|}"
        local n; n="$(grep -cE "$re" "$tmp" || true)"
        if [[ "${n:-0}" -gt 0 ]]; then
            found=1
            caution "${name}: ${n}"
            grep -E "$re" "$tmp" | tail -3 | cut -c1-220 | sed 's/^/      /'
        else
            ok "${name}: none"
        fi
    done
    echo
    echo "  A hit tells you where to look. A crash in the Brotli decoder on an unfixed runtime is"
    echo "  worth treating as an incident: check what the process could reach (env secrets, DB"
    echo "  credentials, tokens) and rotate them. Guard blocks show what tried to decode Brotli;"
    echo "  from an attacker-reachable route, that's the request to look at."
    return "$found"
}

# ---------- dispatch ---------------------------------------------------------
main() {
CMD="${1:-check}"; [[ $# -gt 0 ]] && shift
UNITS=(); FORCE=""
case "$CMD" in -V|--version|version) echo "${SCRIPT_NAME} ${SCRIPT_VERSION} (${SCRIPT_DATE})"; exit 0 ;; esac
case "$CMD" in -h|--help) awk 'f && /^# =+$/ {exit} f {sub(/^# ?/, ""); print} /^# =+$/ {f=1}' "$SELF"; exit 0 ;; --*) set -- "$CMD" "$@"; CMD=check ;; esac
while [[ $# -gt 0 ]]; do
    case "$1" in
        --unit)   UNITS+=("${2:?--unit needs a unit name}"); shift 2 ;;
        --unit=*) UNITS+=("${1#*=}"); shift ;;
        --force)  FORCE=1; shift ;;
        *) die "Unknown option: $1" ;;
    esac
done
echo "${SCRIPT_NAME} ${SCRIPT_VERSION} (${SCRIPT_DATE}), brotli-guard $(grep -oE "GUARD_VERSION = '[^']+'" "$GUARD_SRC" 2>/dev/null | cut -d"'" -f2 || echo '?') - ${CMD} on $(hostname 2>/dev/null || echo '?') at $(date -u +%FT%TZ)"
case "$CMD" in
    check|scan|guard|unguard|status|hunt) "cmd_${CMD}" ;;
    *) die "Unknown command: $CMD (check|scan|guard|unguard|status|hunt)" ;;
esac
}
# ---------- one change at a time ---------------------------------------------------------------------
# lock_for_change CMDS ARGS...: when a command that changes this host is asked for, and it is not a dry run
# (a * in CMDS stands for the default command, for a tool whose default changes the host),
# run the script again under flock(1), so two runs cannot interleave their changes. The second run waits
# PSF_LOCK_WAIT seconds (default 30) and then stops with exit 2. flock -o leaves the lock with the waiting
# flock process, so a service this script starts does not inherit it and hold it. The lock file is
# STATE_DIR/.lock, or /var/lib/psf-security-patches/<script>/.lock. Without flock (macOS) nothing is locked.
# PSF_LOCK_HELD marks the re-run so it does not lock again: the script sets it, leave it unset.
lock_for_change() {
    [[ -z "${PSF_LOCK_HELD:-}" ]] || return 0
    local lk_cmds=" $1 " lk_arg lk_hit=0 lk_words=0 lk_dir lk_rc; shift
    for lk_arg in "$@"; do
        case "$lk_arg" in --dry-run|-h|--help|help|-V|--version|version) return 0 ;; esac
        [[ "$lk_cmds" == *" $lk_arg "* ]] && lk_hit=1
        case "$lk_arg" in -*) ;; *) lk_words=$((lk_words + 1)) ;; esac
    done
    [[ $lk_words -eq 0 && "$lk_cmds" == *" * "* ]] && lk_hit=1      # no command named, and the default command changes the host
    [[ $lk_hit -eq 1 ]] || return 0
    psf_refuse_change "lock_for_change"
    command -v flock >/dev/null 2>&1 || return 0
    lk_dir="${STATE_DIR:-/var/lib/psf-security-patches/${SCRIPT_NAME%.sh}}"
    { mkdir -p "$lk_dir" && [[ -w "$lk_dir" ]]; } 2>/dev/null || return 0
    lk_rc=0; PSF_LOCK_HELD=1 flock -o -E 99 -w "${PSF_LOCK_WAIT:-30}" "$lk_dir/.lock" "${BASH:-bash}" "$0" "$@" || lk_rc=$?   # || keeps set -e from stopping here
    [[ $lk_rc -eq 99 ]] && die "another run of ${SCRIPT_NAME} that changes this host is still in progress after ${PSF_LOCK_WAIT:-30} seconds (lock: $lk_dir/.lock): wait for it to finish, then run it again"
    exit "$lk_rc"
}
lock_for_change "guard unguard" "$@"

main "$@"; exit

# Assisted-by: Claude Opus 5.5
