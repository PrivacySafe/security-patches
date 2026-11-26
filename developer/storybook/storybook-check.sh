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
# shellcheck disable=SC2317,SC2329
set -uo pipefail

SCRIPT_NAME="storybook-check.sh"
SCRIPT_VERSION="1.1.0"
SCRIPT_DATE="2026-11-25"
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
have()    { command -v "$1" >/dev/null 2>&1; }


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
            notaffected) caution "${ver} is older than 8.0.0, outside the advisory's range (7.x and earlier are unsupported and not confirmed clear of other issues: update anyway)"; rc=1; continue ;;
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
