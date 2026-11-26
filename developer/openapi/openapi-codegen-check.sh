#!/usr/bin/env bash
# SPDX-License-Identifier: CC0-1.0
# =============================================================================
# openapi-typescript-codegen code injection, October 2026: read-only checker (v1)
# CVE-2026-108551
#
# If this software is helpful, consider a donation to our 501c3 nonprofit:
# https://privacysafe.foundation
#
# openapi-typescript-codegen (npm, through 0.31.0) copies strings from an
# OpenAPI document into single-quoted JavaScript literals in the TypeScript it
# generates, without escaping them: path keys, parameter names, media types,
# response header names, servers[0].url and info.version. A single quote in
# one of those values ends the literal and the rest runs as code. A value in
# servers[0].url or info.version runs when the generated client is imported;
# a path or parameter name runs when the affected method is called.
#
# The victim is the developer or build job that generates or runs a client
# from a document someone else can influence. It is not a bug in a server.
# The remedy (0.31.0 is the latest release and is affected) is
# to stop using the package, or to stop feeding it documents you do not
# control. This script finds where it is used and checks generated code. It
# changes nothing and never imports, compiles or runs a generated file.
#
# Usage:
#   ./openapi-codegen-check.sh [command] [arguments]
#
#   check (default)  find the package in package.json and lockfiles, in
#                    installed node_modules copies, and the CI jobs, scripts
#                    and Makefiles that run it, flagging inputs fetched from a
#                    URL. Root optional. Exit 0 = not found, 1 = found,
#                    2 = something couldn't be read.
#   scan DIR...      static check of generated TypeScript or JavaScript under
#                    each DIR: a spec-derived value that is not exactly one
#                    well-formed single-quoted literal is reported.
#                    Exit 0 = nothing found, 1 = findings, 2 = bad argument.
#   version          print the script version.
#
# Env overrides:
#   ROOTS="/home /root /srv /var/www /opt /usr/local"
#                         where check looks (default shown). A directory that
#                         does not exist is skipped.
#   MAX_DEPTH=9           how deep check descends under each root
# Containers: with no argument and ROOTS unset, the check also looks in running docker and podman
# containers (SCAN_CONTAINERS=1, the default; 0 skips them). A read-only probe copies the
# package.json and lockfiles that mention the generator, whole, and the installed
# node_modules copy's package.json, into a private temporary directory, and this script runs once
# per container in isolation against that copy. Workflows, Makefiles and shell scripts are not read
# inside containers. Paths shown as .../docker_NAME/... are inside the container NAME.
# =============================================================================

# Commands run as "cmd_${CMD}", which shellcheck can't follow
# shellcheck disable=SC2317,SC2329
set -uo pipefail

CVE="CVE-2026-108551"
PKG="openapi-typescript-codegen"
LAST_AFFECTED="0.31.0"
ROOTS_GIVEN="${ROOTS:+1}"   # ROOTS set by the user means they chose where to look: running containers are then skipped
ROOTS="${ROOTS:-/home /root /srv /var/www /opt /usr/local}"
MAX_DEPTH="${MAX_DEPTH:-9}"
SCRIPT_NAME="openapi-codegen-check.sh"
SCRIPT_VERSION="1.1.0"
SCRIPT_DATE="2026-11-25"
SELF="$0"

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; CYAN='\033[0;36m'; NC='\033[0m'
[[ -t 1 ]] || { RED=''; GREEN=''; YELLOW=''; CYAN=''; NC=''; }
info()    { echo -e "${GREEN}[+]${NC} $*"; }
warn()    { echo -e "${YELLOW}[!]${NC} $*"; }
step()    { echo -e "\n${CYAN}=====${NC} $* ${CYAN}=====${NC}"; }
die()     { echo -e "${RED}[-] FATAL:${NC} $*" >&2; exit 2; }
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

ver_ge() { [[ "$(printf '%s\n%s\n' "$2" "$1" | sort -V | head -1)" == "$2" ]]; }

# ---------- check ------------------------------------------------------------
existing_roots() { local r; for r in $ROOTS; do [[ -d "$r" ]] && echo "$r"; done; }

# Judge one resolved version. Every published release is affected, so only a
# version newer than the last affected one reads as possibly fixed.
judge() {   # <version-or-empty> -> "<rc>|<text>"
    local v="$1"
    if [[ -z "$v" ]]; then echo "2|version unreadable"; return; fi
    if ver_ge "$v" "$LAST_AFFECTED" && [[ "$v" != "$LAST_AFFECTED" ]]; then
        echo "2|${v} is newer than ${LAST_AFFECTED}, the last affected release: check the tracking issue for a fix"
    else
        echo "1|${v} <= ${LAST_AFFECTED}, every release is affected"
    fi
}

report_version() {   # <where> <version>
    local rc why; IFS='|' read -r rc why <<<"$(judge "$2")"
    case $rc in
        1) bad "$1  ${2:-?}  ${RED}exposed${NC}  (${why})"; return 1 ;;
        *) caution "$1  ${2:-?}  ${YELLOW}unknown${NC}  (${why})"; return 2 ;;
    esac
}

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

OPENAPI_PROBE="$(cat <<'EOS'
R="/home /root /srv /var/www /opt /usr/local /app"
PKG="openapi-typescript-codegen"
find $R -maxdepth 9 -type d -name node_modules -prune -o -type f \( -name package.json -o -name package-lock.json -o -name npm-shrinkwrap.json -o -name yarn.lock -o -name pnpm-lock.yaml \) -print 2>/dev/null | head -n 4000 | while read -r f; do
  grep -q "$PKG" "$f" 2>/dev/null && echo "F $f"
done
find $R -maxdepth 11 -type f -path "*/node_modules/$PKG/package.json" 2>/dev/null | head -n 40 | while read -r f; do echo "F $f"; done
exit 0
EOS
)"

container_run() {   # <staged directory> : the generator in one container, judged by this script run in isolation
    local s="$1" out rc
    [[ -n "$(find "$s" -mindepth 1 -maxdepth 1 2>/dev/null | head -n1)" ]] || return 0
    step "openapi-typescript-codegen in a container (${s##*/})"
    out="$(SCAN_CONTAINERS=0 ROOTS="$s" bash "$SELF" check  2>&1)"; rc=$?
    tail -n +3 <<<"$out"
    return "$rc"
}

cmd_check() {
    local rc=0 crc=0 _s
    if [[ -z "${ROOTS_GIVEN:-}" && "${SCAN_CONTAINERS:-1}" == 1 ]]; then
        stage_probe "$OPENAPI_PROBE"
        for _s in ${STAGED_DIRS[@]:+"${STAGED_DIRS[@]}"}; do
            container_run "$_s" || crc=1
        done
    fi
    cmd_check_host || rc=$?
    if [[ $crc -eq 1 && $rc -eq 0 ]]; then rc=1; fi
    return "$rc"
}

cmd_check_host() {
    local rc=0 exposed=0 unknownz=0 f v roots n
    roots="$(existing_roots)"
    [[ -n "$roots" ]] || die "None of the ROOTS exist: ${ROOTS}"

    step "Projects that depend on ${PKG}"

    limited_view "project folders"
    n=0
    while IFS= read -r f; do
        [[ -n "$f" ]] || continue
        grep -q "$PKG" "$f" 2>/dev/null || continue
        n=$((n + 1))
        case "${f##*/}" in
            package.json)
                v="$(grep -oE "\"${PKG}\"[[:space:]]*:[[:space:]]*\"[^\"]*\"" "$f" | head -1 | sed -E 's/.*:[[:space:]]*"([^"]*)"/\1/')"
                if [[ -n "$v" ]]; then
                    bad "${f}  declares ${PKG} ${v}  (every published release is affected)"; exposed=1
                fi ;;
            package-lock.json|npm-shrinkwrap.json)
                v="$(grep -A3 "\"node_modules/${PKG}\"" "$f" | grep -m1 '"version"' | sed -E 's/.*"version"[[:space:]]*:[[:space:]]*"([^"]*)".*/\1/')"
                report_version "$f (lockfile)" "$v"; case $? in 1) exposed=1 ;; 2) unknownz=1 ;; esac ;;
            yarn.lock)
                v="$(grep -A2 -E "^\"?${PKG}@" "$f" | grep -m1 'version' | sed -E 's/.*version:?[[:space:]]*"?([0-9][^"]*)"?.*/\1/')"
                report_version "$f (lockfile)" "$v"; case $? in 1) exposed=1 ;; 2) unknownz=1 ;; esac ;;
            pnpm-lock.yaml)
                v="$(grep -oE "${PKG}@[0-9][0-9A-Za-z.+-]*" "$f" | head -1 | sed -E "s/.*@//")"
                report_version "$f (lockfile)" "$v"; case $? in 1) exposed=1 ;; 2) unknownz=1 ;; esac ;;
        esac
    done < <(while IFS= read -r r; do
                find "$r" -maxdepth "$MAX_DEPTH" -type d -name node_modules -prune -o \
                     -type f \( -name package.json -o -name package-lock.json -o -name npm-shrinkwrap.json \
                                -o -name yarn.lock -o -name pnpm-lock.yaml \) -print 2>/dev/null
             done <<<"$roots")
    [[ $n -gt 0 ]] || inf "no package.json or lockfile under ${roots//$'\n'/ } mentions ${PKG}"

    step "Installed copies"
    n=0
    while IFS= read -r f; do
        [[ -n "$f" ]] || continue
        n=$((n + 1))
        v="$(grep -m1 '"version"' "$f" 2>/dev/null | sed -E 's/.*"version"[[:space:]]*:[[:space:]]*"([^"]*)".*/\1/')"
        report_version "${f%/package.json}" "$v"; case $? in 1) exposed=1 ;; 2) unknownz=1 ;; esac
    done < <(for r in $roots; do
                find "$r" -maxdepth "$((MAX_DEPTH + 2))" -type f -path "*/node_modules/${PKG}/package.json" 2>/dev/null
             done)
    [[ $n -gt 0 ]] || inf "no installed copy under node_modules"
    inf "a global install lives under a prefix such as /usr/local/lib/node_modules; include it in ROOTS if yours is elsewhere"

    step "Jobs and scripts that run the generator"
    n=0
    local line input
    while IFS= read -r line; do
        [[ -n "$line" ]] || continue
        n=$((n + 1))
        input="local input"
        [[ "$line" =~ https?:// ]] && input="${RED}fetches its input from a URL${NC}"
        caution "${line:0:200}   [${input}]"
    done < <(for r in $roots; do
                find "$r" -maxdepth "$MAX_DEPTH" -type d -name node_modules -prune -o -type f \
                     \( -path '*/.github/workflows/*.yml' -o -path '*/.github/workflows/*.yaml' \
                        -o -name .gitlab-ci.yml -o -name Jenkinsfile -o -name Makefile -o -name '*.sh' \
                        -o -name package.json \) -print 2>/dev/null
             done | while IFS= read -r f; do
                grep -HnE "${PKG}|(^|[[:space:]\"'])openapi[[:space:]]+(-i|--input)[[:space:]]" "$f" 2>/dev/null
             done | grep -vE '"(dependencies|devDependencies)"' | grep -vE "\"${PKG}\"[[:space:]]*:" )
    [[ $n -gt 0 ]] || inf "no workflow, Makefile, shell script or package.json script runs the generator"
    [[ $n -eq 0 ]] || inf "a job that regenerates a client from a remote document, or a document anyone else can edit, runs that document's strings as code"

    step "Verdict"
    [[ $exposed -eq 1 ]] && rc=1
    [[ $rc -eq 0 && $unknownz -eq 1 ]] && rc=2
    case $rc in
        0) info "${PKG} was not found where this could read" ;;
        1) warn "${PKG} is in use and ${CVE} is affected in every release. Move to a maintained generator (upstream suggests @hey-api/openapi-ts), or generate only from documents you review and pin, in a job with no secrets. Run '${SELF} scan DIR' on what it generated" ;;
        *) warn "Some copies couldn't be judged; read them by hand or rerun as root" ;;
    esac
    return "$rc"
}

# ---------- scan -------------------------------------------------------------
# The generator writes each spec-derived value inside ONE single-quoted literal
# and nothing else on the line. So rather than look for dangerous characters,
# this accepts only that shape: an opening quote, characters that are not an
# unescaped quote, a closing quote, and an optional trailing comma. Code after
# the closing quote, or a quote in the middle of the value, does not fit.
Q="'"
LIT="${Q}([^${Q}\\\\]|\\\\.)*${Q}"
IDENT='[A-Za-z_$][A-Za-z0-9_$.]*'
VALUE_KEYS='(url|BASE|VERSION|mediaType|responseHeader)'
KEY_OPEN="^[[:space:]]*${VALUE_KEYS}:[[:space:]]*${Q}"
KEY_STRICT="^[0-9]+:[[:space:]]*${VALUE_KEYS}:[[:space:]]*${LIT},?[[:space:]]*\$"
PROP_OPEN="^[[:space:]]*${Q}"
PROP_STRICT="^[0-9]+:[[:space:]]*${LIT}:[[:space:]]*(${LIT}|${IDENT}),?[[:space:]]*\$"

scan_file() {   # <file> -> prints findings, returns 1 if any
    local f="$1" found=1 hit n text reason
    while IFS= read -r hit; do
        [[ -n "$hit" ]] || continue
        n="${hit%%:*}"; text="${hit#*:}"; text="${text#"${text%%[![:space:]]*}"}"
        reason="a value is not exactly one well-formed single-quoted literal"
        bad "${f}:${n}"
        echo "      ${reason}"
        echo "      ${text:0:180}"
        found=0
    done < <( { grep -nE "$KEY_OPEN" "$f" 2>/dev/null | grep -vE "$KEY_STRICT"
                grep -nE "$PROP_OPEN" "$f" 2>/dev/null | grep -vE "$PROP_STRICT" | grep -E "^[0-9]+:[[:space:]]*${Q}[^${Q}]*${Q}?[^:]*:" ; } | sort -t: -k1,1n -u )
    return "$found"
}

cmd_scan() {
    [[ $# -gt 0 ]] || die "scan needs at least one directory"
    local d f total=0 files=0 any=0
    for d in "$@"; do
        [[ -d "$d" ]] || die "Not a directory: ${d}"
    done
    step "Scanning generated code (never imported or run)"
    for d in "$@"; do
        while IFS= read -r f; do
            files=$((files + 1))
            if scan_file "$f"; then any=1; total=$((total + 1)); fi
        done < <(find "$d" -type d -name node_modules -prune -o -type f \
                      \( -name '*.ts' -o -name '*.js' -o -name '*.mjs' -o -name '*.cjs' \) -print 2>/dev/null | sort)
    done
    step "Verdict"
    inf "${files} file(s) read"
    if [[ $any -eq 0 ]]; then
        info "Every checked value is a single well-formed literal"
        inf "This scan reads the shape the generator writes. A clean result covers that generator's output and says nothing about code generated by another tool"
        return 0
    fi
    warn "${total} file(s) have a value that breaks out of its literal. Do not import this output. Treat the OpenAPI document it came from as hostile, find who supplied it, and rotate any secret the generating job could reach"
    return 1
}

# ---------- dispatch ---------------------------------------------------------
main() {
    CMD="${1:-check}"; [[ $# -gt 0 ]] && shift
    case "$CMD" in -V|--version|version) echo "${SCRIPT_NAME} ${SCRIPT_VERSION} (${SCRIPT_DATE})"; exit 0 ;; esac
    case "$CMD" in -h|--help|help) awk 'f && /^# =+$/ {exit} f {sub(/^# ?/, ""); print} /^# =+$/ {f=1}' "$SELF"; exit 0 ;; esac
    echo "${SCRIPT_NAME} ${SCRIPT_VERSION} (${SCRIPT_DATE}) - ${CMD} on $(hostname 2>/dev/null || echo '?') at $(date -u +%FT%TZ)"
    echo "${CVE}; every release through 0.31.0 is affected"
    case "$CMD" in
        check) [[ $# -eq 0 ]] || die "check takes no arguments (set ROOTS to choose where it looks)"; cmd_check ;;
        scan)  cmd_scan "$@" ;;
        *) die "Unknown command: ${CMD} (check|scan|version)" ;;
    esac
}
main "$@"; exit

# Assisted-by: Claude Sonnet 5.5
