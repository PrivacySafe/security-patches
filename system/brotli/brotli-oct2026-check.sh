#!/usr/bin/env bash
# SPDX-License-Identifier: CC0-1.0
# =============================================================================
# Brotli decoder out-of-bounds write, October 2026: read-only checker  (v1)
# CVE-2026-111497
#
# If this software is helpful, consider a donation to our 501c3 nonprofit:
# https://privacysafe.foundation
#
# Known as Broccoli2Shell (first called Node2Shell). Google's Brotli decoder
# (libbrotli / libbrotlidec, 1.0.3 through 1.2.0) can be handed a block switch
# that cannot happen. DecodeBlockTypeAndLength() returned a plain boolean, so
# the caller could not tell a malformed stream from one that needed more input,
# and the fast path ignored the result. The decoder kept appending attacker
# bytes to an eight-byte internal buffer, writing past its end: a crash, a
# memory disclosure, or remote code execution (CWE-252 and CWE-787). The flaw
# is in the upstream C library, and the same CVE has advisories across
# everything that bundles it: Node.js, Bun, Envoy, Istio, the Python brotli and
# brotlicffi bindings, the Ruby and PHP extensions, and OS packages. Some
# people are calling the broadened picture "HTTP2Shell", since any HTTP path
# that decodes untrusted Brotli can be a route to it.
#
# Fixed upstream in Brotli 1.0.10, 1.1.1 and 1.2.1 (the decoder now returns
# BROTLI_DECODER_ERROR_FORMAT_BLOCK_SWITCH, -17). Distributions backport the
# fix into their own libbrotli builds, sometimes under an older version number.
# A copy older than 1.0.3 is outside the advisory's affected range, but this
# script still reports it as not fixed: it is unsupported, so it moves to 1.0.10,
# 1.1.1 or 1.2.1.
#
# This is read-only: it finds what needs updating and judges each against the
# fixes. It does NOT change anything. The fix is to update the library or the
# runtime. There is no host-wide switch to turn Brotli off; disabling Brotli
# decoding is application-specific (reject
# Content-Encoding: br before it is decompressed, turn off automatic Brotli in
# HTTP clients, disable the Brotli decompressor filter in Envoy/Istio). See
# the repository README and https://patchtheplanet.org/brotli
#
# For the Node.js guard (loading a require-hook that refuses to decode),
# use runtimes/node/node-oct2026-mitigate.sh and runtimes/node/brotli-guard.cjs instead. This
# script only reports Node's version.
#
# Usage:
#   ./brotli-oct2026-check.sh [command]
#
#   check (default)  every libbrotli on the host, the running processes that
#                    have libbrotlidec loaded (and any still running a library
#                    that was replaced on disk), the runtimes that bundle their
#                    own Brotli (Node.js, Bun, Python's brotli and brotlicffi,
#                    the Ruby brotli gem, the PHP brotli extension, Envoy,
#                    Istio, cdxgen), and libbrotli inside running containers,
#                    with whether each carries the fix. It also lists other
#                    software on PATH that bundles an unfixed copy (.NET,
#                    DuckDB, ClickHouse); that list is informational. Root
#                    optional. Exit 0 = nothing exposed, 1 = a vulnerable
#                    Brotli is present, 2 = something couldn't be read.
#   hunt             read-only: the journal and logs for process crashes that
#                    look like a Brotli decoder overflow (segfaults with
#                    brotli/BrotliDecoder frames, heap corruption aborts).
#                    Exit 0 = clean, 1 = findings.
#   version          print the script version.
#
# Env overrides:
#   FIXED_BUILDS="1.0.9-2+deb12u2 1.1.0-2ubuntu0.1"
#                                     extra distro libbrotli builds known to
#                                     carry the fix, space-separated full
#                                     versions. Checked alongside a built-in
#                                     list of known builds (Debian 13's
#                                     1.1.0-2+deb13u1), which a value here does
#                                     not replace.
#   BRANCH_FIXED="1.0:1.0.10 1.1:1.1.1 1.2:1.2.1"
#                                     first fixed upstream release per branch
#   RUBY_BROTLI_FIXED="0.9.1"         first fixed Ruby brotli gem
#   PHP_BROTLI_FIXED="0.21.1"         first fixed PHP brotli extension
#   SCAN_CONTAINERS=1                 1 = read libbrotli inside running
#                                     containers (default 1; 0 to skip)
#   HUNT_SINCE="2026-10-01"           how far back hunt reads the journal
#   HUNT_LOGS="/srv/app/log/*.log"    extra log globs for hunt
#   NODE_FIXED="22.23.4 24.22.1 26.12.1"
#                                     first fixed Node.js release per line
#   BUN_FIXED=1.4.4                   first fixed Bun release
#   PYBROTLICFFI_FIXED=1.2.1.0        first fixed pybrotlicffi release
#   ENVOY_FIXED="1.40.0 1.39.3 1.38.6 1.37.8 1.36.12"
#                                     first fixed Envoy release per line
#   ISTIO_FIXED="1.29.9 1.30.6 1.31.2"  first fixed Istio release per line
#   CDXGEN_FIXED="13.5.0 12.8.9"       first fixed cdxgen release per line
# =============================================================================

# Commands run as "cmd_${CMD}", which shellcheck can't follow
# shellcheck disable=SC2317,SC2329
set -euo pipefail

# ---------- config -----------------------------------------------------------
CVE="CVE-2026-111497"
# First fixed upstream release for each minor branch.
declare -A BRANCH_FIXED_DEFAULT=([1.0]=1.0.10 [1.1]=1.1.1 [1.2]=1.2.1)
FIXED_BUILDS="${FIXED_BUILDS:-}"
# Distro builds known to carry the fix under an older-looking upstream number.
# Checked alongside any user-supplied FIXED_BUILDS, so a user override does not
# drop these. Debian 13 (trixie): brotli 1.1.0-2+deb13u1, 23 Oct 2026.
FIXED_BUILDS_KNOWN="1.1.0-2+deb13u1"
CHANGELOG_MARKERS=(CVE-2026-111497)
SCAN_CONTAINERS="${SCAN_CONTAINERS:-1}"
HUNT_SINCE="${HUNT_SINCE:-2026-10-01}"
HUNT_LOGS="${HUNT_LOGS:-}"
# Fixed runtime releases (first fixed per line), for things that bundle Brotli.
NODE_FIXED="${NODE_FIXED:-22.23.4 24.22.1 26.12.1}"
BUN_FIXED="${BUN_FIXED:-1.4.4}"
PYBROTLICFFI_FIXED="${PYBROTLICFFI_FIXED:-1.2.1.0}"
ENVOY_FIXED="${ENVOY_FIXED:-1.40.0 1.39.3 1.38.6 1.37.8 1.36.12}"
ISTIO_FIXED="${ISTIO_FIXED:-1.29.9 1.30.6 1.31.2}"
CDXGEN_FIXED="${CDXGEN_FIXED:-13.5.0 12.8.9}"
RUBY_BROTLI_FIXED="${RUBY_BROTLI_FIXED:-0.9.1}"
PHP_BROTLI_FIXED="${PHP_BROTLI_FIXED:-0.21.1}"
# Date the list of unfixed bundlers in cmd_check was last reviewed.
BUNDLED_REVIEWED="2026-10-25"
SCRIPT_NAME="brotli-oct2026-check.sh"
SCRIPT_VERSION="1.4.0"
SCRIPT_DATE="2026-11-25"
SELF="$0"
UPSTREAM="https://github.com/google/brotli"

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
branch_fixed_for() { local n="${BRANCH_FIXED:-}"; if [[ -n "$n" ]]; then for p in $n; do [[ "${p%%:*}" == "$1" ]] && { echo "${p#*:}"; return; }; done; fi; echo "${BRANCH_FIXED_DEFAULT[$1]:-}"; }

# ---------- libbrotli discovery and versioning -------------------------------
find_libs() {   # <soname-stem> -> resolved paths
    local stem="$1" c
    {
        shopt -s nullglob
        for c in /usr/lib/*/"${stem}".so* /usr/lib/"${stem}".so* /usr/lib64/"${stem}".so* \
                 /usr/local/lib/*/"${stem}".so* /usr/local/lib/"${stem}".so* /lib/*/"${stem}".so* \
                 /opt/*/lib/"${stem}".so* /opt/*/*/lib/"${stem}".so*; do
            echo "$c"
        done
        shopt -u nullglob
        have ldconfig && ldconfig -p 2>/dev/null | grep -oE "/[^ ]*${stem}\.so[^ ]*" || true
    } | while read -r c; do [[ -e "$c" ]] && readlink -f "$c"; done | sort -u
}

# The soname carries the library version (libbrotlidec.so.1.0.9 is 1.0.9). A
# shared object also holds unrelated X.Y.Z strings, so the filename is the
# reliable source. Reading it runs nothing.
lib_version() {   # <path> -> X.Y.Z or empty
    local real base v
    real="$(readlink -f "$1" 2>/dev/null || echo "$1")"
    base="$(basename "$real")"
    v="$(grep -oE '\.so\.[0-9]+\.[0-9]+\.[0-9]+$' <<<"$base" | sed 's/^\.so\.//' || true)"
    [[ -n "$v" ]] || v="$(grep -aoE '^[0-9]+\.[0-9]+\.[0-9]+$' "$real" 2>/dev/null | head -1 || true)"
    echo "$v"
}

owner_pkg() { have dpkg-query || return 0; dpkg -S "$(readlink -f "$1")" 2>/dev/null | head -1 | cut -d: -f1 || true; }

# Judge an upstream X.Y.Z against the per-branch fix. "<rc>|<why>"
upstream_state() {   # <X.Y.Z>
    local v="$1" mm fixed
    [[ -n "$v" ]] || { echo "2|version unreadable"; return; }
    mm="${v%.*}"; fixed="$(branch_fixed_for "$mm")"
    if [[ -n "$fixed" ]]; then
        if ver_ge "$v" "$fixed"; then echo "0|${v} >= ${fixed}"; else echo "1|${v} < ${fixed} (branch ${mm})"; fi
        return
    fi
    # A branch newer than 1.2 shipped after the fixes; older than 1.0 predates them.
    if ver_ge "$v" "1.3.0"; then echo "0|${v} is newer than the fixed releases"
    else echo "1|${v}: branch ${mm} moves to 1.0.10, 1.1.1 or 1.2.1"; fi
}

# A distro package can carry the fix under an older upstream number, so judge a
# dpkg-owned library on its package build first, then on the branch fix.
lib_state() {   # <X.Y.Z> <path>
    local v="$1" p="${2:-}" pkg full f m cl
    [[ -n "$v" ]] || { echo "2|version unreadable"; return; }
    if [[ -n "$p" ]]; then
        pkg="$(owner_pkg "$p")"
        if [[ -n "$pkg" ]]; then
            full="$(dpkg-query -W -f='${Version}' "$pkg" 2>/dev/null || true)"
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
            local rc why; IFS='|' read -r rc why <<<"$(upstream_state "$v")"
            if [[ $rc -eq 0 ]]; then
                # Upstream number is already fixed; a distro at this number is fixed too.
                echo "0|${pkg} ${full} (upstream ${why})"
            else
                echo "1|${pkg} ${full} (upstream ${v} is vulnerable, changelog doesn't name ${CVE}). A backport may exist under this number: check the distro advisory, then add it to FIXED_BUILDS"
            fi
            return
        fi
    fi
    upstream_state "$v"   # self-built or bundled: branch fix only
}

# ---------- runtimes that bundle their own Brotli ----------------------------
# Compare "X.Y.Z" against a space list of first-fixed-per-line releases. The
# release model differs: Node.js and Bun cut a line per MAJOR, Envoy and Istio
# per MAJOR.MINOR. Pass "major" or "minor" so the right fix is matched.
line_key() { [[ "$2" == major ]] && echo "${1%%.*}" || echo "${1%.*}"; }
line_state() {   # <ver> "<fixed...>" [major|minor]
    local v="$1" list="$2" gran="${3:-minor}" key f base pre=""
    [[ -n "$v" ]] || { echo "2|version unreadable"; return; }
    # Text that does not start with a dotted number is unreadable, never "newer than the fix"
    # (version sort ranks non-numeric text after every number)
    [[ "$v" =~ ^([0-9]+(\.[0-9]+)+)(.*)$ ]] || { echo "2|'${v}' is not a version number"; return; }
    base="${BASH_REMATCH[1]}"
    # A pre-release (24.22.1-pre, -rc.0, -nightly..., dev, preview) is a build made before that
    # release: at the fix version itself it may not carry the fix
    [[ "${BASH_REMATCH[3]}" =~ ^[-+~._]?(pre|rc|alpha|beta|dev|nightly|canary|snapshot|preview) ]] && pre=1
    key="$(line_key "$base" "$gran")"
    for f in $list; do
        if [[ "$(line_key "$f" "$gran")" == "$key" ]]; then
            if ver_ge "$base" "$f"; then
                if [[ -n "$pre" && "$base" == "$f" ]]; then echo "2|${v} is a pre-release build made before ${f} was released: it may not carry the fix"
                else echo "0|${v} >= ${f}"; fi
            else echo "1|${v} < ${f}"; fi
            return
        fi
    done
    # Newer than every listed fix is fixed; otherwise no fix for this line.
    local newest; newest="$(tr -s ' \t' '\n' <<<"$list" | sort -V | tail -1)"
    if ver_ge "$base" "$newest"; then
        if [[ -n "$pre" && "$base" == "$newest" ]]; then echo "2|${v} is a pre-release build made before ${newest} was released: it may not carry the fix"
        else echo "0|${v} is newer than ${newest}"; fi
    else echo "1|${v}: line ${key} moves to a fixed line"; fi
}

runtime_report() {   # <label> <version> "<fixed list>" <major|minor> <extra note>
    local label="$1" v="$2" list="$3" gran="${4:-minor}" note="${5:-}" rc why
    [[ -n "$v" ]] || { inf "${label}: not found"; return; }
    IFS='|' read -r rc why <<<"$(line_state "$v" "$list" "$gran")"
    case $rc in
        0) ok "${label} ${v}  $(state_word 0)  (${why})${note:+  ${note}}" ;;
        1) bad "${label} ${v}  $(state_word 1)  (${why})${note:+  ${note}}"; return 1 ;;
        *) caution "${label} ${v}  $(state_word 2)  (${why})" ;;
    esac
    return 0
}

node_versions() {   # prints each node binary's version, one per line
    local c
    { type -a -P node 2>/dev/null || true
      shopt -s nullglob
      for c in /usr/bin/node /usr/local/bin/node /opt/*/bin/node \
               /root/.nvm/versions/node/*/bin/node /home/*/.nvm/versions/node/*/bin/node; do echo "$c"; done
      shopt -u nullglob
    } | while read -r c; do [[ -x "$c" ]] && readlink -f "$c"; done | sort -u | while read -r b; do
        [[ -n "$b" ]] || continue
        v="$(run_found "$b" --version 2>/dev/null | head -n1 | sed 's/^v//' || true)"
        [[ -n "$v" ]] && echo "$v"
    done | sort -uV
}

py_brotli_modules() {   # prints "<module>|<version>" for each importable Python Brotli binding
    have python3 || return 0
    python3 - <<'PY' 2>/dev/null || true
import sys
try:
    from importlib.metadata import version as dist_version
except Exception:
    dist_version = None
for mod, dist in (("brotli", "Brotli"), ("brotlicffi", "brotlicffi")):
    try:
        m = __import__(mod)
    except Exception:
        continue
    # Only the real Brotli codec bindings expose decompress(); skip an
    # unrelated or namespace module that merely shares the name.
    if not hasattr(m, "decompress"):
        continue
    v = getattr(m, "__version__", "") or getattr(m, "version", "")
    if not v and dist_version:
        try:
            v = dist_version(dist)
        except Exception:
            v = ""
    sys.stdout.write("%s|%s\n" % (mod, str(v)))
PY
}

ruby_brotli_versions() {   # prints each installed Ruby brotli gem version, one per line
    have gem || return 0
    { gem list --local '^brotli$' 2>/dev/null || true; } \
        | sed -n -E 's/^brotli \((.*)\)$/\1/p' | tr ',' '\n' | grep -oE '[0-9]+(\.[0-9]+)+' | sort -uV || true
}

php_brotli_version() {   # prints the PHP CLI's brotli extension version, or nothing
    have php || return 0
    php -r '$v = phpversion("brotli"); if ($v !== false) { echo $v; }' 2>/dev/null || true
}

# Processes that have libbrotlidec mapped. A mapping marked (deleted) means the
# library file was replaced after the process started, so the process still
# runs the old code until it is restarted. Other users' maps need root.
mapped_procs() {   # "pid|comm|user|live-or-deleted"
    local m pid comm user st
    shopt -s nullglob
    for m in /proc/[0-9]*/maps; do
        grep -aqE 'libbrotlidec\.so' "$m" 2>/dev/null || continue
        pid="${m#/proc/}"; pid="${pid%/maps}"
        comm="$(tr -d '\n' < "/proc/${pid}/comm" 2>/dev/null || echo '?')"
        user="$(stat -c %U "/proc/${pid}" 2>/dev/null || echo '?')"
        if grep -aE 'libbrotlidec\.so' "$m" 2>/dev/null | grep -a '(deleted)' >/dev/null; then st=deleted; else st=live; fi
        echo "${pid}|${comm}|${user}|${st}"
    done
    shopt -u nullglob
}

# ---------- containers -------------------------------------------------------
container_libs() {   # "runtime|ref|version"
    [[ "$SCAN_CONTAINERS" == 1 ]] || return 0
    local rt id name v
    for rt in docker podman; do
        have "$rt" || continue
        "$rt" ps --format '{{.ID}} {{.Names}}' 2>/dev/null | while read -r id name; do
            [[ -n "$id" ]] || continue
            v="$("$rt" exec "$id" sh -c 'for p in /usr/lib/*/libbrotlidec.so* /usr/lib/libbrotlidec.so* /usr/local/lib/libbrotlidec.so*; do [ -e "$p" ] && { echo "${p##*/libbrotlidec.so.}"; break; }; done' 2>/dev/null | head -1 || true)"
            [[ -n "$v" && "$v" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]] && echo "${rt}|${name:-$id}|${v}"
        done
    done
}

# ---------- check ------------------------------------------------------------
cmd_check() {
    local rc=0 exposed=0 unknownz=0 p v ps how any

    step "libbrotli on the host"
    any=0
    local stem
    for stem in libbrotlidec libbrotlienc libbrotlicommon; do
        while read -r p; do
            [[ -n "$p" ]] || continue
            any=1
            v="$(lib_version "$p")"
            IFS='|' read -r ps how <<<"$(lib_state "$v" "$p")"
            case $ps in
                0) ok "${p}  ${v:-?}  $(state_word 0)  (${how})" ;;
                1) bad "${p}  ${v:-?}  $(state_word 1)  (${how})"; exposed=1 ;;
                *) caution "${p}  ${v:-?}  $(state_word 2)  (${how})"; unknownz=1 ;;
            esac
        done < <(find_libs "$stem")
    done
    if [[ $any -eq 0 ]]; then
        inf "no libbrotli found on the host (it may live only inside a runtime or container, checked below)"
    else
        inf "the decoder (libbrotlidec) is the vulnerable path; libbrotlienc and libbrotlicommon ship from the same package and are shown for completeness"
    fi

    step "Running processes that have libbrotlidec loaded"
    local mpid mcomm muser mst nproc=0 nstale=0
    while IFS='|' read -r mpid mcomm muser mst; do
        [[ -n "$mpid" ]] || continue
        nproc=$((nproc + 1))
        if [[ "$mst" == deleted ]]; then
            nstale=$((nstale + 1))
            bad "${mcomm} (pid ${mpid}, ${muser})  still runs a libbrotlidec that was replaced on disk; restart it to load the new library"
            exposed=1
        elif [[ $nproc -le 15 ]]; then
            inf "${mcomm} (pid ${mpid}, ${muser})  has libbrotlidec loaded"
        fi
    done < <(mapped_procs)
    if [[ $nproc -eq 0 ]]; then inf "no readable process has libbrotlidec loaded"
    elif [[ $nstale -eq 0 ]]; then ok "${nproc} process(es) with libbrotlidec loaded, none running a replaced library"
    fi
    [[ $EUID -eq 0 ]] || inf "not running as root, so other users' processes are not read"
    inf "Node.js, Bun and Python wheels carry their own copy and do not show up here; statically linked programs do not either"

    step "Runtimes that bundle their own Brotli"
    local nv had_node=0
    while read -r nv; do
        [[ -n "$nv" ]] || continue
        had_node=1
        runtime_report "Node.js" "$nv" "$NODE_FIXED" major "guard available: see runtimes/node/node-oct2026-mitigate.sh in this repo" || exposed=1
    done < <(node_versions)
    [[ $had_node -eq 1 ]] || inf "Node.js: not found"

    if have bun; then runtime_report "Bun" "$(bun --version 2>/dev/null | head -1 || true)" "$BUN_FIXED" major || exposed=1; else inf "Bun: not found"; fi

    # Python Brotli bindings. The "brotli" package is versioned per upstream
    # branch; "brotlicffi" carries its own four-part version, fixed at 1.2.1.0.
    # An HTTP client such as urllib3 or requests decodes Content-Encoding: br
    # on its own whenever either binding is importable, so a present binding is
    # a live decode path, not dormant code.
    local dist pv pstate pwhy had_py=0
    while IFS='|' read -r dist pv; do
        [[ -n "$dist" ]] || continue
        had_py=1
        if [[ "$dist" == brotlicffi ]]; then
            if [[ -z "$pv" ]]; then caution "Python brotlicffi (version unreadable)  $(state_word 2)"; unknownz=1
            elif ver_ge "$pv" "$PYBROTLICFFI_FIXED"; then ok "Python brotlicffi ${pv}  $(state_word 0)  (>= ${PYBROTLICFFI_FIXED})"
            else bad "Python brotlicffi ${pv}  $(state_word 1)  (< ${PYBROTLICFFI_FIXED}); upgrade the brotlicffi wheel to ${PYBROTLICFFI_FIXED}"; exposed=1; fi
        else
            IFS='|' read -r pstate pwhy <<<"$(upstream_state "$pv")"
            case $pstate in
                0) ok "Python brotli ${pv}  $(state_word 0)  (${pwhy})" ;;
                1) bad "Python brotli ${pv}  $(state_word 1)  (${pwhy}); upgrade the brotli wheel to 1.2.1"; exposed=1 ;;
                *) caution "Python brotli ${pv}  $(state_word 2)  (${pwhy})"; unknownz=1 ;;
            esac
        fi
    done < <(py_brotli_modules)
    [[ $had_py -eq 1 ]] || inf "Python Brotli bindings (brotli, brotlicffi): not found (or not importable)"

    if have envoy; then runtime_report "Envoy" "$(envoy --version 2>/dev/null | grep -oE '[0-9]+\.[0-9]+\.[0-9]+' | head -1 || true)" "$ENVOY_FIXED" minor "disable the Brotli decompressor filter if you can't upgrade" || exposed=1; else inf "Envoy: not found"; fi
    if have istioctl; then runtime_report "Istio (istioctl)" "$(istioctl version --remote=false 2>/dev/null | grep -oE '[0-9]+\.[0-9]+\.[0-9]+' | head -1 || true)" "$ISTIO_FIXED" minor || exposed=1; else inf "Istio (istioctl): not found"; fi
    if have cdxgen; then runtime_report "cdxgen" "$(cdxgen --version 2>/dev/null | grep -oE '[0-9]+\.[0-9]+\.[0-9]+' | head -1 || true)" "$CDXGEN_FIXED" major "standalone binaries and images bundle Brotli; rebuild them, a version bump alone is not enough" || exposed=1; else inf "cdxgen: not found on PATH"; fi

    local rbv had_rb=0 phpv
    while read -r rbv; do
        [[ -n "$rbv" ]] || continue
        had_rb=1
        runtime_report "Ruby brotli gem" "$rbv" "$RUBY_BROTLI_FIXED" minor "0.9.1 and later bundle Brotli 1.2.1; older releases may link the system libbrotli" || exposed=1
    done < <(ruby_brotli_versions)
    [[ $had_rb -eq 1 ]] || inf "Ruby brotli gem: not found"
    phpv="$(php_brotli_version)"
    if [[ -n "$phpv" ]]; then
        runtime_report "PHP brotli extension (CLI)" "$phpv" "$PHP_BROTLI_FIXED" minor "0.21.1 and later bundle Brotli 1.2.1; restart PHP-FPM or Apache after updating, since the CLI and FPM can load different builds" || exposed=1
    else
        inf "PHP brotli extension: not loaded in the PHP CLI (or php not found)"
    fi

    inf "Bun, Envoy, Istio and cdxgen bundle Brotli; upgrading the runtime is the fix. This script reads only the versions it can reach from the command line"

    step "Other software that bundles its own Brotli (unfixed as of ${BUNDLED_REVIEWED})"
    local bw bcmd bnote any_b=0
    for bw in "dotnet|the .NET runtime bundles 1.1.0" \
              "duckdb|DuckDB bundles an unpatched copy and decodes Brotli Parquet files" \
              "clickhouse|ClickHouse bundles its own fork" \
              "clickhouse-server|ClickHouse bundles its own fork"; do
        bcmd="${bw%%|*}"; bnote="${bw#*|}"
        if have "$bcmd"; then any_b=1; caution "${bcmd} found on PATH: ${bnote}; see system/brotli/README.md for the fixed releases"; fi
    done
    [[ $any_b -eq 1 ]] || inf "none of dotnet, duckdb or clickhouse found on PATH"
    inf "This list is informational and does not change the exit code. Many more projects vendor a copy; system/brotli/README.md lists the ones known so far"

    step "libbrotli inside running containers"
    if [[ "$SCAN_CONTAINERS" != 1 ]]; then
        inf "container scan disabled (SCAN_CONTAINERS=0)"
    elif ! have docker && ! have podman; then
        inf "no docker or podman CLI"
    else
        local rt ref cv any_c=0
        while IFS='|' read -r rt ref cv; do
            [[ -n "$ref" ]] || continue
            any_c=1
            IFS='|' read -r ps how <<<"$(upstream_state "$cv")"
            case $ps in
                0) ok "${rt} ${ref}  libbrotlidec ${cv}  $(state_word 0)  (${how})" ;;
                1) bad "${rt} ${ref}  libbrotlidec ${cv}  $(state_word 1)  (${how}); rebuild the image, a restart won't change the library"; exposed=1 ;;
                *) caution "${rt} ${ref}  libbrotlidec ${cv}  $(state_word 2)  (${how})"; unknownz=1 ;;
            esac
        done < <(container_libs)
        [[ $any_c -eq 1 ]] || inf "no running container exposes a readable libbrotlidec (or no permission to exec in them)"
    fi

    step "Verdict"
    [[ $exposed -eq 1 ]] && rc=1
    [[ $rc -eq 0 && $unknownz -eq 1 ]] && rc=2
    case $rc in
        0) info "No vulnerable Brotli found where this could read one" ;;
        1) warn "A vulnerable Brotli is present. Update libbrotli (and the runtimes that bundle it), rebuild anything that bundles it, and restart. Upstream: ${UPSTREAM} (update your distro/package, don't vendor it). Until a fixed build reaches you, disable Brotli decoding of untrusted data" ;;
        *) warn "Some builds couldn't be judged. For a dpkg build, confirm against the distro advisory and add it to FIXED_BUILDS. Rerun as root to read more" ;;
    esac
    return "$rc"
}

# ---------- hunt -------------------------------------------------------------
cmd_hunt() {
    step "Hunting for Brotli decoder crashes since ${HUNT_SINCE}"
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
             /var/log/nginx/*.log /var/log/apache2/*.log /srv/*/log/*.log /var/www/*/log/*.log $HUNT_LOGS; do
        for f in $g; do [[ -r "$f" && -f "$f" ]] && files+=("$f"); done
    done
    shopt -u nullglob
    [[ ${#files[@]} -gt 0 ]] || { warn "No readable journal or logs (try as root, or set HUNT_LOGS)"; return 0; }
    inf "reading ${#files[@]} source(s)"

    local found=0 name re c n
    local -a checks=(
        "Brotli decoder frames in a crash/backtrace|(libbrotlidec|BrotliDecoder|brotli_decode|BrotliDecompress|ProcessCommands|SafeDecodeInternal)"
        "process segfault or protection fault|(segfault at|general protection|trap invalid opcode)"
        "heap corruption abort|(double free or corruption|free\(\): invalid (pointer|size)|malloc\(\): (corrupted|unaligned)|corrupted size vs\. prev_size|stack smashing detected)"
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
    echo "  A hit tells you where to look: plenty of things segfault. A crash with Brotli decoder frames"
    echo "  on a vulnerable build, especially on a service that decompresses untrusted Brotli, is worth"
    echo "  treating as an incident: check what the process could reach (secrets, database credentials,"
    echo "  tokens) and rotate them."
    return "$found"
}

# ---------- dispatch ---------------------------------------------------------
main() {
CMD="${1:-check}"; [[ $# -gt 0 ]] && shift
case "$CMD" in -V|--version|version) echo "${SCRIPT_NAME} ${SCRIPT_VERSION} (${SCRIPT_DATE})"; exit 0 ;; esac
case "$CMD" in -h|--help) awk 'f && /^# =+$/ {exit} f {sub(/^# ?/, ""); print} /^# =+$/ {f=1}' "$SELF"; exit 0 ;; esac
[[ $# -eq 0 ]] || die "Unknown option: $1"
echo "${SCRIPT_NAME} ${SCRIPT_VERSION} (${SCRIPT_DATE}) - ${CMD} on $(hostname 2>/dev/null || echo '?') at $(date -u +%FT%TZ)"
echo "${CVE}; upstream: ${UPSTREAM}"
case "$CMD" in
    check|hunt) "cmd_${CMD}" ;;
    *) die "Unknown command: $CMD (check|hunt|version)" ;;
esac
}
main "$@"; exit

# Assisted-by: Claude Opus 5.5
