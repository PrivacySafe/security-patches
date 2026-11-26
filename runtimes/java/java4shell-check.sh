#!/usr/bin/env bash
# SPDX-License-Identifier: CC0-1.0
# =============================================================================
# Java4Shell: OpenJDK Base64 decoder intrinsic out-of-bounds write, November 2026 (v1)
# CVE-2026-114938 (Oracle CVSS 3.1 8.1; public memory-corruption proof of concept)
#
# If this software is helpful, consider a donation to our 501c3 nonprofit:
# https://privacysafe.foundation
#
# On x86-64 processors with AVX-512 VBMI (Intel Ice Lake or newer, AMD Zen 4 or newer), the JIT's
# fast path for java.util.Base64 decoding can write past the end of its buffer when it decodes
# input an attacker chose. Tokens, authorization headers, SAML and uploads all go through Base64,
# and researchers showed it against Jira, Confluence, Artifactory and Jenkins. ARM servers and
# older x86 processors never take that path.
#
# Affected: Java 17.0.6 and later, 21, 25 and 27 from any vendor without the November 2026 fix,
# and Oracle's Java 8 Performance Pack. Standard Java 8 and 11 are not affected. Fixed (Oracle):
# 17.0.21.1, 21.0.13.1, 25.0.5.1 and 27.0.1.1, 17 November 2026; Corretto, Temurin, Red Hat,
# Ubuntu and Debian builds followed, and a distribution package is judged by its changelog.
#
# Usage:
#   ./java4shell-check.sh [command] [options]
#
#   check (default)  Read-only. Reads this CPU's flags, then every Java runtime:
#                    the ones under /usr/lib/jvm and ROOTS (including the copies
#                    Jira, Confluence, Jenkins and others bundle), and the ones
#                    running now, whose command line and environment also show
#                    whether the workaround flag is in effect. A runtime is
#                    judged by its release file and is never run; a
#                    distribution package also by its changelog. Exit 0 = not
#                    exposed, 1 = an affected runtime on a CPU with AVX-512 VBMI
#                    (or a CPU whose flags could not be read), 2 = a runtime
#                    could not be judged.
#   mitigate [--dry-run] [--restart]   (root) For each running systemd service
#                    whose Java is affected and does not already have it, adds
#                    a drop-in that sets JAVA_TOOL_OPTIONS to the service's own
#                    value plus "-XX:+IgnoreUnrecognizedVMOptions
#                    -XX:-UseBASE64Intrinsics", which turns off only the
#                    vulnerable fast path (the workaround AWS documents; not an
#                    official Oracle one). It takes effect when the service
#                    restarts: add --restart, or restart them yourself. Java
#                    started some other way is listed with the flag to add.
#   rollback [--dry-run] [--restart]   Removes those drop-ins.
#   version          Prints the script version.
#
# Env overrides:
#   ROOTS="/usr/lib/jvm /opt /srv /usr/local /var/lib /home"   where check looks for runtimes
#   MAX_DEPTH=7
#   CPUINFO_FILE=/proc/cpuinfo
#   DROPIN_ROOT=/etc/systemd/system
#   STATE_DIR (default /var/lib/psf-security-patches/java4shell)
#   PSF_LOCK_WAIT      seconds a run that changes the host waits for another (default 30)
#   UNIT_FOR_PID       the service every Java process belongs to (testing only)
# =============================================================================

# shellcheck disable=SC2317,SC2329
set -uo pipefail

SCRIPT_NAME="java4shell-check.sh"
SCRIPT_VERSION="1.1.0"
SCRIPT_DATE="2026-11-25"
SELF="$0"
CVE="CVE-2026-114938"
ROOTS="${ROOTS:-/usr/lib/jvm /opt /srv /usr/local /var/lib /home}"
MAX_DEPTH="${MAX_DEPTH:-7}"
CPUINFO_FILE="${CPUINFO_FILE:-/proc/cpuinfo}"
DROPIN_ROOT="${DROPIN_ROOT:-/etc/systemd/system}"
STATE_DIR="${STATE_DIR:-/var/lib/psf-security-patches/java4shell}"
FLAG="-XX:-UseBASE64Intrinsics"
DROPIN_NAME="90-psf-java4shell.conf"

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; CYAN='\033[0;36m'; NC='\033[0m'
[[ -t 1 ]] || { RED=''; GREEN=''; YELLOW=''; CYAN=''; NC=''; }
info()    { echo -e "${GREEN}[+]${NC} $*"; }
warn()    { echo -e "${YELLOW}[!]${NC} $*"; }
step()    { echo -e "\n${CYAN}=====${NC} $* ${CYAN}=====${NC}"; }
die()     { echo -e "${RED}[-] FATAL:${NC} $*" >&2; exit 2; }
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
have()    { command -v "$1" >/dev/null 2>&1; }
# Temporary files are registered here and removed when the script ends, however it ends.
PSF_TMP=()
trap '[[ ${#PSF_TMP[@]} -eq 0 ]] || rm -f "${PSF_TMP[@]}"' EXIT
is_root() { [[ "${EUID:-$(id -u)}" -eq 0 ]]; }
SELF_CMD="$(printf '%q ' "$0" "$@")"; SELF_CMD="${SELF_CMD% }"
need_root() {
    local how=", or add --dry-run to see what it would do" msg
    if is_root; then root_note; return 0; fi
    if have sudo; then msg="${1}: run it as root, for example: sudo ${SELF_CMD}${how}"
    else msg="${1}: run it as root (sudo is not installed here)${how}"; fi
    die "$msg"
}
ROOT_NOTED=0
root_note() {
    [[ $ROOT_NOTED -eq 0 ]] || return 0
    ROOT_NOTED=1
    [[ -z "${PSF_NO_ROOT_NOTE:-}" && -z "${SUDO_USER:-}" && -t 2 && ! -f /.dockerenv ]] || return 0
    have sudo && [[ "$(logname 2>/dev/null || true)" == root ]] || return 0
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

# ---------- judging a runtime ------------------------------------------------
ver_lt() { [[ "$1" != "$2" && "$(printf '%s\n%s\n' "$1" "$2" | sort -V | head -1)" == "$1" ]]; }
four() {   # "21.0.13.0.3+1-Ubuntu" -> "21.0.13.0"; "21.0.13" -> "21.0.13.0"
    local v="${1%%[+-]*}" a b c d
    IFS=. read -r a b c d _ <<<"$v"
    printf '%s.%s.%s.%s' "${a:-0}" "${b:-0}" "${c:-0}" "${d:-0}"
}
# judge VERSION -> "<rc>|<text>": 0 not affected or fixed, 1 affected, 2 unknown
judge() {
    local raw="$1" v major
    if [[ "$raw" =~ ^1\.8\. || "$raw" =~ ^8u || "$raw" == 8 || "$raw" =~ ^8\. ]]; then
        if [[ "$raw" == *perf* ]]; then echo "1|Java 8 Performance Pack: see Oracle's advisory for its fixed build"; else echo "0|Java 8 is not affected"; fi; return
    fi
    [[ "$raw" =~ ^[0-9]+(\.[0-9]+)* ]] || { echo "2|version '${raw:-?}' could not be read"; return; }
    v="$(four "$raw")"; major="${v%%.*}"
    case "$major" in
        9|10|11) echo "0|Java ${major} is not affected" ;;
        17) if ver_lt "$v" 17.0.6.0; then echo "0|before 17.0.6, not affected"
            elif ver_lt "$v" 17.0.21.1; then echo "1|before 17.0.21.1"; else echo "0|17.0.21.1 or later"; fi ;;
        21) if ver_lt "$v" 21.0.13.1; then echo "1|before 21.0.13.1"; else echo "0|21.0.13.1 or later"; fi ;;
        25) if ver_lt "$v" 25.0.5.1; then echo "1|before 25.0.5.1"; else echo "0|25.0.5.1 or later"; fi ;;
        27) if ver_lt "$v" 27.0.1.1; then echo "1|before 27.0.1.1"; else echo "0|27.0.1.1 or later"; fi ;;
        12|13|14|15|16) echo "0|Java ${major} predates the vulnerable code (and is out of support: move to a supported line)" ;;
        18|19|20|22|23|24|26) echo "1|Java ${major} is out of support and has no fix: move to 21, 25 or 27" ;;
        *) if [[ "$major" -gt 27 ]]; then echo "0|newer than the affected lines"; else echo "2|Java ${major} is not a line the advisory covers"; fi ;;
    esac
}

# A distribution's package can carry the fix under its own version: read its changelog.
backported() {   # <java binary> -> 0 if the owning package's changelog names the CVE
    local bin="$1" pkg doc
    if have dpkg-query; then
        pkg="$(dpkg-query -S "$(readlink -f "$bin")" 2>/dev/null | head -n1 | cut -d: -f1)"
        if [[ -n "$pkg" ]]; then
            for doc in "/usr/share/doc/${pkg}/changelog.Debian.gz" "/usr/share/doc/${pkg%%:*}/changelog.Debian.gz"; do
                [[ -r "$doc" ]] && zcat "$doc" 2>/dev/null | head -n 400 | grep -q "$CVE" && return 0
            done
        fi
    fi
    if have rpm; then
        pkg="$(rpm -qf "$(readlink -f "$bin")" 2>/dev/null | head -n1)"
        [[ -n "$pkg" && "$pkg" != *"not owned"* ]] && rpm -q --changelog "$pkg" 2>/dev/null | head -n 400 | grep -q "$CVE" && return 0
    fi
    return 1
}

# Only the release file is read. A runtime is never run: under /home or /opt it may belong to
# anyone, and running it as root would run their code. -f is false for a link to a FIFO or device.
runtime_version() {   # <java home> -> version from its release file
    local home="$1" v=""
    if [[ -f "$home/release" && -r "$home/release" ]]; then
        v="$(sed -nE 's/^JAVA_RUNTIME_VERSION="?([^"]*)"?.*/\1/p' "$home/release" | head -n1)"
        [[ -n "$v" ]] || v="$(sed -nE 's/^JAVA_VERSION="?([^"]*)"?.*/\1/p' "$home/release" | head -n1)"
    fi
    printf '%s' "$v"
}

VBMI=""   # yes, no or unknown
cpu_check() {
    if [[ ! -r "$CPUINFO_FILE" ]]; then VBMI=unknown; return; fi
    if [[ "$(uname -m 2>/dev/null)" != x86_64 && -z "${CPUINFO_FILE_GIVEN:-}" ]] && ! grep -q '^flags' "$CPUINFO_FILE"; then VBMI=no; return; fi
    if grep -qw avx512vbmi "$CPUINFO_FILE" 2>/dev/null; then VBMI=yes; else VBMI=no; fi
}

N_AFF=0; N_UNK=0; N_MITIGATED=0
AFFECTED_HOMES=" "
judge_home() {   # <java home> <label>
    local home="$1" label="$2" v rc why
    v="$(runtime_version "$home")"
    IFS='|' read -r rc why <<<"$(judge "$v")"
    if [[ $rc -eq 1 ]] && backported "$home/bin/java"; then rc=0; why="the package's changelog names ${CVE}: fixed by the distribution"; fi
    case "$rc" in
        0) inf "${label}  ${v}  (${why})" ;;
        1) N_AFF=$((N_AFF + 1)); AFFECTED_HOMES+="$(readlink -f "$home") "; bad "${label}  ${v:-?}  ${RED}affected${NC} (${why})" ;;
        *) N_UNK=$((N_UNK + 1)); caution "${label}: ${why}" ;;
    esac
    return "$rc"
}

java_homes() {   # every directory with bin/java under ROOTS, once
    local r
    for r in $ROOTS; do [[ -d "$r" ]] && find "$r" -maxdepth "$MAX_DEPTH" -type f -path '*/bin/java' 2>/dev/null; done \
        | while IFS= read -r j; do d="$(dirname "$(dirname "$j")")"; readlink -f "$d"; done | awk '!seen[$0]++'
}
# running JVMs: "pid<TAB>java home<TAB>flag-state"
running_jvms() {
    local p exe home flag
    for p in /proc/[0-9]*; do
        exe="$(readlink "$p/exe" 2>/dev/null)" || continue
        [[ "${exe##*/}" == java ]] || continue
        home="$(dirname "$(dirname "$exe")")"
        # A JVM in a container: its paths are inside the container, which /proc/PID/root shows from here.
        if [[ ! -f "$home/release" && -f "${p}/root${home}/release" ]]; then home="${p}/root${home}"; fi
        flag=no
        if tr '\0' ' ' < "$p/cmdline" 2>/dev/null | grep -q -- "$FLAG"; then flag=yes
        elif tr '\0' '\n' < "$p/environ" 2>/dev/null | grep -E '^(JAVA_TOOL_OPTIONS|JDK_JAVA_OPTIONS|_JAVA_OPTIONS)=' | grep -q -- "$FLAG"; then flag=yes; fi
        printf '%s\t%s\t%s\n' "${p#/proc/}" "$home" "$flag"
    done
}

cmd_check() {
    [[ $# -eq 0 ]] || die "check takes no arguments (set ROOTS to choose where it looks)"
    limited_view "Java runtimes and processes"
    [[ "${CPUINFO_FILE}" != /proc/cpuinfo ]] && CPUINFO_FILE_GIVEN=1
    cpu_check
    step "CPU"
    case "$VBMI" in
        yes) bad "this CPU has AVX-512 VBMI: an affected Java takes the vulnerable path" ;;
        no) inf "this CPU has no AVX-512 VBMI: the vulnerable path is never taken here (a move to another host can change that)" ;;
        *) caution "the CPU flags could not be read: treated as exposed" ;;
    esac
    step "Java runtimes"
    local h n=0
    while IFS= read -r h; do [[ -n "$h" ]] || continue; n=$((n + 1)); judge_home "$h" "$h"; done < <(java_homes)
    [[ $n -gt 0 ]] || inf "no Java runtime under ${ROOTS}"
    step "Running Java processes"
    local pid home flag v rc why m=0
    while IFS=$'\t' read -r pid home flag; do
        [[ -n "$pid" ]] || continue; m=$((m + 1))
        v="$(runtime_version "$home")"; IFS='|' read -r rc why <<<"$(judge "$v")"
        if [[ $rc -eq 1 ]] && backported "$home/bin/java"; then rc=0; fi
        if [[ $rc -eq 1 && $flag == yes ]]; then N_MITIGATED=$((N_MITIGATED + 1)); info "pid ${pid}: ${home} ${v}: affected, but runs with ${FLAG}"
        elif [[ $rc -eq 1 ]]; then
            case "$AFFECTED_HOMES" in *" $(readlink -f "$home") "*) ;; *) N_AFF=$((N_AFF + 1)); AFFECTED_HOMES+="$(readlink -f "$home") " ;; esac
            bad "pid ${pid}: ${home} ${v}: ${RED}affected${NC}, without the workaround flag ($(tr '\0' ' ' < /proc/$pid/cmdline 2>/dev/null | cut -c1-120))"
        else inf "pid ${pid}: ${home} ${v:-?}"; fi
    done < <(running_jvms)
    [[ $m -gt 0 ]] || inf "no Java process running"

    step "Verdict"
    if [[ $N_AFF -gt 0 && "$VBMI" != no ]]; then
        warn "${N_AFF} affected runtime(s) on a CPU that takes the vulnerable path (${CVE}). Update Java (Oracle 17.0.21.1, 21.0.13.1, 25.0.5.1, 27.0.1.1, or your vendor's November build); for a product that bundles its own Java (Jira, Confluence, Jenkins and others), update the product or its bundled runtime. Restart each JVM after updating. Until then: 'sudo ${SELF} mitigate --restart' sets ${FLAG} for running services."
        return 1
    fi
    if [[ $N_AFF -gt 0 ]]; then warn "${N_AFF} affected runtime(s), not exposed on this CPU. Update anyway: a migration, a cluster node or a new instance type can have AVX-512 VBMI."; return 0; fi
    if [[ $N_UNK -gt 0 ]]; then warn "${N_UNK} runtime(s) could not be judged (above)."; return 2; fi
    info "No affected Java runtime found."
    return 0
}

# ---------- mitigate and rollback ---------------------------------------------
RESTART=0
manifest_add() { mkdir -p "$STATE_DIR" && printf '%s\t%s\n' "$1" "$2" >> "$STATE_DIR/manifest"; }
unit_of_pid() { [[ -n "${UNIT_FOR_PID:-}" ]] && { echo "$UNIT_FOR_PID"; return; }; sed -nE 's#.*/([^/]+\.service)$#\1#p' "/proc/$1/cgroup" 2>/dev/null | head -n1; }
cmd_mitigate() {
    local dry=0 a
    for a in "$@"; do case "$a" in --dry-run) dry=1 ;; --restart) RESTART=1 ;; *) die "Unknown option: $a (mitigate [--dry-run] [--restart])" ;; esac; done
    [[ $dry -eq 1 ]] || need_root "mitigate adds systemd drop-ins"
    have systemctl || die "systemctl not found: add ${FLAG} to each JVM's options yourself"
    local pid home flag v rc why unit cur new f units=() others=()
    while IFS=$'\t' read -r pid home flag; do
        [[ -n "$pid" && "$flag" == no ]] || continue
        v="$(runtime_version "$home")"; IFS='|' read -r rc why <<<"$(judge "$v")"
        [[ $rc -eq 1 ]] || continue
        backported "$home/bin/java" && continue
        unit="$(unit_of_pid "$pid")"
        if [[ -z "$unit" ]]; then others+=("pid ${pid} (${home} ${v})"); continue; fi
        case " ${units[*]-} " in *" $unit "*) continue ;; esac
        units+=("$unit")
    done < <(running_jvms)
    step "Services to change"
    if [[ ${#units[@]} -eq 0 ]]; then inf "no running systemd service runs an affected Java without the flag"; fi
    for unit in ${units[@]+"${units[@]}"}; do
        cur="$(systemctl show -p Environment --value "$unit" 2>/dev/null | tr ' ' '\n' | sed -nE 's/^JAVA_TOOL_OPTIONS=//p' | head -n1)"
        if [[ "$cur" == *[\"\\\$\`]* ]]; then caution "${unit}: its JAVA_TOOL_OPTIONS holds quotes or backslashes: add ${FLAG} to it yourself"; continue; fi
        new="${cur:+$cur }-XX:+IgnoreUnrecognizedVMOptions ${FLAG}"
        f="${DROPIN_ROOT}/${unit}.d/${DROPIN_NAME}"
        if [[ $dry -eq 1 ]]; then inf "would write ${f}: Environment=\"JAVA_TOOL_OPTIONS=${new}\""; continue; fi
        mkdir -p "$(dirname "$f")" || { bad "${unit}: cannot create $(dirname "$f")"; continue; }
        printf '# Written by %s %s: workaround for %s until Java is updated. Remove with: %s rollback\n[Service]\nEnvironment="JAVA_TOOL_OPTIONS=%s"\n' \
            "$SCRIPT_NAME" "$SCRIPT_VERSION" "$CVE" "$SCRIPT_NAME" "$new" > "$f"
        manifest_add dropin "$f"
        info "${unit}: ${f}"
    done
    for v in ${others[@]+"${others[@]}"}; do caution "${v}: not a systemd service: add ${FLAG} to its JVM options yourself, then restart it"; done
    if [[ $dry -eq 1 ]]; then info "DRY RUN: nothing was written."; return 0; fi
    [[ ${#units[@]} -eq 0 ]] && return 0
    systemctl daemon-reload 2>/dev/null || bad "systemctl daemon-reload failed"
    if [[ $RESTART -eq 1 ]]; then
        for unit in "${units[@]}"; do if systemctl restart "$unit"; then info "restarted ${unit}"; else bad "${unit} did not restart: run '${SELF} rollback' if the flag is the cause"; fi; done
    else warn "Not in effect until each service restarts: add --restart, or run: systemctl restart ${units[*]}"; fi
    return 0
}
cmd_rollback() {
    local dry=0 a kind f
    for a in "$@"; do case "$a" in --dry-run) dry=1 ;; --restart) RESTART=1 ;; *) die "Unknown option: $a (rollback [--dry-run] [--restart])" ;; esac; done
    local manifest="${STATE_DIR}/manifest"
    [[ -s "$manifest" ]] || { info "Nothing to roll back (no manifest in ${STATE_DIR})"; return 0; }
    [[ $dry -eq 1 ]] || need_root "rollback removes systemd drop-ins"
    local units=()
    while IFS=$'\t' read -r kind f; do
        [[ "$kind" == dropin ]] || continue
        if [[ $dry -eq 1 ]]; then echo "  would remove ${f}"; continue; fi
        rm -f "$f" && info "removed ${f}"; rmdir "$(dirname "$f")" 2>/dev/null || true
        units+=("$(basename "$(dirname "$f")" .d)")
    done < "$manifest"
    [[ $dry -eq 1 ]] && return 0
    mv "$manifest" "${manifest}.rolled-back-$(date +%s)" 2>/dev/null || true
    have systemctl && systemctl daemon-reload 2>/dev/null
    if [[ $RESTART -eq 1 ]]; then for a in ${units[@]+"${units[@]}"}; do systemctl restart "$a" && info "restarted ${a}"; done
    elif [[ ${#units[@]} -gt 0 ]]; then warn "Restart to drop the flag: systemctl restart ${units[*]}"; fi
    return 0
}
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

main() {
    local CMD="${1:-check}"; [[ $# -gt 0 ]] && shift
    case "$CMD" in -V|--version|version) echo "${SCRIPT_NAME} ${SCRIPT_VERSION} (${SCRIPT_DATE})"; exit 0 ;; esac
    case "$CMD" in -h|--help|help) awk 'f && /^# =+$/ {exit} f {sub(/^# ?/,""); print} /^# =+$/ {f=1}' "$SELF"; exit 0 ;; esac
    lock_for_change "mitigate rollback" "$CMD" "$@"
    echo "${SCRIPT_NAME} ${SCRIPT_VERSION} (${SCRIPT_DATE}) - ${CMD} on $(hostname 2>/dev/null || echo '?') at $(date -u +%FT%TZ)"
    echo "${CVE} (Java4Shell): Java 17.0.6+, 21, 25 and 27 on CPUs with AVX-512 VBMI"
    case "$CMD" in
        check) cmd_check "$@" ;;
        mitigate) cmd_mitigate "$@" ;;
        rollback) cmd_rollback "$@" ;;
        *) die "Unknown command: ${CMD} (check|mitigate|rollback|version)" ;;
    esac
}
main "$@"; exit

# Assisted-by: Claude Opus 5.5
