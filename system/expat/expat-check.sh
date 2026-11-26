#!/usr/bin/env bash
# SPDX-License-Identifier: CC0-1.0
# =============================================================================
# libexpat billion laughs detection delay: read-only checker  (v1)
# CVE-2026-115506 (and CVE-2026-113351, CVE-2026-117610, CVE-2026-118370, fixed
# in the same release)
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
#   Affected: libexpat through 2.9.0, that is every release before the fix
#   Fixed:    Expat 2.10.0, released 2 November 2026. The planned 2.9.1 was
#             never released; the fix shipped as 2.10.0 instead.
#
# Expat 2.10.0 also fixes CVE-2026-113351 (denial of service through
# XML_ParserReset), CVE-2026-117610 (a crash on an initial, non-final, empty
# subparser parse call) and CVE-2026-118370 (signed integer overflow of attIndex
# and nPrefixes in storeAtts). The script reports every copy older than 2.10.0
# as affected and 2.10.0 or newer as fixed. Distribution
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
#
# Output and automation (every command):
#   --output jsonl      JSON Lines for programs and language models: a start record,
#                       an event for each finding, a text record for any other line
#                       and a verdict, written when the command ends (format in
#                       automation/README.md; psf-report turns it into Markdown, HTML
#                       or PDF). --output text, the default, is the output above.
#   PSF_READ_ONLY=1     has nothing to refuse here: this tool never changes the host.
# =============================================================================

# Commands run as "cmd_${CMD}", which shellcheck can't follow
# shellcheck disable=SC2317,SC2329
set -uo pipefail

SCRIPT_NAME="expat-check.sh"
SCRIPT_VERSION="1.2.0"
SCRIPT_DATE="2026-11-25"
SELF="$0"
FIXED_VERSION="2.10.0"

# ---------- common helpers (the same block is used in every check script) ----
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
    if ! is_semver "$ver"; then caution "${label}: cannot parse version '${ver}'; treating it as not confirmed fixed"; AFFECTED=$((AFFECTED+1)); return 0; fi
    if ! expat_affected "$ver"; then
        ok "${label}: expat ${ver} is ${FIXED_VERSION} or newer"; return 0
    fi
    if [[ -n "$probe" ]]; then
        if distro_mentions "$probe" CVE-2026-115506 CVE-2026-113351 CVE-2026-117610 CVE-2026-118370; then
            ok "${label}: expat ${ver}, and package ${DISTRO_PKG} changelog mentions ${DISTRO_HIT}: a backported fix is likely"
            return 0
        elif [[ $? -eq 1 ]]; then
            bad "${label}: expat ${ver} is affected; package ${DISTRO_PKG} does not mention the CVE yet"
            AFFECTED=$((AFFECTED+1)); return 0
        fi
    fi
    bad "${label}: expat ${ver} is affected (older than 2.10.0)"
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
  v=$(run_found "$p" -c 'import pyexpat; print(pyexpat.EXPAT_VERSION)' 2>/dev/null | head -n 1)
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

cmd_check() {
    local rc=0 crc=0 _s
    if [[ "${SCAN_CONTAINERS:-1}" == 1 ]]; then
        stage_probe "$EXPAT_PROBE"
        for _s in ${STAGED_DIRS[@]:+"${STAGED_DIRS[@]}"}; do
            container_run "$_s" || crc=1
        done
    fi
    cmd_check_host || rc=$?
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
        v="$(run_found "$p" -c 'import pyexpat; print(pyexpat.EXPAT_VERSION)' 2>/dev/null | sed 's/^expat_//')"
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
        warn "${AFFECTED} affected copy(ies) of ${CHECKED} checked. Expat ${FIXED_VERSION} (2 November 2026) fixes this and three more flaws."
        inf "Install your distribution's expat or libexpat update as soon as it ships, then restart the processes listed above."
        inf "Until then, reduce exposure (PrivacySafe recommendation): cap the size of XML bodies at the proxy, and run services that parse untrusted XML under CPU and memory limits (systemd CPUQuota and MemoryMax) so one request cannot starve the host."
        inf "libexpat exposes tuning calls for its amplification protection, but the upstream notes do not say that tightening them avoids this flaw, so do not rely on that."
        inf "Upstream: https://blog.hartwork.org/posts/expat-2-10-0-released/ (backporters: pull request #1439 in particular)"
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
    echo "CVE-2026-115506 (and three more); fixed in libexpat 2.10.0"
    case "$CMD" in
        check|deep) "cmd_${CMD}" "$@" ;;
        *) die "Unknown command: ${CMD} (check|deep|version)" ;;
    esac
}
main "$@"; exit

# Assisted-by: Claude Sonnet 5.5
