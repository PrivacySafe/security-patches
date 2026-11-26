#!/usr/bin/env bash
# SPDX-License-Identifier: CC0-1.0
# =============================================================================
# Zammad session hijack and local privilege escalation: read-only checker  (v2)
# CVE-2026-102489 and CVE-2026-102490
#
# If this software is helpful, consider a donation to our 501c3 nonprofit:
# https://privacysafe.foundation
#
# Zammad is an open-source helpdesk and ticket system. The Dutch Institute for
# Vulnerability Disclosure (DIVD) reported that two previously unknown flaws in Zammad
# were used to breach its own instance, with first access on 21 September 2026. CISA
# added both to the Known Exploited Vulnerabilities catalog on 2 October 2026.
#
#   CVE-2026-102489  CVSS 9.4 (CVSS 4.0, CISA)  A session hijack that leads to remote
#                    code execution as the zammad service user. Exploitable on 6.3.0
#                    through 6.5.4. The same code is present in 7.0.0 through 7.1.3 but
#                    is reported as not exploitable there. Zammad says exploitation is
#                    possible only on 6.5 and older and that 7.0 and later are not
#                    affected. 7.2.0 contains hardening for it.
#   CVE-2026-102490  CVSS 8.5 to 9.4 depending on who scores it  A local privilege
#                    escalation from the zammad user to root. DIVD lists 1.5.0 through
#                    7.1.0-alpha. Zammad disputes the report. It needs code already running as
#                    the zammad user.
#
#   Chained: CVE-2026-102489 gives code as zammad, then CVE-2026-102490 gives root.
#   Zammad's advice is to update to version 7 or take the instance offline.
#
# What this script can and cannot say. It reports the remote chain (CVE-2026-102489)
# from the version. It does NOT claim that any version is fixed for CVE-2026-102490:
# no source confirms a patch.
#
# This script is read-only.
#
# Usage:
#   ./zammad-check.sh [command]
#   check (default)  find Zammad, read its version, report. Exit 0 = the remote chain is
#                    not open, 1 = exposed or unclear.
#   hunt             look for persistence a root compromise would leave: changed
#                    authorized_keys, changed root and zammad crontabs, files owned by root
#                    under the Zammad root, new SUID files. These are indicators of
#                    this campaign. Exit 0 = nothing found, 1 = a lead.
#   version          print the script version.
#
# Env: ZAMMAD_ROOT         the Zammad install directory (default /opt/zammad, /usr/share/zammad)
#      ZAMMAD_HUNT_SINCE   YYYY-MM-DD for the hunt (default 2026-09-21)
#      ZAMMAD_HUNT_HOMES   directories searched for authorized_keys
#                          (default /root /home/zammad /opt/zammad)
#      ZAMMAD_CRON_DIRS    crontab directories (default /var/spool/cron/crontabs /var/spool/cron)
#      SCAN_CONTAINERS=1   (the default) check also reads /opt/zammad/VERSION and
#                          /usr/share/zammad/VERSION inside running docker and podman containers;
#                          0 skips them. The hunt is host-only.
# =============================================================================

# Commands run as "cmd_${CMD}", which shellcheck cannot follow
# shellcheck disable=SC2317,SC2329
set -uo pipefail

SCRIPT_NAME="zammad-check.sh"
SCRIPT_VERSION="2.1.0"
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


# Print the help text: everything between the first two ===== lines of this file.
print_help() { awk 'f && /^# =+$/ {exit} f {sub(/^# ?/,""); print} /^# =+$/ {f=1}' "$SELF"; }
# ---------- version rules ----------------------------------------------------
# prints: chain | old | seven | hardened | prerelease | unknown
#   prerelease a build before a release (7.2.0-pre): not judged as the release
#   chain    6.3.0 to before 7.0.0: the remote session chain is exploitable
#   old      1.5.0 to before 6.3.0: the session flaw does not apply; the local one is reported
#   seven    7.0.0 to before 7.2.0: the session flaw is present but reported not exploitable
#   hardened 7.2.0 or later: hardening for the session flaw; no confirmed fix for the local one
zammad_status() {
    local v; v="$(norm_ver "${1%-pre}")"
    # a pre-release only matters at the 7.2.0 boundary: below it, judge by the version it leads to
    [[ "$1" == *-pre ]] && is_semver "$v" && ver_ge "$v" 7.2.0 && { echo prerelease; return; }
    is_semver "$v" || { echo unknown; return; }
    ver_ge "$v" 7.2.0 && { echo hardened; return; }
    ver_ge "$v" 7.0.0 && { echo seven; return; }
    ver_ge "$v" 6.3.0 && { echo chain; return; }
    ver_ge "$v" 1.5.0 && { echo old; return; }
    echo unknown
}
# Zammad's VERSION file holds just the version (6.5.4); the package version is a fallback
zammad_version_of() {
    local root="$1" v=""
    if [[ -r "$root/VERSION" ]]; then
        v="$(head -n1 "$root/VERSION" 2>/dev/null | grep -oE '[0-9]+\.[0-9]+\.[0-9]+' | head -n1)"
        # a pre-release (7.2.0-pre) is a build before the release, not the release
        head -n1 "$root/VERSION" 2>/dev/null | grep -qiE '^v?[0-9]+\.[0-9]+\.[0-9]+-(pre|alpha|beta|rc)' && [[ -n "$v" ]] && v="${v}-pre"
    fi
    if [[ -z "$v" && -z "${CLABEL[$root]:-}" ]] && have dpkg-query; then v="$(dpkg-query -W -f='${Version}' zammad 2>/dev/null | grep -oE '^[0-9]+\.[0-9]+\.[0-9]+' | head -n1)"; fi
    if [[ -z "$v" && -z "${CLABEL[$root]:-}" ]] && have rpm; then v="$(rpm -q --qf '%{VERSION}' zammad 2>/dev/null | grep -oE '^[0-9]+\.[0-9]+\.[0-9]+' | head -n1)"; fi
    echo "$v"
}
# A Zammad inside a running container: copy its VERSION file into a staging directory so the same
# rules judge it. The package-database fallback is skipped for these, because it describes the host.
ZM_STAGE=""
declare -a CROOTS=()
declare -A CLABEL=()
zammad_container_roots() {
    local rt id name d v s
    [[ "${SCAN_CONTAINERS:-1}" == 1 ]] || return 0
    for rt in docker podman; do
        have "$rt" || continue
        while read -r id name; do
            [[ -n "$id" ]] || continue
            for d in /opt/zammad /usr/share/zammad; do
                v="$("$rt" exec "$id" cat "$d/VERSION" 2>/dev/null | head -n1)" || true
                [[ -n "$v" ]] || continue
                if [[ -z "$ZM_STAGE" ]]; then
                    ZM_STAGE="$(mktemp -d)" || return 0
                    trap 'rm -rf "${ZM_STAGE:-}"' EXIT
                fi
                s="$ZM_STAGE/${rt}_${id}"; mkdir -p "$s"; printf '%s\n' "$v" > "$s/VERSION"
                CROOTS+=("$s"); CLABEL["$s"]="${rt} container ${name:-$id}: ${d}"
                break
            done
        done < <("$rt" ps --format '{{.ID}} {{.Names}}' 2>/dev/null)
    done
}
find_roots() {
    local d
    [[ -n "${ZAMMAD_ROOT:-}" && -d "${ZAMMAD_ROOT}" ]] && echo "${ZAMMAD_ROOT}"
    for d in /opt/zammad /usr/share/zammad; do [[ -d "$d" ]] && echo "$d"; done
}

cmd_check() {
    local rc=0 found=0 ver st root
    step "Looking for Zammad"
    local -a roots=(); local -A seen=()
    while IFS= read -r root; do [[ -n "$root" && -z "${seen[$root]:-}" ]] && { seen[$root]=1; roots+=("$root"); }; done < <(find_roots)
    zammad_container_roots
    for root in "${CROOTS[@]:-}"; do [[ -n "$root" ]] && roots+=("$root"); done
    if [[ ${#roots[@]} -eq 0 ]]; then info "No Zammad installation found on the host or in a running container (set ZAMMAD_ROOT if it is not under /opt/zammad)"; return 0; fi
    for root in "${roots[@]}"; do
        found=$((found+1))
        ver="$(zammad_version_of "$root")"
        step "Zammad ${ver:-unknown} at ${CLABEL[$root]:-$root}"
        [[ -n "$ver" ]] || { caution "could not read a version (looked for ${CLABEL[$root]:-${root}}/VERSION$([[ -n "${CLABEL[$root]:-}" ]] || echo ' and the package database'))"; rc=1; continue; }
        st="$(zammad_status "$ver")"
        case "$st" in
            chain)
                bad "Zammad ${ver} (6.3.0 to 6.5.4 and the 6.x line): CVE-2026-102489, the session hijack that leads to code execution as the zammad user, is exploitable; with CVE-2026-102490 it reaches root"
                inf "update to 7.2.0 or later, or take the instance offline, as Zammad advises"
                rc=1 ;;
            old)
                caution "Zammad ${ver}: CVE-2026-102489 does not apply before 6.3.0, but this release is long unsupported and CVE-2026-102490 (local, disputed) is reported against it: update to 7.2.0 or later"
                rc=1 ;;
            seven)
                caution "Zammad ${ver}: the session flaw is present in the code but reported not exploitable on 7.x, so the remote chain is not open; 7.2.0 adds hardening, update to it"
                inf "CVE-2026-102490 (local privilege escalation) is disputed by the vendor" ;;
            hardened)
                ok "Zammad ${ver} is 7.2.0 or later: it has the hardening for CVE-2026-102489"
                inf "CVE-2026-102490 (local privilege escalation to root, needs code as the zammad user) is disputed by the vendor; the host's own hardening is the control for it" ;;
            prerelease) caution "Zammad ${ver} is a pre-release build, not a release: it may not have the hardening. Update to 7.2.0 or later"; rc=1 ;;
            *)  caution "version '${ver}' could not be compared: update to 7.2.0 or later"; rc=1 ;;
        esac
    done
    step "Verdict"
    if [[ $rc -eq 0 ]]; then info "The remote chain is not open on the Zammad found (${found} checked)."
    else
        warn "Zammad exposed or unclear. Advisory: https://zammad.com/en/advisories/cve-2026-102489-cve-2026-102490"
        inf "If an instance on 6.x was reachable after 21 September 2026, treat it as possibly compromised and run: $0 hunt"
    fi
    return "$rc"
}

cmd_hunt() {
    local rc=0 f d root n since="${ZAMMAD_HUNT_SINCE:-2026-09-21}"
    step "Hunting for persistence a root compromise would leave (changes since ${since})"
    limited_view
    inf "these are indicators of this campaign; DIVD published a log check for it (https://csirt.divd.nl/DIVD-2026-00015)"
    # 1. authorized_keys changed
    local homes="${ZAMMAD_HUNT_HOMES:-/root /home/zammad /opt/zammad}"
    # shellcheck disable=SC2086
    for d in $homes; do
        [[ -d "$d" ]] || continue
        while IFS= read -r f; do
            bad "${f} changed since ${since}: confirm with whoever administers this host"; rc=1
        done < <(find "$d" -xdev -maxdepth 3 -type f \( -name authorized_keys -o -name authorized_keys2 \) -newermt "$since" 2>/dev/null)
    done
    # 2. root and zammad crontabs changed
    local cdirs="${ZAMMAD_CRON_DIRS:-/var/spool/cron/crontabs /var/spool/cron}"
    # shellcheck disable=SC2086
    for d in $cdirs; do
        [[ -d "$d" ]] || continue
        for f in "$d/root" "$d/zammad"; do
            [[ -f "$f" ]] || continue
            n="$(find "$f" -newermt "$since" 2>/dev/null | grep -c .)"
            [[ "${n:-0}" -gt 0 ]] && { bad "${f} changed since ${since}: review its entries"; rc=1; }
        done
    done
    # 3. files owned by root under the Zammad root (it runs as the zammad user)
    local -a roots=(); while IFS= read -r root; do roots+=("$root"); done < <(find_roots)
    for root in "${roots[@]:-}"; do
        [[ -n "$root" ]] || continue
        n="$(find "$root" -xdev -maxdepth 6 -user root -type f -newermt "$since" -not -path '*/tmp/*' -not -path '*/log/*' 2>/dev/null | grep -c .)"
        if [[ "${n:-0}" -gt 0 ]]; then
            inf "${n} file(s) under ${root} owned by root and changed since ${since} (a package update does this too; review):"
            find "$root" -xdev -maxdepth 6 -user root -type f -newermt "$since" -not -path '*/tmp/*' -not -path '*/log/*' 2>/dev/null | head -n 8 | sed 's/^/        /'
        fi
    done
    # 4. SUID files created since
    n="$(find /usr /opt /var /tmp /home /root -xdev -type f -perm -4000 -newermt "$since" 2>/dev/null | grep -c .)"
    if [[ "${n:-0}" -gt 0 ]]; then
        inf "${n} SUID file(s) created or changed since ${since} (system updates replace some; review):"
        find /usr /opt /var /tmp /home /root -xdev -type f -perm -4000 -newermt "$since" 2>/dev/null | head -n 8 | sed 's/^/        /'
    fi
    step "Verdict"
    if [[ $rc -eq 0 ]]; then info "No persistence lead found: none of the published indicators were found."
    else warn "Lead(s) found. If a 6.x instance was reachable after 21 September 2026, treat the host as possibly compromised: restore from a backup taken before that date, rotate every credential Zammad could read, and review accounts."; fi
    return "$rc"
}

main() {
    CMD="${1:-check}"; [[ $# -gt 0 ]] && shift
    case "$CMD" in -V|--version|version) echo "${SCRIPT_NAME} ${SCRIPT_VERSION} (${SCRIPT_DATE})"; exit 0 ;; esac
    case "$CMD" in -h|--help|help) print_help; exit 0 ;; esac
    echo "${SCRIPT_NAME} ${SCRIPT_VERSION} (${SCRIPT_DATE}) - ${CMD} on $(hostname 2>/dev/null || echo '?') at $(date -u +%FT%TZ)"
    echo "CVE-2026-102489 and CVE-2026-102490 (Zammad session hijack to code execution, local privilege escalation)"
    case "$CMD" in
        check) cmd_check "$@" ;;
        hunt)  cmd_hunt "$@" ;;
        *) die "Unknown command: ${CMD} (check|hunt|version)" ;;
    esac
}
main "$@"; exit

# Assisted-by: Claude Sonnet 5.5
