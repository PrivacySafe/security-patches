#!/usr/bin/env bash
# SPDX-License-Identifier: CC0-1.0
# =============================================================================
# Apache Pulsar October 2026: read-only checker  (v1)
# CVE-2026-105869 (broker, forged JWT roles, critical 9.2)
# CVE-2026-105942 (broker, proxied requests, high 7.7)
# CVE-2026-105944 (Pulsar Manager, missing authentication, CVSS 10, retired)
#
# If this software is helpful, consider a donation to our 501c3 nonprofit:
# https://privacysafe.foundation
#
# BROKER. The Apache Pulsar PMC published 14 advisories on 21 October 2026, all fixed in
# 4.0.14, 4.2.5 and 5.0.0. This script covers two that depend on configuration:
#
#   CVE-2026-105869  2.8.1 before 4.0.14, and 4.1.0 before 4.2.5. With
#                    MultiRolesTokenAuthorizationProvider and a NON-EMPTY
#                    anonymousUserRole, HTTP and WebSocket requests whose credentials
#                    FAIL authentication fall back to the anonymous role, and the
#                    provider then authorizes them with the roles listed in the
#                    UNVERIFIED bearer token. A forged or unsigned token can claim a
#                    superuser role. The binary protocol is not affected.
#   CVE-2026-105942  2.8.1 before 4.0.14, and 4.1.0 before 4.2.5. For requests a proxy
#                    sends on behalf of a user, the broker authorized the original
#                    principal with the proxy's own authentication data: with
#                    MultiRolesTokenAuthorizationProvider the user gains the roles in
#                    the proxy's token, and, whatever the provider, the tenant admin
#                    check of a proxied admin REST request passed without checking the
#                    original principal when the proxy role was a tenant admin.
#                    Only relevant when a proxy role is configured (proxyRoles).
#
# Neither is reachable on a default broker: authentication, authorization,
# anonymousUserRole and proxyRoles are all off or empty by default.
# The other twelve advisories in the same announcement are fixed by the same
# upgrade; they are not counted separately here.
#
# PULSAR MANAGER. CVE-2026-105944 (CVSS 10): in 0.3.0 and later anyone who can reach
# Pulsar Manager over the network can take full control of it (the call that creates the
# first administrator is available without authentication and stays available after
# setup), and in all versions, when it holds an HTTP authentication credential for a
# cluster, any user who can reach it can perform the admin operations that credential
# permits and can have it send the credential to a host of their choosing. Affected:
# 0.1.0 through 0.4.0, which is every release. The Pulsar PMC has RETIRED it: there is no
# fix and there will not be one. The advice is to stop using it and remove it.
#
# This script is read-only. It finds Pulsar brokers (by their jars), reads their
# broker.conf and standalone.conf, scans configuration files, compose files, Helm values
# and env files for the exposing settings, and looks for Pulsar Manager (jars, running
# processes, listeners on 7750 and 9527, container images). It does not open the
# container images: for containers it reads the files beside them and tells you to
# check the tag.
#
# Usage:
#   ./pulsar-check.sh [command] [DIR ...]
#
#   check (default)  scan DIR (default /opt /srv /usr/local /var/lib /etc /home /root).
#                    Exit 0 = nothing exposed, 1 = an affected broker with an exposing
#                    configuration, an exposing configuration of unknown version, or
#                    Pulsar Manager present.
#   version          print the script version.
# Containers: with no argument the check also looks in running docker and podman containers
# (SCAN_CONTAINERS=1, the default; 0 skips them). A read-only probe copies the broker jar names
# (empty files, only the name carries the version) and, from each configuration file, only the lines
# that mention authorizationProvider, anonymousUserRole, authorizationEnabled or proxyRoles, so
# tokens and secret keys never leave the container. This script then runs once per container in
# isolation against that copy. Paths shown as .../docker_NAME/... are inside the container NAME.
# =============================================================================

# Commands run as "cmd_${CMD}", which shellcheck can't follow
# shellcheck disable=SC2317,SC2329
set -uo pipefail

SCRIPT_NAME="pulsar-check.sh"
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


# Print the help text: everything between the first two ===== lines of this file.
print_help() { awk 'f && /^# =+$/ {exit} f {sub(/^# ?/,""); print} /^# =+$/ {f=1}' "$SELF"; }

# ---------- version rule (broker) --------------------------------------------
# prints: vulnerable | fixed | unknown
pulsar_status() {
    local n; n="$(norm_ver "$1")"; is_semver "$n" || { echo unknown; return; }
    local maj="${n%%.*}" rest min pat
    rest="${n#*.}"; min="${rest%%.*}"; pat="${rest#*.}"
    (( maj < 4 )) && { echo vulnerable; return; }
    if (( maj == 4 )); then
        case "$min" in
            0) (( pat < 14 )) && echo vulnerable || echo fixed ;;
            1) echo vulnerable ;;
            2) (( pat < 5 )) && echo vulnerable || echo fixed ;;
            *) echo fixed ;;
        esac
        return
    fi
    echo fixed
}

# ---------- configuration ----------------------------------------------------
# A setting appears as key=value (broker.conf, env files), key: value (YAML) or
# PULSAR_PREFIX_key=value. These helpers read one file and ignore comment lines.
conf_lines() { grep -vE '^[[:space:]]*#' "$1" 2>/dev/null; }
# Every test below reads all of its input (grep without -q, output discarded). With
# pipefail, a pipeline ending in "grep -q" can report a miss when grep exits at its
# first match and the producer dies of SIGPIPE, which happens on large files.
setting_nonempty() {   # file, key -> 0 if the key is set to a non-empty value
    conf_lines "$1" | grep -E "(^|[^A-Za-z0-9]|PULSAR_PREFIX_)${2}[\"']?[[:space:]]*[:=][[:space:]]*[\"']?[A-Za-z0-9_.@:/,-]+" >/dev/null
}
setting_true() { conf_lines "$1" | grep -E "(^|[^A-Za-z0-9]|PULSAR_PREFIX_)${2}[\"']?[[:space:]]*[:=][[:space:]]*[\"']?true" >/dev/null; }
uses_multiroles() { conf_lines "$1" | grep -E "authorizationProvider[\"']?[[:space:]]*[:=].*MultiRolesTokenAuthorizationProvider" >/dev/null; }

# prints a one-line summary of what a configuration file exposes: 105869 and/or 105942
conf_exposure() {
    local f="$1" out=""
    if uses_multiroles "$f" && setting_nonempty "$f" anonymousUserRole && setting_true "$f" authorizationEnabled; then out+="105869 "; fi
    if setting_nonempty "$f" proxyRoles && setting_true "$f" authorizationEnabled; then out+="105942 "; fi
    echo "$out"
}

# ---------- listeners --------------------------------------------------------
listeners_on() {   # port(s) -> prints "addr (loopback only|reachable from the network)" lines
    have ss || return 0
    local p addr line
    while read -r line; do
        addr="$(awk '{print $4}' <<<"$line")"
        for p in "$@"; do
            [[ "$addr" == *":${p}" ]] || continue
            case "$addr" in
                127.0.0.1:*|"[::1]:"*) echo "${addr} (loopback only)" ;;
                *) echo "${addr} (reachable from the network)" ;;
            esac
        done
    done < <(ss -H -ltn 2>/dev/null)
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

PULSAR_PROBE="$(cat <<'EOS'
R="/opt /srv /usr/local /var/lib /etc /home /root /pulsar /app"
KEYS="authorizationProvider|anonymousUserRole|authorizationEnabled|proxyRoles"
find $R -xdev -maxdepth 9 -type f \( -name "pulsar-broker-[0-9]*.jar" -o -name "org.apache.pulsar-pulsar-broker-[0-9]*.jar" -o -name "pulsar-manager*.jar" -o -path "*pulsar-manager/bin/pulsar-manager" \) 2>/dev/null | head -n 40 | while read -r f; do echo "E $f"; done
find $R -xdev -maxdepth 9 -type f \( -name "broker.conf" -o -name "standalone.conf" \) -size -2000k 2>/dev/null | head -n 40 | while read -r f; do
  v=$(grep -E "$KEYS" "$f" 2>/dev/null)
  [ -n "$v" ] || v="# none of the settings this check reads"
  echo "B $f $(printf '%s\n' "$v" | base64 | tr -d '\n')"
done
find $R -xdev -maxdepth 9 -type f \( -name "docker-compose*.yml" -o -name "docker-compose*.yaml" -o -name "compose*.yml" -o -name "compose*.yaml" -o -name "values*.yaml" -o -name "values*.yml" -o -name "*.env" \) -not -path "*/node_modules/*" -size -2000k 2>/dev/null | head -n 100 | while read -r f; do
  v=$(grep -E "$KEYS" "$f" 2>/dev/null)
  [ -n "$v" ] && echo "B $f $(printf '%s\n' "$v" | base64 | tr -d '\n')"
done
exit 0
EOS
)"

container_run() {   # <staged directory> : Pulsar in one container, judged by this script run in isolation
    local s="$1" out rc
    [[ -n "$(find "$s" -mindepth 1 -maxdepth 1 2>/dev/null | head -n1)" ]] || return 0
    step "Apache Pulsar in a container (${s##*/})"
    out="$(SCAN_CONTAINERS=0 bash "$SELF" check "$s" 2>&1)"; rc=$?
    tail -n +3 <<<"$out"
    return "$rc"
}

# shellcheck disable=SC2120
cmd_check() {
    local rc=0 crc=0 _s
    if [[ $# -eq 0 && "${SCAN_CONTAINERS:-1}" == 1 ]]; then
        stage_probe "$PULSAR_PROBE"
        for _s in ${STAGED_DIRS[@]:+"${STAGED_DIRS[@]}"}; do
            container_run "$_s" || crc=1
        done
    fi
    cmd_check_host "$@" || rc=$?
    if [[ $crc -eq 1 && $rc -eq 0 ]]; then rc=1; fi
    return "$rc"
}

cmd_check_host() {
    local -a dirs=() existing=()
    local rc=0 d f base ver root st conf any_conf ex nbrokers=0 nmgr=0 l pm_img
    if [[ $# -gt 0 ]]; then dirs=("$@"); else dirs=(/opt /srv /usr/local /var/lib /etc /home /root); fi
    for d in "${dirs[@]}"; do [[ -d "$d" ]] && existing+=("$d"); done
    step "Looking for Apache Pulsar brokers"
    if [[ ${#existing[@]} -eq 0 ]]; then info "None of the search directories exist"; return 0; fi
    declare -A seen=() known=() mgr_seen=()
    while IFS= read -r f; do
        [[ -n "$f" ]] || continue
        base="$(basename "$f")"
        ver="$(sed -E 's/^(org\.apache\.pulsar-)?pulsar-broker-([0-9][0-9A-Za-z.]*)\.jar$/\2/' <<<"$base")"
        ver="$(norm_ver "$ver")"
        root="$(dirname "$(dirname "$f")")"
        [[ -n "${seen[$root|$ver]:-}" ]] && continue; seen["$root|$ver"]=1
        nbrokers=$((nbrokers+1))
        known["$root/conf/broker.conf"]=1; known["$root/conf/standalone.conf"]=1
        step "Pulsar broker ${ver} at ${root}"
        st="$(pulsar_status "$ver")"
        case "$st" in
            fixed)   ok "${ver} has the fixes (4.0.14, 4.2.5 or 5.0.0 or newer)"; continue ;;
            unknown) caution "cannot parse version '${ver}': check it against 4.0.14, 4.2.5 and 5.0.0"; rc=1; continue ;;
        esac
        inf "version ${ver} is in an affected range of the 21 October 2026 advisories (fixed in 4.0.14, 4.2.5 and 5.0.0; 3.x and 4.1.x are end of life: move to a fixed line)"
        if ver_lt "$(norm_ver "$ver")" "2.8.1"; then
            caution "older than 2.8.1: the two configuration-dependent flaws checked here start at 2.8.1, but this release is unsupported and affected by other advisories in the set: upgrade"
            continue
        fi
        any_conf=0
        for conf in "$root/conf/broker.conf" "$root/conf/standalone.conf"; do
            [[ -r "$conf" ]] || continue
            any_conf=1
            ex="$(conf_exposure "$conf")"
            if [[ -z "$ex" ]]; then
                ok "$(basename "$conf"): none of the exposing settings is present (MultiRoles provider with anonymousUserRole, or proxyRoles, with authorization enabled)"
            else
                [[ "$ex" == *105869* ]] && { bad "$(basename "$conf"): MultiRolesTokenAuthorizationProvider, a non-empty anonymousUserRole and authorizationEnabled=true: CVE-2026-105869, a client with a forged token can claim any role over HTTP or WebSocket"; rc=1; }
                [[ "$ex" == *105942* ]] && { bad "$(basename "$conf"): proxyRoles is set and authorization is enabled: CVE-2026-105942, proxied requests are authorized with the proxy's credentials"; rc=1; }
            fi
        done
        if [[ $any_conf -eq 0 ]]; then
            caution "no conf/broker.conf or conf/standalone.conf beside this install: the settings cannot be read (they may come from environment variables or a mounted file). Reporting it as exposed so you can review it."
            rc=1
        fi
    done < <(find "${existing[@]}" -xdev -maxdepth 9 -type f \( -name 'pulsar-broker-[0-9]*.jar' -o -name 'org.apache.pulsar-pulsar-broker-[0-9]*.jar' \) 2>/dev/null | sort -u)

    step "Configuration files (compose, Helm values, env files, broker.conf), whatever the version"
    local nconf=0
    while IFS= read -r f; do
        [[ -n "$f" ]] || continue
        [[ -n "${known[$f]:-}" ]] && continue
        ex="$(conf_exposure "$f")"
        [[ -n "$ex" ]] || continue
        nconf=$((nconf+1))
        [[ "$ex" == *105869* ]] && { bad "${f}: MultiRolesTokenAuthorizationProvider with a non-empty anonymousUserRole and authorizationEnabled=true (CVE-2026-105869)"; rc=1; }
        [[ "$ex" == *105942* ]] && { bad "${f}: proxyRoles is set with authorization enabled (CVE-2026-105942)"; rc=1; }
        inf "this file does not say which version runs: if the broker image or release is older than 4.0.14 (or 4.1.x, or 4.2.x before 4.2.5) it is exposed; check the tag"
    done < <(find "${existing[@]}" -xdev -maxdepth 9 -type f \( -name 'broker.conf' -o -name 'standalone.conf' -o -name 'docker-compose*.yml' -o -name 'docker-compose*.yaml' -o -name 'compose*.yml' -o -name 'compose*.yaml' -o -name 'values*.yaml' -o -name 'values*.yml' -o -name '*.env' \) \
                -not -path '*/node_modules/*' -size -2000k 2>/dev/null | sort -u)
    [[ $nconf -eq 0 ]] && ok "no configuration file with the exposing settings"

    step "Looking for Pulsar Manager (CVE-2026-105944, retired)"
    while IFS= read -r f; do
        [[ -n "$f" ]] || continue
        root="$(dirname "$f")"; [[ "$(basename "$root")" == bin ]] && root="$(dirname "$root")"
        [[ -n "${mgr_seen[$root]:-}" ]] && continue; mgr_seen["$root"]=1
        nmgr=$((nmgr+1))
        ver="$(sed -nE 's/^pulsar-manager-([0-9][0-9.]*)\.jar$/\1/p' <<<"$(basename "$f")")"
        bad "Pulsar Manager found: ${f}${ver:+ (version ${ver})}: every release (0.1.0 to 0.4.0) is affected and the project is retired: remove it"
        rc=1
    done < <(find "${existing[@]}" -xdev -maxdepth 9 -type f \( -name 'pulsar-manager*.jar' -o -path '*pulsar-manager/bin/pulsar-manager' \) 2>/dev/null | sort -u)
    if have ps; then
        while IFS= read -r l; do
            [[ -n "$l" ]] || continue
            nmgr=$((nmgr+1)); bad "a running process looks like Pulsar Manager: $(cut -c1-120 <<<"$l")"; rc=1
        done < <(ps -eo args= 2>/dev/null | grep -iE 'pulsar-manager' | grep -v grep | grep -v "${SCRIPT_NAME}" | head -n 3)
    fi
    while IFS= read -r l; do
        [[ -n "$l" ]] || continue
        inf "listener on a Pulsar Manager port: ${l}"
        [[ "$l" == *"reachable from the network"* ]] && { warn "a listener on 7750 or 9527 is reachable from the network: if that is Pulsar Manager, anyone who can reach it can take it over"; }
    done < <(listeners_on 7750 9527)
    if have docker; then
        pm_img="$(mktemp "${TMPDIR:-/tmp}/psf-pm.XXXXXX")" || pm_img=""
        if [[ -n "$pm_img" ]] && timeout 5 docker ps -a --format '{{.Image}}' >"$pm_img" 2>/dev/null; then
            while IFS= read -r l; do
                [[ -n "$l" ]] || continue
                nmgr=$((nmgr+1)); bad "a container uses a Pulsar Manager image: ${l}"; rc=1
            done < <(grep -iE 'pulsar-manager' "$pm_img")
        else
            inf "docker is installed but this account cannot use it, so container images were not checked (run it with sudo, or join the docker group)"
        fi
        [[ -n "$pm_img" ]] && rm -f "$pm_img"
    fi
    [[ $nmgr -eq 0 ]] && ok "no Pulsar Manager found (jars, running processes, container images)"

    step "Verdict"
    if [[ $nbrokers -eq 0 && $nconf -eq 0 && $nmgr -eq 0 ]]; then
        info "No Apache Pulsar broker, exposing configuration or Pulsar Manager found under: ${existing[*]}"
    elif [[ $rc -eq 0 ]]; then
        info "Nothing exposed (${nbrokers} broker install(s) checked). An affected broker without the exposing settings still needs the upgrade."
    else
        warn "Exposed Pulsar component found."
        [[ $nmgr -gt 0 ]] && {
            inf "Pulsar Manager: stop and remove it (the Pulsar PMC retired it) and move to an alternative from https://pulsar.apache.org/docs/administration-ui"
            inf "If it was reachable from a network you do not fully trust, treat the Pulsar credential or token signing key it held as compromised and replace it, and check its user list for administrators you did not create."
        }
        inf "Broker: upgrade to 4.0.14, 4.2.5 or 5.0.0 or newer. Until then (ours): empty anonymousUserRole, do not expose the HTTP and WebSocket ports to untrusted clients, and keep the broker behind the proxy with strict network rules."
        inf "Advisories: https://pulsar.apache.org/security/CVE-2026-105869/ and https://seclists.org/oss-sec/2026/q4/296"
    fi
    return "$rc"
}

# ---------- dispatch ---------------------------------------------------------
main() {
    CMD="${1:-check}"; [[ $# -gt 0 ]] && shift
    case "$CMD" in -V|--version|version) echo "${SCRIPT_NAME} ${SCRIPT_VERSION} (${SCRIPT_DATE})"; exit 0 ;; esac
    case "$CMD" in -h|--help|help) print_help; exit 0 ;; esac
    echo "${SCRIPT_NAME} ${SCRIPT_VERSION} (${SCRIPT_DATE}) - ${CMD} on $(hostname 2>/dev/null || echo '?') at $(date -u +%FT%TZ)"
    echo "CVE-2026-105869 and CVE-2026-105942 (fixed in Pulsar 4.0.14, 4.2.5, 5.0.0); CVE-2026-105944 (Pulsar Manager, retired)"
    case "$CMD" in
        check) cmd_check "$@" ;;
        *) die "Unknown command: ${CMD} (check|version)" ;;
    esac
}
main "$@"; exit

# Assisted-by: Claude Sonnet 5.5
