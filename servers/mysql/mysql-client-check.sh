#!/usr/bin/env bash
# SPDX-License-Identifier: CC0-1.0
# =============================================================================
# MySQL client programs check for CVE-2026-114952  (v1)
#
# If this software is helpful, consider a donation to our 501c3 nonprofit:
# https://privacysafe.foundation
#
# CVE-2026-114952: Oracle MySQL, "Client programs" component.
#
# Published 17 November 2026 as part of Oracle's November 2026 Critical
# Security Patch Update (CSPU). CVSS 3.1 9.1 (critical), vector
# CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N: network-reachable, no
# authentication, no user interaction, full read/write/delete impact on
# data the client can see, no availability impact noted. CISA's record
# lists CWE-287 (improper authentication).
#
# Oracle's own advisories for MySQL, as a matter of long-standing practice,
# name only the product, the affected component ("Client programs"), the
# protocol ("MySQL Protocol"), the CVSS score and the affected version
# ranges; they do not publish the technical root cause. Secondary analysis
# circulating as of 19 November 2026 (unconfirmed by Oracle; treat as a
# plausible read, not a established fact) describes a client-side trust
# failure during the connection/authentication handshake, in which a MySQL
# client program accepts a server's authentication outcome and releases
# data or a relayable credential to a server it has not actually verified.
# If that is correct, the attacker here is a party controlling or able to
# intercept a MySQL server or a man-in-the-middle position on the
# connection, not a party attacking a listening mysqld directly; the victim
# is whatever process or person is running a MySQL client program.
#
# "Client programs" is the component that ships the mysql, mysqldump,
# mysqlbinlog, mysqlimport, mysqlshow, mysqladmin and similar CLI tools
# alongside every MySQL Server and MySQL Cluster installation, on the same
# package that provides mysqld; this is not a separate install most hosts
# would lack.
#
# No confirmed config directive or runtime flag closes this: Oracle has
# published no workaround, and the only CONFIRMED fix is upgrading those
# binaries. What follows is the one unconfirmed, speculative exception this
# script makes, added specifically for hosts stuck on MySQL 8.0 with no
# official patch to move to at all:
#
# The same unconfirmed secondary analysis mentioned above names the client
# cleartext authentication plugin ("mysql_clear_password", enabled per
# connection by the real, documented --enable-cleartext-plugin option, or
# the MYSQL_ENABLE_CLEARTEXT_PLUGIN / LIBMYSQL_ENABLE_CLEARTEXT_PLUGIN
# environment variables) as the specific mechanism it suspects: if a client
# program will hand a password to a server in the clear without the
# operator ever confirming the server's identity, that fits a
# "client trusts an unverified server" shape. The option and both
# environment variables are real, documented MySQL client features (not a
# detail invented by that analysis) and default to disabled, so turning
# them off where found removes one concrete pathway a client misconfigured
# this way could be attacked through. This is defense-in-depth against a
# guess, not a fix for a confirmed root cause: Oracle has not said this
# plugin is involved, there may be other pathways this does not touch, and
# running 'harden' is not a substitute for upgrading once a real fix exists
# for your line. It is offered because for a MySQL 8.0 host with no patch
# to move to, "do something plausible" is a more honest position than
# "nothing can be done," as long as it is labeled for what it is.
#
# Affected / fixed versions: Oracle's bulletin for this CSPU batch (which
# covers CVE-2026-114952 alongside several other CVEs, not this one alone)
# lists affected ranges through MySQL Server/Cluster 8.4.0-8.4.13,
# 9.7.0-9.7.4, and 26.10 (26.10.0), plus MySQL Shell and MySQL Workbench
# 26.10.0. Oracle's list for this CSPU does not include MySQL Server 8.0.x
# at all; 8.0 moved to Oracle's Sustaining Support phase in April 2026, and
# Sustaining Support does not include new CPU/CSPU security patches. This
# script therefore cannot say 8.0.x is "fixed" or report a fixed version
# for it, and reports any installed 8.0.x client package as affected with
# no confirmed remediation path besides moving off 8.0 and asking Oracle
# support directly about your specific entitlement if you are on Extended
# Support. For 8.4, 9.7 and the 26.x Innovation line, this script treats
# the next release after the last-listed-affected point in each line as
# the fixed version, since Oracle's practice is to ship the CPU/CSPU fix as
# the next quarterly release on the affected line; this is an inference
# from Oracle's release cadence, not a figure Oracle's bulletin states
# directly, and the override variables below exist so you can correct it
# against your own vendor's advisory text without waiting on this script.
#
# What this script does:
#   check    - read-only. Finds installed MySQL client packages (dpkg or
#              rpm) and reports each one's version against the
#              known-affected ranges above. Also audits the usual MySQL
#              client config files and this shell's environment for the
#              cleartext-plugin settings described above and reports
#              whether any are active, clearly labeled as unconfirmed.
#              Exits 1 if any installed client package is in an affected or
#              unconfirmed range, 0 if every one found is at or above its
#              line's fixed version, 2 if no MySQL client package was found
#              or the result could not be determined.
#   harden [--dry-run] - speculative defense-in-depth only, not a confirmed fix (see
#              above). Comments out any active 'enable-cleartext-plugin'
#              line in the config files it walks. Cannot unset an
#              environment variable in another process or a systemd unit
#              on your behalf; 'check' reports where it found one set so
#              you can remove it yourself. Backs up every file it touches.
#              Requires root. No --reload: there is no long-running
#              daemon reading this config, since it's read fresh by each
#              client invocation.
#   rollback [--dry-run] - restores every file 'harden' backed up. Requires
#              root, except with --dry-run.
#   rules    - prints the guidance above and exits. No side effects.
#   version  - prints this script's version.
#
# There is deliberately no 'hunt' command: Oracle has not published a
# technical root cause, and no log signature has been publicly associated
# with this CVE as of this script's writing; a hunt heuristic written
# without either would be guesswork dressed up as detection.
#
# --dry-run (harden, rollback): prints what would change and writes nothing,
# so it needs no root.
# Exit codes: check: 0 clear, 1 exposed/unconfirmed, 2 not found/error.
# PSF_LOCK_WAIT: seconds a run that changes the host waits for another one
# that is already changing it (default 30), then exit 2.
# =============================================================================
set -u
SCRIPT_NAME="mysql-client-check.sh"
SCRIPT_VERSION="1.4.0"
SCRIPT_DATE="2026-11-25"
case "${1:-}" in
  -h|--help) awk 'f && /^# =+$/ {exit} f {sub(/^# ?/, ""); print} /^# =+$/ {f=1}' "$0"; exit 0 ;;
esac
ADVISORY="https://www.oracle.com/security-alerts/cspunov2026.html"
CVE_REF="https://www.cve.org/CVERecord?id=CVE-2026-114952"

RED=$'\033[31m'; YEL=$'\033[33m'; GRN=$'\033[32m'; BLU=$'\033[34m'; RST=$'\033[0m'
[ -t 1 ] || { RED=""; YEL=""; GRN=""; BLU=""; RST=""; }
warn() { printf '%s[!]%s %s\n' "$RED" "$RST" "$1" >&2; }
note() { printf '%s[*]%s %s\n' "$YEL" "$RST" "$1"; }
ok()   { printf '%s[+]%s %s\n' "$GRN" "$RST" "$1"; }
inf()  { printf '%s[i]%s %s\n' "$BLU" "$RST" "$1"; }
die()  { warn "$1"; exit 2; }

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
# Nothing to check on this host: say so in a Verdict section, record "not applicable" and stop with exit 0.
na_exit() { psf_not_applicable "$1"; echo; echo "===== Verdict ====="; echo "[i] Not applicable: $1."; exit 0; }

is_root() { [ "${EUID:-$(id -u)}" -eq 0 ]; }
SELF_CMD="$(printf '%q ' "$0" "$@")"; SELF_CMD="${SELF_CMD% }"
# need_root WHAT: stop unless root, and name the sudo command to run instead.
need_root() {
    is_root && return 0
    if command -v sudo >/dev/null 2>&1; then
        die "${1}: run it as root, for example: sudo ${SELF_CMD}"
    else
        die "${1}: run it as root (sudo is not installed here)"
    fi
}

# Last-confirmed-affected point of each line per Oracle's November 2026
# CSPU bulletin, and this script's inferred fixed version (the next
# quarterly release on that line). Override any of these if your vendor's
# advisory gives a different number for your packaging.
AFFECTED_84_THROUGH="${MYSQL_114952_AFFECTED_84:-8.4.13}"
FIXED_84="${MYSQL_114952_FIXED_84:-8.4.14}"
AFFECTED_97_THROUGH="${MYSQL_114952_AFFECTED_97:-9.7.4}"
FIXED_97="${MYSQL_114952_FIXED_97:-9.7.5}"
AFFECTED_26x_THROUGH="${MYSQL_114952_AFFECTED_26X:-26.10.0}"
FIXED_26x="${MYSQL_114952_FIXED_26X:-26.10.1}"

BACKUP_DIR="${PSF_BACKUP_DIR:-/var/backups/psf-security-patches/mysql-client}"

# Config files MySQL client programs read, in the order they're applied
# (later files override earlier ones; this script audits all of them
# rather than trying to resolve the final effective value, since harden
# needs to find every place the option could be set, not just the one that
# currently wins).
CLIENT_CONFIG_FILES=(
    /etc/my.cnf
    /etc/mysql/my.cnf
)
CLIENT_CONFIG_DIRS=(
    /etc/my.cnf.d
    /etc/mysql/conf.d
    /etc/mysql/mysql.conf.d
)
[ -n "${HOME:-}" ] && CLIENT_CONFIG_FILES+=("$HOME/.my.cnf")

list_client_config_files() {
    local f d
    for f in "${CLIENT_CONFIG_FILES[@]}"; do [ -f "$f" ] && echo "$f"; done
    for d in "${CLIENT_CONFIG_DIRS[@]}"; do
        [ -d "$d" ] && find "$d" -maxdepth 1 -type f -name '*.cnf' 2>/dev/null
    done
}

active_lines() {
    local pattern="$1"; shift
    grep -EHin "$pattern" "$@" 2>/dev/null | grep -Ev ':\s*[#;]'
}

check_cleartext() {
    local files hits env_hits=0
    files=$(list_client_config_files)
    if [ -n "$files" ]; then
        hits=$(active_lines 'enable[-_]cleartext[-_]plugin' $files)
        if [ -n "$hits" ]; then
            warn "The cleartext authentication plugin is enabled in config (unconfirmed as the actual mechanism for CVE-2026-114952, see the script header):"
            printf '%s\n' "$hits" | sed 's/^/      /'
        fi
    fi
    for v in MYSQL_ENABLE_CLEARTEXT_PLUGIN LIBMYSQL_ENABLE_CLEARTEXT_PLUGIN; do
        if [ -n "${!v:-}" ]; then
            warn "Environment variable $v is set in this shell (value: ${!v}). This script cannot see or change other processes' or systemd units' environments; check service files and login profiles by hand."
            env_hits=1
        fi
    done
    [ -n "${hits:-}" ] || [ "$env_hits" -eq 1 ] && return 1
    return 0
}

ver_ge() { [ "$(printf '%s\n%s\n' "$1" "$2" | sort -V | head -1)" = "$2" ]; }
ver_le() { [ "$(printf '%s\n%s\n' "$1" "$2" | sort -V | tail -1)" = "$2" ]; }

# Classify one version string against the three lines above. Echoes a
# verdict word (fixed / affected / unconfirmed-80 / unknown-line) on stdout.
classify() {
    local v="$1"
    case "$v" in
        8.0.*)
            echo "unconfirmed-80"
            ;;
        8.4.*)
            if ver_le "$v" "$AFFECTED_84_THROUGH"; then echo affected
            elif ver_ge "$v" "$FIXED_84"; then echo fixed
            else echo unknown-line; fi
            ;;
        9.7.*)
            if ver_le "$v" "$AFFECTED_97_THROUGH"; then echo affected
            elif ver_ge "$v" "$FIXED_97"; then echo fixed
            else echo unknown-line; fi
            ;;
        26.*)
            if ver_le "$v" "$AFFECTED_26x_THROUGH"; then echo affected
            elif ver_ge "$v" "$FIXED_26x"; then echo fixed
            else echo unknown-line; fi
            ;;
        *)
            echo unknown-line
            ;;
    esac
}

# Packages across Debian/Ubuntu and RHEL/Fedora naming. Deliberately scoped
# to Oracle's own MySQL packaging, not MariaDB: MariaDB forked from MySQL
# long ago, Oracle's advisory does not mention it, and this script makes no
# claim about MariaDB client code one way or the other.
DEB_PKGS="mysql-client mysql-client-core mysql-community-client"
RPM_PKGS="mysql mysql-community-client community-mysql"

find_dpkg() {
    command -v dpkg-query >/dev/null 2>&1 || return 1
    local p
    for p in $DEB_PKGS; do
        dpkg-query -W -f='${Package}\t${Version}\n' "${p}*" 2>/dev/null
    done
}

find_rpm() {
    command -v rpm >/dev/null 2>&1 || return 1
    local p
    for p in $RPM_PKGS; do
        rpm -q --qf '%{NAME}\t%{VERSION}\n' "$p" 2>/dev/null | grep -v 'not installed'
    done
}

# Reduce a distro package version string (which can carry a Debian revision
# or RPM release suffix) down to the dotted MySQL upstream version at its
# front, e.g. '8.4.13-0ubuntu0.24.04.1' -> '8.4.13'.
upstream_ver() {
    echo "$1" | grep -Eo '^[0-9]+\.[0-9]+(\.[0-9]+)?'
}

do_check() {
    local found=0 worst="fixed" pkg ver uv verdict rows
    rows=$(find_dpkg; find_rpm)
    rows=$(printf '%s\n' "$rows" | sort -u | sed '/^$/d')

    if [ -z "$rows" ]; then
        # Also check for a bare mysql client binary installed from a
        # tarball or vendor-specific package this script's name lists
        # don't cover; report what version it claims, flagged undetermined
        # rather than guessed into a verdict.
        if command -v mysql >/dev/null 2>&1; then
            local raw
            raw=$(mysql --version 2>/dev/null)
            warn "Found a 'mysql' client binary (${raw:-version unknown}) but no matching dpkg/rpm package. Could not classify it against the affected ranges; check its version against this script's header by hand."
            return 2
        fi
        warn "No MySQL client package (dpkg or rpm) and no 'mysql' binary on PATH was found."
        return 2
    fi

    while IFS=$'\t' read -r pkg ver; do
        [ -n "$pkg" ] || continue
        # dpkg-query -W lists every package matching the glob that dpkg has
        # ever known about, including ones not actually installed (empty
        # Version field); skip those rather than reporting them as
        # unparseable.
        [ -n "$ver" ] || continue
        found=1
        uv=$(upstream_ver "$ver")
        if [ -z "$uv" ]; then
            warn "$pkg $ver: could not parse an upstream MySQL version from this string."
            worst="affected"
            continue
        fi
        verdict=$(classify "$uv")
        case "$verdict" in
            fixed)
                ok "$pkg $ver: at or above the fixed release for its line ($uv)."
                ;;
            affected)
                warn "$pkg $ver: in the range Oracle lists as affected for the November 2026 CSPU batch."
                worst="affected"
                ;;
            unconfirmed-80)
                warn "$pkg $ver: MySQL 8.0.x. Oracle's November 2026 CSPU bulletin does not list a fixed version for the Server line on 8.0 (it moved to Sustaining Support in April 2026, which does not receive CPU/CSPU security patches). Treat this as exposed with no confirmed remediation besides moving off 8.0, or your own support entitlement if you're on Extended Support."
                worst="affected"
                ;;
            unknown-line)
                note "$pkg $ver: version $uv does not match any range this script knows (8.4.x, 9.7.x, 26.x). It may predate or postdate what this script was written against; check it by hand against: ${ADVISORY}"
                [ "$worst" = "fixed" ] && worst="unknown"
                ;;
        esac
    done <<< "$rows"

    if [ "$found" -eq 0 ]; then
        na_exit "no MySQL client package is installed"
    fi

    inf "Checking the cleartext-plugin setting (unconfirmed as the actual mechanism; see 'rules' and the script header)."
    if check_cleartext; then
        ok "Cleartext authentication plugin not found enabled in the config files or environment this script checked."
    else
        note "See 'harden' if you want to turn this off as unconfirmed defense-in-depth. This is not a substitute for upgrading."
    fi

    case "$worst" in
        fixed) ok "Verdict: CLEAR. Every MySQL client package found is at or above its line's fixed version."; return 0 ;;
        unknown) note "Verdict: UNDETERMINED. See the notes above."; return 2 ;;
        *) warn "Verdict: EXPOSED or UNCONFIRMED. CVE-2026-114952 affects the 'Client programs' component; see above for which package. Advisory: ${ADVISORY} ; CVE: ${CVE_REF}"; return 1 ;;
    esac
}

ensure_backup_dir() { mkdir -p "$BACKUP_DIR" || die "Could not create $BACKUP_DIR"; }

backup_file() {
    local f="$1" stamp base
    stamp=$(date -u +%Y%m%dT%H%M%SZ)
    base=$(echo "$f" | sed 's#^/##; s#/#_#g')
    cp -a "$f" "$BACKUP_DIR/${stamp}.${base}.bak" || die "Could not back up $f"
    printf '%s\t%s\n' "$f" "$BACKUP_DIR/${stamp}.${base}.bak" >> "$BACKUP_DIR/.manifest.tsv"
}

do_harden() {
    local files changed=0 dry="${1:-0}"
    [ "$dry" = "1" ] || need_root "harden changes the host"
    note "This is speculative defense-in-depth against an UNCONFIRMED guess at the mechanism, not a fix for CVE-2026-114952. Upgrading is the only confirmed remedy; see 'rules'."
    files=$(list_client_config_files)
    if [ -z "$files" ]; then
        warn "No MySQL client config files found to harden."
    else
        [ "$dry" = "1" ] || ensure_backup_dir
        for f in $files; do
            local hits
            hits=$(active_lines 'enable[-_]cleartext[-_]plugin' "$f")
            [ -n "$hits" ] || continue
            inf "Found active cleartext-plugin setting in $f"
            printf '%s\n' "$hits" | sed 's/^/      /'
            if [ "$dry" = "1" ]; then inf "Dry run: would comment out the line(s) above in $f"; changed=1; continue; fi
            backup_file "$f"
            sed -i -E '/^[[:space:]]*[#;]/! s/^([[:space:]]*)(enable[-_]cleartext[-_]plugin.*)$/\1# disabled by psf-security-patches (CVE-2026-114952, unconfirmed): \2/' "$f"
            changed=1
        done
    fi
    for v in MYSQL_ENABLE_CLEARTEXT_PLUGIN LIBMYSQL_ENABLE_CLEARTEXT_PLUGIN; do
        if [ -n "${!v:-}" ]; then
            warn "$v is set in this shell's own environment. This script can only edit files, not unset a variable in your shell, a systemd unit, or another process; remove it from wherever it's set (a profile script, a unit's Environment= line, etc.) by hand."
        fi
    done
    if [ "$dry" = "1" ]; then
        inf "Dry run: no files were changed."
    elif [ "$changed" -eq 1 ]; then
        ok "Commented out the cleartext-plugin setting(s) found above."
    else
        ok "Nothing to change in config files: no active cleartext-plugin setting was found there."
    fi
    return 0
}

do_rollback() {
    local dry="${1:-0}"
    [ "$dry" = "1" ] || need_root "rollback changes the host"
    [ -f "$BACKUP_DIR/.manifest.tsv" ] || { warn "No backup manifest found at $BACKUP_DIR; nothing to roll back."; return 2; }
    local failed=0 orig backup
    # read from a process substitution, not a pipe, so a failure is not lost in a subshell
    while IFS=$'\t' read -r orig backup; do
        [ -f "$backup" ] || { warn "Backup missing: $backup"; failed=1; continue; }
        if [ "$dry" = "1" ]; then inf "Dry run: would restore $orig from $backup"; continue; fi
        if cp -a "$backup" "$orig"; then ok "Restored $orig"; else warn "Failed to restore $orig"; failed=1; fi
    done < <(tac "$BACKUP_DIR/.manifest.tsv" 2>/dev/null)
    if [ "$dry" = "1" ]; then inf "Dry run: no files were changed."; return "$failed"; fi
    return "$failed"
}

do_rules() {
    cat <<EOF
CVE-2026-114952: MySQL "Client programs", CVSS 9.1, unauthenticated,
network-reachable. Oracle has not published the technical root cause.

There is no configuration change that closes this: the affected code is in
the client binaries (mysql, mysqldump, mysqlbinlog, and the other CLI
tools), so the only confirmed fix is upgrading those packages to the
versions shown by 'check' above, or newer.

Until you've upgraded, Oracle's own guidance for this class of issue is
behavioral: do not run MySQL client programs against a server you do not
fully control and trust, and do not do so over a network path an attacker
could sit on. If backup scripts, CI pipelines, or administrative tooling on
this host run mysqldump, mysqlbinlog, or similar against a remote or
third-party-managed MySQL endpoint, that is the exposure this CVE
describes, not a locally listening mysqld being attacked.

If any installed client package reported above is MySQL 8.0.x: Oracle's
November 2026 CSPU bulletin does not cover that line at all, because it
left Premier/CPU-eligible support in April 2026. There is no vendor-shipped
fix to upgrade to on 8.0 for this CVE; moving to 8.4 or later is the only
CONFIRMED path this script can point to, short of a direct conversation
with Oracle if you hold Extended Support.

For that 8.0 case specifically, where there is genuinely nothing confirmed
to upgrade to: unconfirmed secondary analysis of this CVE (not published
or endorsed by Oracle) guesses the mechanism is a client-side trust
failure during authentication, and points at the client's cleartext
authentication plugin (the real, documented --enable-cleartext-plugin
option and its MYSQL_ENABLE_CLEARTEXT_PLUGIN / LIBMYSQL_ENABLE_CLEARTEXT_PLUGIN
environment variables) as one concrete thing that would fit that shape.
'harden' turns this off wherever 'check' found it active in a config file.
This is a guess about a guess, not a confirmed fix, and does not replace
upgrading once a real patch exists for your line; it exists because for a
host stuck on 8.0 with nothing official to move to, doing something
plausible and clearly labeled as such beats doing nothing at all.
EOF
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
lock_for_change "harden rollback" "$@"

case "${1:-check}" in
    check) do_check; exit $? ;;
    harden|rollback)
        cmd="$1"; shift; dry=0
        for a in "$@"; do
            case "$a" in
                --dry-run) dry=1 ;;
                *) die "Unknown $cmd option: $a (--dry-run)" ;;
            esac
        done
        "do_${cmd}" "$dry"; exit $? ;;
    rules) do_rules; exit 0 ;;
    version) echo "mysql-client-check.sh $SCRIPT_VERSION ($SCRIPT_DATE)"; exit 0 ;;
    *) die "Usage: $0 {check|harden [--dry-run]|rollback [--dry-run]|rules|version}" ;;
esac

# Assisted-by: Claude Sonnet 5
