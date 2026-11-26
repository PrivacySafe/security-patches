#!/usr/bin/env bash
# SPDX-License-Identifier: CC0-1.0
# =============================================================================
# Incus October 2026 host-compromise flaws: read-only checker  (v1)
# CVE-2026-115375 (instance backup path traversal, CVSS 4.0 9.4)
# CVE-2026-115377 (migration stream symlink, CVSS 4.0 9.4)
# CVE-2026-115372 (restricted project mkfs argument injection, 8.5)
#
# If this software is helpful, consider a donation to our 501c3 nonprofit:
# https://privacysafe.foundation
#
# Incus is a system container and virtual machine manager. All three flaws let a client
# the daemon is meant to confine (a user restricted to a project) act as root on the
# HOST. A full administrator is already as powerful as host root, so these matter where
# you have restricted projects, restricted client certificates, or members of the
# unprivileged `incus` unix group, or where an instance can be migrated in from a server
# you do not control.
#
#   CVE-2026-115375  7.0.0 before 7.0.2, and 7.1.0 before 7.5.0. Importing an instance
#                    backup validates the instance and snapshot names but not the names
#                    of the dependent custom volumes in the backup's index.yaml, which
#                    become path segments on the host. Any client allowed to create
#                    instances in a project can make the daemon create root-owned
#                    directories with attacker-controlled content at arbitrary host
#                    paths. 6.x is not affected.
#   CVE-2026-115377  before 6.0.7, 6.1.0 before 7.0.2, and 7.1.0 before 7.5.0. When
#                    receiving an instance or volume by migration (copy, move, refresh,
#                    push or pull) through rsync or an optimized btrfs transfer, a
#                    malicious source can plant a symlink (rootfs pointing at /) and
#                    write through it as root. Any client allowed to create an instance
#                    or custom volume, or any server a target is told to copy or move
#                    from, can exploit it. Optimized ZFS transfers are NOT affected.
#   CVE-2026-115372  7.3.0 before 7.5.0. A user of a restricted project can set
#                    block.create_options through volume update, copy and move
#                    operations and inject arguments into mkfs, which runs as root.
#
#   Fixed: 6.0.7 (the 6.0 LTS, for CVE-2026-115377 only), 7.0.2 (the 7.0 LTS) and
#          7.5.0 (feature release).
#
# The project's own release notes list many other critical project-escape advisories in
# earlier releases this year; moving to a current release fixes those too. Treat a
# restricted project as a security boundary only on a release that has these fixes.
#
# This script is read-only. It reads the version (the daemon's, if it answers, else the
# package's, else the client's), looks in a package changelog for a backport of these
# fixes, and asks the daemon read-only questions: restricted projects, the network
# listener, trusted client certificates, configured remotes, plus the members of the
# unix group `incus`. It never changes anything.
#
# Usage:
#   ./incus-check.sh [command]
#
#   check (default)  Exit 0 = nothing exposed, 1 = an affected version that cannot be
#                    shown to be admin-only, or one that could not be verified.
#   version          print the script version.
#
# Env: INCUS_BIN to name the incus client; INCUS_CHANGELOG to name a changelog file.
# =============================================================================

# Commands run as "cmd_${CMD}", which shellcheck can't follow
# shellcheck disable=SC2317,SC2329
set -uo pipefail

SCRIPT_NAME="incus-check.sh"
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


# Print the help text: everything between the first two ===== lines of this file.
print_help() { awk 'f && /^# =+$/ {exit} f {sub(/^# ?/,""); print} /^# =+$/ {f=1}' "$SELF"; }

# ---------- version parsing --------------------------------------------------
# Incus feature releases are "7.4" and LTS point releases "6.0.3". Prints X.Y.Z or empty.
incus_semver() {
    local v="$1"
    v="${v#*:}"                      # drop a Debian epoch such as 1:
    v="${v%%-*}"                     # drop the Debian or RPM revision
    v="${v%%~*}"; v="${v%%+*}"
    [[ "$v" =~ ^([0-9]+)\.([0-9]+)(\.([0-9]+))?$ ]] || { echo ""; return; }
    echo "${BASH_REMATCH[1]}.${BASH_REMATCH[2]}.${BASH_REMATCH[4]:-0}"
}
# Each rule prints "affected" or "ok" for a semver
rule_115375() { local v="$1"; ver_lt "$v" "7.0.0" && { echo ok; return; }; if ver_lt "$v" "7.0.2"; then echo affected; elif ver_lt "$v" "7.1.0"; then echo ok; elif ver_lt "$v" "7.5.0"; then echo affected; else echo ok; fi; }
rule_115377() { local v="$1"; if ver_lt "$v" "6.0.7"; then echo affected; elif ver_lt "$v" "6.1.0"; then echo ok; elif ver_lt "$v" "7.0.2"; then echo affected; elif ver_lt "$v" "7.1.0"; then echo ok; elif ver_lt "$v" "7.5.0"; then echo affected; else echo ok; fi; }
rule_115372() { local v="$1"; ver_lt "$v" "7.3.0" && { echo ok; return; }; ver_lt "$v" "7.5.0" && echo affected || echo ok; }

# ---------- running the client safely ----------------------------------------
trusted_exec() {   # a root user must not run a binary that others can write
    local b="$1" st
    [[ -x "$b" ]] || return 1
    [[ "$(id -u)" != 0 ]] && return 0
    st="$(stat -c '%u %a' "$b" 2>/dev/null)" || return 1
    [[ "${st%% *}" == 0 ]] || return 1
    local mode="${st##* }"; mode="${mode: -3}"
    (( (8#$mode & 8#022) == 0 ))
}
find_client() {
    local c
    for c in "${INCUS_BIN:-}" /usr/bin/incus /opt/incus/bin/incus /usr/local/bin/incus /snap/bin/incus; do
        [[ -n "$c" ]] && trusted_exec "$c" && { echo "$c"; return; }
    done
    return 1
}
q() { timeout 15 "$CLIENT" "$@" 2>/dev/null; }   # a read-only question to the daemon

# ---------- package changelog (a backport can hide behind an old version) -----
backport_in_changelog() {
    local f ids='CVE-2026-(115375|115377|115372)|GHSA-(hpjh-q53p-f27r|579w-c4rw-c8q3|4cph-ccqv-hm3c)'
    for f in "${INCUS_CHANGELOG:-}" /usr/share/doc/incus/changelog.Debian.gz /usr/share/doc/incus-base/changelog.Debian.gz; do
        [[ -n "$f" && -r "$f" ]] || continue
        zcat -f "$f" 2>/dev/null | grep -E "$ids" >/dev/null && return 0
    done
    if have rpm && rpm -q incus >/dev/null 2>&1; then
        rpm -q --changelog incus 2>/dev/null | grep -E "$ids" >/dev/null && return 0
    fi
    return 1
}
package_version() {
    local v=""
    if have dpkg-query; then v="$(dpkg-query -W -f='${Version}' incus 2>/dev/null)"; [[ -z "$v" ]] && v="$(dpkg-query -W -f='${Version}' incus-base 2>/dev/null)"; fi
    if [[ -z "$v" ]] && have rpm; then v="$(rpm -q --qf '%{VERSION}' incus 2>/dev/null)"; [[ "$v" == *"not installed"* ]] && v=""; fi
    echo "$v"
}

# ---------- check ------------------------------------------------------------
cmd_check() {
    local rc=0 CLIENT cli_ver srv_ver pkg_ver sv src restricted=0 https="" nremotes=0 ntrust=0 nunpriv=0 line name unpriv=0
    step "Looking for Incus"
    CLIENT="$(find_client)" || CLIENT=""
    pkg_ver="$(package_version)"
    if [[ -z "$CLIENT" && -z "$pkg_ver" ]]; then info "No Incus client or package found (searched PATH locations, dpkg and rpm)"; return 0; fi
    cli_ver=""; srv_ver=""
    if [[ -n "$CLIENT" ]]; then
        cli_ver="$(timeout 10 "$CLIENT" --version 2>/dev/null | head -n1)"
        srv_ver="$(timeout 10 "$CLIENT" version 2>/dev/null | sed -n 's/^Server version:[[:space:]]*//p' | head -n1)"
        inf "client: ${CLIENT} ${cli_ver:+(version ${cli_ver})}"
    fi
    [[ -n "$pkg_ver" ]] && inf "package: incus ${pkg_ver}"
    if [[ -n "$srv_ver" && "$srv_ver" != unreachable ]]; then sv="$(incus_semver "$srv_ver")"; src="the daemon (${srv_ver})"
    elif [[ -n "$pkg_ver" ]]; then sv="$(incus_semver "$pkg_ver")"; src="the package (${pkg_ver})"
    else sv="$(incus_semver "$cli_ver")"; src="the client binary (${cli_ver}); the daemon did not answer"; fi
    [[ -n "$sv" ]] || { caution "cannot parse an Incus version (daemon '${srv_ver}', package '${pkg_ver}', client '${cli_ver}')"; return 1; }
    inf "using the version of ${src}"

    local a1 a2 a3; a1="$(rule_115375 "$sv")"; a2="$(rule_115377 "$sv")"; a3="$(rule_115372 "$sv")"
    step "Version ${sv}"
    if [[ "$a1" == ok && "$a2" == ok && "$a3" == ok ]]; then
        ok "Incus ${sv} is outside the affected ranges of CVE-2026-115375, CVE-2026-115377 and CVE-2026-115372 (fixed in 6.0.7, 7.0.2 and 7.5.0)"
        return 0
    fi
    [[ "$a1" == affected ]] && bad "CVE-2026-115375 (instance backup path traversal): ${sv} is affected (fixed in 7.0.2 and 7.5.0)"
    [[ "$a2" == affected ]] && bad "CVE-2026-115377 (migration stream symlink): ${sv} is affected (fixed in 6.0.7, 7.0.2 and 7.5.0)"
    [[ "$a3" == affected ]] && bad "CVE-2026-115372 (restricted project mkfs injection): ${sv} is affected (fixed in 7.5.0)"
    if { [[ -n "$pkg_ver" ]] || [[ -n "${INCUS_CHANGELOG:-}" ]]; } && backport_in_changelog; then
        ok "the package changelog names these fixes: this build appears to carry a backport, so the version number understates its state"
        inf "check that it names all three; this script only looks for any of them"
        return 0
    elif [[ -n "$pkg_ver" || -n "${INCUS_CHANGELOG:-}" ]]; then
        inf "the package changelog does not mention these fixes (no backport found), so a distribution package with an old version number is affected"
    fi

    step "Who can reach the daemon"
    if [[ -z "$CLIENT" ]] || [[ "$srv_ver" == unreachable || -z "$srv_ver" ]]; then
        caution "the daemon did not answer (or no client is installed), so projects, listeners and remotes cannot be read: reporting it as exposed so you can review it"
        rc=1
    else
        https="$(q config get core.https_address | head -n1)"
        [[ -n "$https" ]] && inf "network API listening: core.https_address = ${https}" || inf "no network API (core.https_address is empty): clients reach the daemon through the local unix socket"
        while IFS= read -r line; do
            [[ -n "$line" ]] || continue
            name="${line%%,*}"; name="${name% (current)}"
            [[ "$(q project get "$name" restricted | head -n1)" == true ]] && { restricted=$((restricted+1)); inf "restricted project: ${name}"; }
        done < <(q project list -f csv)
        ntrust="$(q config trust list -f csv | grep -c . )"
        [[ "$ntrust" -gt 0 ]] && inf "${ntrust} trusted client certificate(s) in the trust store"
        while IFS= read -r line; do
            [[ -n "$line" ]] || continue
            IFS=',' read -r name url proto _auth public _rest <<<"$line"
            [[ "$proto" == incus && "$url" != unix://* && "$public" == NO ]] && { nremotes=$((nremotes+1)); inf "remote server that could be a migration source: ${name%% *} (${url})"; }
        done < <(q remote list -f csv)
        if have getent; then
            nunpriv="$(getent group incus | awk -F: '{print $4}' | tr ',' '\n' | grep -c .)"
            [[ "$nunpriv" -gt 0 ]] && inf "${nunpriv} member(s) of the unprivileged unix group 'incus' (project-confined local users)"
        fi
        # judge each CVE against who can reach the daemon
        unpriv=0; { [[ $restricted -gt 0 ]] || [[ $nunpriv -gt 0 ]] || { [[ -n "$https" && $ntrust -gt 0 ]]; }; } && unpriv=1
        step "Exposure"
        if [[ "$a1" == affected ]]; then
            if [[ $unpriv -eq 1 ]]; then bad "CVE-2026-115375: restricted or unprivileged clients can create instances, and can make the daemon write as root on the host"; rc=1
            else ok "CVE-2026-115375: no restricted project, unprivileged group member or network client was found, so only full administrators (already host root) can reach it"; caution "upgrade anyway"; fi
        fi
        if [[ "$a2" == affected ]]; then
            if [[ $unpriv -eq 1 || $nremotes -gt 0 ]]; then bad "CVE-2026-115377: unprivileged clients, or a configured remote server acting as a migration source, can write to the host as root"; rc=1
            else ok "CVE-2026-115377: no unprivileged client and no remote migration source was found"; caution "upgrade anyway: copying an instance from a server you do not control would be enough"; fi
        fi
        if [[ "$a3" == affected ]]; then
            if [[ $restricted -gt 0 ]]; then bad "CVE-2026-115372: restricted project(s) exist, and their users can inject arguments into mkfs"; rc=1
            else ok "CVE-2026-115372: no restricted project was found, so there is no restriction to bypass"; caution "upgrade anyway: a restricted project created later would be affected"; fi
        fi
    fi
    step "Verdict"
    if [[ $rc -eq 0 ]]; then
        info "Nothing exposed on this host's current configuration. The affected version still needs the upgrade."
    else
        warn "Exposed or unverifiable Incus found. Upgrade to 7.5.0, or to 7.0.2 (7.0 LTS) or 6.0.7 (6.0 LTS) at the least."
        inf "PrivacySafe recommendation: do not treat restricted projects as a security boundary on this release; remove untrusted users from the incus group and the trust store; do not copy or move instances from servers you do not control; ZFS-optimized transfers are not affected by CVE-2026-115377."
        inf "Advisories: https://github.com/lxc/incus/security/advisories/GHSA-hpjh-q53p-f27r, GHSA-579w-c4rw-c8q3 and GHSA-4cph-ccqv-hm3c"
    fi
    return "$rc"
}

# ---------- dispatch ---------------------------------------------------------
main() {
    CMD="${1:-check}"; [[ $# -gt 0 ]] && shift
    case "$CMD" in -V|--version|version) echo "${SCRIPT_NAME} ${SCRIPT_VERSION} (${SCRIPT_DATE})"; exit 0 ;; esac
    case "$CMD" in -h|--help|help) print_help; exit 0 ;; esac
    echo "${SCRIPT_NAME} ${SCRIPT_VERSION} (${SCRIPT_DATE}) - ${CMD} on $(hostname 2>/dev/null || echo '?') at $(date -u +%FT%TZ)"
    echo "CVE-2026-115375, CVE-2026-115377, CVE-2026-115372; fixed in Incus 6.0.7, 7.0.2 and 7.5.0"
    case "$CMD" in
        check) cmd_check "$@" ;;
        *) die "Unknown command: ${CMD} (check|version)" ;;
    esac
}
main "$@"; exit

# Assisted-by: Claude Sonnet 5.5
