#!/usr/bin/env bash
# SPDX-License-Identifier: CC0-1.0
# =============================================================================
# Plex Media Server "Plex2Shell" RCE chain: check and hunt  (v1)
# CVE-2026-96651 CVE-2026-96652 CVE-2026-96654 CVE-2026-96655 CVE-2026-96656
#
# If this software is helpful, consider a donation to our 501c3 nonprofit:
# https://privacysafe.foundation
#
# "Plex2Shell" chains flaws in Plex Media Server into unauthenticated remote
# code execution: an SSRF on /player/timeline (CVE-2026-96652), an admin-token
# theft via searchOne (CVE-2026-96654), a second SSRF on the transcode path
# (CVE-2026-96655), and a file write into the Codecs directory that drops and
# runs an ELF shared object (CVE-2026-96656); CVE-2026-96651 was fixed in the
# same release. Plex fixed all of them in Plex Media Server 1.43.3.10861 (3
# August 2026). A public proof-of-concept landed on 16 October 2026 and
# exploitation began the next day: attackers drop an XMRig miner (seen as
# "mylovelyminer", fetched as "x12345") and a reverse-proxy backdoor
# ("myawesomeproxy"), with mining and proxy traffic to proxystream[.]st.
#
# The fix is to upgrade to 1.43.3.10861 or later (including NAS, Docker and VM
# installs) and restart, which this script does not do for you. It is
# read-only: it reports the Plex version on the host and in containers and
# judges it, and hunts for the known compromise indicators. Successful
# exploitation runs code as the Plex service account, so if this host was
# exposed and unpatched, treat it as compromised: rebuild from a clean install,
# rotate the Plex account credentials and server token, and remove
# any router port-forwarding to Plex until it is updated. Attackers rotate file
# names, domains and ports, so a clean hunt means none of the published indicators were found; the version is the reliable signal.
#
# Usage:
#   ./plex2shell-oct2026-check.sh [command]
#
#   check (default)  the Plex Media Server version on the host and in running
#                    containers, judged against 1.43.3.10861. Read-only, root
#                    optional. Exit 0 = fixed/none, 1 = a vulnerable Plex is
#                    present, 2 = a version couldn't be read.
#   hunt             read-only: Plex data directories, /tmp and logs for the
#                    known indicators (the miner and proxy file names, the
#                    Codecs-directory payload, the proxyware banner, the mining
#                    domain and attacker IPs) and for the miner/proxy running.
#                    Exit 0 = clean, 1 = findings.
#   version          print the script version.
#
# Env overrides:
#   PLEX_FIXED=1.43.3.10861           first fixed Plex Media Server build
#   PLEX_DATA_PATHS="/var/lib/plexmediaserver ..."
#                                     where to look for Plex data directories
#   SCAN_CONTAINERS=1                 1 = read the Plex version inside containers
#   HUNT_LOGS="/srv/app/log/*.log"    extra log globs for hunt
#   SCAN_DEPTH=7                      how deep the search for Plex data directories goes
#   CODECS_SINCE_DAYS=30              how far back hunt lists changed files in the
#                                     Codecs directory
#   HUNT_ROOTS="/tmp /var/tmp /dev/shm"
#                                     scratch directories hunt searches for payload
#                                     files and indicator strings
# =============================================================================

# Commands run as "cmd_${CMD}", which shellcheck can't follow
# shellcheck disable=SC2317,SC2329
set -euo pipefail

# ---------- config -----------------------------------------------------------
CVES="CVE-2026-96651 CVE-2026-96652 CVE-2026-96654 CVE-2026-96655 CVE-2026-96656"
PLEX_FIXED="${PLEX_FIXED:-1.43.3.10861}"
PLEX_DATA_PATHS="${PLEX_DATA_PATHS:-/var/lib/plexmediaserver /config /opt /srv /home /root}"
SCAN_CONTAINERS="${SCAN_CONTAINERS:-1}"
SCAN_DEPTH="${SCAN_DEPTH:-7}"
HUNT_LOGS="${HUNT_LOGS:-}"
HUNT_ROOTS="${HUNT_ROOTS:-/tmp /var/tmp /dev/shm}"
# Known indicators (attackers rotate these; see the caveat hunt prints).
IOC_NAMES='x12345|mylovelyminer|myawesomeproxy'
IOC_NET='proxystream\.st|217\.60\.194\.116|91\.92\.40\.202|176\.65\.139\.228|45\.194\.92\.222'
IOC_BANNER='agree to the potential external use of your internet traffic'
SCRIPT_NAME="plex2shell-oct2026-check.sh"
SCRIPT_VERSION="1.1.0"
SCRIPT_DATE="2026-11-25"
SELF="$0"

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
ver_ge() { [[ "$(printf '%s\n%s\n' "$2" "$1" | sort -V | head -1)" == "$2" ]]; }
state_word() { case "$1" in 0) echo -e "${GREEN}fixed${NC}" ;; 1) echo -e "${RED}vulnerable${NC}" ;; *) echo -e "${YELLOW}unknown${NC}" ;; esac; }

# Plex versions look like 1.43.3.10861-xxxxxxxxx; compare the numeric part.
# This script's own text names the indicators it looks for, so a content scan that reaches
# the script (run from the directory it was downloaded to, or saved under /tmp) would report
# the script itself. The script's own file, and only that exact file, is left out.
SELF_REAL="$(readlink -f "$0" 2>/dev/null || echo "$0")"
not_self() { local x; while IFS= read -r x; do [[ "$(readlink -f "$x" 2>/dev/null || echo "$x")" == "$SELF_REAL" ]] || echo "$x"; done; }
plex_num() { local v="${1%%-*}"; grep -oE '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+' <<<"$v" || grep -oE '^[0-9]+\.[0-9]+\.[0-9]+' <<<"$v" || true; }
plex_state() {   # <version> -> rc|why
    local v; v="$(plex_num "$1")"
    [[ -n "$v" ]] || { echo "2|version unreadable"; return; }
    if ver_ge "$v" "$PLEX_FIXED"; then echo "0|${v} >= ${PLEX_FIXED}"
    else echo "1|${v} < ${PLEX_FIXED} (Plex2Shell is fixed in ${PLEX_FIXED})"; fi
}

# ---------- host version -----------------------------------------------------
host_plex_version() {
    if have dpkg-query; then dpkg-query -W -f='${Version}' plexmediaserver 2>/dev/null && return 0; fi
    # Non-dpkg installs: look for a version string in the server resources.
    local f
    for f in /usr/lib/plexmediaserver/*.txt /usr/lib/plexmediaserver/VERSION; do
        [[ -f "$f" ]] && { grep -oE '[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+' "$f" 2>/dev/null | head -1 && return 0; }
    done
    return 0
}
plex_installed() { have dpkg-query && dpkg-query -W plexmediaserver >/dev/null 2>&1 && return 0; [[ -e "/usr/lib/plexmediaserver/Plex Media Server" ]]; }

# ---------- data directories -------------------------------------------------
plex_data_dirs() {
    # shellcheck disable=SC2086
    find $PLEX_DATA_PATHS -maxdepth "$SCAN_DEPTH" -type d -name "Plex Media Server" 2>/dev/null \
        | while read -r d; do [[ -d "$d/Codecs" || -d "$d/Logs" ]] && echo "$d"; done | sort -u
}

# ---------- check ------------------------------------------------------------
cmd_check() {
    local rc=0 exposed=0 unknownz=0 v st how
    step "Plex Media Server on the host"
    if plex_installed; then
        v="$(host_plex_version)"
        IFS='|' read -r st how <<<"$(plex_state "$v")"
        case $st in
            0) ok "Plex Media Server ${v:-?}  $(state_word 0)  (${how})" ;;
            1) bad "Plex Media Server ${v:-?}  $(state_word 1)  (${how})"; exposed=1 ;;
            *) caution "Plex Media Server found but version unreadable; confirm it reports ${PLEX_FIXED} or later"; unknownz=1 ;;
        esac
    else inf "no Plex Media Server install found on the host"; fi

    step "Plex Media Server inside running containers"
    if [[ "$SCAN_CONTAINERS" != 1 ]]; then inf "container scan disabled (SCAN_CONTAINERS=0)"
    elif ! have docker && ! have podman; then inf "no docker or podman CLI"
    else
        local rt id name cv any_c=0
        for rt in docker podman; do
            have "$rt" || continue
            while read -r id name; do
                [[ -n "$id" ]] || continue
                cv="$("$rt" exec "$id" sh -c 'dpkg-query -W -f="${Version}" plexmediaserver 2>/dev/null || cat /usr/lib/plexmediaserver/*.txt 2>/dev/null' 2>/dev/null | grep -oE '[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+' | head -1 || true)"
                [[ -n "$cv" ]] || continue
                any_c=1
                IFS='|' read -r st how <<<"$(plex_state "$cv")"
                case $st in
                    0) ok "${rt} ${name:-$id}: Plex ${cv}  $(state_word 0)  (${how})" ;;
                    1) bad "${rt} ${name:-$id}: Plex ${cv}  $(state_word 1)  (${how}); pull a fixed image and recreate the container"; exposed=1 ;;
                    *) caution "${rt} ${name:-$id}: Plex version unreadable"; unknownz=1 ;;
                esac
            done < <("$rt" ps --format '{{.ID}} {{.Names}}' 2>/dev/null)
        done
        [[ $any_c -eq 1 ]] || inf "no running container reports a Plex version (or no permission to exec in them)"
    fi

    step "Verdict"
    [[ $exposed -eq 1 ]] && rc=1
    [[ $rc -eq 0 && $unknownz -eq 1 ]] && rc=2
    case $rc in
        0) info "No vulnerable Plex Media Server found where this could read a version" ;;
        1) warn "A vulnerable Plex Media Server is present and Plex2Shell is exploited in the wild. Upgrade to ${PLEX_FIXED} or later (NAS, Docker and VM installs too) and restart. Until then, remove any router port-forwarding to Plex so it is not reachable from the internet. Then run 'hunt'." ;;
        *) warn "A Plex version couldn't be read. Confirm the running build is ${PLEX_FIXED} or later, especially on Docker and NAS" ;;
    esac
    return "$rc"
}

# ---------- hunt -------------------------------------------------------------
cmd_hunt() {
    local found=0
    step "Known payload file names in Plex data, /tmp and scratch dirs"
    # shellcheck disable=SC2206
    local -a roots=($HUNT_ROOTS)
    local d
    while read -r d; do [[ -n "$d" ]] && roots+=("$d"); done < <(plex_data_dirs)
    local f
    for d in "${roots[@]}"; do
        [[ -d "$d" ]] || continue
        while read -r f; do
            [[ -n "$f" ]] || continue
            found=1; bad "payload-named file: ${f}"
        done < <(find "$d" -maxdepth "$SCAN_DEPTH" -type f 2>/dev/null | grep -E "/($IOC_NAMES)(\.|$|[^/]*)" || true)
    done
    [[ $found -eq 1 ]] || ok "no files named like the known miner/proxy payloads"

    step "Recently changed files in the Codecs directory"
    # CVE-2026-96656 writes the payload here. Plex's own codecs are ELF shared
    # objects too, so this does not flag them as malware; it lists what changed
    # recently for you to review.
    local cx=0 since="${CODECS_SINCE_DAYS:-30}"
    while read -r d; do
        [[ -n "$d" && -d "$d/Codecs" ]] || continue
        while read -r f; do
            [[ -n "$f" ]] || continue
            cx=1; caution "changed in the last ${since} days: ${f}"
        done < <(find "$d/Codecs" -maxdepth 4 -type f -mtime "-${since}" 2>/dev/null || true)
    done < <(plex_data_dirs)
    [[ $cx -eq 1 ]] || ok "no files changed in the Codecs directories in the last ${since} days"
    inf "a payload-named file above, or an unexpected shared object here, is the concern; CVE-2026-96656 writes to Codecs"

    step "Proxyware banner and mining domain in files"
    local bn=0
    for d in "${roots[@]}"; do
        [[ -d "$d" ]] || continue
        while read -r f; do [[ -n "$f" ]] && { found=1; bn=1; bad "proxyware/mining indicator in: ${f}"; }; done \
            < <(grep -rlaE "$IOC_BANNER|$IOC_NET" "$d" 2>/dev/null | not_self | head -20 || true)
    done
    [[ $bn -eq 1 ]] || ok "no proxyware banner or proxystream.st indicator in the scanned files"

    step "Miner or proxy process running"
    if have ps; then
        local pn
        pn="$(ps -eo pid,comm,args 2>/dev/null | grep -E "$IOC_NAMES|xmrig" | grep -v grep || true)"
        if [[ -n "$pn" ]]; then found=1; caution "suspicious process(es):"; echo "$pn" | sed 's/^/      /'
        else ok "no miner/proxy process by the known names is running"; fi
    fi

    step "Attacker IPs and mining domain in logs"
    local -a files=(); local g
    shopt -s nullglob
    while read -r d; do [[ -d "$d/Logs" ]] && for f in "$d"/Logs/*.log; do [[ -r "$f" ]] && files+=("$f"); done; done < <(plex_data_dirs)
    # shellcheck disable=SC2086
    for g in /var/log/syslog /var/log/messages /var/log/nginx/*.log /var/log/apache2/*.log $HUNT_LOGS; do
        for f in $g; do [[ -r "$f" && -f "$f" ]] && files+=("$f"); done
    done
    shopt -u nullglob
    if [[ ${#files[@]} -eq 0 ]]; then inf "no readable logs to scan"
    else
        local n; n="$( { grep -hEc "$IOC_NET" "${files[@]}" 2>/dev/null || true; } | awk '{s+=$1} END{print s+0}')"
        if [[ "${n:-0}" -gt 0 ]]; then found=1; caution "attacker IP / mining-domain hits in logs: ${n}"; { grep -hE "$IOC_NET" "${files[@]}" 2>/dev/null || true; } | tail -3 | cut -c1-200 | sed 's/^/      /'
        else ok "no attacker IPs or mining domain in the scanned logs"; fi
    fi

    echo
    echo "  Attackers rotate file names, domains and ports, so a clean hunt means none of the published indicators were found;"
    echo "  the Plex version is the reliable signal. If anything matched, or this host was exposed and"
    echo "  unpatched, treat it as compromised: rebuild from a clean install, rotate the Plex"
    echo "  account credentials and server token, and remove port-forwarding until updated."
    return "$found"
}

# ---------- dispatch ---------------------------------------------------------
main() {
CMD="${1:-check}"; [[ $# -gt 0 ]] && shift
case "$CMD" in -V|--version|version) echo "${SCRIPT_NAME} ${SCRIPT_VERSION} (${SCRIPT_DATE})"; exit 0 ;; esac
case "$CMD" in -h|--help) awk 'f && /^# =+$/ {exit} f {sub(/^# ?/, ""); print} /^# =+$/ {f=1}' "$SELF"; exit 0 ;; esac
[[ $# -eq 0 ]] || die "Unknown option: $1"
echo "${SCRIPT_NAME} ${SCRIPT_VERSION} (${SCRIPT_DATE}) - ${CMD} on $(hostname 2>/dev/null || echo '?') at $(date -u +%FT%TZ)"
echo "Plex2Shell: ${CVES}"
case "$CMD" in
    check|hunt) "cmd_${CMD}" ;;
    *) die "Unknown command: $CMD (check|hunt|version)" ;;
esac
}
main "$@"; exit

# Assisted-by: Claude Opus 5.5
