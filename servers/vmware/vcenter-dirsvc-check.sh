#!/usr/bin/env bash
# SPDX-License-Identifier: CC0-1.0
# psf-run: manual (needs the names of the vCenter servers, unless run on the appliance)
# =============================================================================
# VMware vCenter directory service authentication bypass, November 2026 (v1)
# CVE-2026-123890 (CVSS 3.1 9.8, VMSA-2026-0009, exploited, CISA KEV 20 November 2026)
#
# If this software is helpful, consider a donation to our 501c3 nonprofit:
# https://privacysafe.foundation
#
# Anyone who can reach vCenter's directory service (the single sign-on port 2012) can get an
# administrator session without a password. ARMORY CASTLE (formerly UNC5221) used it from
# early September with a tool Mandiant calls BONESAW: it created an SSO administrator account
# and copied the directory database, which holds the key that signs login tokens, so the
# attackers could forge a login for any user ("golden SAML"). Broadcom fixed it on 19 November:
# vCenter 9.1.1.0200 (build 25901347), 9.0.2.0200 (build 25901331) and 8.0 Update 3m
# (8.0.3.01200, build 25934264); VCF 5.x through 5.2.5. There is no workaround and no public
# fix for 7.0 (extended-support customers ask Broadcom); 6.5 and 6.7 are presumed affected.
#
# vCenter is an appliance on Photon OS. This tool runs from any GNU/Linux machine, asking each
# vCenter for its version over its web API the way the vSphere client does, without logging
# in; or on the appliance itself from its root shell.
#
# Usage:
#   ./vcenter-dirsvc-check.sh [command] [arguments]
#
#   check [HOST...]   Read-only. With hosts: asks each vCenter for its version
#                    and build (an unauthenticated RetrieveServiceContent call
#                    to https://HOST/sdk, the call every vSphere client makes
#                    first) and judges it; says whether this machine can reach
#                    the host's port 2012. Without hosts, on a vCenter
#                    appliance: judges the local build (vpxd -v). Exit 0 = all
#                    fixed, 1 = affected, 2 = a version could not be read.
#   hunt             Read-only. On any GNU/Linux machine: the files Mandiant
#                    found on the GNU/Linux machines the attackers used to reach
#                    vCenter (/tmp/123, /tmp/sss, /tmp/dbr, /usr/bin/vmtoolscs).
#                    On a vCenter appliance also: single sign-on log entries
#                    of the last HUNT_DAYS days that create users or add them
#                    to groups, for a look by hand. Exit 0 = nothing found,
#                    1 = leads, 2 = nothing could be read.
#   mitigate [--dry-run]   (root, on the appliance) Lets only the addresses in
#                    ALLOW_FROM reach the directory service port 2012 (and
#                    PORTS, if you add 443), with an iptables chain of its own,
#                    as Mandiant recommends. Keeps loopback and connections
#                    already open. Not a fix, and not supported by Broadcom:
#                    it narrows who can attack until you patch. The appliance
#                    rebuilds its firewall at boot, so run it again after a
#                    reboot. Include every other vCenter in the same SSO domain
#                    (Enhanced Linked Mode) in ALLOW_FROM.
#   rollback [--dry-run]   Removes that chain.
#   version          Prints the script version.
#
# Env overrides:
#   ALLOW_FROM="10.0.0.5 10.0.1.0/24"  who may reach the ports (mitigate)
#   PORTS="2012"       ports mitigate restricts (Mandiant: 443 too stops forged logins being used)
#   VPXD_V_OUTPUT      text that stands in for "vpxd -v" (testing only)
#   SDK_PORT=443       port of the vCenter web API
#   CURL_TIMEOUT=10    seconds per host
#   HUNT_DAYS=60       how far back hunt reads the SSO logs
#   SSO_LOG_DIR=/var/log/vmware/sso
#   IOC_PATHS="/tmp/123 /tmp/sss /tmp/dbr /usr/bin/vmtoolscs"
#   PSF_LOCK_WAIT      seconds a run that changes the host waits for another (default 30)
#   STATE_DIR          (default /var/lib/psf-security-patches/vcenter-dirsvc)
# =============================================================================

# Commands run as "cmd_${CMD}", which shellcheck can't follow
# shellcheck disable=SC2317,SC2329
set -uo pipefail

SCRIPT_NAME="vcenter-dirsvc-check.sh"
SCRIPT_VERSION="1.1.0"
SCRIPT_DATE="2026-11-25"
SELF="$0"
CVE="CVE-2026-123890"
# Fixed builds per release line (Broadcom VMSA-2026-0009, build numbers from KB 326316)
FIX_91=25901347; FIX_90=25901331; FIX_80=25934264
ALLOW_FROM="${ALLOW_FROM:-}"
PORTS="${PORTS:-2012}"
SDK_PORT="${SDK_PORT:-443}"
CURL_TIMEOUT="${CURL_TIMEOUT:-10}"
HUNT_DAYS="${HUNT_DAYS:-60}"
SSO_LOG_DIR="${SSO_LOG_DIR:-/var/log/vmware/sso}"
IOC_PATHS="${IOC_PATHS:-/tmp/123 /tmp/sss /tmp/dbr /usr/bin/vmtoolscs}"
STATE_DIR="${STATE_DIR:-/var/lib/psf-security-patches/vcenter-dirsvc}"
CHAIN="PSF_VCENTER_DIRSVC"

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

# judge VERSION BUILD -> "<rc>|<text>": 0 fixed, 1 affected, 2 unknown
judge() {
    local v="$1" b="$2" line fix
    [[ "$b" =~ ^[0-9]+$ ]] || { echo "2|build '${b:-?}' could not be read"; return; }
    line="$(printf '%s' "$v" | cut -d. -f1,2)"
    case "$line" in
        9.1) fix=$FIX_91 ;;
        9.0) fix=$FIX_90 ;;
        8.0) fix=$FIX_80 ;;
        7.0) echo "1|7.0 is affected and has no public fix (extended-support customers ask Broadcom)"; return ;;
        6.*|5.*) echo "1|${line} is past end of support and presumed affected: no fix will come"; return ;;
        9.*) [[ "${line#9.}" -gt 1 ]] 2>/dev/null && { echo "0|${line} is newer than the fixed lines"; return; }
             echo "2|${line} is not a line Broadcom's advisory lists"; return ;;
        *) echo "2|version '${v:-?}' is not one this script knows"; return ;;
    esac
    if [[ "$b" -ge "$fix" ]]; then echo "0|build ${b} is at or after the fix (${fix})"
    else echo "1|build ${b} is before the fix (${line}: build ${fix})"; fi
}

N_AFF=0; N_UNK=0; N_FIX=0
report() {   # <where> <version> <build>
    local rc why; IFS='|' read -r rc why <<<"$(judge "$2" "$3")"
    case "$rc" in
        0) N_FIX=$((N_FIX + 1)); info "${1}: vCenter ${2} build ${3}: fixed (${why})" ;;
        1) N_AFF=$((N_AFF + 1)); bad "${1}: vCenter ${2} build ${3}: ${RED}affected${NC} (${why})" ;;
        *) N_UNK=$((N_UNK + 1)); caution "${1}: ${why}" ;;
    esac
}

# The SOAP call every vSphere client makes before logging in; it returns the product, version and build.
SOAP='<?xml version="1.0" encoding="UTF-8"?><soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/" xmlns:urn="urn:vim25"><soapenv:Body><urn:RetrieveServiceContent><urn:_this type="ServiceInstance">ServiceInstance</urn:_this></urn:RetrieveServiceContent></soapenv:Body></soapenv:Envelope>'
xml_field() { sed -n "s:.*<$1>\([^<]*\)</$1>.*:\1:p" | head -n1; }
probe_host() {
    local h="$1" out name v b api
    if [[ -n "${SDK_RESPONSE_DIR:-}" ]]; then out="$(cat "$SDK_RESPONSE_DIR/$h" 2>/dev/null)"   # testing only
    else
        have curl || die "curl is needed to ask a vCenter for its version"
        # -k: vCenter ships a self-signed certificate. Nothing secret is sent; only the reply's version is read.
        out="$(curl -sk --max-time "$CURL_TIMEOUT" -H 'Content-Type: text/xml; charset=utf-8' -H 'SOAPAction: "urn:vim25/8.0"' \
               --data "$SOAP" "https://${h}:${SDK_PORT}/sdk" 2>/dev/null)"
    fi
    out="$(printf '%s' "$out" | tr -d '\r\n')"
    api="$(printf '%s' "$out" | xml_field apiType)"; name="$(printf '%s' "$out" | xml_field fullName)"
    v="$(printf '%s' "$out" | xml_field version)"; b="$(printf '%s' "$out" | xml_field build)"
    if [[ -z "$out" ]]; then N_UNK=$((N_UNK + 1)); caution "${h}: no answer from https://${h}:${SDK_PORT}/sdk"; return; fi
    if [[ "$api" == HostAgent ]]; then inf "${h}: ${name:-an ESXi host}: ESXi is not affected by this flaw"; return; fi
    if [[ "$api" != VirtualCenter ]]; then N_UNK=$((N_UNK + 1)); caution "${h}: answered, but not as a vCenter (${name:-no product name})"; return; fi
    report "$h" "$v" "$b"
    if [[ -z "${SDK_RESPONSE_DIR:-}" ]] && timeout 3 bash -c "exec 3<>/dev/tcp/${h}/2012" 2>/dev/null; then
        caution "${h}: this machine can reach its directory service port 2012. Anything on this machine, or on this network segment, could attack it"
    fi
}

is_appliance() { [[ -n "${VPXD_V_OUTPUT:-}" || -x /usr/sbin/vpxd || -f /etc/vmware/deployment.node.type ]]; }
local_build() {   # -> "version build"
    local out
    if [[ -n "${VPXD_V_OUTPUT:-}" ]]; then out="$VPXD_V_OUTPUT"; else out="$(/usr/sbin/vpxd -v 2>/dev/null)"; fi
    printf '%s' "$out" | sed -nE 's/.*VirtualCenter ([0-9.]+) build-([0-9]+).*/\1 \2/p' | head -n1
}

cmd_check() {
    local h v b
    if [[ $# -gt 0 ]]; then
        step "vCenter servers"
        for h in "$@"; do
            [[ "$h" =~ ^[A-Za-z0-9._:-]+$ ]] || die "Not a host name or address: ${h}"
            probe_host "$h"
        done
    elif is_appliance; then
        step "This vCenter appliance"
        read -r v b <<<"$(local_build)"
        report "this appliance" "${v:-?}" "${b:-?}"
    else
        die "not a vCenter appliance: name the vCenter servers to check, for example: ${SELF} check vcenter.example.com"
    fi
    step "Verdict"
    if [[ $N_AFF -gt 0 ]]; then
        warn "${N_AFF} affected vCenter(s) (${CVE}, exploited). Patch now: 9.1.1.0200, 9.0.2.0200 or 8.0 Update 3m (VCF 5.x: 5.2.5); there is no workaround. Until then, let only trusted hosts reach ports 2012 and 443 ('mitigate' on the appliance, or your network firewall), and run 'hunt': a patch does not remove an attacker who is already in."
        warn "Before upgrading to VCF 9.1.1: Broadcom says 8.0 U3m and 9.0.2.0200 block that upgrade until 9.1.2."
        return 1
    fi
    if [[ $N_UNK -gt 0 ]]; then warn "${N_UNK} vCenter(s) could not be judged (above)."; return 2; fi
    info "Every vCenter checked is fixed."
    return 0
}

cmd_hunt() {
    [[ $# -eq 0 ]] || die "hunt takes no arguments"
    limited_view "files and logs"
    local p leads=0 read=0 f line
    step "Files Mandiant found on the machines used to reach vCenter"
    for p in $IOC_PATHS; do
        if [[ -e "$p" ]]; then leads=$((leads + 1)); bad "${p} exists ($(stat -c '%s bytes, modified %y' "$p" 2>/dev/null | cut -d. -f1)): keep a copy for investigators and treat this machine as compromised"; fi
    done
    [[ $leads -gt 0 ]] || inf "none of ${IOC_PATHS}"
    read=1
    if is_appliance || [[ -d "$SSO_LOG_DIR" ]]; then
        step "SSO users created or added to groups (last ${HUNT_DAYS} days)"
        local n=0
        if [[ -d "$SSO_LOG_DIR" ]]; then
            while IFS= read -r line; do
                n=$((n + 1)); [[ $n -le 40 ]] && caution "${line:0:240}"
            done < <(find "$SSO_LOG_DIR" -type f -mtime "-${HUNT_DAYS}" 2>/dev/null | while IFS= read -r f; do
                        zcat -f "$f" 2>/dev/null | grep -aiE 'createLocal(Person|Solution)User|addUsersToGroup|addUserToGroup|addSubjectsToGroup|createLocalGroup' | sed "s#^#${f##*/}: #"
                     done)
            [[ $n -gt 0 ]] || inf "no user or group change in ${SSO_LOG_DIR}"
            [[ $n -eq 0 ]] || inf "check each one against your own changes. An administrator you did not create is a break-in: the attackers also took the token-signing key, so also replace the STS signing certificate"
        else inf "${SSO_LOG_DIR} not found"; fi
    fi
    step "Verdict"
    if [[ $leads -gt 0 ]]; then warn "${leads} indicator(s) found: treat this machine as compromised and look at every vCenter it could reach."; return 1; fi
    [[ $read -eq 1 ]] || return 2
    info "No indicator found on this machine. Run hunt on the other GNU/Linux machines that can reach vCenter, too."
    return 0
}

cmd_mitigate() {
    local dry=0 a ip p
    for a in "$@"; do case "$a" in --dry-run) dry=1 ;; *) die "Unknown option: $a (mitigate [--dry-run])" ;; esac; done
    is_appliance || die "mitigate runs on the vCenter appliance itself (its root shell). Elsewhere, restrict ports ${PORTS} in your network firewall"
    [[ -n "$ALLOW_FROM" ]] || die "set ALLOW_FROM to the addresses that may reach ports ${PORTS} (your admin hosts, and every other vCenter in the same SSO domain)"
    for ip in $ALLOW_FROM; do [[ "$ip" =~ ^[0-9]{1,3}(\.[0-9]{1,3}){3}(/[0-9]{1,2})?$ ]] || die "Not an IPv4 address or network: ${ip}"; done
    for p in $PORTS; do [[ "$p" =~ ^[0-9]+$ ]] || die "Not a port: ${p}"; done
    [[ $dry -eq 1 ]] || need_root "mitigate changes the firewall"
    local ports; ports="$(echo $PORTS | tr ' ' ',')"
    local rules=("-N ${CHAIN}" "-A ${CHAIN} -i lo -j RETURN" "-A ${CHAIN} -m conntrack --ctstate ESTABLISHED,RELATED -j RETURN")
    for ip in $ALLOW_FROM; do rules+=("-A ${CHAIN} -s ${ip} -j RETURN"); done
    rules+=("-A ${CHAIN} -j DROP" "-I INPUT 1 -p tcp -m multiport --dports ${ports} -j ${CHAIN}")
    step "Rules"
    for r in "${rules[@]}"; do echo "  iptables $r"; done
    if [[ $dry -eq 1 ]]; then info "DRY RUN: nothing was changed."; return 0; fi
    have iptables || die "iptables not found"
    if iptables -n -L "$CHAIN" >/dev/null 2>&1; then die "the ${CHAIN} chain is already in place: run rollback first to change it"; fi
    local r
    for r in "${rules[@]}"; do
        # shellcheck disable=SC2086
        if ! iptables $r; then bad "iptables ${r} failed: removing what was added"; cmd_rollback >/dev/null 2>&1; return 1; fi
    done
    mkdir -p "$STATE_DIR" && printf '%s\n' "$ALLOW_FROM" > "$STATE_DIR/allow_from"
    info "Only ${ALLOW_FROM} (and this appliance itself) can now open new connections to ports ${ports}."
    warn "Not persistent: the appliance rebuilds its firewall at boot, so run this again after a reboot. This narrows the attack; only the patch fixes it."
    return 0
}

cmd_rollback() {
    local dry=0 a
    for a in "$@"; do case "$a" in --dry-run) dry=1 ;; *) die "Unknown option: $a (rollback [--dry-run])" ;; esac; done
    if [[ $dry -eq 1 ]]; then echo "  would remove the INPUT jump to ${CHAIN}, then the chain"; return 0; fi
    need_root "rollback changes the firewall"
    have iptables || die "iptables not found"
    local ports; ports="$(echo $PORTS | tr ' ' ',')"
    while iptables -D INPUT -p tcp -m multiport --dports "$ports" -j "$CHAIN" 2>/dev/null; do :; done
    iptables -F "$CHAIN" 2>/dev/null; iptables -X "$CHAIN" 2>/dev/null
    if iptables -n -L "$CHAIN" >/dev/null 2>&1; then bad "the ${CHAIN} chain could not be removed (another rule still jumps to it?)"; return 1; fi
    info "Removed: ports ${ports} are open to whoever the appliance's own firewall allows."
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
    echo "${CVE}: vCenter directory service authentication bypass; fixed in 9.1.1.0200, 9.0.2.0200 and 8.0 U3m"
    case "$CMD" in
        check) cmd_check "$@" ;;
        hunt) cmd_hunt "$@" ;;
        mitigate) cmd_mitigate "$@" ;;
        rollback) cmd_rollback "$@" ;;
        *) die "Unknown command: ${CMD} (check|hunt|mitigate|rollback|version)" ;;
    esac
}
main "$@"; exit

# Assisted-by: Claude Opus 5.5
