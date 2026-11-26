#!/usr/bin/env bash
# SPDX-License-Identifier: CC0-1.0
# =============================================================================
# OpenSSL DTLS handshake retransmission read (heap disclosure): read-only checker  (v1)
# CVE-2026-84782
#
# If this software is helpful, consider a donation to our 501c3 nonprofit:
# https://privacysafe.foundation
#
# OpenSSL's security release of 29 September 2026 fixed 14 flaws. One is rated High:
# CVE-2026-84782, "DTLS retransmits handshake messages from a stale buffer offset".
# When DTLS retransmits a handshake message it can read from the wrong place in a buffer,
# so a remote peer may receive unintended plaintext heap memory in the handshake data, or
# the program may crash. CISA scored it 8.2 (confidentiality low, availability high).
# Found by Laurent Gaffie (Secorizon); fix by Ryan Hooper. The FIPS module is not affected.
#
# It matters only to software that speaks DTLS (TLS over UDP): VPN servers such as ocserv,
# VoIP and WebRTC servers such as Asterisk, FreeSWITCH, Janus and coturn, and IoT
# endpoints. Ordinary TLS (HTTPS, SMTP, IMAP, databases) does not use the vulnerable
# code. Node.js and Python's ssl module have no DTLS API.
#
#   Affected: 4.0.0 before 4.0.3, 3.6 before 3.6.5, 3.5 before 3.5.9, 3.4 before 3.4.8,
#             3.0 before 3.0.23, 1.1.1 before 1.1.1zj, 1.0.2 before 1.0.2zs.
#   Fixed:    public releases 4.0.3, 3.6.5, 3.5.9, 3.4.8. The fixes for 3.0 (3.0.23),
#             1.1.1 (1.1.1zj) and 1.0.2 (1.0.2zs) are available only to premium-support
#             customers, and public support for 3.0 ended on 7 September 2026. Branches
#             3.1 to 3.3 are end of life and were not evaluated by OpenSSL.
#   Ubuntu:   fixed in openssl 3.5.5-1ubuntu3.6 (26.04), 3.0.13-0ubuntu3.16 (24.04) and
#             3.0.2-0ubuntu1.30 (22.04); older Ubuntu releases were still "needs
#             evaluation". Other distributions backport under their own version numbers.
#
# How this script decides. A distribution package is judged by its changelog naming
# CVE-2026-84782 (a backport), and for Ubuntu also against the fixed package versions
# above. A copy that no package owns (a local build, a bundled library) is judged by the
# upstream version compared with the table. The script points you to your distribution's advisory when a
# distribution package has no changelog entry and no published fixed version to compare.
# It also reports DTLS-capable daemons that are running and processes still holding an
# old libssl in memory (a library update does not reach a running process until it
# restarts).
#
# This script is read-only.
#
# Usage:
#   ./openssl-check.sh [check]
#   check (default)  Exit 0 = nothing exposed, 1 = an affected or unconfirmed OpenSSL.
#   version          print the script version.
#
# Env: OPENSSL_BIN, OPENSSL_PKG_VERSION, OPENSSL_OS_RELEASE, OPENSSL_CHANGELOG, OPENSSL_PROC,
#      OPENSSL_NODE override the openssl command, the package version, /etc/os-release, a
#      changelog file (plain or .gz), /proc and the node command. OPENSSL_NO_PACKAGE=1 treats
#      the installed openssl as not owned by a package (a local build).
#      SCAN_CONTAINERS=1 (the default) also reads OpenSSL inside running docker and podman
#      containers, judged by each container's own distribution and packages; 0 skips them.
# =============================================================================

# Commands run as "cmd_${CMD}", which shellcheck cannot follow
# shellcheck disable=SC2317,SC2329
set -uo pipefail

SCRIPT_NAME="openssl-check.sh"
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


# Print the help text: everything between the first two ===== lines of this file.
print_help() { awk 'f && /^# =+$/ {exit} f {sub(/^# ?/,""); print} /^# =+$/ {f=1}' "$SELF"; }
# ---------- version rules ----------------------------------------------------
# compare the letter suffix of 1.0.2 and 1.1.1 releases: a < z < za < zj  (length first, then letters)
suffix_ge() {   # A B -> 0 if A >= B
    local a="$1" b="$2"
    (( ${#a} > ${#b} )) && return 0
    (( ${#a} < ${#b} )) && return 1
    [[ "$a" > "$b" || "$a" == "$b" ]]
}
# prints: fixed | affected | nopublicfix | eol | unknown     (for an upstream version)
#   nopublicfix = affected, and the fix exists only for premium-support customers (3.0, 1.1.1, 1.0.2)
#   eol         = a branch OpenSSL no longer supports and did not evaluate (3.1 to 3.3)
openssl_status() {
    local v="$1" maj min pat suf
    # a development or alpha/beta build of a release is a tree heading toward that release: of the
    # fixed release itself it may not carry the fix; of a later release it does
    if [[ "$v" =~ ^(.+)-(dev|alpha[0-9]*|beta[0-9]*)$ ]]; then
        v="${BASH_REMATCH[1]}"
        case "$v" in 4.0.3|3.6.5|3.5.9|3.4.8|3.0.23|1.1.1zj|1.0.2zs) echo prerelease; return ;; esac
    fi
    [[ "$v" =~ ^([0-9]+)\.([0-9]+)\.([0-9]+)([a-z]*)$ ]] || { echo unknown; return; }
    maj="${BASH_REMATCH[1]}"; min="${BASH_REMATCH[2]}"; pat="${BASH_REMATCH[3]}"; suf="${BASH_REMATCH[4]}"
    case "${maj}.${min}.${pat}" in
        1.1.1) suffix_ge "$suf" zj && echo fixed || echo nopublicfix; return ;;
        1.0.2) suffix_ge "$suf" zs && echo fixed || echo nopublicfix; return ;;
    esac
    case "${maj}.${min}" in
        4.0) (( pat >= 3 ))  && echo fixed || echo affected ;;
        3.6) (( pat >= 5 ))  && echo fixed || echo affected ;;
        3.5) (( pat >= 9 ))  && echo fixed || echo affected ;;
        3.4) (( pat >= 8 ))  && echo fixed || echo affected ;;
        3.0) (( pat >= 23 )) && echo fixed || echo nopublicfix ;;
        3.1|3.2|3.3) echo eol ;;
        *) if (( maj > 4 || (maj == 4 && min > 0) )); then echo fixed; else echo unknown; fi ;;
    esac
}

# ---------- the installed OpenSSL --------------------------------------------
parse_cli_line() {   # "OpenSSL 3.0.13 30 Jan 2024" -> 3.0.13 ; a LibreSSL line -> libressl ; else nothing
    local out="$1"
    if [[ "$out" =~ ^OpenSSL[[:space:]]+([0-9]+\.[0-9]+\.[0-9]+[a-z]*(-(dev|alpha[0-9]*|beta[0-9]*))?)([[:space:]]|$) ]]; then echo "${BASH_REMATCH[1]}"
    elif [[ "$out" == LibreSSL* ]]; then echo "libressl"; fi
}
cli_version() {   # the version the openssl command reports, or LibreSSL, or empty
    parse_cli_line "$("${OPENSSL_BIN:-openssl}" version 2>/dev/null | head -n1)"
}
package_info() {   # "<package> <version>" of the installed runtime library, or nothing
    local line
    [[ -n "${OPENSSL_NO_PACKAGE:-}" ]] && return 0
    if [[ -n "${OPENSSL_PKG_VERSION:-}" ]]; then echo "libssl ${OPENSSL_PKG_VERSION}"; return; fi
    if have dpkg-query; then
        line="$(dpkg-query -W -f='${Package} ${Version}\n' libssl3t64 libssl3 libssl1.1 libssl1.0.0 openssl 2>/dev/null | awk 'NF>=2 {print; exit}')"
        [[ -n "$line" ]] && { echo "$line"; return; }
    fi
    if have rpm; then
        line="$(rpm -q --qf '%{NAME} %{VERSION}-%{RELEASE}\n' openssl-libs openssl 2>/dev/null | awk 'NF>=2 && $0 !~ /not installed/ {print; exit}')"
        [[ -n "$line" ]] && echo "$line"
    fi
}
changelog_names_cve() {
    local pkg c
    # OPENSSL_NO_PACKAGE=1 means "no package owns this build": the host's own package changelog says nothing about it
    if [[ -n "${OPENSSL_NO_PACKAGE:-}" && -z "${OPENSSL_CHANGELOG:-}" ]]; then return 1; fi
    if [[ -n "${OPENSSL_CHANGELOG:-}" ]]; then
        [[ -r "${OPENSSL_CHANGELOG}" ]] || return 1
        if zcat -f "${OPENSSL_CHANGELOG}" 2>/dev/null | grep -F 'CVE-2026-84782' >/dev/null; then return 0; fi
        return 1
    fi
    if have dpkg; then
        for pkg in libssl3t64 libssl3 libssl1.1 openssl; do
            for c in "/usr/share/doc/${pkg}/changelog.Debian.gz" "/usr/share/doc/${pkg}/changelog.gz"; do
                [[ -r "$c" ]] || continue
                if zcat -f "$c" 2>/dev/null | grep -F 'CVE-2026-84782' >/dev/null; then return 0; fi
            done
        done
    fi
    if have rpm && rpm -q openssl-libs >/dev/null 2>&1; then
        if rpm -q --changelog openssl-libs 2>/dev/null | grep -F 'CVE-2026-84782' >/dev/null; then return 0; fi
    fi
    return 1
}
ubuntu_fix_for() {   # <os id> <version id> -> the fixed package version for that Ubuntu release, or empty
    local id="$1" vid="$2"
    [[ "$id" == ubuntu ]] || return 0
    case "$vid" in
        26.04) echo "3.5.5-1ubuntu3.6" ;;
        24.04) echo "3.0.13-0ubuntu3.16" ;;
        22.04) echo "3.0.2-0ubuntu1.30" ;;
        *)     echo "unlisted" ;;
    esac
}
ubuntu_fixed_package() {   # os-release -> the fixed package version for this Ubuntu release, or empty
    local f="${OPENSSL_OS_RELEASE:-/etc/os-release}" id vid
    [[ -r "$f" ]] || return 0
    id="$(sed -nE 's/^ID=//p' "$f" | tr -d '"')"; vid="$(sed -nE 's/^VERSION_ID=//p' "$f" | tr -d '"')"
    ubuntu_fix_for "$id" "$vid"
}

# ---------- running containers -----------------------------------------------
# One probe script, fed to "sh -s" inside each running container, prints what is needed to judge
# its OpenSSL by the container's OWN distribution and package database, never the host's.
OPENSSL_PROBE='. /etc/os-release 2>/dev/null
echo "OSID=${ID:-}"; echo "OSVER=${VERSION_ID:-}"
if command -v dpkg-query >/dev/null 2>&1; then
    echo "PKG=$(dpkg-query -W -f="\${Package} \${Version}\n" libssl3t64 libssl3 libssl1.1 libssl1.0.0 openssl 2>/dev/null | awk "NF>=2 {print; exit}")"
elif command -v rpm >/dev/null 2>&1; then
    echo "PKG=$(rpm -q --qf "%{NAME} %{VERSION}-%{RELEASE}\n" openssl-libs openssl 2>/dev/null | awk "NF>=2 && \$0 !~ /not installed/ {print; exit}")"
elif command -v apk >/dev/null 2>&1; then
    echo "PKG=$(apk info -v 2>/dev/null | grep -E "^(libssl|libcrypto|openssl)" | head -n1 | sed -E "s/^(.*)-([0-9][^-]*-r[0-9]+)\$/\1 \2/")"
fi
echo "CLI=$(openssl version 2>/dev/null | head -n1)"
for c in /usr/share/doc/libssl3t64/changelog.Debian.gz /usr/share/doc/libssl3/changelog.Debian.gz /usr/share/doc/libssl1.1/changelog.Debian.gz /usr/share/doc/openssl/changelog.Debian.gz; do
    if [ -r "$c" ] && zcat -f "$c" 2>/dev/null | grep -F CVE-2026-84782 >/dev/null; then echo "CHG=1"; fi
done
exit 0'

# The verdict for one container's OpenSSL, by the same rules as the system OpenSSL above.
# Returns 0 fixed or not affected, 1 affected or unconfirmed, 2 no OpenSSL in this container.
container_openssl() {   # <label> <os id> <os version> <"package version"> <changelog 0|1> <openssl version line>
    local label="$1" osid="$2" osver="$3" pkginfo="$4" chg="$5" cline="$6" cliv pkg pkgver ufix st
    cliv="$(parse_cli_line "$cline")"; pkg="${pkginfo%% *}"; pkgver="${pkginfo#* }"; [[ -n "$pkginfo" ]] || pkgver=""
    if [[ "$cliv" == libressl ]]; then inf "${label}: LibreSSL, which is not OpenSSL and not affected"; return 0; fi
    if [[ -z "$cliv" && -z "$pkginfo" ]]; then
        # nothing readable: no OpenSSL here, or an openssl command whose output cannot be read
        [[ -n "$cline" ]] || return 2
        caution "${label}: an openssl command is present but its version could not be read ('${cline}'): check it by hand"; return 1
    fi
    if [[ "$chg" == 1 ]]; then ok "${label}: the package changelog names CVE-2026-84782: this build carries the fix (a backport), whatever its version number says"; return 0; fi
    if [[ -n "$pkginfo" ]]; then
        ufix="$(ubuntu_fix_for "$osid" "$osver")"
        if [[ -n "$ufix" && "$ufix" != unlisted ]]; then
            if ! have dpkg || [[ ! "$pkgver" =~ ^([0-9]+:)?[0-9][A-Za-z0-9.+~:-]*$ ]]; then
                caution "${label}: package ${pkg} ${pkgver} cannot be compared here: check it against Ubuntu's fixed version ${ufix}"; return 1
            fi
            if dpkg --compare-versions "$pkgver" ge "$ufix" 2>/dev/null; then ok "${label}: package ${pkgver} is at or beyond Ubuntu's fixed version ${ufix}"; return 0; fi
            bad "${label}: package ${pkgver} is older than Ubuntu's fixed version ${ufix}: CVE-2026-84782 is NOT fixed in this container"; return 1
        fi
        if [[ "$ufix" == unlisted ]]; then
            caution "${label}: check ubuntu.com/security/ for the fixed package for this release: ${pkg} ${pkgver}"; return 1
        fi
        caution "${label}: the changelog of ${pkg} does not name CVE-2026-84782 and this distribution's fixed version is not in the sources used. Check your distribution's advisory for ${pkg} ${pkgver}"; return 1
    fi
    st="$(openssl_status "$cliv")"
    case "$st" in
        fixed)      ok "${label}: OpenSSL ${cliv} (no package database in the container) is at or beyond the fixed release of its branch"; return 0 ;;
        affected)   bad "${label}: OpenSSL ${cliv} (no package database in the container) is below the fixed release of its branch (4.0.3, 3.6.5, 3.5.9, 3.4.8): rebuild the image on a fixed base"; return 1 ;;
        nopublicfix|eol) bad "${label}: OpenSSL ${cliv} is on a branch with no public fix (${st}): move the image to a supported branch"; return 1 ;;
        prerelease) caution "${label}: OpenSSL ${cliv} is a development or pre-release build of the fixed release, not the release: it may not carry the fix"; return 1 ;;
        *)          caution "${label}: cannot interpret OpenSSL version '${cliv}'"; return 1 ;;
    esac
}

CONT_RC=0
containers_report() {
    CONT_RC=0
    local rt id name osid osver pkginfo chg cline l seen=0 any=0 r
    step "Running containers"
    if [[ "${SCAN_CONTAINERS:-1}" != 1 ]]; then inf "container scan disabled (SCAN_CONTAINERS=0)"; return 0; fi
    if ! have docker && ! have podman; then inf "no docker or podman CLI"; return 0; fi
    for rt in docker podman; do
        have "$rt" || continue
        while read -r id name; do
            [[ -n "$id" ]] || continue
            seen=$((seen + 1)); osid=""; osver=""; pkginfo=""; chg=0; cline=""
            while IFS= read -r l; do
                case "$l" in OSID=*) osid="${l#OSID=}" ;; OSVER=*) osver="${l#OSVER=}" ;; PKG=*) pkginfo="${l#PKG=}" ;; CLI=*) cline="${l#CLI=}" ;; CHG=1) chg=1 ;; esac
            done < <(printf '%s\n' "$OPENSSL_PROBE" | "$rt" exec -i "$id" sh -s 2>/dev/null)
            container_openssl "${rt} ${name:-$id}" "$osid" "$osver" "$pkginfo" "$chg" "$cline"; r=$?
            case $r in 0) any=$((any + 1)) ;; 1) any=$((any + 1)); CONT_RC=1 ;; esac
        done < <("$rt" ps --format '{{.ID}} {{.Names}}' 2>/dev/null)
    done
    inf "${seen} running container(s) examined, ${any} with an OpenSSL"
    inf "OpenSSL linked statically into a program inside a container is not visible here; rebuild such images on a fixed base"
}

cmd_check() {
    local rc=0 cliv pkginfo pkg pkgver ufix st f v
    step "The system OpenSSL"
    cliv="$(cli_version)"; pkginfo="$(package_info)"; pkg="${pkginfo%% *}"; pkgver="${pkginfo#* }"; [[ -n "$pkginfo" ]] || pkgver=""
    if [[ "$cliv" == libressl ]]; then inf "the openssl command is LibreSSL, which is not OpenSSL and not affected"
    elif [[ -z "$cliv" && -z "$pkginfo" ]] && have "${OPENSSL_BIN:-openssl}"; then caution "an openssl command was found but its version could not be read: check it by hand against 4.0.3, 3.6.5, 3.5.9 or 3.4.8"; rc=1
    elif [[ -z "$cliv" && -z "$pkginfo" ]]; then info "no openssl command or OpenSSL package found"
    else
        [[ -n "$cliv" ]] && inf "openssl command: OpenSSL ${cliv}"
        [[ -n "$pkginfo" ]] && inf "package: ${pkg} ${pkgver}"
        if changelog_names_cve; then
            ok "the package changelog names CVE-2026-84782: this build carries the fix (a backport), whatever its version number says"
        elif [[ -n "$pkginfo" ]]; then
            ufix="$(ubuntu_fixed_package)"
            if [[ -n "$ufix" && "$ufix" != unlisted && ! "$pkgver" =~ ^([0-9]+:)?[0-9][A-Za-z0-9.+~:-]*$ ]]; then
                caution "the package version '${pkgver}' is not a version string this script can compare: check ${pkg} against Ubuntu's fixed version ${ufix}"; rc=1
            elif [[ -n "$ufix" && "$ufix" != unlisted ]]; then
                if have dpkg && dpkg --compare-versions "$pkgver" ge "$ufix" 2>/dev/null; then ok "package ${pkgver} is at or beyond Ubuntu's fixed version ${ufix}"
                else bad "package ${pkgver} is older than Ubuntu's fixed version ${ufix}: CVE-2026-84782 is NOT fixed on this host"; rc=1; fi
            elif [[ "$ufix" == unlisted ]]; then
                caution "check ubuntu.com/security/CVE-2026-84782 for the fixed package for this release (Ubuntu marked older releases 'needs evaluation')"; rc=1
            else
                caution "the changelog of ${pkg} does not name CVE-2026-84782 and this distribution's fixed version is not in the sources used. Check your vendor's security tracker"; rc=1
            fi
        else
            st="$(openssl_status "$cliv")"
            case "$st" in
                fixed)       ok "OpenSSL ${cliv} (not from a package) is at or beyond the fixed release of its branch" ;;
                affected)    bad "OpenSSL ${cliv} (not from a package) is below the fixed release of its branch (4.0.3, 3.6.5, 3.5.9, 3.4.8): update"; rc=1 ;;
                nopublicfix) bad "OpenSSL ${cliv} (not from a package) is affected, and the fix for this branch is available only to premium-support customers: move to a supported branch (3.4 or later) or use a vendor package that carries the fix"; rc=1 ;;
                eol)         bad "OpenSSL ${cliv} is on an end-of-life branch OpenSSL did not evaluate: move to a supported branch"; rc=1 ;;
                prerelease)  caution "OpenSSL ${cliv} is a development or pre-release build of the fixed release, not the release: it may not carry the fix. Build or install 3.6.5, 3.5.9, 3.4.8 or 4.0.3 or later"; rc=1 ;;
                *)           caution "cannot interpret OpenSSL version '${cliv}'"; rc=1 ;;
            esac
        fi
    fi
    step "Copies bundled outside the system"
    local n=0 seen=""
    while IFS= read -r f; do
        f="$(readlink -f "$f" 2>/dev/null)"; [[ -n "$f" && "$seen" != *"|$f|"* ]] || continue; seen+="|$f|"
        v="$(grep -a -oE 'OpenSSL [0-9]+\.[0-9]+\.[0-9]+[a-z]*' "$f" 2>/dev/null | head -n1 | sed 's/^OpenSSL //')"
        [[ -n "$v" ]] || continue
        n=$((n+1)); st="$(openssl_status "$v")"
        if [[ "$st" == fixed ]]; then ok "${f}: OpenSSL ${v}"
        else bad "${f}: bundled OpenSSL ${v} is affected (${st}); it is updated by whoever ships that software, not by the system package"; rc=1; fi
    done < <(find /opt /usr/local /srv /home -xdev -maxdepth 6 -type f \( -name 'libcrypto.so*' -o -name 'libcrypto-*.so' \) 2>/dev/null | head -n 60)
    [[ $n -eq 0 ]] && ok "no OpenSSL library found under /opt, /usr/local, /srv or /home"
    local nv; nv="$("${OPENSSL_NODE:-node}" -p 'process.versions.openssl' 2>/dev/null | head -n1)"
    if [[ -n "$nv" ]]; then
        st="$(openssl_status "$nv")"
        inf "Node.js bundles OpenSSL ${nv} ($([[ "$st" == fixed ]] && echo 'fixed' || echo 'below the fixed release')). Node.js has no DTLS API, so this flaw is not reachable through it; it still updates with Node.js releases"
    fi
    step "Where DTLS could be in use"
    local base="${OPENSSL_PROC:-/proc}" p comm m nmap=0 nstale=0 dl="" sl=""
    local dtls_re='^(turnserver|coturn|asterisk|freeswitch|janus|janus-gateway|kamailio|opensips|ocserv|ocserv-main|dtls.*|coap.*)$'
    for p in "$base"/[0-9]*; do
        [[ -r "$p/maps" ]] || continue
        m="$(grep -E 'lib(ssl|crypto)[^ ]*\.so' "$p/maps" 2>/dev/null)"; [[ -n "$m" ]] || continue
        nmap=$((nmap+1)); comm="$(cat "$p/comm" 2>/dev/null)"
        if [[ "$comm" =~ $dtls_re && "$dl" != *"|$comm|"* ]]; then dl+="|$comm|"; fi
        if grep -E '\(deleted\)' <<<"$m" >/dev/null; then nstale=$((nstale+1)); [[ "$sl" != *"|$comm|"* ]] && sl+="|$comm|"; fi
    done
    inf "${nmap} process(es) have OpenSSL mapped"
    if [[ -n "$dl" ]]; then caution "DTLS-capable services are running: $(sed 's/^|*//; s/|*$//; s/||*/ /g' <<<"$dl"): these are the software the flaw can reach"
    else inf "no DTLS-capable service from the usual list is running; ordinary TLS services do not use the vulnerable code"; fi
    if [[ $nstale -gt 0 ]]; then caution "${nstale} process(es) still hold a replaced OpenSSL in memory and keep the old code until restarted: $(sed 's/^|*//; s/|*$//; s/||*/ /g' <<<"$sl")"; rc=1; fi
    containers_report
    if [[ $CONT_RC -eq 1 ]]; then rc=1; fi
    step "Verdict"
    if [[ $rc -eq 0 ]]; then info "No affected or unconfirmed OpenSSL found."
    else
        warn "OpenSSL affected or unconfirmed (CVE-2026-84782, High). Update the OpenSSL package, then restart services that use it (needrestart or a reboot)."
        inf "Fixed public releases: 4.0.3, 3.6.5, 3.5.9, 3.4.8. Ubuntu: 3.5.5-1ubuntu3.6, 3.0.13-0ubuntu3.16, 3.0.2-0ubuntu1.30"
    fi
    return "$rc"
}

main() {
    CMD="${1:-check}"; [[ $# -gt 0 ]] && shift
    case "$CMD" in -V|--version|version) echo "${SCRIPT_NAME} ${SCRIPT_VERSION} (${SCRIPT_DATE})"; exit 0 ;; esac
    case "$CMD" in -h|--help|help) print_help; exit 0 ;; esac
    echo "${SCRIPT_NAME} ${SCRIPT_VERSION} (${SCRIPT_DATE}) - ${CMD} on $(hostname 2>/dev/null || echo '?') at $(date -u +%FT%TZ)"
    echo "CVE-2026-84782 (OpenSSL DTLS handshake retransmission read); fixed in 4.0.3, 3.6.5, 3.5.9, 3.4.8"
    case "$CMD" in
        check) cmd_check "$@" ;;
        *) die "Unknown command: ${CMD} (check|version)" ;;
    esac
}
main "$@"; exit

# Assisted-by: Claude Sonnet 5.5
