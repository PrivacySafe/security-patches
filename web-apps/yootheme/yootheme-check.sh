#!/usr/bin/env bash
# SPDX-License-Identifier: CC0-1.0
# =============================================================================
# YOOtheme Pro 5 unauthenticated remote code execution: checker  (v1)
# CVE-2026-102785
#
# If this software is helpful, consider a donation to our 501c3 nonprofit:
# https://privacysafe.foundation
#
# YOOtheme Pro is a widely used commercial theme and page builder for WordPress
# and Joomla. Its publicly reachable image handler (the route that creates and
# caches resized and cropped images) does not fully bind the normalized image
# operations and the output destination to the request signature. An
# unauthenticated attacker can reuse a signature disclosed in an ordinary public
# image URL, inject extra image operations, traverse out of the intended cache
# directory, and write an attacker-controlled PNG/PHP polyglot file into an
# executable public media directory. That file is then requested to run code.
# CVSS 10.0. Disclosed 21 to 22 October 2026. It is not listed as known
# exploited, but a CVSS 10 pre-authentication flaw with a published
# mechanism should be treated as likely to be exploited quickly.
#
#   Affected: YOOtheme Pro 5.0.0 through 5.0.52
#   Fixed:    5.0.53 (released 21 October 2026)
#   Not affected: YOOtheme Pro 4 and earlier (vendor statement)
#
# Sources disagree slightly: the CVE record is filed against the Joomla extension
# and one aggregator title says "5.0.0-5.0.55". The vendor's own notice, the
# changelog and the CVE description text say 5.0.52 and earlier, fixed in 5.0.53,
# for YOOtheme Pro 5 in general, so this script applies the rule to the WordPress
# theme as well as the Joomla template.
#
# This script is read-only. "check" finds YOOtheme Pro installs and reads their
# version. "hunt" looks for what the attack leaves behind: PHP files inside
# media, upload and cache directories, PHP code inside image files, and web log
# requests that run such files. It sends nothing to your site and exercises no
# part of the flaw.
#
# Usage:
#   ./yootheme-check.sh [command] [DIR ...]
#
#   check (default)  scan DIR (default /var/www /srv /opt /home) for YOOtheme.
#                    Exit 0 = nothing affected, 1 = an affected version found.
#   hunt             check, then search for signs of the attack. Exit 0 = nothing
#                    found, 1 = an indicator or an affected version was found.
#   mitigate [options]   (root) changes the host. PrivacySafe protection
#                    documented: refuses PHP files under uploads, media, images and
#                    cache paths with a 403, so a file an attacker managed to write
#                    cannot run. It does NOT stop the write: update to 5.0.53. It
#                    only acts when an affected or unreadable YOOtheme is found
#                    (--force overrides). Options:
#                      --web auto|apache|nginx  which web server (default auto: every
#                                               one found)
#                      --dir DIR                where to look for YOOtheme (repeat;
#                                               default /var/www /srv /opt /home)
#                      --dry-run                show the changes, change nothing
#                      --reload                 graceful reload afterwards (systemd)
#                      --force                  apply even if no affected install is found
#                    Apache: writes psf-yootheme-deny-php.conf (conf-available and
#                    a2enconf on Debian, conf.d on RHEL) and checks it with a
#                    configtest. nginx: writes a snippet and adds an include as the
#                    FIRST line of every server block that serves PHP (the first
#                    matching regex location wins), then checks with nginx -t
#                    (NGINX_MAIN_CONF=FILE checks a non-default main file). If the
#                    web server rejects the result everything is undone at once.
#                    The rule applies to EVERY PHP virtual host on the machine, and
#                    it also blocks a legitimate PHP file requested directly under a
#                    directory named cache, images, media or uploads.
#   rollback [--dry-run] [--reload]   remove what mitigate added and restore the files
#                    it edited.
#   version          print the script version.
#
# Environment: HUNT_WEB_LOGS (extra web access log paths for the hunt). STATE_DIR
# (default /var/lib/psf-security-patches/yootheme) holds the backups and manifest.
#
# Version reading: the script reads the standard WordPress theme header
# (style.css, Version:) and the Joomla template manifest (templateDetails.xml,
# <version>). If it cannot read a version it says so; the YOOtheme dashboard also
# shows the version.
# Containers: with no argument the check also looks in running docker and podman containers
# (SCAN_CONTAINERS=1, the default; 0 skips them). A read-only probe copies only the first few KB of
# each theme's style.css or templateDetails.xml, where the version is, into a private temporary
# directory, and this script runs once per container in isolation against that copy. The hunt
# command does not look inside containers. Paths shown as .../docker_NAME/... are inside the
# container NAME.
#      PSF_LOCK_WAIT    seconds a run that changes the host waits for another one that is already
#                       changing it (default 30), then stops with exit 2; the lock is STATE_DIR/.lock
# =============================================================================

# Commands run as "cmd_${CMD}", which shellcheck can't follow
# shellcheck disable=SC2317,SC2329
set -uo pipefail

SCRIPT_NAME="yootheme-check.sh"
SCRIPT_VERSION="1.1.0"
SCRIPT_DATE="2026-11-25"
SELF="$0"
STATE_DIR="${STATE_DIR:-/var/lib/psf-security-patches/yootheme}"

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
# need_root WHAT [HOW]: stop unless root, and name the sudo command to run instead. HOW ends the
# message (default: offer --dry-run); pass "" for a command that has no dry run.
need_root() {
    local how="${2-, or add --dry-run to see what it would do}" msg
    if is_root; then root_note; return 0; fi
    if command -v sudo >/dev/null 2>&1; then msg="${1}: run it as root, for example: sudo ${SELF_CMD}${how}"
    else msg="${1}: run it as root (sudo is not installed here)${how}"; fi
    die "$msg"
}
# root_note: one line, never a stop, for someone logged in as the root account itself while sudo is
# available. Shown once, only on a terminal, not under sudo or in a container. PSF_NO_ROOT_NOTE=1 hides it.
ROOT_NOTED=0
root_note() {
    [[ $ROOT_NOTED -eq 0 ]] || return 0
    ROOT_NOTED=1
    [[ -z "${PSF_NO_ROOT_NOTE:-}" && -z "${SUDO_USER:-}" && -t 2 && ! -f /.dockerenv ]] || return 0
    command -v sudo >/dev/null 2>&1 && [[ "$(logname 2>/dev/null || true)" == root ]] || return 0
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

# ---------- version rule -----------------------------------------------------
# prints: vulnerable | fixed | notaffected | unknown
yoo_status() {
    local n; n="$(norm_ver "$1")"
    is_semver "$n" || { echo unknown; return; }
    case "${n%%.*}" in
        0|1|2|3|4) echo notaffected ;;
        5) ver_lt "$n" "5.0.53" && echo vulnerable || echo fixed ;;
        *) echo fixed ;;
    esac
}

find_installs() {   # prints  kind<TAB>dir  (wp or joomla)
    local d
    while IFS= read -r d; do
        [[ -n "$d" ]] || continue
        case "$d" in
            */wp-content/themes/yootheme) [[ -r "$d/style.css" ]] && printf 'wp\t%s\n' "$d" ;;
            */templates/yootheme)         [[ -r "$d/templateDetails.xml" ]] && printf 'joomla\t%s\n' "$d" ;;
        esac
    done < <(find "$@" -xdev -maxdepth 9 -type d -name yootheme \( -path '*/wp-content/themes/*' -o -path '*/templates/*' \) 2>/dev/null | sort -u)
}

read_version() {   # kind dir
    case "$1" in
        wp)     sed -n 's/^[[:space:]]*Version:[[:space:]]*//p' "$2/style.css" 2>/dev/null | head -n1 | tr -d '\r ' ;;
        joomla) sed -n 's#.*<version>\([^<]*\)</version>.*#\1#p' "$2/templateDetails.xml" 2>/dev/null | head -n1 | tr -d '\r ' ;;
    esac
}

site_root() {   # kind dir
    case "$1" in
        wp)     dirname "$(dirname "$(dirname "$2")")" ;;    # .../wp-content/themes/yootheme -> site root
        joomla) dirname "$(dirname "$2")" ;;                 # .../templates/yootheme -> site root
    esac
}

# ---------- check ------------------------------------------------------------
INSTALLS=()
# ---------- running containers -----------------------------------------------
# A project inside a container is not on the host. For each running container, a small read-only
# probe (find, grep, test; nothing is modified or started) lists what this check needs, and those
# are copied into a private temporary directory (mode 0700, removed on exit) that the normal
# checks then judge like a host directory. Each probe line is one of:
#   F <path>          copy this file
#   D <path>          create this directory (its existence is what the check looks at)
#   E <path>          create an empty file (only its name matters, no content leaves the container)
#   L <path> <text>   write one short sanitized line of text
#   M <path> <epoch>  set the modification time of a staged file (a copy would otherwise carry the copy time)
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
                    M) [[ "$rest" =~ ^[0-9]{1,12}$ && -e "$s$p" ]] && touch -d "@$rest" "$s$p" 2>/dev/null ;;
                esac
            done <<<"$out"
            [[ -z "$s" ]] || STAGED_DIRS+=("$s")
        done < <("$rt" ps --format '{{.ID}} {{.Names}}' 2>/dev/null)
    done
}

YOOTHEME_PROBE="$(cat <<'EOS'
find /var/www /srv /opt /home -xdev -maxdepth 9 -type d -name yootheme \( -path "*/wp-content/themes/*" -o -path "*/templates/*" \) 2>/dev/null | head -n 40 | while read -r d; do
  [ -f "$d/style.css" ] && echo "B $d/style.css $(head -c 8192 "$d/style.css" | base64 | tr -d '\n')"
  [ -f "$d/templateDetails.xml" ] && echo "B $d/templateDetails.xml $(head -c 20000 "$d/templateDetails.xml" | base64 | tr -d '\n')"
done
exit 0
EOS
)"

container_run() {   # <staged directory> : YOOtheme in one container, judged by this script run in isolation
    local s="$1" out rc
    [[ -n "$(find "$s" -mindepth 1 -maxdepth 1 2>/dev/null | head -n1)" ]] || return 0
    step "YOOtheme in a container (${s##*/})"
    out="$(SCAN_CONTAINERS=0 bash "$SELF" check "$s" 2>&1)"; rc=$?
    tail -n +3 <<<"$out"
    return "$rc"
}

# shellcheck disable=SC2120
cmd_check() {
    local rc=0 crc=0 _s
    if [[ $# -eq 0 && "${SCAN_CONTAINERS:-1}" == 1 ]]; then
        stage_probe "$YOOTHEME_PROBE"
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
    local rc=0 found=0 d kind dir ver st
    if [[ $# -gt 0 ]]; then dirs=("$@"); else dirs=(/var/www /srv /opt /home); fi
    for d in "${dirs[@]}"; do [[ -d "$d" ]] && existing+=("$d"); done
    step "Looking for YOOtheme"
    if [[ ${#existing[@]} -eq 0 ]]; then info "None of the search directories exist"; return 0; fi
    INSTALLS=()
    while IFS=$'\t' read -r kind dir; do
        [[ -n "$kind" ]] || continue
        found=$((found+1)); INSTALLS+=("${kind}"$'\t'"${dir}")
        ver="$(read_version "$kind" "$dir")"
        step "YOOtheme (${kind}) ${ver:-version unreadable} at ${dir}"
        if [[ -z "$ver" ]]; then
            caution "could not read a version: check it in the YOOtheme dashboard. Affected is 5.0.0 through 5.0.52; fixed is 5.0.53."
            rc=1; continue
        fi
        st="$(yoo_status "$ver")"
        case "$st" in
            fixed)       ok "YOOtheme ${ver} has the fix (5.0.53 or newer)" ;;
            notaffected) ok "YOOtheme ${ver} is older than 5, which the vendor says is not affected" ;;
            unknown)     caution "cannot compare version '${ver}': check it against 5.0.53"; rc=1 ;;
            vulnerable)  bad "YOOtheme Pro ${ver} is affected by CVE-2026-102785 (fixed in 5.0.53): unauthenticated remote code execution"
                         inf "update now, then run: $0 hunt   (an update does not remove files an attacker already wrote)"
                         rc=1 ;;
        esac
    done < <(find_installs "${existing[@]}")
    step "Verdict"
    if [[ $found -eq 0 ]]; then
        info "No YOOtheme found under: ${existing[*]}"
    elif [[ $rc -eq 0 ]]; then
        info "No affected YOOtheme found (${found} checked)"
    else
        warn "Affected or unverifiable YOOtheme found. Update YOOtheme Pro to 5.0.53 or later."
        inf "PrivacySafe protection: deny the web server from running PHP in upload, media and cache directories (see the README for nginx and Apache rules). That blocks the written file from running; it does not stop the write."
        inf "Vendor notice: https://x.com/yootheme and the YOOtheme Pro changelog (5.0.53)"
    fi
    return "$rc"
}

# ---------- hunt -------------------------------------------------------------
hunt_site() {   # kind dir
    local kind="$1" dir="$2" root rc=0 out f
    local -a media=()
    root="$(site_root "$kind" "$dir")"
    step "Hunting in ${root} (${kind})"
    case "$kind" in
        wp)     media=("$root/wp-content/uploads" "$root/wp-content/cache" "$dir/cache") ;;
        joomla) media=("$root/images" "$root/cache" "$root/media" "$dir/cache") ;;
    esac
    local -a ex=(); for f in "${media[@]}"; do [[ -d "$f" ]] && ex+=("$f"); done
    if [[ ${#ex[@]} -eq 0 ]]; then inf "no upload, media or cache directory found to search"; return 0; fi
    inf "searching: ${ex[*]}"

    # 1. PHP files where none belongs (WordPress writes tiny index.php placeholders into some directories)
    out=""
    while IFS= read -r f; do
        [[ -n "$f" ]] || continue
        if [[ "$(basename "$f")" == "index.php" ]] && [[ "$(wc -c <"$f" 2>/dev/null)" -lt 120 ]] && grep -qi 'silence is golden' "$f" 2>/dev/null; then continue; fi
        out+="${f}"$'\n'
    done < <(find "${ex[@]}" -type f \( -iname '*.php' -o -iname '*.phtml' -o -iname '*.phar' -o -iname '*.php[0-9]' -o -iname '*.pht' \) 2>/dev/null | head -n200)
    if [[ -n "$out" ]]; then bad "PHP files inside upload, media or cache directories (nothing legitimate normally puts PHP there):"; grep -v '^$' <<<"$out" | sed 's/^/        /' | head -n15; rc=1
    else ok "no PHP file in the upload, media and cache directories"; fi

    # 2. PHP code inside image files (a PNG/PHP polyglot). Only the 5-byte "<?php": a 3-byte "<?=" would match random image data.
    out="$(find "${ex[@]}" -type f \( -iname '*.png' -o -iname '*.jpg' -o -iname '*.jpeg' -o -iname '*.gif' -o -iname '*.webp' \) -size -8M \
              -exec grep -laE '<\?php' {} + 2>/dev/null | head -n50)"
    if [[ -n "$out" ]]; then bad "image files that contain PHP code (a polyglot):"; sed 's/^/        /' <<<"$out" | head -n15; rc=1
    else ok "no image file contains a PHP open tag"; fi
    return "$rc"
}

hunt_logs() {
    local rc=0 f out
    local -a wl=()
    shopt -s nullglob
    for f in /var/log/apache2/*access*.log /var/log/nginx/*access*.log /var/log/httpd/*access*log \
             /var/log/apache2/other_vhosts_access.log ${HUNT_WEB_LOGS:-}; do
        [[ -r "$f" && -f "$f" ]] && wl+=("$f")
    done
    shopt -u nullglob
    step "Web logs: requests that run a PHP file from a media, upload or cache path"
    if [[ ${#wl[@]} -eq 0 ]]; then inf "no readable web access logs found (set HUNT_WEB_LOGS to add paths)"; return 0; fi
    # common/combined log format: $1 client, $7 path, $9 status
    out="$(cat "${wl[@]}" 2>/dev/null | awk '{p=tolower($7); s=$9; sub(/\?.*/,"",p)} p ~ /\/(cache|images|media|uploads)\/.*\.(php|phtml|phar)$/ && s ~ /^2/ {print $1, p}' | sort | uniq -c | sort -rn | head -n8)"
    if [[ -n "$out" ]]; then
        bad "successful requests (2xx) to PHP files under cache, images, media or uploads paths (count, client, path):"
        sed 's/^/        /' <<<"$out"; rc=1
    else
        ok "no successful request to a PHP file under a cache, images, media or uploads path in the readable logs"
    fi
    return "$rc"
}

cmd_hunt() {
    local rc=0 line kind dir
    cmd_check "$@" || rc=1
    if [[ ${#INSTALLS[@]} -gt 0 ]]; then
        for line in "${INSTALLS[@]}"; do
            kind="${line%%$'\t'*}"; dir="${line#*$'\t'}"
            hunt_site "$kind" "$dir" || rc=1
        done
        hunt_logs || rc=1
    fi
    step "Verdict"
    limited_view
    if [[ $rc -eq 0 ]]; then
        info "No indicator found: none of the published indicators were found."
    else
        warn "An affected version or an indicator was found. If a PHP file or polyglot is present, treat the site as compromised."
        inf "Keep a copy of the file for analysis before you delete it, update YOOtheme Pro, and remove any file you did not put there."
        inf "Then look for other changes (new admin users, modified theme and plugin files), rotate the CMS, database and hosting credentials, and consider restoring from a backup taken before 21 October 2026."
    fi
    return "$rc"
}


# ---------- mitigate and rollback --------------------------------------------
YM_RULE_RE='^/(.+/)?(cache|images|media|uploads)/.+\.(php|phtml|phar|pht|php[0-9])$'
YM_MANIFEST=""; YM_DRY=0
ym_run() { if [[ "$YM_DRY" -eq 1 ]]; then echo "  would run: $*"; return 0; fi; "$@"; }
ym_note() { [[ "$YM_DRY" -eq 1 ]] || echo "$1" >>"$YM_MANIFEST"; }

ym_backup() {
    local f="$1" b
    grep -qF "conf|${f}|" "$YM_MANIFEST" 2>/dev/null && return 0
    b="${STATE_DIR}/$(printf '%s' "$f" | sed 's#/#_#g').orig"
    cp -p "$f" "$b" || return 1
    echo "conf|${f}|${b}" >>"$YM_MANIFEST"
}

ym_apache_ctl() { local c; for c in apache2ctl apachectl httpd; do have "$c" && { echo "$c"; return 0; }; done; return 1; }

ym_apache_apply() {   # -> 0 ok, 1 failed (and undone)
    local ctl avail enabled confd target name=psf-yootheme-deny-php
    ctl="$(ym_apache_ctl)" || return 2
    avail="${APACHE_CONF_AVAILABLE:-/etc/apache2/conf-available}"; enabled="${APACHE_CONF_ENABLED:-/etc/apache2/conf-enabled}"
    confd="${APACHE_CONFD:-/etc/httpd/conf.d}"
    if [[ -d "$avail" ]]; then target="${avail}/${name}.conf"
    elif [[ -d "$confd" ]]; then target="${confd}/${name}.conf"
    else caution "Apache found but neither ${avail} nor ${confd} exists: add the rule by hand (see the README)"; return 1; fi
    if [[ "$YM_DRY" -eq 1 ]]; then
        echo "  would write ${target}:"; ym_apache_text | sed 's/^/      /'
        [[ "$target" == "${avail}/"* ]] && echo "  would run: a2enconf ${name}"
        echo "  would run: ${ctl} configtest"; return 0
    fi
    ym_apache_text >"$target" || return 1
    ym_note "file|${target}"
    if [[ "$target" == "${avail}/"* ]]; then
        if have a2enconf; then a2enconf "$name" >/dev/null 2>&1 || true
        else mkdir -p "$enabled" && ln -sf "$target" "${enabled}/${name}.conf"; fi
        ym_note "a2conf|${name}|${enabled}"
    fi
    if "$ctl" configtest >/dev/null 2>&1; then ok "Apache: ${target} written and ${ctl} configtest accepts it"; return 0; fi
    bad "Apache: configtest REJECTS the new rule: removing it"
    ym_apache_remove "$target" "$name" "$enabled"; return 1
}
ym_apache_text() {
    printf '%s\n' '# psf-security-patches: CVE-2026-102785 protective measure (yootheme-check.sh mitigate). Remove with: rollback' \
        "<LocationMatch \"(?i)${YM_RULE_RE}\">" '    Require all denied' '</LocationMatch>'
}
ym_apache_remove() {   # target name enabled
    have a2disconf && a2disconf "$2" >/dev/null 2>&1 || true
    rm -f "${3}/${2}.conf" "$1"
}

ym_nginx_files() {
    local f
    if [[ -n "${NGINX_CONF_FILES:-}" ]]; then for f in $NGINX_CONF_FILES; do [[ -r "$f" ]] && echo "$f"; done; return 0; fi
    { nginx -T 2>/dev/null | sed -n 's/^# configuration file \(.*\):$/\1/p'
      echo /etc/nginx/nginx.conf; ls /etc/nginx/conf.d/*.conf /etc/nginx/sites-enabled/* 2>/dev/null; } | while IFS= read -r f; do [[ -f "$f" && -r "$f" ]] && echo "$f"; done | awk '!s[$0]++'
}
read -r -d '' YM_AWK_NGINX <<'AWKEOF'
function flush(   i) {
    for (i = 1; i <= n; i++) {
        print buf[i]
        if (i == 1 && php && !has) print "    include " snip ";"
    }
    n = 0; php = 0; has = 0
}
{
    raw = $0; code = raw; sub(/#.*/, "", code)
    o = gsub(/\{/, "{", code); c = gsub(/\}/, "}", code)
    if (!inserv) {
        if (raw ~ /^[ \t]*server[ \t]*\{/) {
            inserv = 1; sdepth = depth; buf[++n] = raw; depth += o - c
            if (index(raw, "fastcgi_pass") || raw ~ /\.php/) php = 1
            if (depth <= sdepth) { flush(); inserv = 0 }
        } else { print raw; depth += o - c }
    } else {
        buf[++n] = raw
        if (code ~ /fastcgi_pass|fastcgi_param|\.php/) php = 1
        if (index(raw, snip)) has = 1
        depth += o - c
        if (depth <= sdepth) { flush(); inserv = 0 }
    }
}
END { if (n > 0) flush() }
AWKEOF

ym_nginx_test() {   # NGINX_MAIN_CONF names a non-default main configuration file
    if [[ -n "${NGINX_MAIN_CONF:-}" ]]; then nginx -t -c "$NGINX_MAIN_CONF" >/dev/null 2>&1; else nginx -t >/dev/null 2>&1; fi
}

ym_nginx_apply() {
    local snipdir snip f tmp n changed=0 files=() line
    have nginx || return 2
    snipdir="${NGINX_SNIPPET_DIR:-/etc/nginx/snippets}"; snip="${snipdir}/psf-yootheme-deny-php.conf"
    while IFS= read -r f; do [[ -n "$f" ]] && files+=("$f"); done < <(ym_nginx_files)
    if [[ ${#files[@]} -eq 0 ]]; then caution "nginx found but no readable configuration file: add the rule by hand (see the README)"; return 1; fi
    if [[ "$YM_DRY" -eq 0 ]]; then
        mkdir -p "$snipdir" || return 1
        printf '%s\n%s\n' '# psf-security-patches: CVE-2026-102785 protective measure (yootheme-check.sh mitigate). Remove with: rollback' \
            "location ~* ${YM_RULE_RE} { return 403; }" >"$snip" || return 1
        ym_note "file|${snip}"
    else echo "  would write ${snip}: location ~* ${YM_RULE_RE} { return 403; }"; fi
    tmp="$(mktemp "${TMPDIR:-/tmp}/ymng.XXXXXX")" || return 1
    for f in "${files[@]}"; do
        awk -v snip="$snip" "$YM_AWK_NGINX" "$f" >"$tmp" || continue
        cmp -s "$f" "$tmp" && continue
        n=$(diff "$f" "$tmp" | grep -c '^>')
        if [[ "$YM_DRY" -eq 1 ]]; then echo "  would add ${n} include line(s) to ${f}"
        else ym_backup "$f" && cat "$tmp" >"$f" && { ok "nginx: added the include to ${n} server block(s) in ${f}"; changed=1; }; fi
    done
    rm -f "$tmp"
    if [[ "$YM_DRY" -eq 1 ]]; then echo "  would run: nginx -t"; return 0; fi
    if [[ $changed -eq 0 ]]; then inf "nginx: no PHP-serving server block needed the include"; fi
    if ym_nginx_test; then ok "nginx: nginx -t accepts the new configuration"; return 0; fi
    bad "nginx: nginx -t REJECTS the new configuration: restoring the originals now"
    while IFS= read -r line; do
        [[ "$line" == conf\|* ]] || continue
        f="${line#conf|}"; f="${f%%|*}"; cat "${line##*|}" >"$f"
    done <"$YM_MANIFEST"
    rm -f "$snip"; : >"$YM_MANIFEST"; return 1
}

ym_reload() {
    [[ "${YM_RELOAD:-0}" -eq 1 ]] || return 0
    local u did=0
    for u in "$@"; do
        if have systemctl && grep -q "^${u}" <<<"$(systemctl list-unit-files 2>/dev/null)"; then
            ym_run systemctl reload "$u" && inf "reloaded ${u} (graceful)"; did=1
        fi
    done
    [[ $did -eq 1 ]] || caution "--reload given but no matching systemd unit found: reload the web server yourself"
}

cmd_mitigate() {
    local web=auto force=0 rc=0 kind dir ver st bad_n=0 any_web=0 r
    local -a dirs=() reload_units=()
    YM_DRY=0; YM_RELOAD=0
    while [[ $# -gt 0 ]]; do
        case "$1" in
            --dry-run) YM_DRY=1 ;; --reload) YM_RELOAD=1 ;; --force) force=1 ;;
            --web) shift; web="${1:-}"; case "$web" in auto|apache|nginx) ;; *) die "--web needs auto, apache or nginx" ;; esac ;;
            --dir) shift; [[ -n "${1:-}" ]] || die "--dir needs a directory"; dirs+=("$1") ;;
            *) die "Unknown mitigate option: $1 (--web --dir --dry-run --reload --force)" ;;
        esac
        shift
    done
    [[ $YM_DRY -eq 1 ]] || need_root "mitigate changes the host"
    [[ ${#dirs[@]} -gt 0 ]] || dirs=(/var/www /srv /opt /home)
    step "Looking for YOOtheme"
    local -a existing=(); for dir in "${dirs[@]}"; do [[ -d "$dir" ]] && existing+=("$dir"); done
    if [[ ${#existing[@]} -gt 0 ]]; then
        while IFS=$'\t' read -r kind dir; do
            [[ -n "$kind" ]] || continue
            ver="$(read_version "$kind" "$dir")"; st="$(yoo_status "${ver:-x}")"
            case "$st" in
                vulnerable) bad "YOOtheme ${ver} at ${dir} is affected"; bad_n=$((bad_n+1)) ;;
                unknown) caution "YOOtheme at ${dir}: version unreadable, treated as affected"; bad_n=$((bad_n+1)) ;;
                *) ok "YOOtheme ${ver} at ${dir}: not affected" ;;
            esac
        done < <(find_installs "${existing[@]}")
    fi
    if [[ $bad_n -eq 0 && $force -eq 0 ]]; then info "No affected YOOtheme found: nothing to do (use --force to apply the rule anyway)"; return 0; fi
    if [[ $YM_DRY -eq 0 ]]; then
        mkdir -p "$STATE_DIR" || die "cannot create ${STATE_DIR}"
        YM_MANIFEST="${STATE_DIR}/manifest.txt"; touch "$YM_MANIFEST"
    else YM_MANIFEST=/dev/null; step "Dry run: nothing will be changed"; fi
    step "Web server rule"
    if [[ "$web" == auto || "$web" == apache ]]; then
        ym_apache_apply; r=$?
        case $r in 0) any_web=1; reload_units+=(apache2 httpd) ;; 1) rc=1 ;; 2) [[ "$web" == apache ]] && { caution "no Apache found"; rc=1; } ;; esac
    fi
    if [[ "$web" == auto || "$web" == nginx ]]; then
        ym_nginx_apply; r=$?
        case $r in 0) any_web=1; reload_units+=(nginx) ;; 1) rc=1 ;; 2) [[ "$web" == nginx ]] && { caution "no nginx found"; rc=1; } ;; esac
    fi
    if [[ $any_web -eq 0 && $rc -eq 0 ]]; then caution "no Apache or nginx found: add the rule by hand (see the README), or put it in your proxy"; rc=1; fi
    if [[ $any_web -eq 1 && $YM_RELOAD -eq 1 && $YM_DRY -eq 0 ]]; then
        ym_reload "${reload_units[@]}"
    fi
    step "Result"
    if [[ $YM_DRY -eq 1 ]]; then info "Dry run finished: nothing was changed"
    elif [[ $any_web -eq 1 ]]; then
        info "PHP under uploads, media, images and cache paths is now refused. Backups and manifest: ${STATE_DIR}. Undo with: $0 rollback"
        [[ $YM_RELOAD -eq 1 ]] || inf "reload the web server for it to take effect (or re-run with --reload)"
    fi
    inf "This stops a written file from running; it does not stop the write. Update YOOtheme Pro to 5.0.53, then rotate credentials if the site was exposed."
    return "$rc"
}

cmd_rollback() {
    local line f b kind rc=0 name enabled
    YM_DRY=0; YM_RELOAD=0
    while [[ $# -gt 0 ]]; do
        case "$1" in --dry-run) YM_DRY=1 ;; --reload) YM_RELOAD=1 ;; *) die "Unknown rollback option: $1 (--dry-run --reload)" ;; esac
        shift
    done
    YM_MANIFEST="${STATE_DIR}/manifest.txt"
    [[ -s "$YM_MANIFEST" ]] || { info "Nothing to roll back (no manifest in ${STATE_DIR})"; return 0; }
    [[ $YM_DRY -eq 1 ]] || need_root "rollback changes the host"
    step "Rolling back"
    while IFS= read -r line; do
        kind="${line%%|*}"
        case "$kind" in
            conf) f="${line#conf|}"; f="${f%%|*}"; b="${line##*|}"
                  if [[ ! -r "$b" ]]; then bad "${f}: backup ${b} is missing, left alone"; rc=1; continue; fi
                  if [[ $YM_DRY -eq 1 ]]; then echo "  would restore ${f} from ${b}"; else cat "$b" >"$f" && ok "restored ${f}"; fi ;;
            a2conf) name="${line#a2conf|}"; enabled="${name#*|}"; name="${name%%|*}"
                  if [[ $YM_DRY -eq 1 ]]; then echo "  would disable ${name}"; else { have a2disconf && a2disconf "$name" >/dev/null 2>&1; rm -f "${enabled}/${name}.conf"; } || true; ok "disabled ${name}"; fi ;;
            file) f="${line#file|}"
                  if [[ $YM_DRY -eq 1 ]]; then echo "  would remove ${f}"; else rm -f "$f" && ok "removed ${f}"; fi ;;
        esac
    done <"$YM_MANIFEST"
    if [[ $YM_DRY -eq 0 && $rc -eq 0 ]]; then
        mv "$YM_MANIFEST" "${YM_MANIFEST}.rolled-back-$(date +%s)" 2>/dev/null || true
        info "Rolled back. Reload the web server for it to take effect."
    fi
    ym_reload apache2 httpd nginx
    return "$rc"
}

# ---------- dispatch ---------------------------------------------------------
main() {
    CMD="${1:-check}"; [[ $# -gt 0 ]] && shift
    case "$CMD" in -V|--version|version) echo "${SCRIPT_NAME} ${SCRIPT_VERSION} (${SCRIPT_DATE})"; exit 0 ;; esac
    case "$CMD" in -h|--help|help) print_help; exit 0 ;; esac
    echo "${SCRIPT_NAME} ${SCRIPT_VERSION} (${SCRIPT_DATE}) - ${CMD} on $(hostname 2>/dev/null || echo '?') at $(date -u +%FT%TZ)"
    echo "CVE-2026-102785; fixed in YOOtheme Pro 5.0.53"
    case "$CMD" in
        check|hunt|mitigate|rollback) "cmd_${CMD}" "$@" ;;
        *) die "Unknown command: ${CMD} (check|hunt|mitigate|rollback|version)" ;;
    esac
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
lock_for_change "mitigate rollback" "$@"

main "$@"; exit

# Assisted-by: Claude Sonnet 5.5
