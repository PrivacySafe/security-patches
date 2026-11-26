#!/usr/bin/env bash
# SPDX-License-Identifier: CC0-1.0
# =============================================================================
# WordPress core page-template path traversal: read-only checker  (v1)
# CVE-2026-87902
#
# If this software is helpful, consider a donation to our 501c3 nonprofit:
# https://privacysafe.foundation
#
# Disclosed and fixed on 22 September 2026. CVSS 9.2 (Critical). Unauthenticated
# path traversal in WordPress core's page-template resolver, present in every
# release from 4.7.0 through 7.1.1, roughly a decade. Exploitation was
# observed on the same day as disclosure. CISA added CVE-2026-87902 to its
# Known Exploited Vulnerabilities catalog on 25 September 2026.
#
# Root cause: get_page_template() in wp-includes/template.php calls urldecode()
# on the pagename query variable after sanitization has run. A double-encoded
# traversal sequence (%252E%252E%252F) passes the first decode as a percent
# literal, survives sanitize_title_with_dashes(), and is decoded a second time
# by WordPress into ../, which escapes the theme directory. WordPress then builds
# a candidate template name and, on servers where a PHP file exists at the
# traversed path, includes it.
#
# The fix (7.1.2 and the matching branch releases) changes one file, wp-includes/template.php,
# in two places: the decoded pagename is used only if validate_file() accepts it, and a
# template found by locate_template() is loaded only if the new function
# _wp_is_template_path_allowed() accepts it. This script reads both from the source, so
# a distribution backport under an older version number is recognized.
#
#   Affected: WordPress 4.7.0 through 7.1.1, across every supported branch.
#             WordPress before 4.7.0 is not affected.
#   Fixed:    7.1.2, 7.0.6, 6.9.9, 6.8.10, 6.7.9, 6.6.9 and backports down
#             to 4.7.37 (released September 22, 2026). WordPress 4.6 and
#             earlier move to a supported branch.
#
# WordPress releases a fixed version for every branch on the same day, so
# updating within your branch is always safe. On 7.1: update to 7.1.2. On
# 7.0: update to 7.0.6. And so on. Use `wp core update` or the admin panel.
# There is no official workaround.
#
# Discovered by Robert Ressl.
# Advisory: GHSA-7hp8-65ch-5whp
#
# This script is read-only. It finds WordPress installs by wp-includes/version.php.
#
# Usage:
#   ./wordpress-pt-check.sh [check] [DIR ...]
#   check (default)  find WordPress under DIR, read each version, and read template.php
#                    for the two fixes. Exit 0 = nothing exposed, 1 = an install
#                    without the fix, or one whose state is unclear.
#   hunt             look in web server logs for an encoded traversal in the pagename
#                    parameter and for the scanner user agents seen in the attacks.
#                    Exit 0 = nothing found, 1 = a strong lead. A clean hunt means none of the published indicators were found.
#   version          print the script version.
#
# Env: WPT_LOGS (space separated paths or globs) to name web server logs.
# Containers: with no directory argument the check also copies the files it reads from running
# docker and podman containers (SCAN_CONTAINERS=1, the default; 0 skips them) and judges them like
# host installs. The copies are temporary: a path shown as .../docker_NAME_PATH is the PATH inside
# the container NAME.
# =============================================================================

# Commands run as "cmd_${CMD}", which shellcheck cannot follow
# shellcheck disable=SC2317,SC2329
set -uo pipefail

SCRIPT_NAME="wordpress-pt-check.sh"
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
SELF_CMD="$(printf '%q ' "$0" "$@")"; SELF_CMD="${SELF_CMD% }"

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
# ---------- version table (GHSA-7hp8-65ch-5whp and the WordPress 7.1.2 release notes) -----
# prints: affected | fixed | notaffected | unlisted | unknown
#   unlisted = a branch whose fixed number is not published in the sources used here
#              (5.0 to 5.7 and 4.9): the source files decide instead
wp_pt_status() {
    local raw="$1" v maj min fixed=""
    raw="${raw%-src}"; v="${raw%%-*}"
    [[ "$v" =~ ^([0-9]+)\.([0-9]+) ]] || { echo unknown; return; }
    maj="${BASH_REMATCH[1]}"; min="${BASH_REMATCH[2]}"
    (( maj < 4 )) && { echo notaffected; return; }
    (( maj == 4 && min < 7 )) && { echo notaffected; return; }
    (( maj > 7 )) && { echo fixed; return; }
    case "${maj}.${min}" in
        7.1) fixed=7.1.2 ;;  7.0) fixed=7.0.6 ;;
        6.9) fixed=6.9.9 ;;  6.8) fixed=6.8.10 ;; 6.7) fixed=6.7.9 ;;
        6.6) fixed=6.6.9 ;;  6.5) fixed=6.5.12 ;; 6.4) fixed=6.4.12 ;;
        6.3) fixed=6.3.12 ;; 6.2) fixed=6.2.13 ;; 6.1) fixed=6.1.14 ;;
        6.0) fixed=6.0.16 ;; 5.9) fixed=5.9.18 ;; 5.8) fixed=5.8.17 ;;
        4.8) fixed=4.8.32 ;; 4.7) fixed=4.7.37 ;;
        4.9|5.0|5.1|5.2|5.3|5.4|5.5|5.6|5.7) echo unlisted; return ;;
        *) (( maj > 7 || (maj == 7 && min > 1) )) && { echo fixed; return; }; echo unknown; return ;;
    esac
    ver_lt "$(norm_ver "$v")" "$fixed" && echo affected || echo fixed
}

# ---------- source signatures: the fix touches only wp-includes/template.php --------
# 1. the guard: a decoded pagename that differs from the raw one is used only if it
#    passes validate_file() (the entry point of the traversal)
# 2. the boundary: a template found by locate_template() is loaded only if
#    _wp_is_template_path_allowed() accepts it
WPT_GUARD='0 === validate_file( $pagename_decoded )'
guard_in_source() {
    local f="$1/wp-includes/template.php"
    [[ -r "$f" ]] || { echo "n/a"; return; }
    if grep -F -- "$WPT_GUARD" "$f" >/dev/null; then echo yes; else echo no; fi
}
boundary_in_source() {
    local f="$1/wp-includes/template.php"
    [[ -r "$f" ]] || { echo "n/a"; return; }
    if grep -F -- '_wp_is_template_path_allowed' "$f" >/dev/null; then echo yes; else echo no; fi
}

# ---------- running containers -----------------------------------------------
# An install inside a container is not on the host. For each running container, find installs by
# their marker file, copy ONLY the files this check reads into a temporary directory (one per
# install, named after the container and the path inside it, mode 0700, removed on exit), and let
# the normal checks judge it like a host install. Paths the container reports are checked before
# they are used. The check never runs anything in a container beyond "find" and a file copy.
# It runs once, in the main shell (a subshell's exit would delete the copies early).
STAGE=""
declare -a STAGED_DIRS=()
stage_containers() {   # <marker file, relative to the install root> <other relative files the check reads>...
    local marker="$1" rt id name roots r f s; shift
    [[ "${SCAN_CONTAINERS:-1}" == 1 ]] || return 0
    for rt in docker podman; do
        have "$rt" || continue
        while read -r id name; do
            [[ -n "$id" ]] || continue
            roots="$("$rt" exec "$id" sh -c "find /var/www /srv /opt /home /usr/share -maxdepth 8 -path '*/${marker}' -type f 2>/dev/null | head -n 20" 2>/dev/null)" || continue
            while read -r r; do
                [[ "$r" =~ ^/[A-Za-z0-9._/@+-]+$ && "$r" == */"$marker" ]] || continue
                r="${r%/"$marker"}"
                if [[ -z "$STAGE" ]]; then
                    STAGE="$(mktemp -d)" || return 0
                    trap 'rm -rf "${STAGE:-}"' EXIT
                fi
                s="$STAGE/${rt}_${name:-$id}_${r//\//_}"; mkdir -p "$s"
                for f in "$marker" "$@"; do
                    mkdir -p "$s/$(dirname "$f")"
                    "$rt" cp "${id}:${r}/${f}" "$s/$f" >/dev/null 2>&1 || rm -f "$s/$f"
                    [[ -L "$s/$f" ]] && rm -f "$s/$f"
                done
                STAGED_DIRS+=("$s")
            done <<<"$roots"
        done < <("$rt" ps --format '{{.ID}} {{.Names}}' 2>/dev/null)
    done
}

cmd_check() {
    # running containers: stage once, here in the main shell, then pass the staged directories on
    # as ordinary directory arguments
    if [[ $# -eq 0 ]]; then
        stage_containers 'wp-includes/version.php' 'wp-includes/template.php'
        if [[ ${#STAGED_DIRS[@]} -gt 0 ]]; then
            local _d; local -a _a=()
            for _d in /var/www /srv /home /opt /usr/share/wordpress /usr/share/nginx /var/lib/wordpress; do [[ -d "$_d" ]] && _a+=("$_d"); done
            set -- ${_a[@]:+"${_a[@]}"} "${STAGED_DIRS[@]}"
        fi
    fi
    local -a dirs=() existing=() roots=()
    local rc=0 found=0 d f root ver st gd bd
    if [[ $# -gt 0 ]]; then dirs=("$@"); else dirs=(/var/www /srv /home /opt /usr/share/wordpress /usr/share/nginx /var/lib/wordpress); fi
    for d in "${dirs[@]}"; do [[ -d "$d" ]] && existing+=("$d"); done
    step "Looking for WordPress"
    if [[ ${#existing[@]} -eq 0 ]]; then info "None of the search directories exist"; return 0; fi
    while IFS= read -r f; do [[ -n "$f" ]] && roots+=("$(dirname "$(dirname "$f")")"); done < <(find "${existing[@]}" -xdev -maxdepth 8 -path '*/wp-includes/version.php' -type f 2>/dev/null | sort -u)
    for root in "${roots[@]:-}"; do
        [[ -n "$root" ]] || continue
        found=$((found+1))
        ver="$(sed -nE "s/^[[:space:]]*\\\$wp_version[[:space:]]*=[[:space:]]*'([^']+)'.*/\\1/p" "$root/wp-includes/version.php" 2>/dev/null | head -n1)"
        step "WordPress ${ver:-unknown} at ${root}"
        [[ -n "$ver" ]] || { caution "could not read the version from wp-includes/version.php"; rc=1; continue; }
        st="$(wp_pt_status "$ver")"
        gd="$(guard_in_source "$root")"; bd="$(boundary_in_source "$root")"
        if [[ "$st" == notaffected ]]; then caution "${ver} is before 4.7.0: outside the range of CVE-2026-87902, but WordPress this old has had no security fixes for years and is not confirmed clear of other issues: update it"; rc=1; continue; fi
        if [[ "$gd" != "n/a" ]]; then
            # the source decides: both fixes present means fixed, whatever the version string says
            if [[ "$gd" == yes && "$bd" == yes ]]; then
                if [[ "$st" == affected || "$st" == unlisted ]]; then
                    ok "version ${ver} would be in the affected range, but template.php carries both fixes (a distribution backport): not exposed"
                    inf "the version string understates this install's state; update to a fixed release when you can"
                else ok "${ver} has the fix"; fi
                continue
            fi
            if [[ "$gd" == yes || "$bd" == yes ]]; then
                bad "WordPress ${ver}: template.php carries only one of the two fixes (pagename guard ${gd}, template path boundary ${bd}): partially patched"
                rc=1; continue
            fi
            if [[ "$st" == fixed ]]; then
                caution "version ${ver} is a fixed release, but template.php still has the vulnerable code: the files do not match the version (a partial or failed update)"
            else
                bad "WordPress ${ver} has CVE-2026-87902: unauthenticated path traversal in page-template resolution, potentially leading to local PHP file inclusion. Fixed in 7.1.2, 7.0.6, 6.9.9, 6.8.10, 6.7.9, 6.6.9 and the older branches down to 4.7.37"
            fi
            inf "source check: pagename guard ${gd}; template path boundary ${bd}"
            rc=1; continue
        fi
        # template.php unreadable: fall back to the version table
        case "$st" in
            fixed)    ok "${ver} is a fixed release (template.php could not be read to confirm)" ;;
            affected) bad "WordPress ${ver} is below the fixed release of its branch (CVE-2026-87902); template.php could not be read to check for a backport"; rc=1 ;;
            *)        caution "WordPress ${ver}: this branch's fixed number is not in the sources used, and template.php could not be read: update to the newest release"; rc=1 ;;
        esac
    done
    step "Verdict"
    if [[ $found -eq 0 ]]; then
        info "No WordPress found under: ${existing[*]}"
    elif [[ $rc -eq 0 ]]; then
        info "No exposed WordPress found (${found} checked)."
    else
        warn "Exposed WordPress found. Update core: wp core update (7.1.2, 7.0.6, 6.9.9, 6.8.10, 6.7.9 or the fixed release of your branch)."
        inf "If the site was reachable after 22 September 2026, run: $0 hunt"
        inf "Advisory: GHSA-7hp8-65ch-5whp and https://www.cve.org/CVERecord?id=CVE-2026-87902"
    fi
    return "$rc"
}

cmd_hunt() {
    local unread=0
    local rc=0 n f nlog=0 g total=0
    step "Hunting for CVE-2026-87902 exploitation in web server logs"
    local -a logs=()
    if [[ -n "${WPT_LOGS:-}" ]]; then
        # shellcheck disable=SC2206
        for g in $WPT_LOGS; do for f in $g; do if [[ -f "$f" ]]; then if [[ -r "$f" ]]; then logs+=("$f"); else unread=$((unread+1)); fi; fi; done; done
    else
        for g in /var/log/nginx/access.log* /var/log/nginx/*access*.log* /var/log/apache2/access.log* /var/log/apache2/*access*.log* /var/log/httpd/access_log* /var/log/httpd/*access*log* /var/log/angie/access.log*; do
            for f in $g; do if [[ -f "$f" ]]; then if [[ -r "$f" ]]; then logs+=("$f"); else unread=$((unread+1)); fi; fi; done
        done
    fi
    if [[ ${#logs[@]} -eq 0 ]]; then
        inf "no web server access logs found (set WPT_LOGS to name them)"
    else
        # an encoded dot or slash in the pagename value, however many times it is encoded:
        # N times encoded is a percent sign, then 25 repeated N-1 times, then 2E or 2F
        # (a plain ../ is included: it is never legitimate in a pagename), and the scanner
        # user agents that were seen in the attacks
        local re='pagename=[^&" ]*%(25)+(2[Ee]|2[Ff])|pagename=[^&" ]*(\.\./|%2[Ee]%2[Ee]|\.\.%2[Ff])|cve-2026-87902-poc|nuclei-cve-2026-87902'
        for f in "${logs[@]}"; do
            nlog=$((nlog+1))
            n="$(zcat -f "$f" 2>/dev/null | grep -Ec "$re")"
            total=$((total+n))
            [[ "$n" -gt 0 ]] && inf "${f}: ${n} matching request(s)"
        done
        inf "read ${nlog} log file(s)"
        if [[ $total -gt 0 ]]; then
            bad "${total} request(s) carry an encoded traversal in the pagename parameter, or a scanner user agent: a strong lead"
            for f in "${logs[@]}"; do zcat -f "$f" 2>/dev/null | grep -E "$re" | head -n 3 | cut -c1-200 | sed 's/^/        /'; done | head -n 8
            rc=1
        else
            ok "no encoded traversal in a pagename parameter found in the logs read"
        fi
        inf "a POST body is not recorded in an access log, and the public exploits send the payload in the body: a quiet log does not rule out an attempt"
    fi
    step "Verdict"
    if [[ $rc -eq 0 && $unread -gt 0 ]]; then
        warn "No strong lead in the logs that could be read, but ${unread} log file(s) could not be read by this user, so this is not a clean result. Run it with sudo: sudo ${SELF_CMD}"; rc=2
    elif [[ $rc -eq 0 ]]; then info "No strong lead found: none of the published indicators were found."
    else warn "Strong lead found. If the site was not updated at the time, look for PHP files outside the theme and plugin directories and for new administrator accounts."; fi
    return "$rc"
}

main() {
    CMD="${1:-check}"; [[ $# -gt 0 ]] && shift
    case "$CMD" in -V|--version|version) echo "${SCRIPT_NAME} ${SCRIPT_VERSION} (${SCRIPT_DATE})"; exit 0 ;; esac
    case "$CMD" in -h|--help|help) print_help; exit 0 ;; esac
    echo "${SCRIPT_NAME} ${SCRIPT_VERSION} (${SCRIPT_DATE}) - ${CMD} on $(hostname 2>/dev/null || echo '?') at $(date -u +%FT%TZ)"
    echo "CVE-2026-87902 (WordPress page-template path traversal); fixed in 7.1.2, 7.0.6, 6.9.9, 6.8.10 and older-branch backports"
    case "$CMD" in
        check) cmd_check "$@" ;;
        hunt)  cmd_hunt "$@" ;;
        *) die "Unknown command: ${CMD} (check|hunt|version)" ;;
    esac
}
main "$@"; exit

# Assisted-by: Claude Sonnet 5.5
