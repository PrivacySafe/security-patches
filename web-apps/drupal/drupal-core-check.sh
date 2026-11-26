#!/usr/bin/env bash
# SPDX-License-Identifier: CC0-1.0
# =============================================================================
# Drupal core Field UI and Entity List remote code execution: checker with mitigation  (v2)
# CVE-2026-108097 (SA-CORE-2026-014) and CVE-2026-108099 (SA-CONTRIB-2026-218)
#
# If this software is helpful, consider a donation to our 501c3 nonprofit:
# https://privacysafe.foundation
#
# The Field UI module in Drupal core does not properly validate PHP callbacks
# while it renders its tables. Drupal rates it Critical, 19/25. Drupal core
# alone is not directly exploitable: the callbacks have to be reachable from
# data an attacker controls, and that happens through contributed modules or
# custom code. At least one such path needs no authentication, which is why the
# Drupal Security Team announced it in advance (PSA-2026-10-12) and called for
# emergency patching. A research write-up with laboratory artifacts has been
# published; at disclosure no public exploit for real sites existed.
#
#   Affected: Drupal core 8.9.0 up to 10.6.19, 11.0.0 up to 11.3.19,
#             11.4.0 up to 11.4.10, and Drupal 12 before 12.0.0-beta2
#   Fixed:    10.6.19, 11.3.19, 11.4.10 (released 14 October 2026), and
#             12.0.0-beta2 for Drupal 12
#   Move to:  a supported branch. 10.5.x and earlier, 11.2.x and earlier, 9.x and
#             8.9.x are end of life
#   Workaround published by Drupal: uninstall the core Field UI module. It covers
#             only this advisory. The same release fixes two other core issues
#             that only the update fixes.
#
# CVE-2026-108099 is the same story for the contributed Entity List module
# (project entity_list), which builds lists of entities without Views. Versions
# before 3.0.10 have a critical remote code execution flaw (Drupal rating 19/25).
# It is not directly exploitable by itself, but multiple serious exploit paths exist
# with other contributed modules, at least one needs no authentication, and custom
# code may expose it. Fixed: Entity List 3.0.10 (14 October 2026). UPDATING DRUPAL
# CORE DOES NOT REPLACE THE MODULE: it needs its own update. The script checks it on
# every site it finds, whatever the core version is.
#
# "check" is read-only; "mitigate" and "rollback" are the only commands that change
# anything. "check" finds Drupal sites from core/lib/Drupal.php (and
# composer.lock), applies the version rules, reads exported configuration
# (core.extension.yml) to see whether Field UI is enabled, and flags the
# contributed Entity List module and compares its version with 3.0.10 (read from
# its info.yml, or from composer.lock when the info file carries no version).
#
# Usage:
#   ./drupal-core-check.sh [command] [DIR ...]
#
#   check (default)  scan DIR (default /var/www /srv /opt /home). Exit 0 = nothing
#                    exposed, 1 = an affected site is exposed, unverifiable, or on
#                    an end-of-life branch that cannot be patched.
#   mitigate [--dir DIR] [--dry-run] [--force]   (root) changes the host. Drupal's own
#                    published workaround for CVE-2026-108097: uninstalls the Field UI
#                    module with drush (pm:uninstall field_ui) on every site whose core is
#                    affected and where the LIVE site (not only exported configuration)
#                    still has it enabled. drush runs as the owner of the site, never as
#                    root, and is looked up in the project's vendor/bin, then PATH. The
#                    field management screens are unavailable until you reinstall Field UI.
#                    It covers this advisory only: the same release fixes two other core
#                    issues, so update core as well. --force uninstalls on a core that is
#                    not in the affected range.
#   rollback [--dry-run]   reinstall Field UI (pm:install field_ui) on the sites mitigate changed.
#   version          print the script version.
#
# Configuration kept only in the database is not visible to a file scan. On a
# live site, run in the Drupal root:
#   drush pm:list --status=enabled --type=module --format=list | grep -x field_ui
# Containers: with no directory argument the check also copies the files it reads from running
# docker and podman containers (SCAN_CONTAINERS=1, the default; 0 skips them) and judges them like
# host installs. The copies are temporary: a path shown as .../docker_NAME_PATH is the PATH inside
# the container NAME.
#      PSF_LOCK_WAIT    seconds a run that changes the host waits for another one that is already
#                       changing it (default 30), then stops with exit 2; the lock is STATE_DIR/.lock
# =============================================================================

# Commands run as "cmd_${CMD}", which shellcheck can't follow
# shellcheck disable=SC2317,SC2329
set -uo pipefail

SCRIPT_NAME="drupal-core-check.sh"
SCRIPT_VERSION="2.1.0"
SCRIPT_DATE="2026-11-25"
SELF="$0"
STATE_DIR="${STATE_DIR:-/var/lib/psf-security-patches/drupal}"

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
# prints: vulnerable | eol | fixed | dev | old | out
dcore_status() {
    local raw="$1" n major minor
    [[ "$raw" == *-dev || "$raw" == *.x-dev || "$raw" == dev-* ]] && { echo dev; return; }
    n="$(norm_ver "$raw")"
    is_semver "$n" || { echo dev; return; }
    major="${n%%.*}"; minor="${n#*.}"; minor="${minor%%.*}"
    case "$major" in
        7|6|5|4|3|2|1|0) echo out ;;
        8) ver_ge "$n" "8.9.0" && echo eol || echo old ;;
        9) echo eol ;;
        10)
            if (( minor >= 7 )); then echo fixed
            elif (( minor == 6 )); then ver_lt "$n" "10.6.19" && echo vulnerable || echo fixed
            else echo eol; fi ;;
        11)
            if (( minor >= 5 )); then echo fixed
            elif (( minor == 4 )); then ver_lt "$n" "11.4.10" && echo vulnerable || echo fixed
            elif (( minor == 3 )); then ver_lt "$n" "11.3.19" && echo vulnerable || echo fixed
            else echo eol; fi ;;
        12)
            # 12.0.0 alpha and beta1 are affected; beta2 and later are fixed
            if [[ "$raw" =~ ^12\.0\.0-(alpha|beta1$|beta1[^0-9]) ]]; then echo vulnerable; else echo fixed; fi ;;
        *) echo fixed ;;
    esac
}

core_version_from_source() {   # path to core/lib/Drupal.php
    sed -n "s/^[[:space:]]*const VERSION = '\([^']*\)'.*/\1/p" "$1" | head -n1
}

lock_pkg_version() {
    awk -v pkg="\"name\": \"$2\"" 'index($0,pkg){f=1;next} f && /"version":/{gsub(/[",]/,"",$2); print $2; exit}' "$1"
}

# field_ui state from exported configuration: prints enabled | disabled | unknown
field_ui_state() {   # project root
    local root="$1" f found=0
    while IFS= read -r f; do
        [[ -n "$f" ]] || continue
        found=1
        if grep -qE '^[[:space:]]+field_ui:[[:space:]]*[0-9]+' "$f"; then echo enabled; return; fi
    done < <(find "$root" -maxdepth 8 -name core.extension.yml -type f \
                -not -path '*/vendor/*' -not -path '*/core/*' -not -path '*/tests/*' -not -path '*/node_modules/*' 2>/dev/null)
    if [[ $found -eq 1 ]]; then echo disabled; else echo unknown; fi
}

# Entity List (CVE-2026-108099): its own version rule, independent of the core version
entity_list_check() {   # project root -> returns 1 when it needs action
    local root="$1" info path v lockv
    info="$(find "$root" -maxdepth 8 -path '*/entity_list/entity_list.info.yml' -type f -not -path '*/tests/*' 2>/dev/null | head -n1)"
    [[ -n "$info" ]] || return 0
    path="$(dirname "$info")"
    v="$(sed -n "s/^version:[[:space:]]*['\"]\{0,1\}\([^'\"]*\)['\"]\{0,1\}.*/\1/p" "$info" | head -n1)"
    v="${v#8.x-}"
    if [[ -z "$v" && -r "${root}/composer.lock" ]]; then
        lockv="$(lock_pkg_version "${root}/composer.lock" drupal/entity_list)"; v="${lockv#v}"; v="${v#8.x-}"
    fi
    if [[ -z "$v" ]]; then
        caution "Entity List is installed at ${path} but its version could not be read: check it (composer show drupal/entity_list). Anything before 3.0.10 has CVE-2026-108099, a critical remote code execution flaw that updating core does not fix."
        return 1
    fi
    if [[ "$v" == *dev* ]]; then
        caution "Entity List ${v} (a development version) at ${path}: confirm it includes the 3.0.10 fix for CVE-2026-108099"
        return 1
    fi
    if ver_lt "$(norm_ver "$v")" "3.0.10"; then
        bad "the contributed Entity List module ${v} at ${path} is affected by CVE-2026-108099 (SA-CONTRIB-2026-218, fixed in 3.0.10): critical remote code execution with at least one unauthenticated exploit path via other contributed modules. Updating core does NOT fix it."
        return 1
    fi
    ok "Entity List ${v} has the fix (3.0.10 or newer)"
    return 0
}

# ---------- check ------------------------------------------------------------
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
        stage_containers 'core/lib/Drupal.php' 'composer.lock'
        if [[ ${#STAGED_DIRS[@]} -gt 0 ]]; then
            local _d; local -a _a=()
            for _d in /var/www /srv /opt /home; do [[ -d "$_d" ]] && _a+=("$_d"); done
            set -- ${_a[@]:+"${_a[@]}"} "${STAGED_DIRS[@]}"
        fi
    fi
    local -a dirs=() existing=()
    local rc=0 found=0 d f root ver lockver lock st fu
    if [[ $# -gt 0 ]]; then dirs=("$@"); else dirs=(/var/www /srv /opt /home); fi
    for d in "${dirs[@]}"; do [[ -d "$d" ]] && existing+=("$d"); done
    step "Looking for Drupal sites"
    if [[ ${#existing[@]} -eq 0 ]]; then info "None of the search directories exist"; return 0; fi
    while IFS= read -r f; do
        [[ -n "$f" ]] || continue
        found=$((found+1))
        ver="$(core_version_from_source "$f")"
        # core/lib/Drupal.php -> docroot is two levels up; the project root may be one more
        root="$(dirname "$(dirname "$(dirname "$f")")")"
        [[ "$(basename "$root")" == "web" || "$(basename "$root")" == "docroot" ]] && root="$(dirname "$root")"
        lockver=""; lock="${root}/composer.lock"
        [[ -r "$lock" ]] && lockver="$(lock_pkg_version "$lock" drupal/core)"
        step "Drupal ${ver:-?} at ${root}"
        entity_list_check "$root" || rc=1
        if [[ -z "$ver" ]]; then caution "version not found in ${f}; treating it as not confirmed fixed"; rc=1; continue; fi
        [[ -n "$lockver" && "$(norm_ver "$lockver")" != "$(norm_ver "$ver")" ]] \
            && inf "composer.lock says drupal/core ${lockver}; the installed core says ${ver}; using the installed copy"
        st="$(dcore_status "$ver")"
        case "$st" in
            fixed) ok "Drupal core ${ver} has the fix (10.6.19, 11.3.19, 11.4.10 or 12.0.0-beta2 or newer)"; continue ;;
            out)   caution "Drupal ${ver} is outside the affected range of this advisory (it is end of life; Drupal 7 has its own long-term-support fix path), and not confirmed clear of other issues"; rc=1; continue ;;
            old)   caution "Drupal ${ver} is older than 8.9.0, which the advisory does not describe; it is end of life regardless and not confirmed clear of other issues"; rc=1; continue ;;
            dev)   caution "development or unparseable version '${ver}': check the exact commit against the advisory"; rc=1; continue ;;
            eol)   bad "Drupal core ${ver} is affected by CVE-2026-108097 and its branch is end of life: it will not be patched, move to 10.6.19, 11.3.19 or 11.4.10"; rc=1 ;;
            vulnerable) bad "Drupal core ${ver} is affected by CVE-2026-108097 (fixed in 10.6.19, 11.3.19, 11.4.10, 12.0.0-beta2)" ;;
        esac
        fu="$(field_ui_state "$root")"
        case "$fu" in
            enabled)  bad "the Field UI module is ENABLED in exported configuration: the vulnerable code is present"; [[ "$st" == vulnerable ]] && rc=1 ;;
            disabled)
                ok "Field UI is not enabled in exported configuration: Drupal's published workaround is in effect for this advisory"
                caution "update anyway: the same release fixes two other core issues that the workaround does not cover" ;;
            *)
                caution "no exported core.extension.yml found, so Field UI status is unknown (configuration may live only in the database): treating as exposed"
                inf "check on the live site: drush pm:list --status=enabled --type=module --format=list | grep -x field_ui"
                [[ "$st" == vulnerable ]] && rc=1 ;;
        esac
    done < <(find "${existing[@]}" -maxdepth 7 -path '*/core/lib/Drupal.php' -type f \
                -not -path '*/vendor/*' -not -path '*/node_modules/*' 2>/dev/null | sort -u)
    step "Verdict"
    if [[ $found -eq 0 ]]; then
        info "No Drupal site found under: ${existing[*]}"
    elif [[ $rc -eq 0 ]]; then
        info "No exposed Drupal found (${found} checked)"
    else
        warn "Exposed Drupal found. Update core (and Entity List to 3.0.10 or later if it is installed): composer update 'drupal/core-*' --with-all-dependencies, then drush updb and drush cr."
        inf "If you cannot update today, uninstall Field UI (Drupal's published workaround for this advisory only): drush pm:uninstall field_ui"
        inf "Then review contributed and custom code that passes request data into render arrays or field configuration."
        inf "Advisory: https://www.drupal.org/sa-core-2026-014"
    fi
    return "$rc"
}

# ---------- dispatch ---------------------------------------------------------

# ---------- mitigate and rollback --------------------------------------------
DR_MANIFEST=""; DR_DRY=0
dr_runner() {   # path of runuser, which usually lives in /usr/sbin and may not be on PATH
    local c
    for c in "$(command -v runuser 2>/dev/null || true)" /usr/sbin/runuser /sbin/runuser /usr/bin/runuser; do
        [[ -n "$c" && -x "$c" ]] && { echo "$c"; return 0; }
    done
    return 1
}
dr_drush() {   # owner docroot drushbin args...  (runs as the owner of the site, never as root, so no root-owned cache files appear)
    local owner="$1" docroot="$2" bin="$3" ru; shift 3
    if [[ "${EUID:-$(id -u)}" -eq 0 && -n "$owner" && "$owner" != root ]]; then
        ru="$(dr_runner)" || { echo "cannot run drush as ${owner}: runuser not found" >&2; return 126; }
        "$ru" -u "$owner" -- "$bin" --root="$docroot" "$@"
    else "$bin" --root="$docroot" "$@"; fi
}
dr_field_ui_enabled() { grep -qx field_ui <<<"$(dr_drush "$1" "$2" "$3" pm:list --status=enabled --type=module --format=list 2>/dev/null)"; }

cmd_mitigate() {
    local force=0 rc=0 f ver st root docroot owner bin did=0 found=0 d
    local -a dirs=() existing=()
    DR_DRY=0
    while [[ $# -gt 0 ]]; do
        case "$1" in
            --dry-run) DR_DRY=1 ;; --force) force=1 ;;
            --dir) shift; [[ -n "${1:-}" ]] || die "--dir needs a directory"; dirs+=("$1") ;;
            *) die "Unknown mitigate option: $1 (--dir DIR --dry-run --force)" ;;
        esac
        shift
    done
    [[ $DR_DRY -eq 1 || -n "${DR_ALLOW_NONROOT:-}" ]] || need_root "mitigate changes the host"
    [[ ${#dirs[@]} -gt 0 ]] || dirs=(/var/www /srv /opt /home)
    for d in "${dirs[@]}"; do [[ -d "$d" ]] && existing+=("$d"); done
    step "Looking for affected Drupal sites"
    if [[ ${#existing[@]} -eq 0 ]]; then info "None of the search directories exist"; return 0; fi
    if [[ $DR_DRY -eq 0 ]]; then
        mkdir -p "$STATE_DIR" || die "cannot create ${STATE_DIR}"
        DR_MANIFEST="${STATE_DIR}/manifest.txt"; touch "$DR_MANIFEST"
    else DR_MANIFEST=/dev/null; step "Dry run: nothing will be changed"; fi
    while IFS= read -r f; do
        [[ -n "$f" ]] || continue
        found=$((found+1))
        ver="$(core_version_from_source "$f")"
        docroot="$(dirname "$(dirname "$(dirname "$f")")")"; root="$docroot"
        [[ "$(basename "$root")" == "web" || "$(basename "$root")" == "docroot" ]] && root="$(dirname "$root")"
        step "Drupal ${ver:-?} at ${root}"
        st="$(dcore_status "${ver:-x}")"
        case "$st" in
            vulnerable|eol) bad "core ${ver} is affected by CVE-2026-108097" ;;
            *) if [[ $force -eq 0 ]]; then ok "core ${ver:-unknown} is not in the affected range: left alone (use --force to uninstall Field UI anyway)"; continue; fi
               caution "core ${ver:-unknown} is not affected, applying anyway because of --force" ;;
        esac
        bin=""
        if [[ -x "${root}/vendor/bin/drush" ]]; then bin="${root}/vendor/bin/drush"
        elif [[ -x "${docroot}/../vendor/bin/drush" ]]; then bin="${docroot}/../vendor/bin/drush"
        elif have drush; then bin="$(command -v drush)"; fi
        if [[ -z "$bin" ]]; then caution "no drush found (looked in ${root}/vendor/bin and PATH): uninstall Field UI by hand with  drush pm:uninstall field_ui"; rc=1; continue; fi
        owner="$(stat -c %U "$docroot" 2>/dev/null)"
        if [[ "${EUID:-$(id -u)}" -eq 0 && -n "$owner" && "$owner" != root ]] && ! dr_runner >/dev/null; then
            caution "cannot run drush as ${owner} (runuser not found) and it will not be run as root on that site: uninstall Field UI by hand with  drush pm:uninstall field_ui"; rc=1; continue
        fi
        if ! dr_drush "$owner" "$docroot" "$bin" status --field=bootstrap >/dev/null 2>&1 && [[ "${DR_SKIP_BOOTSTRAP:-0}" -ne 1 ]]; then
            caution "drush cannot bootstrap this site as ${owner:-the current user}: left alone (check the database settings, then retry)"; rc=1; continue
        fi
        if ! dr_field_ui_enabled "$owner" "$docroot" "$bin"; then ok "Field UI is not enabled on the live site: Drupal's workaround is already in effect"; continue; fi
        if [[ $DR_DRY -eq 1 ]]; then echo "  would run (as ${owner:-current user}): ${bin} --root=${docroot} pm:uninstall field_ui -y"; continue; fi
        if dr_drush "$owner" "$docroot" "$bin" pm:uninstall field_ui -y >/dev/null 2>&1 && ! dr_field_ui_enabled "$owner" "$docroot" "$bin"; then
            ok "Field UI uninstalled (Drupal's published workaround); the live site no longer lists it"
            echo "drupal|${docroot}|${bin}|${owner}" >>"$DR_MANIFEST"; did=1
        else bad "drush did not uninstall Field UI: check the site by hand"; rc=1; fi
    done < <(find "${existing[@]}" -maxdepth 7 -path '*/core/lib/Drupal.php' -type f -not -path '*/vendor/*' -not -path '*/node_modules/*' 2>/dev/null | sort -u)
    step "Result"
    [[ $found -gt 0 ]] || info "No Drupal site found under: ${existing[*]}"
    if [[ $DR_DRY -eq 1 ]]; then info "Dry run finished: nothing was changed"
    elif [[ $did -eq 1 ]]; then info "Field UI is uninstalled. The field management screens are gone until you update core and reinstall it. Undo with: $0 rollback"
    else info "Nothing was changed"; fi
    inf "Drupal's own workaround covers this advisory only: the same release fixes two other core issues. Update core: composer update 'drupal/core-*' --with-all-dependencies, then drush updb and drush cr."
    return "$rc"
}

cmd_rollback() {
    local line rest docroot bin owner rc=0
    DR_DRY=0
    while [[ $# -gt 0 ]]; do
        case "$1" in --dry-run) DR_DRY=1 ;; *) die "Unknown rollback option: $1 (--dry-run)" ;; esac
        shift
    done
    DR_MANIFEST="${STATE_DIR}/manifest.txt"
    [[ -s "$DR_MANIFEST" ]] || { info "Nothing to roll back (no manifest in ${STATE_DIR})"; return 0; }
    [[ $DR_DRY -eq 1 || -n "${DR_ALLOW_NONROOT:-}" ]] || need_root "rollback changes the host"
    step "Rolling back"
    while IFS= read -r line; do
        [[ "$line" == drupal\|* ]] || continue
        rest="${line#drupal|}"; docroot="${rest%%|*}"; rest="${rest#*|}"; bin="${rest%%|*}"; owner="${rest#*|}"
        if [[ $DR_DRY -eq 1 ]]; then echo "  would run (as ${owner:-current user}): ${bin} --root=${docroot} pm:install field_ui -y"; continue; fi
        if dr_drush "$owner" "$docroot" "$bin" pm:install field_ui -y >/dev/null 2>&1 && dr_field_ui_enabled "$owner" "$docroot" "$bin"; then ok "Field UI reinstalled on ${docroot}"
        else bad "could not reinstall Field UI on ${docroot}: run  drush pm:install field_ui  by hand"; rc=1; fi
    done <"$DR_MANIFEST"
    if [[ $DR_DRY -eq 0 && $rc -eq 0 ]]; then
        mv "$DR_MANIFEST" "${DR_MANIFEST}.rolled-back-$(date +%s)" 2>/dev/null || true
        info "Rolled back."
    fi
    return "$rc"
}

main() {
    CMD="${1:-check}"; [[ $# -gt 0 ]] && shift
    case "$CMD" in -V|--version|version) echo "${SCRIPT_NAME} ${SCRIPT_VERSION} (${SCRIPT_DATE})"; exit 0 ;; esac
    case "$CMD" in -h|--help|help) print_help; exit 0 ;; esac
    echo "${SCRIPT_NAME} ${SCRIPT_VERSION} (${SCRIPT_DATE}) - ${CMD} on $(hostname 2>/dev/null || echo '?') at $(date -u +%FT%TZ)"
    echo "CVE-2026-108097; fixed in Drupal 10.6.19, 11.3.19, 11.4.10 and 12.0.0-beta2"
    case "$CMD" in
        check) cmd_check "$@" ;;
        mitigate) cmd_mitigate "$@" ;;
        rollback) cmd_rollback "$@" ;;
        *) die "Unknown command: ${CMD} (check|mitigate|rollback|version)" ;;
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
