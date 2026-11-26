#!/usr/bin/env bash
# SPDX-License-Identifier: CC0-1.0
# =============================================================================
# Laravel TokenGuard authentication bypass: read-only checker  (v1)
# CVE-2026-114509 (GHSA-f9x3-7vq9-cph6)
#
# If this software is helpful, consider a donation to our 501c3 nonprofit:
# https://privacysafe.foundation
#
# Laravel's built-in token guard ('driver' => 'token') does not reject a
# crafted non-string credential, such as a JSON body {"api_token": [0]}. On
# MySQL and MariaDB the lookup can then match an unintended existing user, so an
# unauthenticated attacker can sign in as that user on any route protected by
# the token guard. CVSS 9.2 (v4.0). Reported by Hristijan Manasijev.
#
# Fixed in laravel/framework 12.68.0 and 13.29.0, both released 25 August 2026,
# two months before the advisory was published on 19 October 2026. The 11.x
# branch carries the same is_string() check from v11.56.1. 10.x and 9.x apps upgrade to a fixed branch. Apps that use
# Laravel Sanctum or Laravel Passport register their own guard drivers and are
# not the target of this bug.
#
# This script is read-only. It looks at composer.lock and the installed
# vendor/ copy, at config/auth.php for a guard with the token driver, at routes
# that use that guard, and at the database driver in .env.
#
# Usage:
#   ./laravel-tokenguard-check.sh [command] [DIR ...]
#
#   check (default)  scan DIR (default /var/www /srv /home /opt) for Laravel
#                    projects. Exit 0 = nothing exposed, 1 = an affected
#                    project looks exposed or is on a branch that needs an upgrade.
#   middleware       print a protective PHP middleware that rejects non-string
#                    api_token values. It prints to stdout only.
#   version          print the script version.
#
# The protective middleware is for apps that cannot upgrade today. 9.x and 10.x apps should plan an upgrade.
# Containers: with no directory argument the check also reads the project files it needs from
# running docker and podman containers (SCAN_CONTAINERS=1, the default; 0 skips them), through a
# read-only probe, and judges them like host projects. The copies are temporary: a path shown as
# .../docker_NAME/PATH is the PATH inside the container NAME.
# =============================================================================

# Commands run as "cmd_${CMD}", which shellcheck can't follow
# shellcheck disable=SC2317,SC2329
set -uo pipefail

SCRIPT_NAME="laravel-tokenguard-check.sh"
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

# ---------- version rules ----------------------------------------------------
# prints "fixed", "vulnerable" or "unfixed" (vulnerable, no upstream fix)
laravel_status() {
    local v raw="${1#v}"; v="$(norm_ver "$1")"
    # norm_ver drops a pre-release suffix, so 12.68.0-RC1 would read as 12.68.0. A pre-release of a
    # fixed release comes BEFORE it and does not have the fix.
    if [[ "$raw" == *-* ]] && [[ "$v" == 13.29.0 || "$v" == 12.68.0 || "$v" == 11.56.1 ]]; then echo vulnerable; return; fi
    case "${v%%.*}" in
        13) ver_lt "$v" "13.29.0" && echo vulnerable || echo fixed ;;
        12) ver_lt "$v" "12.68.0" && echo vulnerable || echo fixed ;;
        11) ver_lt "$v" "11.56.1" && echo vulnerable || echo fixed ;;
        ''|*[!0-9]*) echo unknown ;;
        *)  if (( ${v%%.*} > 13 )); then echo fixed; else echo unfixed; fi ;;
    esac
}

lock_pkg_version() {   # composer.lock package -> version
    awk -v pkg="\"name\": \"$2\"" 'index($0,pkg){f=1;next} f && /"version":/{gsub(/[",]/,"",$2); print $2; exit}' "$1"
}

installed_version() {  # project dir -> version of vendor/laravel/framework
    local app="$1/vendor/laravel/framework/src/Illuminate/Foundation/Application.php"
    [[ -r "$app" ]] && sed -n "s/.*const VERSION = '\([^']*\)'.*/\1/p" "$app" | head -n1
    return 0
}

token_guards() {       # config/auth.php -> names of guards that use the token driver
    local auth="$1" ln name
    while IFS=: read -r ln _; do
        [[ -n "$ln" ]] || continue
        name="$(sed -n "$(( ln > 6 ? ln-6 : 1 )),${ln}p" "$auth" \
                | grep -E "=>[[:space:]]*\\[" | tail -n1 \
                | sed -E "s/^[[:space:]]*['\"]([A-Za-z0-9_-]+)['\"].*/\\1/")"
        [[ -n "$name" ]] && echo "$name"
    done < <(grep -nE "['\"]driver['\"][[:space:]]*=>[[:space:]]*['\"]token['\"]" "$auth")
    return 0
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
#   L <path> <text>   write one short sanitized line of text (used so .env itself is never copied)
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
                [[ "$p" =~ ^/[]A-Za-z0-9._/@+[-]+$ && "$p" != */../* && "$p" != */.. ]] || continue   # no ".." path component
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
                esac
            done <<<"$out"
            [[ -z "$s" ]] || STAGED_DIRS+=("$s")
        done < <("$rt" ps --format '{{.ID}} {{.Names}}' 2>/dev/null)
    done
}

LARAVEL_PROBE="$(cat <<'EOS'
R="/var/www /srv /home /opt"
find $R -maxdepth 7 \( -name node_modules -o -name vendor \) -prune -o -name composer.lock -type f -print 2>/dev/null | head -n 30 | while read -r l; do
  grep -q "\"name\": \"laravel/framework\"" "$l" 2>/dev/null || continue
  d=${l%/*}
  echo "F $l"
  f=vendor/laravel/framework/src/Illuminate/Foundation/Application.php
  [ -f "$d/$f" ] && echo "F $d/$f"
  [ -f "$d/config/auth.php" ] && echo "F $d/config/auth.php"
  for b in routes app bootstrap; do [ -d "$d/$b" ] && echo "D $d/$b"; done
  find "$d/routes" "$d/app" "$d/bootstrap" -type f -name "*.php" 2>/dev/null | head -n 3000 | xargs -r grep -lIE "auth:[A-Za-z0-9_-]|Auth::guard\(" 2>/dev/null | head -n 50 | while read -r f; do echo "F $f"; done
  if [ -f "$d/.env" ]; then
    v=$(grep -E "^DB_CONNECTION=" "$d/.env" 2>/dev/null | head -n 1 | cut -d= -f2- | tr -d "\"'")
    [ -n "$v" ] && echo "L $d/.env DB_CONNECTION=$v"
  fi
done
exit 0
EOS
)"

cmd_check() {
    # running containers: stage once, here in the main shell, then pass the staged directories on
    # as ordinary directory arguments
    if [[ $# -eq 0 ]]; then
        stage_probe "$LARAVEL_PROBE"
        if [[ ${#STAGED_DIRS[@]} -gt 0 ]]; then
            local _d; local -a _a=()
            for _d in /var/www /srv /home /opt; do [[ -d "$_d" ]] && _a+=("$_d"); done
            set -- ${_a[@]:+"${_a[@]}"} "${STAGED_DIRS[@]}"
        fi
    fi
    local -a dirs=() locks=()
    local rc=0 found=0 lock dir lv iv ver st auth guards g routes db
    if [[ $# -gt 0 ]]; then dirs=("$@"); else dirs=(/var/www /srv /home /opt); fi
    local -a existing=()
    for dir in "${dirs[@]}"; do [[ -d "$dir" ]] && existing+=("$dir"); done
    step "Looking for Laravel projects"
    if [[ ${#existing[@]} -eq 0 ]]; then info "None of the search directories exist"; return 0; fi
    while IFS= read -r lock; do [[ -n "$lock" ]] && locks+=("$lock"); done < <(
        find "${existing[@]}" -maxdepth 7 \( -name node_modules -o -name vendor \) -prune \
             -o -name composer.lock -type f -print 2>/dev/null)
    for lock in "${locks[@]}"; do
        lv="$(lock_pkg_version "$lock" laravel/framework)"
        dir="$(dirname "$lock")"
        iv="$(installed_version "$dir")"
        [[ -z "$lv" && -z "$iv" ]] && continue
        found=$((found+1))
        ver="${iv:-$lv}"
        step "Laravel ${ver} in ${dir}"
        [[ -n "$lv" && -n "$iv" && "$(norm_ver "$lv")" != "$(norm_ver "$iv")" ]] \
            && inf "composer.lock says ${lv}, vendor/ has ${iv}; using the installed copy"
        st="$(laravel_status "$ver")"
        case "$st" in
            fixed)      ok "laravel/framework ${ver} has the TokenGuard fix"; continue ;;
            unknown)    caution "could not parse version '${ver}'; treating it as not confirmed fixed"; rc=1; continue ;;
            vulnerable) bad "laravel/framework ${ver} is affected by CVE-2026-114509 (fixed in 12.68.0 / 13.29.0, 11.x from 11.56.1)" ;;
            unfixed)    bad "laravel/framework ${ver} is affected by CVE-2026-114509: upgrade to 12.68.0, 13.29.0 or, on 11.x, 11.56.1 or later" ;;
        esac
        auth="${dir}/config/auth.php"
        guards=""
        [[ -r "$auth" ]] && guards="$(token_guards "$auth")"
        db="$(grep -E '^DB_CONNECTION=' "${dir}/.env" 2>/dev/null | head -n1 | cut -d= -f2- | tr -d '"' | tr -d "'")"
        [[ -n "$db" ]] && inf "DB_CONNECTION=${db}" || inf "DB_CONNECTION not set in .env"
        if [[ -z "$guards" ]]; then
            if [[ -r "$auth" ]]; then
                ok "no guard in config/auth.php uses the token driver: the TokenGuard path is not in use"
                caution "version is still affected; custom code could build a TokenGuard directly, so upgrade"
            else
                caution "config/auth.php not readable: cannot tell whether the token driver is in use, treating as exposed"
                rc=1
            fi
            continue
        fi
        local exposed=0
        for g in $guards; do
            routes="$(grep -rIlE "auth:${g}([^A-Za-z0-9_]|\$)|Auth::guard\(['\"]${g}['\"]\)" \
                       "${dir}/routes" "${dir}/app" "${dir}/bootstrap" 2>/dev/null | head -n3 | tr '\n' ' ')"
            if [[ -n "$routes" ]]; then
                bad "guard '${g}' uses the token driver and is referenced in: ${routes}"; exposed=1
            else
                caution "guard '${g}' uses the token driver but no route or code references it"
            fi
        done
        case "$db" in
            mysql|mariadb) [[ $exposed -eq 1 ]] && bad "database driver is ${db}: the reported bypass applies" ;;
            '')            [[ $exposed -eq 1 ]] && caution "database driver unknown: the advisory limits the bypass to MySQL and MariaDB" ;;
            *)             [[ $exposed -eq 1 ]] && caution "database driver is ${db}: the advisory describes the bypass on MySQL and MariaDB, still upgrade" ;;
        esac
        if [[ $exposed -eq 1 && "$db" != "sqlite" && "$db" != "pgsql" && "$db" != "sqlsrv" ]]; then rc=1
        elif [[ "$st" == "unfixed" ]]; then rc=1
        fi
    done
    step "Verdict"
    if [[ $found -eq 0 ]]; then
        info "No Laravel project found under: ${existing[*]}"
    elif [[ $rc -eq 0 ]]; then
        info "No exposed Laravel project found (${found} checked)"
    else
        warn "Exposed Laravel found. Run: composer update laravel/framework  (12.68.0+ or 13.29.0+)"
        inf "Cannot upgrade today? Run: $0 middleware  and register the output as global middleware that runs before authentication."
        inf "Longer term, move API auth to Sanctum or Passport and drop the token driver."
        inf "Advisory: GHSA-f9x3-7vq9-cph6 (published 19 October 2026)"
    fi
    return "$rc"
}

cmd_middleware() {
    cat <<'PHP'
<?php
// RejectNonStringApiToken: protection for CVE-2026-114509 (Laravel TokenGuard).
// Save as app/Http/Middleware/RejectNonStringApiToken.php and register it as
// GLOBAL middleware that runs before authentication:
//   Laravel 11 and newer, in bootstrap/app.php:
//     ->withMiddleware(function (Middleware $middleware) {
//         $middleware->prepend(\App\Http\Middleware\RejectNonStringApiToken::class);
//     })
//   Laravel 10 and older, first entry of $middleware in app/Http/Kernel.php.
// Upgrading laravel/framework is the real fix. This only blocks the crafted input.

namespace App\Http\Middleware;

use Closure;
use Illuminate\Http\Request;

class RejectNonStringApiToken
{
    public function handle(Request $request, Closure $next)
    {
        $candidates = [
            $request->query('api_token'),
            $request->request->get('api_token'),
            $request->isJson() ? $request->json('api_token') : null,
        ];
        foreach ($candidates as $value) {
            if ($value !== null && !is_string($value)) {
                abort(401, 'Unauthenticated.');
            }
        }
        return $next($request);
    }
}
PHP
}

# ---------- dispatch ---------------------------------------------------------
main() {
    CMD="${1:-check}"; [[ $# -gt 0 ]] && shift
    case "$CMD" in -V|--version|version) echo "${SCRIPT_NAME} ${SCRIPT_VERSION} (${SCRIPT_DATE})"; exit 0 ;; esac
    case "$CMD" in -h|--help|help) print_help; exit 0 ;; esac
    if [[ "$CMD" == "middleware" ]]; then cmd_middleware; exit 0; fi
    echo "${SCRIPT_NAME} ${SCRIPT_VERSION} (${SCRIPT_DATE}) - ${CMD} on $(hostname 2>/dev/null || echo '?') at $(date -u +%FT%TZ)"
    echo "CVE-2026-114509; fixed in laravel/framework 12.68.0 and 13.29.0"
    case "$CMD" in
        check) cmd_check "$@" ;;
        *) die "Unknown command: ${CMD} (check|middleware|version)" ;;
    esac
}
main "$@"; exit

# Assisted-by: Claude Sonnet 5.5
