#!/usr/bin/env bash
# SPDX-License-Identifier: CC0-1.0
# =============================================================================
# PHP2Shell mitigation for cPanel EasyApache 4  (v1)
#
# If this software is helpful, consider a donation to our 501c3 nonprofit:
# https://privacysafe.foundation
#
# CVE-2026-109618 and CVE-2026-109619 ("PHP2Shell") are fixed by updating PHP
# (8.5.12 / 8.4.27 / 8.3.36 / 8.2.35, or a vendor build that names both CVEs in
# its changelog). Nothing here replaces that. This script covers the hosts the
# Debian tool (php2shell-mitigate.sh) refuses: cPanel servers running
# EasyApache 4 PHP (ea-php74 ... ea-php85) under any handler.
#
# It writes ONE drop-in per ea-php version into that version's php.d directory,
# named so it sorts after every other file there and therefore wins over
# php.ini and the MultiPHP INI Editor. It never edits php.ini. A file in php.d
# is read when the process starts, so the web server and any FPM pools must be
# restarted; apply does that unless told not to.
#
# What the drop-in sets:
#   session.upload_progress.enabled = 0     every version, patched or not:
#                                           closes CVE-2026-115560 on an
#                                           unpatched build, and closes
#                                           CVE-2026-126714 ("phpAfterShell",
#                                           depthfirst, 19 Nov 2026: the same
#                                           callback writes the session file
#                                           non-atomically, and killing the
#                                           worker mid-write can splice two
#                                           sessions together) on every
#                                           build, patched or not, since no
#                                           release is known to fix that one
#   fatal_error_backtraces = 0              PHP 8.5, unpatched builds only
#   memory_limit = -1                       only with --memory-unlimited, and
#                                           only on unpatched builds (PHP's own
#                                           protective measure; it trades the RCE
#                                           for denial of service, so pair it
#                                           with a request body cap)
#   post_max_size / upload_max_filesize     only with --post-max / --upload-max;
#                                           capped to the smaller of the current
#                                           value and your ceiling, never raised
#
# What check reports, besides the above:
#   * the PHP handler of each version (from WHM, when whmapi1 is present)
#   * whether each version is patched: by version, or because the package
#     changelog names both CVEs
#   * settings elsewhere that can undo the drop-in: FPM pool entries,
#     .user.ini and .htaccess php_value / php_flag lines
#   * Apache RLimitMEM / RLimitCPU, which cap processes Apache itself forks
#     (CGI, suEXEC, suPHP) and which PHP's advisory warns against as a memory
#     limit, because a failed allocation sends PHP down the vulnerable path
#   * web server and FPM processes that started before the drop-in changed
#
# Usage:
#   ./php2shell-cpanel-mitigate.sh [command] [options]
#
#   check (default)  read-only report, and the file apply would write
#   apply            write the drop-in for every version, verify it, restart
#   status           what is in place now, and whether workers need a restart
#   restore          remove the drop-ins this script wrote
#   cleanup          once a version is patched, reduce its drop-in to the one
#                    line CVE-2026-115560 still needs (--force to do it for an
#                    unpatched version too)
#
# Options:
#   --post-max SIZE       cap post_max_size (for example 32M; never raises it)
#   --upload-max SIZE     cap upload_max_filesize (default: same as --post-max)
#   --memory-unlimited    memory_limit = -1 on unpatched versions (see above)
#   --no-restart          write files only; you restart Apache and FPM
#   --no-scan             skip the per-directory scan under the home directories
#   --force               with cleanup, also reduce unpatched versions
#   -h, --help            this text
#   -V, --version, version
#
# Exit: check: 0 = every version patched and nothing to review,
#       1 = an unpatched version is present, 2 = patched but something to review.
#       Other commands: 0 = done, 1 = failed.
#
# Env overrides:
#   EA_ROOT=/opt/cpanel                where the ea-php* directories live
#   HOME_ROOT=/home                    where per-directory settings are scanned
#   CPANEL_SCRIPTS=/scripts            where restartsrv_httpd lives
#   APACHE_CONF_DIRS="/etc/apache2/conf /etc/apache2/conf.d"
#   SCAN_DEPTH=12                      how deep the home scan looks
#
# check prints the exact plan before apply makes any change, and restore reverts
# a drop-in it wrote. Run check first and review the plan before apply.
#      PSF_LOCK_WAIT    seconds a run that changes the host waits for another one that is already
#                       changing it (default 30), then stops with exit 2; the lock is STATE_DIR/.lock
# =============================================================================
set -euo pipefail

SCRIPT_NAME="php2shell-cpanel-mitigate.sh"
SCRIPT_VERSION="1.2.0"
SCRIPT_DATE="2026-11-25"

EA_ROOT="${EA_ROOT:-/opt/cpanel}"
HOME_ROOT="${HOME_ROOT:-/home}"
CPANEL_SCRIPTS="${CPANEL_SCRIPTS:-/scripts}"
APACHE_CONF_DIRS="${APACHE_CONF_DIRS:-/etc/apache2/conf /etc/apache2/conf.d}"
SCAN_DEPTH="${SCAN_DEPTH:-12}"

DROPIN="zzzzzzzzzz-php2shell-mitigation.ini"
MARKER="; php2shell-cpanel-mitigate.sh: managed file, do not edit by hand."
MANAGED_KEYS='session\.upload_progress\.enabled|post_max_size|upload_max_filesize|memory_limit|fatal_error_backtraces'
CVE_A="CVE-2026-109618"
CVE_B="CVE-2026-109619"

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; CYAN='\033[0;36m'; NC='\033[0m'
[[ -t 1 ]] || { RED=''; GREEN=''; YELLOW=''; CYAN=''; NC=''; }
step()    { echo -e "\n${CYAN}=====${NC} $* ${CYAN}=====${NC}"; }
ok()      { echo -e "  ${GREEN}✓${NC} $*"; }
bad()     { echo -e "  ${RED}✗${NC} $*"; }
inf()     { echo -e "  • $*"; }
caution() { echo -e "  ${YELLOW}!${NC} $*"; }
die()     { echo -e "${RED}[-] FATAL:${NC} $*" >&2; exit 2; }

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

# ---- arguments ---------------------------------------------------------------
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
lock_for_change "apply restore cleanup" "$@"

CMD=""; POST_CAP=""; UPLOAD_CAP=""; MEM_UNLIMITED=0; DO_RESTART=1; DO_SCAN=1; FORCE=0
usage() { awk 'f && /^# =+$/ {exit} f {sub(/^# ?/, ""); print} /^# =+$/ {f=1}' "$0"; }
while [[ $# -gt 0 ]]; do
    case "$1" in
        -h|--help) usage; exit 0 ;;
        -V|--version|version) echo "${SCRIPT_NAME} ${SCRIPT_VERSION} (${SCRIPT_DATE})"; exit 0 ;;
        --post-max)   [[ $# -ge 2 ]] || die "--post-max needs a size"; POST_CAP="$2"; shift ;;
        --upload-max) [[ $# -ge 2 ]] || die "--upload-max needs a size"; UPLOAD_CAP="$2"; shift ;;
        --memory-unlimited) MEM_UNLIMITED=1 ;;
        --no-restart) DO_RESTART=0 ;;
        --no-scan)    DO_SCAN=0 ;;
        --force)      FORCE=1 ;;
        check|apply|status|restore|cleanup)
            [[ -z "$CMD" ]] || die "only one command at a time (got '$CMD' and '$1')"; CMD="$1" ;;
        *) echo "${SCRIPT_NAME}: unknown argument: $1 (try --help)" >&2; exit 2 ;;
    esac
    shift
done
CMD="${CMD:-check}"

# ---- sizes -------------------------------------------------------------------
# PHP shorthand (128M, 1G, 512K, 2048, -1) to bytes. Prints nothing if it cannot
# be read, which callers treat as "unknown".
bytes_of() {
    local v="${1^^}"
    v="${v// /}"
    [[ "$v" =~ ^(-?[0-9]+)([KMG]?)B?$ ]] || return 0
    local n="${BASH_REMATCH[1]}" unit="${BASH_REMATCH[2]}"
    case "$unit" in
        K) echo $(( n * 1024 )) ;;
        M) echo $(( n * 1024 * 1024 )) ;;
        G) echo $(( n * 1024 * 1024 * 1024 )) ;;
        *) echo "$n" ;;
    esac
}
# The smaller of <current> and <ceiling>. A current value of 0 or -1 means "no
# limit" and a value we cannot read is treated the same way, so the ceiling wins.
smaller_of() {
    local cur_b ceil_b
    cur_b="$(bytes_of "$1")"; ceil_b="$(bytes_of "$2")"
    if [[ -n "$cur_b" && "$cur_b" -gt 0 && "$cur_b" -lt "$ceil_b" ]]; then echo "$1"; else echo "$2"; fi
}
if [[ -n "$POST_CAP" ]]; then
    [[ "$(bytes_of "$POST_CAP")" -gt 0 ]] 2>/dev/null || die "--post-max: not a usable size: $POST_CAP"
    UPLOAD_CAP="${UPLOAD_CAP:-$POST_CAP}"
fi
if [[ -n "$UPLOAD_CAP" ]]; then
    [[ "$(bytes_of "$UPLOAD_CAP")" -gt 0 ]] 2>/dev/null || die "--upload-max: not a usable size: $UPLOAD_CAP"
    [[ -n "$POST_CAP" ]] || die "--upload-max needs --post-max (upload_max_filesize must not exceed post_max_size)"
fi

# ---- temp files --------------------------------------------------------------
TMPDIRS=()
cleanup_tmp() { local d; for d in ${TMPDIRS[@]+"${TMPDIRS[@]}"}; do rm -rf "$d"; done; }
trap cleanup_tmp EXIT

# ---- discovery ---------------------------------------------------------------
VERS=(); ROOTS=()
declare -A HANDLER=()
discover() {
    local r
    while IFS= read -r r; do
        [[ -d "$r" ]] || continue
        VERS+=("$(basename "$(dirname "$r")")"); ROOTS+=("$r")
    done < <(compgen -G "${EA_ROOT}/ea-php*/root" | sort -V || true)
    [[ ${#ROOTS[@]} -gt 0 ]] || [[ "$CMD" != check ]] || na_exit "no EasyApache 4 PHP under ${EA_ROOT}: this is not a cPanel server"
    [[ ${#ROOTS[@]} -gt 0 ]] || die "No EasyApache 4 PHP found under ${EA_ROOT} (looked for ea-php*/root). On Debian, Ubuntu or Trisquel use php2shell-mitigate.sh instead."
}

# WHM's handler per version, best effort: the layout of whmapi1 output is read
# loosely, and any version it cannot place is reported as "unknown".
load_handlers() {
    command -v whmapi1 >/dev/null 2>&1 || return 0
    local out ver hand
    out="$(whmapi1 php_get_handlers 2>/dev/null)" || return 0
    while read -r ver hand; do
        [[ -n "$ver" ]] && HANDLER["$ver"]="$hand"
    done < <(awk '
        function emit() { if (v != "") print v, (h == "" ? "unknown" : h); v = ""; h = "" }
        /^[[:space:]]*-[[:space:]]+[A-Za-z_]+:/ { emit() }
        { s = $0; sub(/^[[:space:]]*-?[[:space:]]*/, "", s) }
        s ~ /^current_handler:/ { sub(/^current_handler:[[:space:]]*/, "", s); h = s }
        s ~ /^version:[[:space:]]*ea-php/ { sub(/^version:[[:space:]]*/, "", s); v = s }
        END { emit() }' <<<"$out")
}

# ---- reading what PHP will actually use --------------------------------------
# key=value lines for every managed setting, as the binary at <php> sees them.
# <scan> overrides PHP_INI_SCAN_DIR when given.
effective_settings() {   # <php> [scan dir]
    local php="$1" scan="${2:-}"
    # shellcheck disable=SC2016  # the dollar signs are PHP's, not the shell's
    local code='foreach (["session.upload_progress.enabled","post_max_size","upload_max_filesize","memory_limit","fatal_error_backtraces"] as $k) { $v = ini_get($k); echo $k, "=", $v === false ? "(n/a)" : $v, "\n"; }'
    if [[ -n "$scan" ]]; then PHP_INI_SCAN_DIR="$scan" "$php" -r "$code"; else "$php" -r "$code"; fi
}
# The same, with our own drop-in left out, so a second run compares against the
# real baseline and not against caps we wrote ourselves.
baseline_settings() {   # <php> <scan dir>
    local php="$1" scandir="$2" tmp f
    tmp="$(mktemp -d)"; TMPDIRS+=("$tmp")
    for f in "$scandir"/*.ini; do
        [[ -e "$f" && "$(basename "$f")" != "$DROPIN" ]] && ln -s "$f" "$tmp/$(basename "$f")"
    done
    effective_settings "$php" "$tmp"
}
setting_of() { sed -n "s/^$2=//p" <<<"$1" | head -n 1; }   # <lines> <key>

# ---- patch state -------------------------------------------------------------
fixed_release_for() {   # <major.minor> -> first fixed upstream release
    case "$1" in
        8.2) echo 8.2.35 ;; 8.3) echo 8.3.36 ;; 8.4) echo 8.4.27 ;; 8.5) echo 8.5.12 ;;
        *) echo "" ;;
    esac
}
version_at_least() { [[ "$(printf '%s\n%s\n' "$1" "$2" | sort -V | head -n 1)" == "$2" ]]; }   # <have> <want>
PATCH_STATE=""; PATCH_WHY=""; PKG_NAME=""
patch_state() {   # <php binary>   sets PATCH_STATE (patched|unpatched) and PATCH_WHY
    local php="$1" ver branch fixed num rest pre=0
    PATCH_STATE="unpatched"; PATCH_WHY=""; PKG_NAME=""
    ver="$("$php" -r 'echo PHP_VERSION;' 2>/dev/null || true)"
    [[ -n "$ver" ]] || { PATCH_WHY="could not read the PHP version"; return 0; }
    branch="${ver%.*}"; fixed="$(fixed_release_for "$branch")"
    # A release candidate, beta, alpha or dev build of the fixed number (8.4.27RC1, 8.4.27-dev) comes
    # BEFORE that release, but sort -V puts it after, so it would read as patched. Judge such a build
    # by its numeric part, and only above the fixed number, never at it.
    num="$(grep -oE '^[0-9]+\.[0-9]+\.[0-9]+' <<<"$ver" || true)"; rest="${ver#"$num"}"
    [[ -n "$num" && "$rest" =~ ^(-?dev|RC|rc|alpha|beta|a[0-9]|b[0-9]) ]] && pre=1
    if [[ -n "$fixed" ]]; then
        if [[ $pre -eq 1 ]]; then
            if version_at_least "$num" "$fixed" && [[ "$num" != "$fixed" ]]; then
                PATCH_STATE="patched"; PATCH_WHY="${ver} is a pre-release of a release above the upstream fix ${fixed}"; return 0
            fi
        elif version_at_least "$ver" "$fixed"; then
            PATCH_STATE="patched"; PATCH_WHY="${ver} is at or above the upstream fix ${fixed}"; return 0
        fi
    fi
    if command -v rpm >/dev/null 2>&1; then
        PKG_NAME="$(rpm -qf --qf '%{NAME}-%{VERSION}-%{RELEASE}' "$php" 2>/dev/null || true)"
        if [[ -n "$PKG_NAME" ]] && rpm -q --changelog "$PKG_NAME" 2>/dev/null | grep "$CVE_A" >/dev/null \
           && rpm -q --changelog "$PKG_NAME" 2>/dev/null | grep "$CVE_B" >/dev/null; then
            PATCH_STATE="patched"; PATCH_WHY="the package changelog of ${PKG_NAME} names both CVEs"; return 0
        fi
    fi
    if [[ -n "$fixed" && $pre -eq 1 && "$num" == "$fixed" ]]; then PATCH_WHY="${ver} is a pre-release of ${fixed}, not the fixed release itself, and no changelog names both CVEs"
    elif [[ -n "$fixed" ]]; then PATCH_WHY="${ver} is below the upstream fix ${fixed} and no changelog names both CVEs"
    else PATCH_WHY="${ver} is an end-of-life branch with no upstream fix and no changelog names both CVEs"; fi
}

# ---- the drop-in -------------------------------------------------------------
# <state> <php version> <baseline post> <baseline upload>
build_dropin() {
    local state="$1" ver="$2" base_post="$3" base_upload="$4" post upload
    echo "$MARKER"
    echo "; Protective measures for ${CVE_A}, ${CVE_B} and CVE-2026-115560."
    echo "; Updating PHP is the only complete fix for the first two."
    echo "; Remove with: ${SCRIPT_NAME} restore"
    echo "session.upload_progress.enabled = 0"
    if [[ "$state" == unpatched && "$ver" =~ ^8\.([5-9]|[1-9][0-9])\. ]]; then
        echo "fatal_error_backtraces = 0"
    fi
    if [[ -n "$POST_CAP" ]]; then
        post="$(smaller_of "$base_post" "$POST_CAP")"
        upload="$(smaller_of "$base_upload" "$UPLOAD_CAP")"
        if [[ "$(bytes_of "$upload")" -gt "$(bytes_of "$post")" ]]; then upload="$post"; fi
        echo "post_max_size = ${post}"
        echo "upload_max_filesize = ${upload}"
    fi
    if [[ "$MEM_UNLIMITED" -eq 1 && "$state" == unpatched ]]; then echo "memory_limit = -1"; fi
}
dropin_is_ours() { [[ -f "$1" ]] && head -n 1 "$1" | grep -qxF "$MARKER"; }
write_dropin() {   # <path> <content>
    local path="$1" content="$2" tmp
    tmp="${path}.tmp"
    printf '%s\n' "$content" > "$tmp"
    chmod 644 "$tmp"
    mv -f "$tmp" "$path"
}
# Compare what we wrote with what the binary now reports.
verify_dropin() {   # <php> <path>
    local php="$1" path="$2" eff key want got bad_n=0
    eff="$(effective_settings "$php")"
    while IFS= read -r line; do
        [[ "$line" =~ ^([a-z_.]+)[[:space:]]*=[[:space:]]*(.*)$ ]] || continue
        key="${BASH_REMATCH[1]}"; want="${BASH_REMATCH[2]}"
        got="$(setting_of "$eff" "$key")"
        if [[ "$got" == "(n/a)" ]]; then
            caution "${key}: this PHP does not know the setting, so the line is ignored and cannot be confirmed"
        elif [[ "$got" != "$want" ]]; then
            bad "${key}: wrote '${want}', PHP reports '${got}' (another file or setting wins)"; bad_n=$((bad_n+1))
        fi
    done < <(grep -v '^;' "$path")
    [[ $bad_n -eq 0 ]]
}

# ---- services ----------------------------------------------------------------
older_workers() {   # <epoch> -> live web server / FPM processes that started before it (zombies are not workers)
    local cutoff="$1" now age n=0
    now="$(date +%s)"
    while read -r age _; do
        [[ "$age" =~ ^[0-9]+$ ]] || continue
        if (( now - age < cutoff )); then n=$((n+1)); fi
    done < <(ps -eo etimes=,stat=,comm= 2>/dev/null | awk '$3 ~ /^(httpd|apache2|php-fpm|lsphp)/ && $2 !~ /^Z/ {print $1, $3}' || true)
    echo "$n"
}
restart_services() {
    local unit units
    step "Restarting so every worker re-reads its settings"
    if [[ -x "${CPANEL_SCRIPTS}/restartsrv_httpd" ]]; then
        if "${CPANEL_SCRIPTS}/restartsrv_httpd" >/dev/null 2>&1; then ok "Apache restarted (${CPANEL_SCRIPTS}/restartsrv_httpd)"
        else bad "Apache restart failed; restart it yourself"; fi
    else
        caution "${CPANEL_SCRIPTS}/restartsrv_httpd not found; restart Apache yourself"
    fi
    if command -v systemctl >/dev/null 2>&1; then
        units="$(systemctl list-units --type=service --state=active --no-legend --plain 'ea-php*-php-fpm*.service' 2>/dev/null | awk '{print $1}' || true)"
        if [[ -z "$units" ]]; then inf "no running ea-php FPM services"; fi
        for unit in $units; do
            if systemctl restart "$unit" >/dev/null 2>&1; then ok "restarted ${unit}"; else bad "could not restart ${unit}"; fi
        done
    else
        caution "systemctl not found; restart any ea-php FPM pools yourself"
    fi
}

# ---- scans -------------------------------------------------------------------
REVIEW=0
note_review() { REVIEW=1; }
scan_pools() {   # <root>
    local root="$1" dir hits
    dir="${root}/etc/php-fpm.d"
    [[ -d "$dir" ]] || return 0
    hits="$(grep -HnE "^[[:space:]]*php(_admin)?_(value|flag)\[(${MANAGED_KEYS})\]" "$dir"/*.conf 2>/dev/null || true)"
    if [[ -n "$hits" ]]; then
        caution "FPM pool settings for managed keys (a pool value beats php.d files; admin values cannot be changed by the site):"
        # shellcheck disable=SC2001
        sed 's/^/      /' <<<"$hits" | head -n 20
        note_review
    else
        ok "no FPM pool entries for the managed settings"
    fi
}
scan_home() {
    [[ -d "$HOME_ROOT" ]] || { inf "${HOME_ROOT} not found; skipping the per-directory scan"; return 0; }
    local hits htaccess ini
    htaccess="$(find "$HOME_ROOT" -xdev -maxdepth "$SCAN_DEPTH" -path '*/virtfs' -prune -o -name .htaccess -type f -print0 2>/dev/null \
        | xargs -0 -r grep -HnEi "^[[:space:]]*php_(admin_)?(value|flag)[[:space:]]+(${MANAGED_KEYS})[[:space:]]" 2>/dev/null || true)"
    ini="$(find "$HOME_ROOT" -xdev -maxdepth "$SCAN_DEPTH" -path '*/virtfs' -prune -o \( -name .user.ini -o -name php.ini \) -type f -print0 2>/dev/null \
        | xargs -0 -r grep -HnEi "^[[:space:]]*(${MANAGED_KEYS})[[:space:]]*=" 2>/dev/null || true)"
    if [[ -z "$htaccess$ini" ]]; then ok "no per-directory settings for the managed keys under ${HOME_ROOT}"; return 0; fi
    caution "per-directory settings under ${HOME_ROOT}:"
    inf ".htaccess php_value / php_flag can undo the drop-in under mod_php; .user.ini can under FPM and CGI."
    inf "A php.ini in a home directory is read before the drop-in, so the drop-in wins; it is listed for completeness."
    { printf '%s\n' "$htaccess"; printf '%s\n' "$ini"; } | grep -v '^$' | sed 's/^/      /' | head -n 30
    note_review
}
scan_rlimits() {
    local d hits=""
    for d in $APACHE_CONF_DIRS; do
        [[ -d "$d" ]] && hits+="$(grep -rnE '^[[:space:]]*RLimit(MEM|CPU)[[:space:]]' "$d" 2>/dev/null || true)"$'\n'
    done
    hits="$(grep -v '^$' <<<"$hits" || true)"
    if [[ -n "$hits" ]]; then
        caution "Apache RLimitMEM / RLimitCPU is set:"
        # shellcheck disable=SC2001
        sed 's/^/      /' <<<"$hits"
        inf "These limit processes Apache forks (CGI, suEXEC, suPHP). PHP's advisory warns against an address-space limit as a memory cap: the failed allocation sends PHP down the vulnerable path."
        inf "In WHM, change it under Apache Configuration (httpd.conf is generated, so hand edits are lost)."
        note_review
    else
        ok "no RLimitMEM or RLimitCPU in the Apache configuration"
    fi
}

# ---- commands ----------------------------------------------------------------
UNPATCHED=0
describe_version() {   # <index>
    local i="$1" root php scan dropin ver base eff
    root="${ROOTS[$i]}"; php="${root}/usr/bin/php"; scan="${root}/etc/php.d"; dropin="${scan}/${DROPIN}"
    echo
    echo -e "  ${CYAN}${VERS[$i]}${NC}  handler: ${HANDLER[${VERS[$i]}]:-unknown}"
    if [[ ! -x "$php" || ! -d "$scan" ]]; then caution "missing ${php} or ${scan}; skipped"; return 0; fi
    ver="$("$php" -r 'echo PHP_VERSION;' 2>/dev/null || echo '?')"
    patch_state "$php"
    if [[ "$PATCH_STATE" == patched ]]; then ok "patched: ${PATCH_WHY}"
    else bad "NOT patched: ${PATCH_WHY}"; UNPATCHED=1; fi
    [[ "${HANDLER[${VERS[$i]}]:-}" == dso ]] && caution "dso (mod_php): the highest-priority exposure in PHP's advisory"
    base="$(baseline_settings "$php" "$scan")"
    inf "settings without this script's drop-in: $(tr '\n' ' ' <<<"$base")"
    if [[ -f "$dropin" ]]; then
        if dropin_is_ours "$dropin"; then
            eff="$(effective_settings "$php")"
            ok "drop-in present; PHP now reports: $(tr '\n' ' ' <<<"$eff")"
        else
            caution "${dropin} exists but was not written by this script; apply will refuse to replace it"; note_review
        fi
    else
        inf "no drop-in yet"
    fi
    if [[ "$CMD" == check ]]; then
        echo "    apply would write ${dropin}:"
        build_dropin "$PATCH_STATE" "$ver" "$(setting_of "$base" post_max_size)" "$(setting_of "$base" upload_max_filesize)" \
            | grep -v '^;' | sed 's/^/        /'
    fi
    scan_pools "$root"
}

env_banner() {
    echo "${SCRIPT_NAME} ${SCRIPT_VERSION} (${SCRIPT_DATE}) on $(hostname 2>/dev/null || echo '?') at $(date -u +%FT%TZ)"
    if [[ -r /usr/local/cpanel/version ]]; then inf "cPanel $(cat /usr/local/cpanel/version 2>/dev/null)"; fi
}

cmd_check() {
    local i
    step "EasyApache 4 PHP versions"
    for i in "${!ROOTS[@]}"; do describe_version "$i"; done
    if [[ "$DO_SCAN" -eq 1 ]]; then step "Per-directory settings that could undo the drop-in"; scan_home; fi
    step "Apache resource limits"; scan_rlimits
    step "Summary"
    if [[ "$UNPATCHED" -eq 1 ]]; then
        bad "at least one version is unpatched: update the ea-php packages (the only complete fix), then restart Apache and FPM"
        inf "protect now: ${SCRIPT_NAME} apply"
        exit 1
    fi
    if [[ "$REVIEW" -eq 1 ]]; then caution "every version is patched, but something above is worth a look"; exit 2; fi
    ok "every version is patched and nothing needs review"
    inf "CVE-2026-126714 ('phpAfterShell') has no known fixed release: keep session.upload_progress.enabled off (apply, then cleanup), regardless of CVE-2026-115560's patch state"
}

cmd_apply() {
    need_root "apply changes the host" ""
    [[ "$MEM_UNLIMITED" -eq 0 ]] || caution "memory_limit = -1 trades the remote code execution for denial of service: one request can use all memory. Pair it with a request body cap (runtimes/php/edge/)."
    local i root php scan dropin ver base content written=0 failed=0
    step "Writing drop-ins"
    for i in "${!ROOTS[@]}"; do
        root="${ROOTS[$i]}"; php="${root}/usr/bin/php"; scan="${root}/etc/php.d"; dropin="${scan}/${DROPIN}"
        if [[ ! -x "$php" || ! -d "$scan" ]]; then caution "${VERS[$i]}: missing ${php} or ${scan}; skipped"; continue; fi
        if [[ -e "$dropin" ]] && ! dropin_is_ours "$dropin"; then bad "${VERS[$i]}: ${dropin} exists and was not written by this script; leaving it alone"; failed=$((failed+1)); continue; fi
        ver="$("$php" -r 'echo PHP_VERSION;')"; patch_state "$php"
        base="$(baseline_settings "$php" "$scan")"
        content="$(build_dropin "$PATCH_STATE" "$ver" "$(setting_of "$base" post_max_size)" "$(setting_of "$base" upload_max_filesize)")"
        write_dropin "$dropin" "$content"; written=$((written+1))
        echo -e "  ${CYAN}${VERS[$i]}${NC} (${PATCH_STATE}): wrote ${dropin}"
        grep -v '^;' <<<"$content" | sed 's/^/        /'
        if verify_dropin "$php" "$dropin"; then ok "verified: PHP reports these values"; else failed=$((failed+1)); fi
    done
    [[ "$written" -gt 0 ]] || die "nothing was written"
    if [[ "$DO_RESTART" -eq 1 ]]; then restart_services; else caution "--no-restart: restart Apache and any FPM pools yourself, or the old settings stay in force"; fi
    [[ "$failed" -eq 0 ]] || { bad "${failed} version(s) did not verify or were skipped"; exit 1; }
}

cmd_status() {
    local i root php scan dropin eff newest=0 m n
    step "Drop-ins"
    for i in "${!ROOTS[@]}"; do
        root="${ROOTS[$i]}"; php="${root}/usr/bin/php"; scan="${root}/etc/php.d"; dropin="${scan}/${DROPIN}"
        [[ -x "$php" ]] || continue
        if dropin_is_ours "$dropin"; then
            eff="$(effective_settings "$php")"
            ok "${VERS[$i]} (${HANDLER[${VERS[$i]}]:-unknown}): $(tr '\n' ' ' <<<"$eff")"
            m="$(stat -c %Y "$dropin" 2>/dev/null || echo 0)"; [[ "$m" -gt "$newest" ]] && newest="$m"
        else
            inf "${VERS[$i]}: no drop-in from this script"
        fi
    done
    if [[ "$newest" -gt 0 ]]; then
        n="$(older_workers "$newest")"
        if [[ "$n" -gt 0 ]]; then caution "${n} web server / FPM process(es) started before the newest drop-in and still use the old settings: restart Apache and FPM"
        else ok "no web server or FPM process predates the newest drop-in"; fi
    fi
}

cmd_restore() {
    need_root "restore changes the host" ""
    local i dropin removed=0
    step "Removing drop-ins"
    for i in "${!ROOTS[@]}"; do
        dropin="${ROOTS[$i]}/etc/php.d/${DROPIN}"
        if [[ ! -e "$dropin" ]]; then inf "${VERS[$i]}: nothing to remove"
        elif dropin_is_ours "$dropin"; then rm -f "$dropin"; ok "${VERS[$i]}: removed"; removed=$((removed+1))
        else caution "${VERS[$i]}: ${dropin} was not written by this script; left alone"; fi
    done
    if [[ "$removed" -gt 0 ]]; then
        caution "CVE-2026-126714 ('phpAfterShell') has no known fixed release; removing the drop-in turns upload progress back on, which reopens it regardless of this version's CVE-2026-115560 patch state."
        if [[ "$DO_RESTART" -eq 1 ]]; then restart_services; else caution "--no-restart: restart Apache and FPM yourself"; fi
    fi
}

cmd_cleanup() {
    need_root "cleanup changes the host" ""
    local i root php scan dropin changed=0
    step "Reducing drop-ins to what CVE-2026-115560 still needs"
    for i in "${!ROOTS[@]}"; do
        root="${ROOTS[$i]}"; php="${root}/usr/bin/php"; scan="${root}/etc/php.d"; dropin="${scan}/${DROPIN}"
        dropin_is_ours "$dropin" || { inf "${VERS[$i]}: no drop-in from this script"; continue; }
        patch_state "$php"
        if [[ "$PATCH_STATE" != patched && "$FORCE" -eq 0 ]]; then caution "${VERS[$i]}: still unpatched; kept as is (--force to reduce it anyway)"; continue; fi
        write_dropin "$dropin" "${MARKER}
; CVE-2026-126714 ('phpAfterShell') has no known fixed release: keep upload progress off
; regardless of this version's CVE-2026-115560 patch state.
session.upload_progress.enabled = 0"
        ok "${VERS[$i]}: reduced to session.upload_progress.enabled = 0"; changed=$((changed+1))
    done
    if [[ "$changed" -gt 0 ]]; then
        if [[ "$DO_RESTART" -eq 1 ]]; then restart_services; else caution "--no-restart: restart Apache and FPM yourself"; fi
    fi
}

# ---- main --------------------------------------------------------------------
env_banner
discover
load_handlers
case "$CMD" in
    check)   cmd_check ;;
    apply)   cmd_apply ;;
    status)  cmd_status ;;
    restore) cmd_restore ;;
    cleanup) cmd_cleanup ;;
esac

# Assisted-by: Claude Opus 5.5
