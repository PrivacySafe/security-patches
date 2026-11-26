#!/usr/bin/env bash
# SPDX-License-Identifier: CC0-1.0
# =============================================================================
# Drupal core installer: site takeover through install.php  (v1)
# CVE-2026-132165 (SA-CORE-2026-017, "Fail2Install") and CVE-2026-136716 (SA-CORE-2026-019)
#
# If this software is helpful, consider a donation to our 501c3 nonprofit:
# https://privacysafe.foundation
#
# Drupal core ships core/install.php, the installer, and it stays on the site after installation.
# Under conditions Drupal does not publish, an anonymous visitor can use it to reinstall a running
# site: a site takeover, or code execution.
#
#   SA-CORE-2026-017 (CVE-2026-132165), 18 November 2026: Highly critical, 20/25. Exploited on live
#     sites from 2026-11-19 19:00 UTC; on CISA's KEV list since 24 November (federal deadline
#     27 November). Fixed in 10.6.22, 11.3.22 and 11.4.13. Drupal: "some (but not all) exploit
#     paths are mitigated if the web server cannot write to or change permissions on settings.php."
#   SA-CORE-2026-019 (CVE-2026-136716), 25 November 2026: Highly critical, 21/25, exploited. Sites
#     "in unusual or incomplete install states" stayed open to takeover after SA-CORE-2026-017,
#     production sites included, and nothing in the interface shows it. Its affected range ends
#     before 10.6.23, 11.3.23 and 11.4.14 (the advisory's solution text still names 10.6.22,
#     11.3.22 and 11.4.13 while the releases were packaged; this script judges by the range).
#     After updating, run update.php (or drush updatedb): an update hook repairs sites in that state.
#     "If you have already secured the installer, you are not vulnerable."
#   Drupal 11.2 and below and 10.5 and below are end of life and get no fix. Drupal 8 and 9 too.
#   Drupal Steward protects its subscribers from the known attack vectors.
#
# Securing the installer protects against both, patched or not. Drupal's guidance offers three
# ways: deny it in the web server configuration, deny it in .htaccess, or remove the file and keep
# it removed. mitigate denies it in the web server (403), because that lasts: a core update or a
# composer install puts a removed core/install.php back, and overwrites a scaffolded .htaccess.
# --remove also takes the file away, moving it into a backup (SHA-256 checked) that rollback puts
# back; a file Drupal ships is never deleted.
#
# Usage:
#   ./drupal-installer-check.sh [check] [--url URL ...]
#   check (default)  Finds the Drupal sites (core/lib/Drupal.php) and reports, for each: the core
#                    version against both advisories, whether core/install.php is there, any rule
#                    that names install.php in its .htaccess or the nginx configuration, and who can
#                    change settings.php. --url URL (repeatable) also asks the live site for
#                    /core/install.php, /install.php and /core/install.php/x: the installer is
#                    blocked only when all three answer 403 or 404. Exit 0 = nothing to do,
#                    1 = a site is affected or its installer reachable, 2 = could not check.
#                    Read-only.
#   hunt             Access logs: requests for install.php (a POST that was answered 200 or 302 is
#                    the strong lead); for each site: PHP files under sites/*/files, and settings.php
#                    changed since 2026-11-18. Says how to check user 1, which Drupal asks you to do
#                    (this script does not open the database). Exit 0 = nothing found, 1 = leads,
#                    2 = nothing could be read. Read-only.
#   mitigate [--remove] [--installer-only] [--dry-run]   (root)
#                    Blocks the installer in the web server, which lasts across core updates:
#                    Apache gets one configuration file for every site (conf-available, enabled,
#                    or conf.d), nginx a snippet (location ^~ /core/install.php { return 403; })
#                    and an include in each server block whose root is a Drupal site. Each file it
#                    edits is backed up first; the change is tested (apachectl -t, nginx -t) and
#                    taken back if the test fails, and only then is the server reloaded. --remove
#                    also moves core/install.php into a backup (SHA-256 checked; a file Drupal ships
#                    is never deleted); a core update or composer install brings it back. Unless
#                    --installer-only, sets settings.php to 0444 and its folder to 0555, as Drupal
#                    recommends. File operations in a site run as the account that owns its folder.
#   rollback [--dry-run]   (root) takes the web server changes back (a file changed since is left
#                    alone), puts back what --remove moved, and restores the modes. An installer
#                    that has come back meanwhile is left in place, and its backup kept.
#   version          print the script version.
#
# Env: DRUPAL_ROOTS (folders to search, space separated; default /var/www /srv /home /opt
#      /usr/share/nginx), ACCESS_LOGS (log files for hunt, instead of the usual nginx, Apache and
#      LiteSpeed access logs), NGINX_CONF (default /etc/nginx), APACHE_CONF (default /etc/apache2,
#      else /etc/httpd), NGINX_BIN and APACHECTL (the programs that test and reload), STATE_DIR (default
#      /var/lib/psf-security-patches/drupal-installer), PSF_LOCK_WAIT (seconds a change waits for
#      another, default 30; the lock is STATE_DIR/.lock)
# =============================================================================

set -uo pipefail

SCRIPT_NAME="drupal-installer-check.sh"
SCRIPT_VERSION="1.0.0"
SCRIPT_DATE="2026-11-25"
SELF="$0"
STATE_DIR="${STATE_DIR:-/var/lib/psf-security-patches/drupal-installer}"
CVE17="CVE-2026-132165"
CVE19="CVE-2026-136716"

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
is_semver() { [[ "$(norm_ver "$1")" =~ ^[0-9]+\.[0-9]+(\.[0-9]+)*$ ]]; }

# Print the help text: everything between the first two ===== lines of this file.
print_help() { awk 'f && /^# =+$/ {exit} f {sub(/^# ?/,""); print} /^# =+$/ {f=1}' "$SELF"; }

# Temporary files are registered here, in the main shell, and removed when the script ends.
PSF_TMP=()
trap '[[ ${#PSF_TMP[@]} -eq 0 ]] || rm -rf "${PSF_TMP[@]}"' EXIT
mk_tmp() { local _t; _t="$(mktemp)" || die "cannot create a temporary file"; PSF_TMP+=("$_t"); printf -v "$1" '%s' "$_t"; }

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
limited_view() {
    is_root && return 0
    if have sudo; then caution "not running as root: ${1:-files, processes and logs} that belong to other accounts may not be readable, so a clean result covers only what this account can see. Run it with sudo: sudo ${SELF_CMD}"
    else caution "not running as root: ${1:-files, processes and logs} that belong to other accounts may not be readable, so a clean result covers only what this account can see. Run it as root."; fi
}
# a regular file that is not a link (FIFOs and devices are never read)
regular() { [[ -f "$1" && ! -L "$1" ]]; }


# ---------- the advisories ---------------------------------------------------
FIX17="10.6:22 11.3:22 11.4:13"
FIX19="10.6:23 11.3:23 11.4:14"
# prints: fixed | affected | eol | notaffected | unknown
judge() {   # <version> <fixes>
    local v="$1" e line pat
    [[ "$v" =~ ^([0-9]+)\.([0-9]+)\.([0-9]+)$ ]] || { echo unknown; return; }
    line="${BASH_REMATCH[1]}.${BASH_REMATCH[2]}"; pat="${BASH_REMATCH[3]}"
    for e in $2; do
        if [[ "${e%%:*}" == "$line" ]]; then if (( pat >= ${e#*:} )); then echo fixed; else echo affected; fi; return; fi
    done
    # every branch below the newest listed one is end of life; a newer branch is outside the affected range
    if ver_lt "$line.0" "11.4.0"; then echo eol; else echo notaffected; fi
}

# a script running as root must not run a program another account could have changed
root_safe_bin() {
    local b p st mode
    b="$(command -v "$1" 2>/dev/null)" || return 1
    is_root || { echo "$b"; return 0; }
    p="$(readlink -f "$b" 2>/dev/null)" || return 1
    while :; do
        st="$(stat -c '%u %a' "$p" 2>/dev/null)" || return 1
        [[ "${st%% *}" == 0 ]] || return 1
        mode="${st##* }"
        if (( (8#$mode & 8#022) != 0 )); then [[ -d "$p" && ${#mode} -eq 4 && "${mode:0:1}" =~ [1357] ]] || return 1; fi
        [[ "$p" == / ]] && break
        p="$(dirname "$p")"
    done
    echo "$b"
}

# ---------- finding the sites ------------------------------------------------
# a site is the folder above core/lib/Drupal.php; prints "<docroot>\t<version>"
find_sites() {
    local r f d v
    for r in ${DRUPAL_ROOTS:-/var/www /srv /home /opt /usr/share/nginx}; do
        [[ -d "$r" ]] || continue
        while IFS= read -r f; do
            regular "$f" || continue
            d="${f%/core/lib/Drupal.php}"
            v="$(sed -n "s/^[[:space:]]*const VERSION = '\([^']*\)';.*/\1/p" "$f" 2>/dev/null | head -n 1)"
            printf '%s\t%s\n' "$d" "${v:-?}"
        done < <(find "$r" -maxdepth 7 -path '*/core/lib/Drupal.php' -not -path '*/vendor/*' -not -path '*/node_modules/*' 2>/dev/null)
    done | sort -u
}

# accounts the web server and PHP run as (the workers, not their root master)
web_users() {
    # a zombie (state Z) has exited and is no running server
    ps -eo user=,stat=,comm= 2>/dev/null | awk '$3 ~ /^(nginx|apache2|httpd|php-fpm|php-fpm[0-9.]+|lsphp|litespeed|lshttpd|caddy|frankenphp)$/ && $1 != "root" && $2 !~ /^Z/ {print $1}' | sort -u
}

# can account <user> write <path>, going by owner, group and mode alone
writable_by() {   # <user> <path>
    local u="$1" p="$2" st uid gid mode ug
    st="$(stat -c '%u %g %a' "$p" 2>/dev/null)" || return 1
    read -r uid gid mode <<<"$st"
    [[ "$(id -u "$u" 2>/dev/null)" == "$uid" ]] && return 0
    ug=" $(id -G "$u" 2>/dev/null) "
    [[ "$ug" == *" $gid "* ]] && (( (8#$mode & 8#020) != 0 )) && return 0
    (( (8#$mode & 8#002) != 0 ))
}

# rules that name install.php: the site's .htaccess and the nginx configuration
installer_rules() {   # <docroot>
    local f
    [[ -f "$1/.htaccess" ]] && grep -n -i 'install\.php' "$1/.htaccess" 2>/dev/null | head -n 3 | sed "s|^|$1/.htaccess:|"
    for f in $(grep -rl -i 'install\.php' "${NGINX_CONF:-/etc/nginx}" ${APACHE_CONF:-/etc/apache2 /etc/httpd} 2>/dev/null | head -n 5); do
        grep -n -i 'install\.php' "$f" | head -n 2 | sed "s|^|$f:|"
    done
}

# ---------- check --------------------------------------------------------------
cmd_check() {
    local urls=() rc=0 n=0 d v s17 s19 present rules users u sf curlb code all base p
    while [[ $# -gt 0 ]]; do
        case "$1" in --url) shift; [[ -n "${1:-}" ]] || die "--url needs a URL"; urls+=("${1%/}") ;; *) die "Unknown check option: $1 (--url URL)" ;; esac
        shift
    done
    limited_view "site files"
    users="$(web_users | tr '\n' ' ')"
    while IFS=$'\t' read -r d v; do
        [[ -n "$d" ]] || continue
        n=$((n+1))
        step "Drupal site ${d}"
        inf "core version: ${v}"
        s17="$(judge "$v" "$FIX17")"; s19="$(judge "$v" "$FIX19")"
        if [[ -e "$d/core/install.php" || -L "$d/core/install.php" ]]; then present=1; else present=0; fi
        case "$s19" in
            fixed)       ok "${v} has the fixes for ${CVE17} (SA-CORE-2026-017) and ${CVE19} (SA-CORE-2026-019)"
                         inf "if update.php (or drush updatedb) has not run since this update, run it: SA-CORE-2026-019's update hook repairs sites left in the vulnerable install state" ;;
            notaffected) ok "${v} is outside both advisories' affected ranges" ;;
            eol)         bad "Drupal ${v%.*} is end of life: no fix for either advisory. Move to 10.6, 11.3 or 11.4 and update" ;;
            unknown)     caution "could not read the core version (core/lib/Drupal.php)" ;;
            affected)
                if [[ "$s17" == affected ]]; then bad "${v} is affected by ${CVE17} (SA-CORE-2026-017, exploited since 2026-11-19) and ${CVE19} (SA-CORE-2026-019, exploited)"
                else bad "${v} is affected by ${CVE19} (SA-CORE-2026-019, exploited): sites in an incomplete install state stayed open after the SA-CORE-2026-017 fix"; fi ;;
        esac
        if [[ $present -eq 0 ]]; then
            ok "core/install.php is not there: the installer is secured, and Drupal says such sites are not vulnerable to SA-CORE-2026-019"
        else
            rules="$(installer_rules "$d")"
            if [[ -n "$rules" ]]; then inf "core/install.php is there; these rules name install.php (blocked only if they answer 403 or 404, which --url URL tests):"; printf '%s\n' "$rules" | sed 's/^/        /'
            else
                if [[ "$s19" == fixed || "$s19" == notaffected ]]; then caution "core/install.php is there and nothing here blocks it: Drupal strongly recommends securing the installer on every site, patched or not"
                else bad "core/install.php is there and nothing here blocks it: this is the path both advisories' attacks use"; fi
            fi
        fi
        for sf in "$d"/sites/*/settings.php; do
            [[ -f "$sf" ]] || continue
            p="$(stat -c '%U %a' "$sf" 2>/dev/null)"
            for u in $users; do
                if [[ "${p%% *}" == "$u" ]]; then bad "${sf#"$d"/} belongs to ${u}, which the web server runs as: it can change the file's permissions whatever they are now (give it to the deploying account)"; rc=1
                elif writable_by "$u" "$sf" || writable_by "$u" "$(dirname "$sf")"; then caution "${sf#"$d"/} (mode ${p##* }) or its folder can be written by ${u}, which the web server runs as: Drupal says this leaves some exploit paths open"; rc=1; fi
            done
            [[ -z "$users" ]] && inf "${sf#"$d"/}: owner ${p%% *}, mode ${p##* } (no running web server found to compare with)"
        done
        if [[ $present -eq 1 || "$s19" == affected || "$s19" == eol ]]; then rc=1; fi
    done < <(find_sites)
    if [[ ${#urls[@]} -gt 0 ]]; then
        step "The live installer"
        curlb="$(root_safe_bin curl)" || { caution "curl is not installed, or as root it is not root's with every folder above it: the URLs were not tested"; curlb=""; }
        for base in "${urls[@]}"; do
            [[ -n "$curlb" ]] || break
            all=1
            for p in /core/install.php /install.php /core/install.php/x; do
                code="$("$curlb" -s -o /dev/null -w '%{http_code}' --max-time 15 "${base}${p}" 2>/dev/null)"
                case "$code" in 403|404) ok "${base}${p}: ${code}" ;; *) bad "${base}${p}: ${code:-no answer} (not 403 or 404)"; all=0 ;; esac
            done
            if [[ $all -eq 1 ]]; then ok "${base}: the installer is blocked"; else rc=1; fi
        done
    fi
    step "Verdict"
    if [[ $n -eq 0 ]]; then
        psf_not_applicable "no Drupal site found (looked for core/lib/Drupal.php under ${DRUPAL_ROOTS:-/var/www /srv /home /opt /usr/share/nginx})"
        info "No Drupal site found under ${DRUPAL_ROOTS:-/var/www /srv /home /opt /usr/share/nginx}. Set DRUPAL_ROOTS to search elsewhere."; return 0
    fi
    if [[ $rc -eq 0 ]]; then info "${n} site(s): nothing to do."
    else
        warn "Update core to 10.6.23, 11.3.23 or 11.4.14 (at least 10.6.22, 11.3.22 or 11.4.13 if those are not out yet), run update.php, and secure the installer: mitigate blocks it in Apache and nginx (403), which lasts across core updates."
        inf "Then run hunt: SA-CORE-2026-019 is exploited, and Drupal asks every site that left its installer open to check user 1."
    fi
    return "$rc"
}

# ---------- hunt -------------------------------------------------------------
cmd_hunt() {
    local rc=0 nlog=0 f lines strong d n sf
    limited_view "logs and site files"
    step "Access logs: requests for install.php"
    local -a logs=()
    if [[ -n "${ACCESS_LOGS:-}" ]]; then for f in $ACCESS_LOGS; do logs+=("$f"); done
    else for f in /var/log/nginx/*access*log* /var/log/apache2/*access*log* /var/log/httpd/*access*log* /usr/local/lsws/logs/*access*log*; do [[ -f "$f" ]] && logs+=("$f"); done; fi
    for f in "${logs[@]+"${logs[@]}"}"; do
        if ! regular "$f" || [[ ! -r "$f" ]]; then caution "${f}: cannot be read"; continue; fi
        nlog=$((nlog+1))
        lines="$(zcat -f "$f" 2>/dev/null | grep -i 'install\.php' | grep -v -i 'update\.php')"
        [[ -n "$lines" ]] || continue
        strong="$(grep -E '"POST [^"]*install\.php[^"]*" (200|302) ' <<<"$lines")"
        if [[ -n "$strong" ]]; then bad "${f}: $(wc -l <<<"$strong") POST(s) to install.php answered 200 or 302: the strongest lead, check that site now"; head -n 3 <<<"$strong" | cut -c1-220 | sed 's/^/        /'; rc=1
        else caution "${f}: $(wc -l <<<"$lines") request(s) for install.php (none a POST answered 200 or 302): scanning, or a look before an attack"; head -n 2 <<<"$lines" | cut -c1-220 | sed 's/^/        /'; rc=1; fi
    done
    [[ $nlog -gt 0 ]] || caution "no access log was read (set ACCESS_LOGS to name them)"
    while IFS=$'\t' read -r d _; do
        [[ -n "$d" ]] || continue
        step "Site ${d}"
        n="$(find "$d"/sites/*/files -type f -iname '*.php*' 2>/dev/null | head -n 20)"
        if [[ -n "$n" ]]; then bad "PHP files in the uploads folders (Drupal never puts PHP there):"; sed 's/^/        /' <<<"$n"; rc=1; else ok "no PHP file under sites/*/files"; fi
        for sf in "$d"/sites/*/settings.php; do
            [[ -f "$sf" ]] || continue
            if [[ -n "$(find "$sf" -newermt '2026-11-18 00:00' 2>/dev/null)" ]]; then caution "${sf#"$d"/} changed since 2026-11-18 ($(date -r "$sf" -u '+%F %H:%M UTC')): a reinstall rewrites it; make sure you made that change"; rc=1
            else ok "${sf#"$d"/} unchanged since before 2026-11-18"; fi
        done
        inf "user 1 (Drupal asks every site that left its installer open to check it): drush user:information --uid=1 shows its name and email; make sure the email is one you control, and consider resetting its password (drush user:password)"
    done < <(find_sites)
    step "Verdict"
    if [[ $rc -eq 1 ]]; then warn "Leads found. They are not proof of a compromise: look at each, and if a site may be compromised follow Drupal's guide: https://www.drupal.org/docs/develop/security/your-drupal-site-got-hacked-now-what"; return 1; fi
    if [[ $nlog -eq 0 ]]; then warn "No access log could be read: this is not a clean result."; return 2; fi
    info "Nothing found in what could be read. A takeover can leave few traces: check user 1 as above."
    return 0
}

# ---------- mitigate and rollback --------------------------------------------
# File operations in a site folder run as the account that owns the folder, on a folder opened with
# O_NOFOLLOW and names relative to it: nothing follows a link. A file is only ever moved: read, kept in
# the backup, compared by SHA-256, and removed only if it still matches; it is put back with O_EXCL, so
# rollback never overwrites a file that has come back.
PY_FS="$(cat <<'EOS'
import base64, hashlib, os, stat, sys
op, d, name = sys.argv[1], sys.argv[2], sys.argv[3]
try:
    fd = os.open(d, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        st = os.stat(name, dir_fd=fd, follow_symlinks=False)
    except FileNotFoundError:
        st = None
    if op == 'read':
        if st is None: print('missing'); sys.exit(0)
        if not stat.S_ISREG(st.st_mode): print('link' if stat.S_ISLNK(st.st_mode) else 'notreg'); sys.exit(0)
        f = os.open(name, os.O_RDONLY | os.O_NOFOLLOW, dir_fd=fd)
        data = b''
        while True:
            c = os.read(f, 1 << 20)
            if not c: break
            data += c
        os.close(f)
        print('ok', oct(stat.S_IMODE(st.st_mode)), st.st_uid, st.st_gid, hashlib.sha256(data).hexdigest())
        print(base64.b64encode(data).decode())
    elif op == 'remove_if':
        if st is None: print('missing'); sys.exit(0)
        if not stat.S_ISREG(st.st_mode): print('notreg'); sys.exit(0)
        f = os.open(name, os.O_RDONLY | os.O_NOFOLLOW, dir_fd=fd)
        h = hashlib.sha256()
        while True:
            c = os.read(f, 1 << 20)
            if not c: break
            h.update(c)
        os.close(f)
        if h.hexdigest() != sys.argv[4]: print('changed'); sys.exit(0)
        os.unlink(name, dir_fd=fd)
        print('ok')
    elif op == 'create':
        data = base64.b64decode(sys.stdin.buffer.read())
        if hashlib.sha256(data).hexdigest() != sys.argv[5]: print('badbackup'); sys.exit(0)
        if st is not None: print('exists'); sys.exit(0)
        f = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=fd)
        os.write(f, data); os.fchmod(f, int(sys.argv[4], 8)); os.fsync(f); os.close(f)
        print('ok')
    elif op == 'chmod':
        if st is None: print('missing'); sys.exit(0)
        if stat.S_ISLNK(st.st_mode): print('link'); sys.exit(0)
        f = os.open(name, os.O_RDONLY | os.O_NOFOLLOW, dir_fd=fd)
        old = stat.S_IMODE(os.fstat(f).st_mode)
        if len(sys.argv) > 5 and int(sys.argv[5], 8) != old: os.close(f); print('moved', oct(old)); sys.exit(0)
        os.fchmod(f, int(sys.argv[4], 8)); os.close(f)
        print('ok', oct(old))
except OSError as e:
    print('error', e.errno)
EOS
)"
# as_owner <dir> <op> <dir> <name> [args...]: the helper, as the account that owns <dir>
as_owner() {
    local owner_dir="$1" uid gid py; shift
    uid="$(stat -c %u "$owner_dir" 2>/dev/null)" || { echo "error stat"; return 0; }
    gid="$(stat -c %g "$owner_dir" 2>/dev/null)"
    if [[ "$uid" == 0 || ! $(id -u) == 0 ]]; then
        py="$(root_safe_bin python3)" || { echo "error python3"; return 0; }
        "$py" -c "$PY_FS" "$@"; return 0
    fi
    if have setpriv; then setpriv --reuid="$uid" --regid="$gid" --clear-groups -- python3 -c "$PY_FS" "$@"
    elif have runuser && getent passwd "$uid" >/dev/null 2>&1; then runuser -u "$(getent passwd "$uid" | cut -d: -f1)" -- python3 -c "$PY_FS" "$@"
    else echo "error noswitch"; fi
}

rules_text() {
cat <<'RULES'
  The rules, to add by hand where mitigate cannot (another web server, or a server block it could not change):
    nginx (inside the site's server block; a prefix match, so /core/install.php/x is caught too):
      location ^~ /core/install.php { return 403; }
    Apache (server or virtual host configuration):
      <LocationMatch "^/core/install\.php"> Require all denied </LocationMatch>
  Then check --url URL should show /core/install.php, /install.php and /core/install.php/x answering 403 or 404,
  and update.php must still work.
RULES
}

# ---------- blocking the installer in the web server ------------------------
SNIP_NAME="psf-drupal-installer.conf"
MARK="# PrivacySafe Security Patches: drupal-installer-check.sh mitigate (CVE-2026-132165, CVE-2026-136716)"
apache_dir() { local d; for d in ${APACHE_CONF:-/etc/apache2 /etc/httpd}; do [[ -d "$d" ]] && { echo "$d"; return 0; }; done; return 1; }
apachectl_bin() { local b; for b in ${APACHECTL:-apachectl apache2ctl}; do b="$(root_safe_bin "$b")" && { echo "$b"; return 0; }; done; return 1; }
nginx_bin() { root_safe_bin "${NGINX_BIN:-nginx}"; }
sha_of() { sha256sum "$1" 2>/dev/null | cut -d' ' -f1; }
note_change() { printf '%s\n' "$1" >>"$STATE_DIR/manifest.tsv"; }

# write a whole file as root: never through a link, into a folder only root can change, via a new file renamed over it
safe_put() {   # <path> <content>
    local p="$1" d tmp st
    d="$(dirname "$p")"
    [[ -L "$p" || -L "$d" ]] && { echo "link"; return 1; }
    st="$(stat -c '%u %a' "$d" 2>/dev/null)" || { echo "nodir"; return 1; }
    if is_root && { [[ "${st%% *}" != 0 ]] || (( (8#${st##* } & 8#022) != 0 )); }; then echo "unsafe"; return 1; fi
    tmp="$(mktemp "$d/.psf-drupal.XXXXXXXX")" || { echo "tmp"; return 1; }
    if printf '%s' "$2" >"$tmp" && chmod 0644 "$tmp" && mv -f "$tmp" "$p"; then return 0; fi
    rm -f "$tmp"; echo "write"; return 1
}

block_apache() {   # <dry>: prints what it did; returns 1 on a problem
    local dry="$1" ad ac file link out
    ad="$(apache_dir)" || return 0
    if [[ -d "$ad/conf-available" && -d "$ad/conf-enabled" ]]; then file="$ad/conf-available/$SNIP_NAME"; link="$ad/conf-enabled/$SNIP_NAME"
    elif [[ -d "$ad/conf.d" ]]; then file="$ad/conf.d/$SNIP_NAME"; link=""
    else caution "${ad}: no conf-available or conf.d folder: add the Apache rule yourself (see below)"; return 1; fi
    if grep -qF "$MARK" "$file" 2>/dev/null; then ok "Apache: ${file} is already in place"; return 0; fi
    if [[ -e "$file" || -L "$file" ]]; then caution "Apache: ${file} exists and is not this script's: left alone"; return 1; fi
    ac="$(apachectl_bin)" || { caution "Apache: apachectl is not installed, or as root it is not root's with every folder above it, so a change could not be tested: Apache left alone (add the rule yourself)"; return 1; }
    if [[ "$dry" -eq 1 ]]; then echo "  would write ${file}${link:+ and link it from ${link}} (403 for /core/install.php on every site), test it with ${ac} -t, and reload Apache"; return 0; fi
    out="$(safe_put "$file" "$MARK"$'\n''<LocationMatch "^/core/install\.php">'$'\n''    Require all denied'$'\n''</LocationMatch>'$'\n')" || { bad "Apache: could not write ${file} (${out})"; return 1; }
    note_change "created	$file	$(sha_of "$file")"
    if [[ -n "$link" ]]; then ln -s "../conf-available/$SNIP_NAME" "$link" && note_change "link	$link	../conf-available/$SNIP_NAME"; fi
    if ! "$ac" -t >/dev/null 2>&1; then
        rm -f "$file"; [[ -n "$link" ]] && rm -f "$link"
        sed -i "\#	${file}	#d; \#	${link:-/nonexistent}	#d" "$STATE_DIR/manifest.tsv"
        bad "Apache: the configuration did not pass ${ac} -t with the rule: the rule was taken out again and Apache was not reloaded"; return 1
    fi
    if "$ac" -k graceful >/dev/null 2>&1; then ok "Apache: ${file} blocks /core/install.php (403) on every site; tested and reloaded"
    else caution "Apache: ${file} is in place and passed ${ac} -t, but the reload failed: reload Apache yourself"; return 1; fi
    return 0
}

block_nginx() {   # <dry> <docroots...>
    local dry="$1"; shift
    local nd nb snip d f rf files=() edited=() id rc=0 esc
    nd="${NGINX_CONF:-/etc/nginx}"; [[ -d "$nd" ]] || return 0
    nb="$(nginx_bin)" || { caution "nginx: nginx is not installed, or as root it is not root's with every folder above it, so a change could not be tested: nginx left alone (add the rule yourself)"; return 1; }
    snip="$nd/snippets/$SNIP_NAME"
    for d in "$@"; do
        esc="$(printf '%s' "$d" | sed 's/[][\.*^$/]/\\&/g')"
        while IFS= read -r f; do
            rf="$(readlink -f "$f")"
            [[ " ${files[*]-} " == *" $rf "* ]] || files+=("$rf")
        done < <(grep -RlE "^[[:space:]]*root[[:space:]]+${esc}/?;" "$nd" 2>/dev/null)
        if ! grep -RqE "^[[:space:]]*root[[:space:]]+${esc}/?;" "$nd" 2>/dev/null; then caution "nginx: no server block with root ${d} found: add the nginx rule to that site's server block yourself"; rc=1; fi
    done
    [[ ${#files[@]} -gt 0 ]] || return "$rc"
    if [[ "$dry" -eq 1 ]]; then
        echo "  would write ${snip} (location ^~ /core/install.php { return 403; }), add 'include ${snip};' after the root line of the Drupal server blocks in: ${files[*]}; test with ${nb} -t; reload nginx"; return "$rc"
    fi
    if ! grep -qF "$MARK" "$snip" 2>/dev/null; then
        if [[ -e "$snip" || -L "$snip" ]]; then caution "nginx: ${snip} exists and is not this script's: left alone"; return 1; fi
        mkdir -p "$nd/snippets" || { bad "nginx: cannot create ${nd}/snippets"; return 1; }
        safe_put "$snip" "$MARK"$'\n''location ^~ /core/install.php { return 403; }'$'\n' >/dev/null || { bad "nginx: could not write ${snip}"; return 1; }
        note_change "created	$snip	$(sha_of "$snip")"
    fi
    mkdir -p "$STATE_DIR/nginx" && chmod 0700 "$STATE_DIR/nginx"
    for rf in "${files[@]}"; do
        if grep -qF "include $snip;" "$rf"; then ok "nginx: ${rf} already includes ${snip}"; continue; fi
        id="$STATE_DIR/nginx/$(date -u +%Y%m%dT%H%M%SZ)-$(printf '%s' "$rf" | sha256sum | cut -c1-12)-$(basename "$rf")"
        cp -p "$rf" "$id" && chmod 0600 "$id" || { bad "nginx: could not back up ${rf}: left alone"; rc=1; continue; }
        out="$(awk -v inc="include $snip;" -v roots="$*" '
            BEGIN { n = split(roots, r, " ") }
            { print }
            /^[[:space:]]*root[[:space:]]+/ { v = $2; sub(/;$/, "", v); sub(/\/$/, "", v)
              for (i = 1; i <= n; i++) if (v == r[i]) { match($0, /^[[:space:]]*/); printf "%s%s  # PrivacySafe Security Patches: the Drupal installer\n", substr($0, 1, RLENGTH), inc; break } }' "$rf")"
        if safe_put "$rf" "$out"$'\n' >/dev/null; then note_change "edited	$rf	$id	$(sha_of "$rf")"; edited+=("$rf")
        else bad "nginx: could not write ${rf}: left alone"; rc=1; fi
    done
    if [[ ${#edited[@]} -gt 0 ]] && ! "$nb" -t >/dev/null 2>&1; then
        bad "nginx: the configuration did not pass ${nb} -t with the include (is that root line inside a location block?): every file is put back and nginx was not reloaded"
        undo_changes nginx; return 1
    fi
    if [[ ${#edited[@]} -gt 0 ]]; then
        if "$nb" -s reload >/dev/null 2>&1; then ok "nginx: /core/install.php answers 403 in the server blocks of ${edited[*]}; tested and reloaded"
        else caution "nginx: the change passed ${nb} -t but the reload failed: reload nginx yourself"; rc=1; fi
    fi
    return "$rc"
}

# undo the web server entries of the manifest (all of them, or one server's), newest first; files changed since are left
undo_changes() {   # [nginx|apache]
    local only="${1:-}" kind p a b c rc=0 keep
    keep="$(mktemp)" || return 1
    while IFS=$'\t' read -r kind p a b c; do
        case "$kind" in created|link|edited) ;; *) printf '%s\t%s\t%s\t%s\t%s\n' "$kind" "$p" "$a" "$b" "$c" >>"$keep"; continue ;; esac
        if [[ -n "$only" ]] && { [[ "$only" == nginx && "$p" != "${NGINX_CONF:-/etc/nginx}"/* && "$kind" != edited ]] || [[ "$only" == apache && "$p" == "${NGINX_CONF:-/etc/nginx}"/* ]]; }; then printf '%s\t%s\t%s\t%s\t%s\n' "$kind" "$p" "$a" "$b" "$c" >>"$keep"; continue; fi
        case "$kind" in
            created) if [[ "$(sha_of "$p")" == "$a" ]]; then rm -f "$p" && ok "removed ${p}"; else caution "${p} was changed since: left in place"; rc=1; fi ;;
            link)    if [[ -L "$p" && "$(readlink "$p")" == "$a" ]]; then rm -f "$p" && ok "removed ${p}"; else caution "${p} is no longer this script's link: left in place"; rc=1; fi ;;
            edited)  if [[ "$(sha_of "$p")" == "$b" && -f "$a" ]]; then cp -p "$a" "$p" && ok "put back ${p} as it was"; else caution "${p} was changed since: left as it is (its backup is ${a})"; rc=1; fi ;;
        esac
    done < <(tac "$STATE_DIR/manifest.tsv")
    tac "$keep" >"$STATE_DIR/manifest.tsv"; rm -f "$keep"
    return "$rc"
}

cmd_mitigate() {
    local dry=0 inst_only=0 remove=0 rc=0 did=0 d out sha mode uid gid b64 id sf sd old
    local -a roots=()
    while [[ $# -gt 0 ]]; do
        case "$1" in --dry-run) dry=1 ;; --installer-only) inst_only=1 ;; --remove) remove=1 ;; *) die "Unknown mitigate option: $1 (--remove --installer-only --dry-run)" ;; esac
        shift
    done
    [[ $dry -eq 1 ]] || need_root "mitigate changes the web server and the sites"
    if [[ $dry -eq 0 ]]; then mkdir -p "$STATE_DIR/backup" && chmod 0700 "$STATE_DIR" "$STATE_DIR/backup" && touch "$STATE_DIR/manifest.tsv" || die "cannot create ${STATE_DIR}"; fi
    [[ $dry -eq 1 ]] && step "Dry run: nothing will be changed"
    while IFS=$'\t' read -r d _; do [[ -n "$d" ]] && roots+=("$d"); done < <(find_sites)
    [[ ${#roots[@]} -gt 0 ]] || { info "No Drupal site found: nothing to do"; return 0; }
    step "Blocking the installer in the web server (403; lasts across core updates)"
    if ! apache_dir >/dev/null && [[ ! -d "${NGINX_CONF:-/etc/nginx}" ]]; then caution "neither Apache nor nginx configuration found: add the rule to your web server yourself, or use --remove"; rc=1; fi
    block_apache "$dry" || rc=1
    block_nginx "$dry" "${roots[@]}" || rc=1
    for d in "${roots[@]}"; do
        step "Site ${d}"
        if [[ $remove -eq 0 ]]; then
            [[ -e "$d/core/install.php" ]] && inf "core/install.php stays on disk, blocked by the web server (--remove also moves it into a backup)"
        elif [[ -L "$d/core" || -L "$d/core/install.php" ]]; then caution "core or core/install.php is a symbolic link: left alone"; rc=1
        elif [[ ! -e "$d/core/install.php" ]]; then ok "core/install.php is not there: nothing to move"
        elif [[ $dry -eq 1 ]]; then echo "  would move ${d}/core/install.php into ${STATE_DIR}/backup (SHA-256 checked; rollback puts it back)"
        else
            out="$(as_owner "$d/core" read "$d/core" install.php)"
            if [[ "$out" != ok\ * ]]; then bad "could not read core/install.php (${out%%$'\n'*}): left in place"; rc=1
            else
                read -r _ mode uid gid sha <<<"$(head -n 1 <<<"$out")"
                b64="$(tail -n +2 <<<"$out")"
                id="$(date -u +%Y%m%dT%H%M%SZ)-$(printf '%s' "$d" | sha256sum | cut -c1-12)"
                if ! printf '%s' "$b64" | base64 -d >"$STATE_DIR/backup/${id}-install.php" 2>/dev/null \
                   || [[ "$(sha256sum "$STATE_DIR/backup/${id}-install.php" | cut -d' ' -f1)" != "$sha" ]]; then
                    bad "the backup of core/install.php did not verify: left in place"; rm -f "$STATE_DIR/backup/${id}-install.php"; rc=1
                else
                    chmod 0600 "$STATE_DIR/backup/${id}-install.php"
                    note_change "move	$d/core	install.php	$STATE_DIR/backup/${id}-install.php	$sha	$mode	$uid	$gid"
                    out="$(as_owner "$d/core" remove_if "$d/core" install.php "$sha")"
                    if [[ "$out" == ok ]]; then ok "moved core/install.php into ${STATE_DIR}/backup/${id}-install.php (SHA-256 ${sha:0:16}...)"; did=1
                    else bad "core/install.php was not removed (${out}): it changed after it was read, or could not be removed; the backup is kept"; rc=1; fi
                fi
            fi
        fi
        [[ $inst_only -eq 1 ]] && continue
        for sf in "$d"/sites/*/settings.php; do
            [[ -f "$sf" && ! -L "$sf" ]] || continue
            sd="$(dirname "$sf")"
            if [[ $dry -eq 1 ]]; then echo "  would set ${sf#"$d"/} to 0444 (now $(stat -c %a "$sf")) and ${sd#"$d"/} to 0555 (now $(stat -c %a "$sd"))"; continue; fi
            out="$(as_owner "$sd" chmod "$sd" settings.php 444)"
            if [[ "$out" == ok\ * ]]; then old="${out#ok }"; note_change "chmod	$sd	settings.php	$old	0o444"; ok "${sf#"$d"/}: ${old#0o} -> 444"; did=1
            else bad "${sf#"$d"/}: could not change its mode (${out})"; rc=1; fi
            out="$(as_owner "$(dirname "$sd")" chmod "$(dirname "$sd")" "$(basename "$sd")" 555)"
            if [[ "$out" == ok\ * ]]; then old="${out#ok }"; note_change "chmod	$(dirname "$sd")	$(basename "$sd")	$old	0o555"; ok "${sd#"$d"/}: ${old#0o} -> 555"; did=1
            else bad "${sd#"$d"/}: could not change its mode (${out})"; rc=1; fi
        done
    done
    step "Result"
    [[ $rc -eq 0 ]] || rules_text
    inf "test the block from outside: $0 check --url https://your.site"
    [[ $dry -eq 0 ]] && grep -qE '^(created|link|edited)	' "$STATE_DIR/manifest.tsv" 2>/dev/null && did=1
    if [[ $dry -eq 1 ]]; then info "Dry run finished: nothing was changed"
    elif [[ $did -eq 1 ]]; then info "Done. Backups and manifest: ${STATE_DIR}. Undo with: $0 rollback"
    else info "Nothing was changed"; fi
    return "$rc"
}

cmd_rollback() {
    local dry=0 rc=0 kind dir name a b c e f out web=0 ac nb
    while [[ $# -gt 0 ]]; do
        case "$1" in --dry-run) dry=1 ;; *) die "Unknown rollback option: $1 (--dry-run)" ;; esac
        shift
    done
    [[ -s "$STATE_DIR/manifest.tsv" ]] || { info "Nothing to roll back (no manifest in ${STATE_DIR})"; return 0; }
    [[ $dry -eq 1 ]] || need_root "rollback changes the web server and the sites"
    step "Rolling back"
    if [[ $dry -eq 1 ]]; then
        while IFS=$'\t' read -r kind dir name _; do case "$kind" in created|link) echo "  would remove ${dir}" ;; edited) echo "  would put back ${dir} from ${name}" ;; move) echo "  would put ${dir}/${name} back" ;; chmod) echo "  would set ${dir}/${name} back" ;; esac; done < <(tac "$STATE_DIR/manifest.tsv")
        info "Dry run finished: nothing was changed"; return 0
    fi
    grep -qE '^(created|link|edited)	' "$STATE_DIR/manifest.tsv" && web=1
    undo_changes || rc=1
    if [[ $web -eq 1 ]]; then
        if ac="$(apachectl_bin)" && apache_dir >/dev/null; then if "$ac" -t >/dev/null 2>&1 && "$ac" -k graceful >/dev/null 2>&1; then ok "Apache tested and reloaded"; else caution "Apache: test or reload failed: check it with ${ac} -t"; rc=1; fi; fi
        if nb="$(nginx_bin)" && [[ -d "${NGINX_CONF:-/etc/nginx}" ]]; then if "$nb" -t >/dev/null 2>&1 && "$nb" -s reload >/dev/null 2>&1; then ok "nginx tested and reloaded"; else caution "nginx: test or reload failed: check it with ${nb} -t"; rc=1; fi; fi
    fi
    # newest first, so a folder's mode comes back after the file inside it
    while IFS=$'\t' read -r kind dir name a b c e f _; do
        case "$kind" in
            move)   # a=backup b=sha c=mode e=uid f=gid
                if [[ ! -f "$a" || "$(sha256sum "$a" | cut -d' ' -f1)" != "$b" ]]; then bad "${a}: the backup is missing or does not match its SHA-256: ${dir}/${name} not restored"; rc=1; continue; fi
                out="$(base64 -w0 "$a" | as_owner "$dir" create "$dir" "$name" "${c#0o}" "$b")"
                case "$out" in
                    ok) ok "put back ${dir}/${name} (mode ${c#0o})"
                        [[ "$(stat -c '%u:%g' "$dir/$name" 2>/dev/null)" == "$e:$f" ]] || caution "${dir}/${name} now belongs to $(stat -c '%U:%G' "$dir/$name"), not to uid ${e}, gid ${f} as before" ;;
                    exists) caution "${dir}/${name} has come back meanwhile (a core update?): left as it is; the backup is kept in ${a}"; rc=1 ;;
                    *) bad "${dir}/${name} could not be put back (${out}); the backup is kept in ${a}"; rc=1 ;;
                esac ;;
            chmod)  # a=old mode b=mode set
                out="$(as_owner "$dir" chmod "$dir" "$name" "${a#0o}" "${b#0o}")"
                case "$out" in
                    ok\ *) ok "${dir}/${name}: back to ${a#0o}" ;;
                    moved\ *) caution "${dir}/${name}: its mode was changed since (now ${out#moved 0o}): left as it is"; rc=1 ;;
                    *) bad "${dir}/${name}: mode not restored (${out})"; rc=1 ;;
                esac ;;
        esac
    done < <(tac "$STATE_DIR/manifest.tsv")
    if [[ $rc -eq 0 ]]; then mv "$STATE_DIR/manifest.tsv" "$STATE_DIR/manifest.tsv.rolled-back-$(date +%s)"; info "Rolled back. The backups stay in ${STATE_DIR} until you remove them."; fi
    return "$rc"
}

# ---------- lock -------------------------------------------------------------
# lock_for_change CMDS ARGS...: when a command that changes this host is asked for, and it is not a
# dry run, run the script again under flock(1), so two runs cannot interleave their changes. The
# second run waits PSF_LOCK_WAIT seconds (default 30) and then stops with exit 2. The lock file is
# STATE_DIR/.lock. Without flock nothing is locked. PSF_LOCK_HELD marks the re-run: leave it unset.
lock_for_change() {
    [[ -z "${PSF_LOCK_HELD:-}" ]] || return 0
    local lk_cmds=" $1 " lk_arg lk_hit=0 lk_dir lk_rc; shift
    for lk_arg in "$@"; do
        case "$lk_arg" in --dry-run|-h|--help|help|-V|--version|version) return 0 ;; esac
        [[ "$lk_cmds" == *" $lk_arg "* ]] && lk_hit=1
    done
    [[ $lk_hit -eq 1 ]] || return 0
    psf_refuse_change "lock_for_change"
    have flock || return 0
    lk_dir="$STATE_DIR"
    { mkdir -p "$lk_dir" && [[ -w "$lk_dir" ]]; } 2>/dev/null || return 0
    lk_rc=0; PSF_LOCK_HELD=1 flock -o -E 99 -w "${PSF_LOCK_WAIT:-30}" "$lk_dir/.lock" "${BASH:-bash}" "$0" "$@" || lk_rc=$?
    [[ $lk_rc -eq 99 ]] && die "another run of ${SCRIPT_NAME} that changes this host is still in progress after ${PSF_LOCK_WAIT:-30} seconds (lock: $lk_dir/.lock): wait for it to finish, then run it again"
    exit "$lk_rc"
}

main() {
    local CMD="${1:-check}"; [[ $# -gt 0 ]] && shift
    case "$CMD" in -V|--version|version) echo "${SCRIPT_NAME} ${SCRIPT_VERSION} (${SCRIPT_DATE})"; exit 0 ;; esac
    case "$CMD" in -h|--help|help) print_help; exit 0 ;; esac
    lock_for_change "mitigate rollback" "$CMD" "$@"
    echo "${SCRIPT_NAME} ${SCRIPT_VERSION} (${SCRIPT_DATE}) - ${CMD} on $(hostname 2>/dev/null || echo '?') at $(date -u +%FT%TZ)"
    echo "Drupal core installer: ${CVE17} (SA-CORE-2026-017) and ${CVE19} (SA-CORE-2026-019)"
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
