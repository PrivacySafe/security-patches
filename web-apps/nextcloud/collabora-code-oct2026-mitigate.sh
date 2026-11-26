#!/usr/bin/env bash
# SPDX-License-Identifier: CC0-1.0
# =============================================================================
# Nextcloud Collabora Built-in CODE Server command injection: mitigation  (v1)
# CVE-2026-110447
#
# If this software is helpful, consider a donation to our 501c3 nonprofit:
# https://privacysafe.foundation
#
# The optional Nextcloud app "Collabora Online - Built-in CODE Server"
# (package richdocumentscode) ships a proxy.php that the web server runs
# directly, outside Nextcloud's code. Before 26.4.303 it built the command to
# start the local CODE server by placing text from the request, including its
# path, inside a double-quoted bash string, so a request with $(...) in its
# path ran commands as the web server account, without logging in. It is
# reachable only while the local CODE server is down (a restart, upgrade or
# crash), which is when proxy.php tries to start it. The flaw has been
# exploited in the wild since September 2026 to plant PHP web shells
# (apps/richdocumentscode/shx*.php). Collabora is explicit that DISABLING the
# app is not enough, because proxy.php is served whether or not the app is
# enabled: it must be updated to >= 26.4.303 or removed. The fixed app needs
# Nextcloud 30 or later; on Nextcloud 29 and older, upgrade Nextcloud or
# remove the app. Standalone Collabora Online servers, and Nextcloud Office
# (richdocuments) without the built-in app, are not affected. A separate
# earlier command-injection fix in the same script does not close this one.
#
# The real fix is to update richdocumentscode to >= 26.4.303 or remove it,
# which this script does not do for you (an app-store update or removal, run
# through Nextcloud's occ, is the administrator's call). What apply does is an
# reversible mitigation: it neutralizes the exploited proxy.php on a
# vulnerable install by replacing it with a stub that returns HTTP 403 and
# builds no command, backing the original up first. That closes the exploited
# path at once and disables the built-in CODE server until you update or
# remove the app; restore puts the original back, and an app update replaces
# the stub with the fixed proxy.php on its own.
#
# Usage:
#   ./collabora-code-oct2026-mitigate.sh [command]
#
#   check (default)  find every Nextcloud with the built-in CODE app, report
#                    the app version (fixed at 26.4.303), the Nextcloud version
#                    (the fix needs 30+), and the proxy.php state. Read-only,
#                    root optional. Exit 0 = nothing exposed, 1 = a vulnerable
#                    app is present, 2 = something couldn't be read.
#   apply            neutralize the exploited proxy.php on every vulnerable
#                    install (backup first, idempotent, reversible). Needs
#                    write access to the app, so run as root or the web user.
#                    Refuses an already-fixed app unless --force.
#   restore          put the original proxy.php back where apply replaced it.
#   status           show which installs this script has mitigated.
#   hunt             read-only: the app folders for planted web shells
#                    (shx*.php and a known shell by hash) and the web server
#                    access logs for the exploitation markers. Exit 0 = clean,
#                    1 = findings, 2 = no app folder and no readable log, so
#                    nothing was searched.
#   version          print the script version.
#
# Env overrides:
#   NC_PATHS="/var/www /srv /opt"     where to look for Nextcloud installs
#   RICHDOC_FIXED=26.4.303            first fixed app version
#   NC_MIN_FOR_FIX=30                 Nextcloud major the fixed app requires
#   BACKUP_ROOT=/var/backups/collabora-code-oct2026
#   HUNT_SINCE="2026-09-01"           how far back hunt reads the journal
#   HUNT_LOGS="/srv/app/log/*.log"    extra access-log globs for hunt
#      PSF_LOCK_WAIT    seconds a run that changes the host waits for another one that is already
#                       changing it (default 30), then stops with exit 2; the lock is STATE_DIR/.lock
# =============================================================================

# Commands run as "cmd_${CMD}", which shellcheck can't follow
# shellcheck disable=SC2317,SC2329
set -euo pipefail

# ---------- config -----------------------------------------------------------
CVE="CVE-2026-110447"
NC_PATHS="${NC_PATHS:-/var/www /srv /opt /usr/share/webapps /var/snap}"
RICHDOC_FIXED="${RICHDOC_FIXED:-26.4.303}"
NC_MIN_FOR_FIX="${NC_MIN_FOR_FIX:-30}"
BACKUP_ROOT="${BACKUP_ROOT:-/var/backups/collabora-code-oct2026}"
HUNT_SINCE="${HUNT_SINCE:-2026-09-01}"
HUNT_LOGS="${HUNT_LOGS:-}"
SCAN_DEPTH="${SCAN_DEPTH:-8}"
STUB_MARKER="PRIVACYSAFE-COLLABORA-STUB"
KNOWN_SHELL_SHA256="4b9fbd0663fbfd6028fc216ed18e0d6ef3ae498a7fdc97083e4b0ce3cec40562"
KNOWN_IPS="139.28.18.122 89.38.98.50"
SCRIPT_NAME="collabora-code-oct2026-mitigate.sh"
SCRIPT_VERSION="1.1.0"
SCRIPT_DATE="2026-11-25"
SELF="$0"
ADVISORY="https://github.com/CollaboraOnline/online/security/advisories/GHSA-g3vx-3m76-fghh"
FORCE=0

# ---------- output -----------------------------------------------------------
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; CYAN='\033[0;36m'; NC='\033[0m'
[[ -t 1 ]] || { RED=''; GREEN=''; YELLOW=''; CYAN=''; NC=''; }
info()    { echo -e "${GREEN}[+]${NC} $*"; }
warn()    { echo -e "${YELLOW}[!]${NC} $*"; }
step()    { echo -e "\n${CYAN}=====${NC} $* ${CYAN}=====${NC}"; }
die()     { echo -e "${RED}[-] FATAL:${NC} $*" >&2; exit 2; }
# Temporary files are registered here and removed when the script ends, however it ends.
PSF_TMP=()
trap '[[ ${#PSF_TMP[@]} -eq 0 ]] || rm -f "${PSF_TMP[@]}"' EXIT
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
is_root() { [[ "${EUID:-$(id -u)}" -eq 0 ]]; }
ver_ge() { [[ "$(printf '%s\n%s\n' "$2" "$1" | sort -V | head -1)" == "$2" ]]; }
is_root() { [[ "$(id -u)" -eq 0 ]]; }

# ---------- discovery --------------------------------------------------------
# Print the app directory of every built-in CODE app found.
find_apps() {
    local d
    # shellcheck disable=SC2086
    find $NC_PATHS -maxdepth "$SCAN_DEPTH" -type d -name richdocumentscode 2>/dev/null | while read -r d; do
        [[ -f "$d/appinfo/info.xml" ]] && echo "$d"
    done | sort -u
}

app_version() {   # <appdir> -> X.Y.Z
    local f="$1/appinfo/info.xml"
    [[ -f "$f" ]] || return 0
    grep -oE '<version>[0-9.]+</version>' "$f" 2>/dev/null | head -1 | grep -oE '[0-9.]+' || true
}

# The Nextcloud root is the directory holding apps/ (or custom_apps/).
nc_root_of() {   # <appdir> -> ncroot or empty
    local parent grand
    parent="$(dirname "$1")"       # .../apps  or .../custom_apps
    grand="$(dirname "$parent")"   # nextcloud root
    [[ -f "$grand/version.php" ]] && { echo "$grand"; return; }
    echo ""
}

nc_version() {   # <ncroot> -> X.Y.Z
    local f="$1/version.php"
    [[ -f "$f" ]] || return 0
    grep -oE "OC_VersionString\s*=\s*'[0-9.]+'" "$f" 2>/dev/null | head -1 | grep -oE '[0-9]+\.[0-9]+(\.[0-9]+)*' \
        || grep -oE 'OC_Version\s*=\s*array\([0-9, ]+\)' "$f" 2>/dev/null | head -1 | grep -oE '[0-9]+' | head -3 | paste -sd. -
}

app_state() {   # <ver> -> rc|why
    local v="$1"
    [[ -n "$v" ]] || { echo "2|version unreadable"; return; }
    if ver_ge "$v" "$RICHDOC_FIXED"; then echo "0|${v} >= ${RICHDOC_FIXED}"
    else echo "1|${v} < ${RICHDOC_FIXED} (every version before ${RICHDOC_FIXED} is affected)"; fi
}

proxy_is_stub() { [[ -f "$1" ]] && grep -q "$STUB_MARKER" "$1" 2>/dev/null; }
backup_dir_for() { echo "${BACKUP_ROOT}/$(echo "$1" | sed 's#^/##; s#/#_#g')"; }

# ---------- check ------------------------------------------------------------
cmd_check() {
    local rc=0 exposed=0 unknownz=0 appdir v ncroot ncv st why proxy any=0
    step "Nextcloud built-in CODE app (richdocumentscode)"
    while read -r appdir; do
        [[ -n "$appdir" ]] || continue
        any=1
        v="$(app_version "$appdir")"
        ncroot="$(nc_root_of "$appdir")"
        ncv="$([[ -n "$ncroot" ]] && nc_version "$ncroot" || true)"
        proxy="$appdir/proxy.php"
        IFS='|' read -r st why <<<"$(app_state "$v")"
        local loc="${appdir}${ncv:+  (Nextcloud ${ncv})}"
        case $st in
            0) ok "${loc}  app ${v} fixed  (${why})" ;;
            1) if proxy_is_stub "$proxy"; then
                   caution "${loc}  app ${v} vulnerable, but proxy.php is neutralized by this script (${why}); still update to ${RICHDOC_FIXED} or remove the app"
               else
                   bad "${loc}  app ${v} vulnerable  (${why})"; exposed=1
               fi
               if [[ -n "$ncv" ]] && ! ver_ge "${ncv%%.*}" "$NC_MIN_FOR_FIX"; then
                   caution "    Nextcloud ${ncv} cannot install the fixed app (needs ${NC_MIN_FOR_FIX}+): upgrade Nextcloud or remove the app"
               fi ;;
            *) caution "${loc}  app version unreadable"; unknownz=1 ;;
        esac
        [[ -f "$proxy" ]] || inf "    note: no proxy.php in ${appdir} (nonstandard layout)"
    done < <(find_apps)
    [[ $any -eq 1 ]] || inf "no built-in CODE app (richdocumentscode) found under: ${NC_PATHS}"

    step "Verdict"
    [[ $exposed -eq 1 ]] && rc=1
    [[ $rc -eq 0 && $unknownz -eq 1 ]] && rc=2
    case $rc in
        0) info "No vulnerable built-in CODE app found where this could read one" ;;
        1) warn "A vulnerable built-in CODE app is present. Update richdocumentscode to ${RICHDOC_FIXED} or later, or remove the app; disabling it is not enough. For a reversible block run 'apply'. Then run 'hunt' to look for planted web shells. Advisory: ${ADVISORY}" ;;
        *) warn "Some installs couldn't be read. Rerun as root to read every install" ;;
    esac
    return "$rc"
}

# ---------- apply / restore --------------------------------------------------
write_stub() {   # <proxy.php path>
    local proxy="$1" tmp
    tmp="$(mktemp)"
    PSF_TMP+=("$tmp")
    cat >"$tmp" <<PHP
<?php
// ${STUB_MARKER} ${CVE}
// The original proxy.php was neutralized as an mitigation because it
// was exploitable (${CVE}). Restore it with this repo's mitigate script
// 'restore' command, or update the app to >= ${RICHDOC_FIXED}, which replaces
// this file with the fixed proxy.php. The built-in CODE server will not start
// while this stub is in place.
http_response_code(403);
header('Content-Type: text/plain');
echo "richdocumentscode temporarily disabled pending update (${CVE}).\n";
PHP
    if have php && ! php -l "$tmp" >/dev/null 2>&1; then rm -f "$tmp"; return 1; fi
    cat "$tmp" >"$proxy"; rm -f "$tmp"
}

cmd_apply() {
    is_root || warn "not running as root; this needs write access to the app files (run as root or the web server user)"
    local appdir v proxy st why bdir did=0 skipped=0 failed=0
    step "Neutralizing the exploited proxy.php on vulnerable installs"
    while read -r appdir; do
        [[ -n "$appdir" ]] || continue
        v="$(app_version "$appdir")"; proxy="$appdir/proxy.php"
        IFS='|' read -r st why <<<"$(app_state "$v")"
        if [[ "$st" == 0 && $FORCE -ne 1 ]]; then inf "${appdir}: app ${v} already fixed, leaving it alone"; continue; fi
        [[ -f "$proxy" ]] || { caution "${appdir}: no proxy.php to neutralize"; continue; }
        if proxy_is_stub "$proxy"; then inf "${appdir}: proxy.php already neutralized"; skipped=$((skipped+1)); continue; fi
        bdir="$(backup_dir_for "$appdir")"; mkdir -p "$bdir"
        if ! cp -p "$proxy" "${bdir}/proxy.php.orig" 2>/dev/null; then bad "${appdir}: cannot back up proxy.php (permission?)"; failed=$((failed+1)); continue; fi
        if write_stub "$proxy"; then ok "${appdir}: proxy.php neutralized (backup at ${bdir}/proxy.php.orig)"; did=$((did+1))
        else bad "${appdir}: stub failed php -l, left untouched"; failed=$((failed+1)); fi
    done < <(find_apps)
    echo
    info "neutralized ${did}, already done ${skipped}, failed ${failed}"
    inf "This block protects the app until you update. Update richdocumentscode to ${RICHDOC_FIXED} or later, or remove the app, then (optionally) 'restore'. Run 'hunt' to check for web shells already planted."
    [[ $failed -eq 0 ]]
}

cmd_restore() {
    is_root || warn "not running as root; restore needs write access to the app files"
    local appdir proxy bdir did=0
    step "Restoring original proxy.php where this script replaced it"
    while read -r appdir; do
        [[ -n "$appdir" ]] || continue
        proxy="$appdir/proxy.php"; bdir="$(backup_dir_for "$appdir")"
        if [[ -f "${bdir}/proxy.php.orig" ]] && proxy_is_stub "$proxy"; then
            if cp -p "${bdir}/proxy.php.orig" "$proxy" 2>/dev/null; then ok "${appdir}: proxy.php restored (the original is vulnerable; update or remove the app)"; did=$((did+1))
            else bad "${appdir}: cannot write proxy.php (permission?)"; fi
        elif proxy_is_stub "$proxy"; then caution "${appdir}: neutralized but no backup found; update or remove the app instead"
        fi
    done < <(find_apps)
    [[ $did -gt 0 ]] || inf "nothing to restore"
}

cmd_status() {
    local appdir proxy any=0
    step "Mitigation status"
    while read -r appdir; do
        [[ -n "$appdir" ]] || continue
        proxy="$appdir/proxy.php"
        if proxy_is_stub "$proxy"; then any=1; caution "${appdir}: proxy.php neutralized by this script"; fi
    done < <(find_apps)
    [[ $any -eq 1 ]] || inf "no install is currently neutralized by this script"
}

# ---------- hunt -------------------------------------------------------------
cmd_hunt() {
    local found=0 appdir f sum any=0
    step "Web shells in the app folders"
    while read -r appdir; do
        [[ -n "$appdir" ]] || continue
        any=1
        shopt -s nullglob
        for f in "$appdir"/sh*.php; do
            [[ -f "$f" ]] || continue
            [[ "$(basename "$f")" == "proxy.php" ]] && continue
            found=1; caution "suspicious file name: ${f}"
        done
        for f in "$appdir"/*.php; do
            [[ -f "$f" ]] || continue
            proxy_is_stub "$f" && continue
            if have sha256sum; then sum="$(sha256sum "$f" 2>/dev/null | awk '{print $1}')"; [[ "$sum" == "$KNOWN_SHELL_SHA256" ]] && { found=1; bad "known web shell by hash: ${f}"; }; fi
            if grep -lqE '_GET\[' "$f" 2>/dev/null && grep -lqE 'shell_exec|passthru|proc_open|system\(' "$f" 2>/dev/null; then
                [[ "$(basename "$f")" == "proxy.php" ]] || { found=1; caution "file runs commands from request input: ${f}"; }
            fi
        done
        shopt -u nullglob
    done < <(find_apps)
    [[ $any -eq 1 ]] || inf "no app folder to scan"
    if [[ $any -eq 1 && $found -eq 0 ]]; then ok "no web-shell files found in the app folders"; fi

    step "Exploitation markers in web server access logs since ${HUNT_SINCE}"
    local -a files=()
    local g
    shopt -s nullglob
    # shellcheck disable=SC2086
    for g in /var/log/nginx/*access*.log /var/log/nginx/*.log /var/log/apache2/*access*.log /var/log/apache2/*.log \
             /var/log/httpd/*access*.log /srv/*/log/*.log /var/www/*/log/*.log $HUNT_LOGS; do
        for f in $g; do [[ -r "$f" && -f "$f" ]] && files+=("$f"); done
    done
    shopt -u nullglob
    local nolog=0
    if [[ ${#files[@]} -eq 0 ]]; then warn "No readable access logs (try as root, or set HUNT_LOGS)"; nolog=1
    else
        inf "reading ${#files[@]} log file(s)"
        local name re n ip c
        local -a checks=(
            "proxy.php requests with an injection marker|richdocumentscode/proxy\.php.*(%2e%2e|\\\$\\(|\\\$\\{IFS\\}|base64 -d)"
            "proxy.php?status probes|richdocumentscode/proxy\.php\?status"
            "webhook.site callback in a request|webhook\.site"
        )
        for c in "${checks[@]}"; do
            name="${c%%|*}"; re="${c#*|}"
            n="$( { grep -hcE "$re" "${files[@]}" 2>/dev/null || true; } | awk '{s+=$1} END{print s+0}')"
            if [[ "${n:-0}" -gt 0 ]]; then found=1; caution "${name}: ${n}"; { grep -hE "$re" "${files[@]}" 2>/dev/null || true; } | tail -2 | cut -c1-200 | sed 's/^/      /'
            else ok "${name}: none"; fi
        done
        for ip in $KNOWN_IPS; do
            n="$( { grep -hcF "$ip" "${files[@]}" 2>/dev/null || true; } | awk '{s+=$1} END{print s+0}')"
            [[ "${n:-0}" -gt 0 ]] && { found=1; bad "known attacker IP ${ip}: ${n} hit(s)"; }
        done
    fi
    echo
    echo "  A hit tells you where to look. A shx*.php file in the app folder, a request to"
    echo "  proxy.php with \$( or \${IFS} in its path, or a known attacker IP is worth"
    echo "  treating as a compromise: anything the web server account could read may be"
    echo "  exposed (check for *.kdbx, wallet.dat, keystore.json and credential stores),"
    echo "  so rotate secrets, and delete any shx*.php under apps/richdocumentscode."
    if [[ $any -eq 0 && $nolog -eq 1 ]]; then warn "No app folder and no readable access log: nothing was searched, which is not a clean result"; return 2; fi
    return "$found"
}

# ---------- dispatch ---------------------------------------------------------
main() {
CMD="${1:-check}"; [[ $# -gt 0 ]] && shift
# only --force is a known option; anything else is refused, so a mistyped or invented flag can never
# turn into a real apply or restore
for a in "$@"; do case "$a" in --force) FORCE=1 ;; *) die "Unknown option: $a (the only option is --force, for apply)" ;; esac; done
case "$CMD" in -V|--version|version) echo "${SCRIPT_NAME} ${SCRIPT_VERSION} (${SCRIPT_DATE})"; exit 0 ;; esac
case "$CMD" in -h|--help) awk 'f && /^# =+$/ {exit} f {sub(/^# ?/, ""); print} /^# =+$/ {f=1}' "$SELF"; exit 0 ;; esac
echo "${SCRIPT_NAME} ${SCRIPT_VERSION} (${SCRIPT_DATE}) - ${CMD} on $(hostname 2>/dev/null || echo '?') at $(date -u +%FT%TZ)"
echo "${CVE}; advisory: ${ADVISORY}"
case "$CMD" in
    check|apply|restore|status|hunt) "cmd_${CMD}" ;;
    *) die "Unknown command: $CMD (check|apply|restore|status|hunt|version)" ;;
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
lock_for_change "apply restore" "$@"

main "$@"; exit

# Assisted-by: Claude Opus 5.5
