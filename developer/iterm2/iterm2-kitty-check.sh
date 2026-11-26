#!/usr/bin/env bash
# SPDX-License-Identifier: CC0-1.0
# =============================================================================
# iTerm2 terminal-reply command execution, November 2026: check and file scan (v1)
# No CVE at time of writing (researcher ii4gsp; fixed in iTerm2 3.7.9, 20 November 2026)
#
# If this software is helpful, consider a donation to our 501c3 nonprofit:
# https://privacysafe.foundation
#
# The rest of this collection is for GNU/Linux. iTerm2 is a macOS terminal, and this flaw
# reaches the machines administrators use to run everything else, so this tool checks Macs.
# Its scan command runs on GNU/Linux as well, to look through repositories and downloads.
#
# iTerm2 3.6.1 to 3.7.8 answer a Kitty graphics file-transfer request with an error reply
# that keeps the control characters from the request. A file that carries such a request,
# shown with "cat README.md", makes iTerm2 type the attacker's text into your shell, which
# runs it: in bash, zsh and fish, on a default install. All you see is a few shell errors.
# The setting "Disable potentially insecure escape sequences" does not cover it. 3.7.9 (macOS
# 13 or later) strips control characters from every reply; macOS 12.4 to 12.x has no fixed
# release, because its newest iTerm2 is 3.6.11.
#
# Usage:
#   ./iterm2-kitty-check.sh [command] [arguments]
#
#   check (default)  Read-only. Finds every iTerm2 copy (/Applications, each
#                    user's ~/Applications, Homebrew's Caskroom, and Spotlight
#                    where it answers), reads its version and judges it
#                    against 3.6.1 to 3.7.8, and says whether this macOS can
#                    run the fix. Exit 0 = no affected copy, 1 = an affected
#                    copy, 2 = a copy whose version could not be read.
#   scan PATH...     Read-only. Looks through files under each PATH for the
#                    Kitty graphics escape sequence the attack hides in text
#                    (ESC _ G), and lists files with other escape sequences
#                    that make a terminal answer (APC, DCS, device status
#                    requests) for a look by hand. Runs on macOS and GNU/Linux.
#                    Exit 0 = nothing found, 1 = files found, 2 = bad argument.
#   version          Prints the script version.
#
# The fix is iTerm2 3.7.9 or later (iTerm2 > Check for Updates), then quit and reopen it:
# a window that is still open runs the old code. Until then, read files from others with
# "less" (which shows escape characters as ^[ instead of sending them to the terminal) or in
# an editor, not with cat, head or tail.
#
# Env overrides:
#   APP_DIRS="/Applications /Users/*/Applications"   where to look for iTerm.app
#   MACOS_VERSION      the macOS version, instead of sw_vers (testing only)
#   SCAN_MAX_SIZE=20   largest file scan reads, in MB
# Works with the bash 3.2 that macOS ships.
# =============================================================================

# shellcheck disable=SC2317,SC2329
set -uo pipefail

SCRIPT_NAME="iterm2-kitty-check.sh"
SCRIPT_VERSION="1.1.0"
SCRIPT_DATE="2026-11-25"
SELF="$0"
FIRST_AFFECTED="3.6.1"   # Kitty image file transfer arrived in 3.6.1; 3.6.0 answers "Unimplemented"
FIXED="3.7.9"
APP_DIRS="${APP_DIRS:-/Applications /Users/*/Applications /opt/homebrew/Caskroom/iterm2 /usr/local/Caskroom/iterm2}"
SCAN_MAX_SIZE="${SCAN_MAX_SIZE:-20}"

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; CYAN='\033[0;36m'; NC='\033[0m'
[[ -t 1 ]] || { RED=''; GREEN=''; YELLOW=''; CYAN=''; NC=''; }
info()    { echo -e "${GREEN}[+]${NC} $*"; }
warn()    { echo -e "${YELLOW}[!]${NC} $*"; }
step()    { echo -e "\n${CYAN}=====${NC} $* ${CYAN}=====${NC}"; }
die()     { echo -e "${RED}[-] FATAL:${NC} $*" >&2; exit 2; }
bad()     { echo -e "  ${RED}x${NC} $*"; }
inf()     { echo -e "  - $*"; }
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

# ver_cmp A B: prints -1, 0 or 1. Numeric, dot by dot, so it works without sort -V (bash 3.2, BSD sort).
ver_cmp() {
    awk -v a="$1" -v b="$2" 'BEGIN { na = split(a, x, "."); nb = split(b, y, "."); n = (na > nb ? na : nb)
        for (i = 1; i <= n; i++) { p = x[i] + 0; q = y[i] + 0; if (p < q) { print -1; exit } if (p > q) { print 1; exit } } print 0 }'
}

# The version in an app bundle's Info.plist, binary or XML, without needing the app to run.
plist_version() {
    local p="$1/Contents/Info.plist" v=""
    [[ -f "$p" && -r "$p" ]] || return 0   # -f: never read a link to a FIFO or a device
    if have plutil; then v="$(plutil -extract CFBundleShortVersionString raw -o - "$p" 2>/dev/null)"; fi
    if [[ -z "$v" ]] && have defaults; then v="$(defaults read "${p%.plist}" CFBundleShortVersionString 2>/dev/null)"; fi
    if [[ -z "$v" ]]; then
        v="$(tr -d '\r' < "$p" | awk '/<key>CFBundleShortVersionString<\/key>/ { getline; gsub(/.*<string>|<\/string>.*/, ""); print; exit }')"
    fi
    printf '%s' "$v"
}

find_apps() {
    local d a
    for d in $APP_DIRS; do
        [[ -d "$d" ]] || continue
        for a in "$d"/iTerm.app "$d"/iTerm2.app "$d"/*/iTerm.app "$d"/*/iTerm2.app; do
            [[ -d "$a" ]] && echo "$a"
        done
    done
    if have mdfind && [[ -z "${APP_DIRS_ONLY:-}" ]]; then
        mdfind "kMDItemCFBundleIdentifier == 'com.googlecode.iterm2'" 2>/dev/null
    fi
}

cmd_check() {
    [[ $# -eq 0 ]] || die "check takes no arguments"
    local os app v n=0 affected=0 unknown=0 old_os=0 seen=" "
    os="${MACOS_VERSION:-}"
    if [[ -z "$os" ]] && have sw_vers; then os="$(sw_vers -productVersion 2>/dev/null)"; fi
    step "This Mac"
    if [[ -z "$os" ]]; then
        inf "not macOS: iTerm2 runs only on macOS. Use 'scan' here to look through files"
    else
        inf "macOS ${os}"
        [[ "$(ver_cmp "$os" 13)" -lt 0 ]] && old_os=1
    fi
    [[ "${EUID:-$(id -u)}" -eq 0 ]] || caution "not running as root: other users' ~/Applications may not be readable. Run it with sudo to check every account"

    step "iTerm2 copies"
    while IFS= read -r app; do
        [[ -n "$app" ]] || continue
        case "$seen" in *" $app "*) continue ;; esac
        seen="${seen}${app} "
        n=$((n + 1))
        v="$(plist_version "$app")"
        if [[ ! "$v" =~ ^[0-9]+(\.[0-9]+)+ ]]; then
            unknown=$((unknown + 1)); caution "${app}: version '${v:-?}' could not be read"
        elif [[ "$(ver_cmp "$v" "$FIRST_AFFECTED")" -lt 0 ]]; then
            inf "${app}: ${v}, older than ${FIRST_AFFECTED}, which has no Kitty file transfer: not affected by this flaw (update anyway: older releases have other fixes missing)"
        elif [[ "$(ver_cmp "$v" "$FIXED")" -lt 0 ]]; then
            affected=$((affected + 1)); bad "${app}: ${v}, ${RED}affected${NC} (${FIRST_AFFECTED} to 3.7.8)"
        else
            inf "${app}: ${v}, fixed"
        fi
    done < <(find_apps)
    [[ $n -gt 0 ]] || inf "no iTerm2 found in ${APP_DIRS}"

    step "Verdict"
    if [[ $affected -gt 0 ]]; then
        if [[ $old_os -eq 1 ]]; then
            warn "${affected} affected copy(ies), and macOS ${os} cannot run the fixed ${FIXED} (it needs macOS 13 or later; the newest iTerm2 for macOS 12, 3.6.11, is affected). Upgrade macOS if you can, or use another terminal (Terminal.app) for files from others."
        else
            warn "${affected} affected copy(ies). Update: iTerm2 > Check for Updates, to ${FIXED} or later, then quit and reopen iTerm2 (open windows run the old code). Until then, do not cat, head or tail files from others in iTerm2: use less or an editor. The 'Disable potentially insecure escape sequences' setting does not cover this."
        fi
        return 1
    fi
    if [[ $unknown -gt 0 ]]; then warn "${unknown} copy(ies) could not be judged: read the version in iTerm2 > About iTerm2."; return 2; fi
    info "No affected iTerm2 found."
    return 0
}

# ---------- scan -------------------------------------------------------------
# The attack hides a Kitty graphics command in text: ESC _ G ... ESC \ (an APC string). A file
# with one has no business being shown in a terminal. Other strings that make a terminal answer
# (any other APC, a DCS such as DECRQSS, a device status or attribute request) are listed for a
# look by hand: they appear in some legitimate captures and test files too.
cmd_scan() {
    [[ $# -gt 0 ]] || die "scan needs at least one file or folder"
    local p f hits=0 review=0 esc kitty apc dcs maxkb
    for p in "$@"; do [[ -e "$p" ]] || die "Not found: ${p}"; done
    esc="$(printf '\033')"; kitty="${esc}_G"; apc="${esc}_"; dcs="${esc}P"
    maxkb=$((SCAN_MAX_SIZE * 1024))
    step "Files with escape sequences that make a terminal answer"
    while IFS= read -r f; do
        if LC_ALL=C grep -qF -- "$kitty" "$f" 2>/dev/null; then
            hits=$((hits + 1)); bad "${f}: a Kitty graphics command (ESC _ G): do not show this file in iTerm2 before ${FIXED}"
        elif LC_ALL=C grep -qF -- "$apc" "$f" 2>/dev/null || LC_ALL=C grep -qF -- "$dcs" "$f" 2>/dev/null \
             || LC_ALL=C grep -qE -- "${esc}\\[[0-9;]*[56]n|${esc}\\[[>=]?c" "$f" 2>/dev/null; then
            review=$((review + 1)); caution "${f}: escape sequences that ask the terminal for a reply (APC, DCS or a status request): look at it with less before showing it in a terminal"
        fi
    done < <(for p in "$@"; do find "$p" -type d -name .git -prune -o -type f -size -"${maxkb}"k -print 2>/dev/null; done \
             | while IFS= read -r f; do LC_ALL=C grep -lF -- "$esc" "$f" 2>/dev/null; done)
    step "Verdict"
    if [[ $hits -gt 0 ]]; then warn "${hits} file(s) carry the escape sequence this attack uses. Find where each came from."; return 1; fi
    if [[ $review -gt 0 ]]; then warn "${review} file(s) ask a terminal for replies (above): read them with less, not cat."; return 1; fi
    info "No file asks the terminal for a reply."
    return 0
}

main() {
    local CMD="${1:-check}"; [[ $# -gt 0 ]] && shift
    case "$CMD" in -V|--version|version) echo "${SCRIPT_NAME} ${SCRIPT_VERSION} (${SCRIPT_DATE})"; exit 0 ;; esac
    case "$CMD" in -h|--help|help) awk 'f && /^# =+$/ {exit} f {sub(/^# ?/,""); print} /^# =+$/ {f=1}' "$SELF"; exit 0 ;; esac
    echo "${SCRIPT_NAME} ${SCRIPT_VERSION} (${SCRIPT_DATE}) - ${CMD} on $(hostname 2>/dev/null || echo '?') at $(date -u +%Y-%m-%dT%H:%M:%SZ)"
    echo "iTerm2 3.6.1 to 3.7.8: a file shown in the terminal can type commands into your shell; fixed in ${FIXED}"
    case "$CMD" in
        check) cmd_check "$@" ;;
        scan) cmd_scan "$@" ;;
        *) die "Unknown command: ${CMD} (check|scan|version)" ;;
    esac
}
main "$@"; exit

# Assisted-by: Claude Opus 5.5
