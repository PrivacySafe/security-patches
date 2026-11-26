#!/usr/bin/env bash
# SPDX-License-Identifier: CC0-1.0
# =============================================================================
# Apache mod_http2 check for CVE-2026-119618  (v1)
#
# If this software is helpful, consider a donation to our 501c3 nonprofit:
# https://privacysafe.foundation
#
# CVE-2026-119618: Apache HTTP Server, mod_http2, heap corruption and
# unauthenticated remote code execution in assign_headers().
#
# Disclosed 11 November 2026 by Anthropic's OSS Scanner and Google Cloud's
# Vulnerability Research team. CVSS 3.1 9.8 (critical), CWE-362 (concurrent
# execution using a shared resource with improper synchronization): two
# HTTP/2 request-handling worker threads can race on a connection-level
# memory allocator inside mod_http2, corrupting heap memory in a way public
# research says reliably leads to code execution on a default-configured
# server, with no authentication and no application behind it needed, only
# HTTP/2 turned on. Fixed in Apache HTTP Server 2.4.71, released the same
# day. The standalone mod_h2 project on GitHub (versions 2.0.8 to 2.0.42,
# the same vulnerable code before it was merged into httpd) was archived by
# its owner on 9 June 2026 and has received no fix; the only remedy for a
# site running that module is to stop using it and move to a current httpd.
#
# Affected: Apache HTTP Server 2.4.55 to 2.4.70 with mod_http2 loaded and
# HTTP/2 (h2 or h2c) enabled via a Protocols directive anywhere in the
# active configuration. mod_http2 ships with httpd but is not loaded by
# default on every distribution's packaging, and loading the module alone
# does not enable HTTP/2; a Protocols directive naming h2 or h2c, at server
# level or inside a VirtualHost, is also required. Red Hat's own httpd
# packaging allocates each HTTP/2 stream from a separate allocator, which
# Red Hat says substantially increases how hard the flaw is to exploit on
# RHEL 9 and RHEL 10, without saying the flaw is absent; RHEL 8 and earlier
# ship no mod_http2 package at all and are not affected for that reason.
#
# What this script does:
#   check     - read-only. Reports the httpd/apache2 version, whether
#               mod_http2 is loaded, and whether an active (uncommented)
#               Protocols directive anywhere in the config tree offers h2
#               or h2c. Exits 1 if exposed, 0 if clear, 2 if undetermined.
#   hunt      - read-only. Greps the error log for the worker-crash
#               signatures public write-ups associate with this flaw.
#               Finding none does not mean the server was never attacked;
#               a successful exploit need not crash a worker at all.
#   mitigate [--dry-run] [--reload] - disables mod_http2 (the broadest fix
#               short of upgrading): comments out every active LoadModule
#               http2_module line and every active Protocols directive that
#               names h2 or h2c, across the config tree. --dry-run prints
#               what would change and writes nothing, so it needs no
#               privilege. Backs up every file it touches and verifies the
#               result with 'httpd -t' / 'apachectl -t' before leaving it in
#               place, rolling back automatically if
#               the test fails. Requires root. --reload gracefully reloads
#               the server afterward (systemctl reload where that unit
#               exists, otherwise apache2ctl -k graceful); without it,
#               reload the server yourself once you're satisfied.
#   rollback [--dry-run] [--reload] - restores every file mitigate backed up, most
#               recent first. Requires root. --reload as above.
#   rules     - prints a short explanation with no side effects.
#   version   - prints this script's version.
#
# What this script can't see: a Protocols directive set by an included
# config file this script's config-tree walk does not reach (for example,
# one pulled in by a module directive this script does not parse, such as
# mod_macro), and any Protocols directive set inside a <Directory> or
# <Location> block scoped narrower than server or virtual-host level, which
# mod_http2's own documentation does not list as a supported context but
# which a misconfigured or third-party include could still contain.
#
# Exit codes: check: 0 clear, 1 exposed, 2 undetermined/error.
#             hunt: 0 nothing found, 1 found a match, 2 error.
#             mitigate/rollback: 0 success, 2 error.
# PSF_LOCK_WAIT: seconds a run that changes the host waits for another one
# that is already changing it (default 30), then exit 2.
# =============================================================================
set -u
SCRIPT_NAME="apache-mod-http2-check.sh"
SCRIPT_VERSION="1.3.0"
SCRIPT_DATE="2026-11-25"
case "${1:-}" in
  -h|--help) awk 'f && /^# =+$/ {exit} f {sub(/^# ?/, ""); print} /^# =+$/ {f=1}' "$0"; exit 0 ;;
esac
ADVISORY="https://httpd.apache.org/security/vulnerabilities_24.html"
CVE_REF="https://access.redhat.com/security/cve/CVE-2026-119618"

RED=$'\033[31m'; YEL=$'\033[33m'; GRN=$'\033[32m'; BLU=$'\033[34m'; RST=$'\033[0m'
[ -t 1 ] || { RED=""; YEL=""; GRN=""; BLU=""; RST=""; }
warn() { printf '%s[!]%s %s\n' "$RED" "$RST" "$1" >&2; }
note() { printf '%s[*]%s %s\n' "$YEL" "$RST" "$1"; }
ok()   { printf '%s[+]%s %s\n' "$GRN" "$RST" "$1"; }
inf()  { printf '%s[i]%s %s\n' "$BLU" "$RST" "$1"; }
die()  { warn "$1"; exit 2; }

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

is_root() { [ "${EUID:-$(id -u)}" -eq 0 ]; }
SELF_CMD="$(printf '%q ' "$0" "$@")"; SELF_CMD="${SELF_CMD% }"
# need_root WHAT: stop unless root, and name the sudo command to run instead.
need_root() {
    is_root && return 0
    if command -v sudo >/dev/null 2>&1; then
        die "${1}: run it as root, for example: sudo ${SELF_CMD}"
    else
        die "${1}: run it as root (sudo is not installed here)"
    fi
}

FIXED_DEFAULT="2.4.71"
FIXED="${APACHE_HTTP2_FIXED:-$FIXED_DEFAULT}"

BACKUP_DIR="${PSF_BACKUP_DIR:-/var/backups/psf-security-patches/apache-mod-http2}"

# Locate the httpd binary and its control tool under whichever name this
# distribution uses. Debian/Ubuntu ship 'apache2'/'apache2ctl'; RHEL/Fedora/
# SUSE ship 'httpd'/'apachectl'. Neither name implies the other is absent.
find_bin() {
    for b in apache2 httpd; do
        command -v "$b" >/dev/null 2>&1 && { echo "$b"; return 0; }
    done
    return 1
}
find_ctl() {
    for c in apache2ctl apachectl; do
        command -v "$c" >/dev/null 2>&1 && { echo "$c"; return 0; }
    done
    return 1
}

httpd_version() {
    local bin="$1"
    "$bin" -v 2>/dev/null | sed -n 's/^Server version: Apache\/\([0-9.]*\).*/\1/p' | head -1
}

ver_ge() { [ "$(printf '%s\n%s\n' "$1" "$2" | sort -V | head -1)" = "$2" ]; }

# Config-file roots to walk, covering Debian/Ubuntu and RHEL/Fedora/SUSE
# layouts. A server started with a nonstandard -f/-d is not covered; 'check'
# says so when it cannot find any of these.
CONFIG_ROOTS=(
    /etc/apache2/apache2.conf
    /etc/apache2/conf-enabled
    /etc/apache2/mods-enabled
    /etc/apache2/sites-enabled
    /etc/httpd/conf/httpd.conf
    /etc/httpd/conf.d
    /etc/httpd/conf.modules.d
)

# List every regular file under the known config roots, following one level
# of Include/IncludeOptional (a second level is rare in packaged layouts and
# is reported as a gap in 'check' rather than walked indefinitely).
list_config_files() {
    local f
    for f in "${CONFIG_ROOTS[@]}"; do
        [ -e "$f" ] || continue
        if [ -d "$f" ]; then
            # -L: Debian/Ubuntu's conf-enabled, mods-enabled and
            # sites-enabled are directories of symlinks into
            # conf-available/mods-available/sites-available; a plain find
            # would skip every file in them.
            find -L "$f" -type f -name '*.conf' 2>/dev/null
            find -L "$f" -type f -name '*.load' 2>/dev/null
        else
            echo "$f"
        fi
    done
}

# Grep for an active (non-comment) directive line. Apache treats a line as a
# comment only when '#' is the first non-blank character; this matches that.
active_lines() {
    local pattern="$1"
    shift
    grep -EHin "$pattern" "$@" 2>/dev/null | grep -Ev ':\s*#'
}

do_check() {
    local bin ctl ver exposed=0 undetermined=0 module_hit protocols_hit files mods_out

    bin=$(find_bin) || { warn "Neither 'apache2' nor 'httpd' found on PATH; apache does not appear to be installed here."; return 0; }
    ctl=$(find_ctl) || true
    ver=$(httpd_version "$bin")

    if [ -z "$ver" ]; then
        warn "Found '$bin' but could not parse its version from '$bin -v'."
        undetermined=1
    else
        inf "Apache HTTP Server $ver ($bin)"
        if ver_ge "$ver" "2.4.55" && ! ver_ge "$ver" "$FIXED"; then
            note "Version is in the affected range (2.4.55 to 2.4.70) for CVE-2026-119618."
        elif ver_ge "$ver" "$FIXED"; then
            ok "Version $ver is at or above the fixed release ($FIXED)."
        else
            ok "Version $ver predates mod_http2's affected code (2.4.55)."
        fi
    fi

    files=$(list_config_files)
    if [ -z "$files" ]; then
        warn "No known Apache config layout found under ${CONFIG_ROOTS[*]}. If this server uses a custom -f/-d path, check manually."
        undetermined=1
    fi

    # Prefer the authoritative module list from the control tool when present;
    # fall back to grepping LoadModule lines if the server is not running or
    # the control tool is unavailable (e.g. inside an image build).
    module_hit=""
    # the output is kept in a variable, never in a file under /tmp
    if [ -n "$ctl" ] && mods_out="$("$ctl" -M 2>/dev/null)"; then
        printf '%s\n' "$mods_out" | grep -q 'http2_module' && module_hit="running module list ($ctl -M)"
    fi
    if [ -z "$module_hit" ] && [ -n "$files" ]; then
        if hit=$(active_lines 'LoadModule[[:space:]]+http2_module' $files); then
            [ -n "$hit" ] && module_hit="config file: $(echo "$hit" | head -1 | cut -d: -f1-2)"
        fi
    fi

    protocols_hit=""
    if [ -n "$files" ]; then
        if hit=$(active_lines 'Protocols[[:space:]]+.*\bh2c?\b' $files); then
            [ -n "$hit" ] && protocols_hit="$(echo "$hit" | head -3)"
        fi
    fi

    if [ -n "$module_hit" ] && [ -n "$protocols_hit" ]; then
        warn "mod_http2 is loaded ($module_hit) and an active Protocols directive offers h2/h2c:"
        printf '%s\n' "$protocols_hit" | sed 's/^/      /'
        exposed=1
    elif [ -n "$module_hit" ] && [ -z "$protocols_hit" ]; then
        note "mod_http2 is loaded ($module_hit) but no active Protocols directive naming h2/h2c was found in the config files this script walked."
        note "Loading the module alone does not enable HTTP/2 negotiation per Apache's own documentation, but this script's config walk is not exhaustive (see the header). Treat this as undetermined, not clear."
        undetermined=1
    else
        ok "mod_http2 does not appear to be loaded."
    fi

    if [ -n "$ver" ] && ver_ge "$ver" "2.4.55" && ! ver_ge "$ver" "$FIXED" && [ "$exposed" -eq 1 ]; then
        warn "Verdict: EXPOSED. Apache $ver with mod_http2 loaded and HTTP/2 enabled. Upgrade to $FIXED, or run 'mitigate' to disable mod_http2 until you can. Advisory: ${ADVISORY} ; CVE: ${CVE_REF}"
        return 1
    elif [ "$undetermined" -eq 1 ]; then
        warn "Verdict: UNDETERMINED. See the notes above; check the Protocols directive by hand before concluding this host is safe."
        return 2
    else
        ok "Verdict: CLEAR."
        return 0
    fi
}

do_hunt() {
    local logs=() found=0 f
    for f in /var/log/apache2/error.log /var/log/httpd/error_log /var/log/httpd/error.log; do
        [ -r "$f" ] && logs+=("$f")
    done
    if [ "${#logs[@]}" -eq 0 ]; then
        warn "No readable Apache error log found in the usual locations. If logging is redirected elsewhere (journald, a custom ErrorLog path), check it by hand."
        return 2
    fi
    inf "Scanning: ${logs[*]}"
    # Public write-ups describe worker processes segfaulting or aborting
    # inside mod_http2 during HTTP/2 stream teardown, and APR pool/allocator
    # corruption messages immediately before such a crash.
    if grep -EHin 'mod_http2|h2_[a-z_]*\(\)|AH[0-9]{5}.*(h2|http2)' "${logs[@]}" 2>/dev/null \
         | grep -Ei 'segmentation fault|signal (6|11)|core dumped|apr_pool|pool cleared without|corrupt' ; then
        warn "Found log lines matching mod_http2 crash/corruption signatures. A match is consistent with exploitation attempts but is not proof of them, and a successful attack need not crash a worker or log anything at all."
        found=1
    else
        ok "No matching crash signatures found in the logs checked."
    fi
    return $found
}

ensure_backup_dir() { mkdir -p "$BACKUP_DIR" || die "Could not create $BACKUP_DIR"; }

backup_file() {
    local f="$1" stamp base
    stamp=$(date -u +%Y%m%dT%H%M%SZ)
    base=$(echo "$f" | sed 's#^/##; s#/#_#g')
    cp -a "$f" "$BACKUP_DIR/${stamp}.${base}.bak" || die "Could not back up $f"
    echo "$BACKUP_DIR/${stamp}.${base}.bak" >> "$BACKUP_DIR/.manifest"
    printf '%s\t%s\n' "$f" "$BACKUP_DIR/${stamp}.${base}.bak" >> "$BACKUP_DIR/.manifest.tsv"
}

do_mitigate() {
    local dry="${1:-0}" files changed=0 ctl bin
    [ "$dry" = "1" ] || need_root "mitigate changes the host"
    bin=$(find_bin) || die "Apache does not appear to be installed here; nothing to mitigate."
    ctl=$(find_ctl) || true
    files=$(list_config_files)
    [ -n "$files" ] || die "No known Apache config layout found; nothing to edit."

    ensure_backup_dir
    for raw in $files; do
        local f hits
        # Resolve conf-enabled/mods-enabled symlinks to the real file in
        # conf-available/mods-available before editing. 'sed -i' renames a
        # new file over its target path; done on the symlink path itself
        # that replaces the symlink with a plain file, silently breaking
        # the a2enconf/a2enmod relationship even though Apache would still
        # read the content fine either way.
        f=$(readlink -f "$raw" 2>/dev/null || echo "$raw")
        hits=$(active_lines 'LoadModule[[:space:]]+http2_module|Protocols[[:space:]]+.*\bh2c?\b' "$f")
        [ -n "$hits" ] || continue
        inf "Found active HTTP/2 directive(s) in $f"
        printf '%s\n' "$hits" | sed 's/^/      /'
        if [ "$dry" = "1" ]; then
            continue
        fi
        backup_file "$f"
        # Comment out the matching lines in place. A line already commented
        # was excluded by active_lines above, so this only touches live
        # directives.
        sed -i -E 's/^([[:space:]]*)(LoadModule[[:space:]]+http2_module.*)$/\1# disabled by psf-security-patches (CVE-2026-119618): \2/' "$f"
        sed -i -E '/^[[:space:]]*#/! s/^([[:space:]]*)(Protocols[[:space:]]+.*\bh2c?\b.*)$/\1# disabled by psf-security-patches (CVE-2026-119618): \2/' "$f"
        changed=1
    done

    if [ "$dry" = "1" ]; then
        inf "Dry run: no files were changed."
        return 0
    fi
    if [ "$changed" -eq 0 ]; then
        ok "Nothing to change: no active HTTP/2 directives were found."
        return 0
    fi

    local test_out
    if [ -n "$ctl" ] && ! test_out="$("$ctl" -t 2>&1)"; then
        warn "'$ctl -t' rejected the result; rolling back."
        printf '%s\n' "$test_out" >&2
        do_rollback
        return 2
    fi
    ok "mod_http2 and any Protocols h2/h2c lines are commented out and the config tests clean."
    if [ "${RELOAD:-0}" -ne 1 ]; then
        note "Reload the server for this to take effect, e.g. 'systemctl reload apache2' or 'systemctl reload httpd', or rerun with --reload."
    fi
    note "This forces all traffic to HTTP/1.1 (or h2c removal only, if you edited Protocols yourself to keep h2). Anything that specifically needs HTTP/2, such as native gRPC, will break until you upgrade to $FIXED and reverse this with 'rollback'."
    return 0
}

do_rollback() {
    local dry="${1:-0}"
    [ "$dry" = "1" ] || need_root "rollback changes the host"
    [ -f "$BACKUP_DIR/.manifest.tsv" ] || { warn "No backup manifest found at $BACKUP_DIR; nothing to roll back."; return 2; }
    local failed=0 orig backup
    # read from a process substitution, not a pipe, so a failure is not lost in a subshell
    while IFS=$'\t' read -r orig backup; do
        [ -f "$backup" ] || { warn "Backup missing: $backup"; failed=1; continue; }
        if [ "$dry" = "1" ]; then inf "Dry run: would restore $orig from $backup"; continue; fi
        if cp -a "$backup" "$orig"; then ok "Restored $orig"; else warn "Failed to restore $orig"; failed=1; fi
    done < <(tac "$BACKUP_DIR/.manifest.tsv" 2>/dev/null)
    if [ "$dry" = "1" ]; then inf "Dry run: no files were changed."; return "$failed"; fi
    return "$failed"
}

do_rules() {
    cat <<EOF
CVE-2026-119618: Apache httpd mod_http2, CVSS 9.8, unauthenticated RCE.

The fix is upgrading to Apache HTTP Server $FIXED. There is no configuration
workaround that keeps HTTP/2 usable and closes this; the only mitigation
short of upgrading is turning HTTP/2 off entirely ('mitigate' above), which
drops every client to HTTP/1.1 (or leaves h2c negotiation off if you manage
Protocols by hand and only disable the module).

If this server uses the standalone mod_h2 project from GitHub rather than
the mod_http2 that now ships inside httpd itself: that project was archived
by its owner on 9 June 2026 and has no fix. Removing it and moving to a
current httpd with the built-in mod_http2 is the only way to clear this.

Red Hat's own httpd packaging on RHEL 9 and RHEL 10 allocates each HTTP/2
stream from its own allocator, which Red Hat says substantially raises the
bar to exploit this, without calling it fixed. RHEL 8 and earlier ship no
mod_http2 package and are not affected for that reason alone, not because
the code is patched there.
EOF
}

reload_apache() {
    [ "${RELOAD:-0}" -eq 1 ] || return 0
    local ctl
    ctl=$(find_ctl) || { note "--reload given but no apache2ctl/apachectl found: reload the server yourself"; return 0; }
    if command -v systemctl >/dev/null 2>&1; then
        for u in apache2 httpd; do
            if systemctl list-unit-files 2>/dev/null | grep -q "^${u}\.service"; then
                systemctl reload "$u" && inf "reloaded ${u} (graceful)" && return 0
            fi
        done
    fi
    "$ctl" -k graceful && inf "reloaded apache (graceful, via ${ctl} -k graceful)" || note "--reload given but the reload failed: reload the server yourself"
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

case "${1:-check}" in
    check) do_check; exit $? ;;
    hunt) do_hunt; exit $? ;;
    mitigate)
        shift
        dry=0; RELOAD=0
        for a in "$@"; do
            case "$a" in
                --dry-run) dry=1 ;;
                --reload) RELOAD=1 ;;
                *) die "Unknown mitigate option: $a (--dry-run --reload)" ;;
            esac
        done
        do_mitigate "$dry"; rc=$?
        [ "$dry" = "1" ] || [ "$rc" != "0" ] || reload_apache
        exit "$rc"
        ;;
    rollback)
        shift
        RELOAD=0; dry=0
        for a in "$@"; do
            case "$a" in
                --dry-run) dry=1 ;;
                --reload) RELOAD=1 ;;
                *) die "Unknown rollback option: $a (--dry-run --reload)" ;;
            esac
        done
        do_rollback "$dry"; rc=$?
        [ "$dry" = "1" ] || [ "$rc" != "0" ] || reload_apache
        exit "$rc"
        ;;
    rules) do_rules; exit 0 ;;
    version) echo "apache-mod-http2-check.sh $SCRIPT_VERSION ($SCRIPT_DATE)"; exit 0 ;;
    *) die "Usage: $0 {check|hunt|mitigate [--dry-run] [--reload]|rollback [--dry-run] [--reload]|rules|version}" ;;
esac

# Assisted-by: Claude Sonnet 5
