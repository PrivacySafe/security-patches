#!/usr/bin/env bash
# SPDX-License-Identifier: CC0-1.0
# =============================================================================
# Apache Roller XML-RPC unauthenticated deserialization check/mitigate  (v1)
# CVE-2026-129448 CVE-2026-82384
#
# If this software is helpful, consider a donation to our 501c3 nonprofit:
# https://privacysafe.foundation
#
# CVE-2026-129448 (CVSS 3.1 9.8, CWE-502 Deserialization of Untrusted Data),
# published 17 November 2026 by the Apache Software Foundation, found by
# n0mi1k and reported by Matt Raible. It is the same underlying bug as
# CVE-2026-82384 (published September 2026), which named only Roller 6.1.5
# as affected; the November advisory widens the affected range back to
# 4.0.0 and says the flaw is being actively exploited. CISA added it to the
# Known Exploited Vulnerabilities catalog on 20 November 2026.
#
# Roller's XML-RPC endpoint (POST /roller-services/xmlrpc, serving the
# legacy Blogger and MetaWeblog APIs) is configured with the XML-RPC
# library's enabledForExtensions option set to true, which makes it accept
# non-standard vendor value types, including one carrying a base64-encoded
# Java-serialized object. The servlet deserializes that object before any
# authentication check runs, so a suitable class on the server's classpath
# turns one unauthenticated POST into remote code execution. The servlet
# mapping for that path is present in every shipped web.xml regardless of
# any application-level setting; in particular, the per-site "XML-RPC"
# toggle in Roller's own admin UI (webservices.enableXmlRpc) does not gate
# this servlet in affected releases, because the deserialization happens
# before that setting is ever read. Fixed in Apache Roller 6.1.6 (11
# November 2026), which disables the vendor extension types outright and
# adds a servlet filter that rejects the request outright when the admin
# UI's XML-RPC toggle is off, so that toggle finally does what it always
# looked like it did. Roller 6.1.7 (the current release) also fixes
# CVE-2026-123374, an unrelated deserialization bug in weblog update ping
# responses, and 15 further, lower-severity issues; this script does not
# audit for any of those.
#
# Usage:
#   ./apache-roller-xmlrpc-check.sh [command] [...]
#
#   check     - read-only. Finds installed Roller web.xml files by finding
#               every Tomcat instance this host has, the same way this
#               collection's tomcat-oct2026-check.sh does: explicit
#               CATALINA_HOME/CATALINA_BASE, every running Java process's
#               -Dcatalina.home=/-Dcatalina.base= (which also catches an
#               install at a non-default path, and a CATALINA_BASE whose
#               webapps/ does not live under its CATALINA_HOME in a
#               multi-instance setup), then the usual filesystem locations
#               as a fallback for an install that is not currently running;
#               walks each one's webapps/ for a web.xml containing the
#               distinctive XML-RPC servlet mapping, or a path given with
#               ROLLER_WEBXML, and reports, for each one: whether the
#               enabledForExtensions setting is on, whether the
#               /roller-services/xmlrpc mapping is still present, and
#               whether the post-fix XmlRpcEnabledFilter (added in 6.1.6)
#               is there. That filter's presence is the one reliable
#               signal this script has for "patched 6.1.6 or later", since
#               a deployed WAR does not reliably carry its own version
#               number anywhere on disk; its absence does not by itself
#               confirm an old version; it means the signal could not be
#               found, same as a missing install. Exits 1 if any install
#               looks exposed (the mapping present, extensions enabled or
#               unchanged from the shipped default, and the fix filter
#               absent), 0 if every one found looks patched or already
#               worked around, 2 if none was found or the result could not
#               be determined.
#   hunt      - read-only. Greps readable Tomcat/httpd access logs for POST
#               requests to /roller-services/xmlrpc. A match is a strong
#               indicator something tried this endpoint, not proof it
#               carried the malicious payload, since the path is also used
#               for legitimate Blogger/MetaWeblog API clients where those
#               are actually in use; finding none does not prove nothing
#               happened, since a successful attack need not appear in any
#               log this script can reach.
#   mitigate [--remove-mapping] [--restart] [--dry-run] [--force] - edits
#               web.xml to set enabledForExtensions to false (the default
#               action), which is one of the two workarounds Apache's own
#               advisory names and, since it only turns off the dangerous
#               vendor extension type rather than the endpoint itself,
#               has no real cost to legitimate Blogger/MetaWeblog API
#               use; this action always runs. --remove-mapping instead
#               comments out the <servlet-mapping> for
#               /roller-services/xmlrpc, the other named workaround,
#               which does have a real cost: it takes the legitimate API
#               offline entirely. Because of that cost, --remove-mapping
#               by default only acts when 'check' would report a Roller
#               install here as exposed (never found, or a version signal
#               that could not be read, counts as not-yet-confirmed-fixed
#               for this purpose, not as clear); when every install found
#               is already confirmed fixed, it changes nothing and says
#               so, unless --force is given to remove the mapping anyway.
#               Backs up the file first and checks the result is still
#               well-formed XML, rolling back automatically if not.
#               Requires root (or whatever user owns the deployed webapp
#               directory), unless --dry-run is given, which prints a diff
#               of what would change for every web.xml found and writes
#               nothing, so it needs no privilege (and skips the exposure
#               gate on --remove-mapping, so you can preview the change
#               either way). Neither Tomcat nor any
#               other servlet container picks up a web.xml edit on its
#               own: the advisory says to restart Roller, and a context
#               reload is not reliably enough, since the servlet and
#               filter instances this bug involves are created once at
#               context start. --restart tries 'systemctl restart'
#               against a detected Tomcat unit;
#               without it, restart the container yourself once you're
#               satisfied with the result.
#   rollback [--restart] [--dry-run] - restores the web.xml mitigate
#               backed up. --dry-run prints which file would be restored
#               from which backup and writes nothing, so it needs no
#               privilege.
#               Requires root. --restart as above.
#   rules     - prints a short explanation with no side effects.
#   version   - prints this script's version.
#
# Environment: ROLLER_WEBXML, an explicit web.xml path (or space-separated
# list), checked before any discovered Tomcat instance. PSF_BACKUP_DIR,
# where backups and the restore manifest are kept (default
# /var/backups/psf-security-patches/apache-roller-xmlrpc).
#
# What this script cannot do: upgrade Roller. mitigate only closes the one
# path named in the advisory; it does not touch CVE-2026-123374 or the other
# issues 6.1.7 fixes, and it cannot tell you whether a deserialization
# already happened before you ran it.
# PSF_LOCK_WAIT: seconds a run that changes the host waits for another one
# that is already changing it (default 30), then exit 2.
# =============================================================================
set -u
SCRIPT_NAME="apache-roller-xmlrpc-check.sh"
SCRIPT_VERSION="1.8.0"
SCRIPT_DATE="2026-11-25"
ADVISORY="https://lists.apache.org/thread/cc0jck13nb9vvcmzxzwotr6n16mx28z9"
PSF_TMP=()
trap '[ "${#PSF_TMP[@]}" -eq 0 ] || rm -f "${PSF_TMP[@]}"' EXIT

if [ -t 2 ] && command -v tput >/dev/null 2>&1 && [ "$(tput colors 2>/dev/null || echo 0)" -ge 8 ]; then
    RED=$(tput setaf 1); GRN=$(tput setaf 2); YEL=$(tput setaf 3); BLU=$(tput setaf 4); RST=$(tput sgr0)
else
    RED=""; GRN=""; YEL=""; BLU=""; RST=""
fi
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
# Nothing to check on this host: say so in a Verdict section, record "not applicable" and stop with exit 0.
na_exit() { psf_not_applicable "$1"; echo; echo "===== Verdict ====="; echo "[i] Not applicable: $1."; exit 0; }

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

BACKUP_DIR="${PSF_BACKUP_DIR:-/var/backups/psf-security-patches/apache-roller-xmlrpc}"
MARKER='/roller-services/xmlrpc'
FILTER_NAME='XmlRpcEnabledFilter'

print_help() { awk 'f && /^# =+$/ {exit} f {sub(/^# ?/,""); print} /^# =+$/ {f=1}' "$0"; }

# catalina_roots: every CATALINA_HOME-or-CATALINA_BASE-shaped directory this
# host has, the same discovery this collection's tomcat-oct2026-check.sh
# uses: explicit CATALINA_HOME/CATALINA_BASE, every running Java process's
# -Dcatalina.home=/-Dcatalina.base= (the only way to find a non-default
# install location, and the only way to find a CATALINA_BASE that doesn't
# share its parent CATALINA_HOME's webapps/ in a multi-instance setup), then
# the usual filesystem locations as a fallback for an install that is not
# currently running.
catalina_roots() {
    local -a out=()
    local d p
    for d in "${CATALINA_HOME:-}" "${CATALINA_BASE:-}"; do [ -n "$d" ] && out+=("$d"); done
    if command -v ps >/dev/null 2>&1; then
        while read -r p; do [ -n "$p" ] && out+=("$p"); done \
            < <(ps -eo args 2>/dev/null | grep -oE -- '-Dcatalina\.(home|base)=[^ ]+' | cut -d= -f2- | sort -u)
    fi
    shopt -s nullglob
    for d in /opt/tomcat* /opt/apache-tomcat* /opt/*/tomcat* /opt/*/apache-tomcat* \
             /usr/share/tomcat* /usr/local/tomcat* /usr/local/apache-tomcat* \
             /srv/tomcat* /srv/apache-tomcat* /var/lib/tomcat* \
             /home/*/apache-tomcat* /home/*/tomcat*; do
        [ -d "$d" ] && out+=("$d")
    done
    shopt -u nullglob
    [ "${#out[@]}" -gt 0 ] || return 0
    printf '%s\n' "${out[@]}" | awk 'NF && !seen[$0]++'
}

# roller_webxml_roots: every web.xml under any discovered Tomcat root's
# webapps/ directory, plus an unpacked Apache distribution layout, plus
# anything named in ROLLER_WEBXML (space-separated explicit paths, checked
# first).
roller_webxml_roots() {
    local f root
    if [ -n "${ROLLER_WEBXML:-}" ]; then
        for f in $ROLLER_WEBXML; do [ -f "$f" ] && echo "$f"; done
    fi
    while IFS= read -r root; do
        [ -n "$root" ] || continue
        shopt -s nullglob
        for f in "$root"/webapps/*/WEB-INF/web.xml; do
            [ -f "$f" ] && echo "$f"
        done
        shopt -u nullglob
    done < <(catalina_roots)
    for f in /opt/apache-roller*/webapp/roller/WEB-INF/web.xml; do
        [ -f "$f" ] && echo "$f"
    done
}

# is_roller_webxml FILE: true if this web.xml carries the XML-RPC mapping,
# live or commented out by this script's own --remove-mapping (the one
# reliable, version-independent marker that this is a Roller deployment and
# not some other webapp that happens to live under webapps/).
is_roller_webxml() { grep -q "$MARKER" "$1" 2>/dev/null; }

# live_mapping FILE: true if an UNCOMMENTED <servlet-mapping>...</servlet-mapping>
# block naming MARKER is present. Plain grep cannot tell a live block from
# one this script's own --remove-mapping wrapped in "<!-- line -->" per
# line, so this walks the file and skips any line that is, after trimming,
# entirely an XML comment.
live_mapping() {
    awk -v marker="$MARKER" '
        {
            t=$0; gsub(/^[[:space:]]+|[[:space:]]+$/,"",t)
            iscomment = (t ~ /^<!--.*-->$/)
        }
        !iscomment && /<servlet-mapping>/ { capturing=1; buf=""; }
        capturing { buf = buf $0 "\n" }
        !iscomment && /<\/servlet-mapping>/ {
            if (capturing && buf ~ marker) { found=1 }
            capturing=0
        }
        END { exit (found ? 0 : 1) }
    ' "$1"
}

# xml_param_value FILE PARAM-NAME: the <param-value> of the <context-param>
# or <init-param> whose <param-name> is PARAM-NAME. Returns empty if absent.
xml_param_value() {
    awk -v name="$2" '
        /<(context-param|init-param)>/ { depth=1; pname=""; pval=""; next }
        depth==1 && /<param-name>/ {
            pname=$0; sub(/.*<param-name>/,"",pname); sub(/<\/param-name>.*/,"",pname)
            gsub(/^[[:space:]]+|[[:space:]]+$/,"",pname)
        }
        depth==1 && /<param-value>/ {
            pval=$0; sub(/.*<param-value>/,"",pval); sub(/<\/param-value>.*/,"",pval)
            gsub(/^[[:space:]]+|[[:space:]]+$/,"",pval)
        }
        /<\/(context-param|init-param)>/ {
            if (depth==1 && pname==name) { print pval; found=1 }
            depth=0
        }
        END { if (!found) exit 1 }
    ' "$1"
}

# xml_wellformed FILE: true if a Python or xmllint parser on this host
# accepts the file as well-formed XML; if neither is available, this check
# is skipped (returns true), same caveat as elsewhere in this collection
# when a verification tool is simply not present.
xml_wellformed() {
    if command -v xmllint >/dev/null 2>&1; then xmllint --noout "$1" 2>/dev/null; return $?; fi
    if command -v python3 >/dev/null 2>&1; then
        python3 -c "import sys,xml.dom.minidom as m; m.parse(sys.argv[1])" "$1" 2>/dev/null; return $?
    fi
    return 0
}

ensure_backup_dir() { mkdir -p "$BACKUP_DIR" 2>/dev/null || die "Could not create $BACKUP_DIR"; }

# check_one FILE: prints a verdict line for one web.xml and returns
# 0 clear, 1 exposed, 2 undetermined.
check_one() {
    local f="$1" ext mapping=0 filter=0
    inf "Roller web.xml: $f"
    if grep -q "<filter-name>${FILTER_NAME}</filter-name>" "$f" 2>/dev/null; then filter=1; fi
    if live_mapping "$f"; then mapping=1; fi
    ext="$(xml_param_value "$f" enabledForExtensions 2>/dev/null || true)"

    if [ "$filter" -eq 1 ]; then
        ok "The post-fix ${FILTER_NAME} is present: this looks like Roller 6.1.6 or later, which rejects the vendor-extension payload and gates the endpoint on the XML-RPC admin setting regardless of enabledForExtensions. Upgrading further, to 6.1.7, still gets you CVE-2026-123374's fix and 15 other issues; see the README."
        return 0
    fi
    if [ "$mapping" -eq 0 ]; then
        ok "No /roller-services/xmlrpc servlet mapping found in this file: the endpoint is not reachable here, whether by the --remove-mapping workaround or a deployment that never had it."
        return 0
    fi
    if [ "$ext" = "false" ]; then
        ok "enabledForExtensions is false: the workaround is applied. The servlet mapping is still present and the admin-UI XML-RPC toggle still does not gate this endpoint in an unpatched build, so this is a stopgap, not a fix; upgrade to 6.1.6 or later (6.1.7 current) when you can."
        return 0
    fi
    warn "Exposed: the /roller-services/xmlrpc mapping is present, enabledForExtensions is ${ext:-unset, which ships as true}, and the post-fix filter is absent. Treat this as CVE-2026-129448/CVE-2026-82384, regardless of what the install reports as its version, since a deployed WAR does not reliably carry a version string this script can read. Upgrade to 6.1.6 or later, or run 'mitigate'. Advisory: ${ADVISORY}"
    return 1
}

do_check() {
    local any=0 worst=0 f rc
    while IFS= read -r f; do
        is_roller_webxml "$f" || continue
        any=1
        check_one "$f"; rc=$?
        [ "$rc" -gt "$worst" ] && worst=$rc
        echo
    done < <(roller_webxml_roots | sort -u)
    if [ "$any" -eq 0 ]; then
        inf "No web.xml with a /roller-services/xmlrpc mapping found under the usual Tomcat webapps directories. If Roller runs from somewhere else, set ROLLER_WEBXML to its web.xml path(s), space-separated."
        NA_MSG="no Apache Roller install was found (no web.xml with a /roller-services/xmlrpc mapping under the usual Tomcat webapps folders; set ROLLER_WEBXML if it runs elsewhere)"
        return 2
    fi
    return "$worst"
}

do_hunt() {
    local any=0 f logs
    logs="$(ls /var/log/tomcat*/*.log /var/log/tomcat*/localhost_access_log*.txt \
              /var/log/apache2/*access*.log /var/log/httpd/*access*log 2>/dev/null | sort -u)"
    if [ -z "$logs" ]; then
        inf "No readable Tomcat or web-server access logs found in the usual locations."
        return 2
    fi
    for f in $logs; do
        local hit
        hit="$(grep -n 'POST[^"]*/roller-services/xmlrpc' "$f" 2>/dev/null)"
        if [ -n "$hit" ]; then
            any=1
            warn "Match in $f:"
            echo "$hit" | sed 's/^/      /'
        fi
    done
    if [ "$any" -eq 0 ]; then
        ok "No POST requests to /roller-services/xmlrpc found in the logs checked."
        return 0
    fi
    note "A match is not proof of the malicious payload specifically, only that something posted to this endpoint; a legitimate Blogger/MetaWeblog client would log the same way. Finding nothing does not prove nothing happened."
    return 1
}

backup_file() {
    local f="$1" rel base
    rel="$(echo "$f" | tr '/' '_')"
    base="${BACKUP_DIR}/${rel}.orig"
    [ -f "$base" ] || cp -a "$f" "$base" || die "Could not back up $f"
    echo "${f}	${base}" >> "${BACKUP_DIR}/.manifest.tsv"
}

do_mitigate() {
    local remove_mapping="${1:-0}" dry="${2:-0}" force="${3:-0}" changed=0 f
    if [ "$remove_mapping" -eq 1 ] && [ "$force" -ne 1 ] && [ "$dry" != "1" ]; then
        local exprc; do_check >/dev/null 2>&1; exprc=$?
        if [ "$exprc" -eq 0 ]; then
            note "Every Roller install found is already confirmed fixed (or the mapping is already gone), and --remove-mapping has a real cost beyond the default action: it takes the legitimate Blogger/MetaWeblog API offline entirely, not just the dangerous vendor extension type. Not changing anything; pass --force to remove the mapping anyway, or --dry-run to preview it. The default action (enabledForExtensions=false, no such cost) is not affected by this and runs normally without --remove-mapping."
            return 0
        fi
    fi
    [ "$dry" = "1" ] || need_root "mitigate changes the host"
    [ "$dry" = "1" ] || ensure_backup_dir
    while IFS= read -r f; do
        is_roller_webxml "$f" || continue
        local tmp
        tmp="$(mktemp)"; PSF_TMP+=("$tmp")
        if [ "$remove_mapping" -eq 1 ]; then
            awk -v marker="$MARKER" '
                BEGIN{skip=0}
                /<servlet-mapping>/ { buf=$0"\n"; capturing=1; next }
                capturing {
                    buf = buf $0 "\n"
                    if ($0 ~ /<\/servlet-mapping>/) {
                        capturing=0
                        if (buf ~ marker) {
                            n=split(buf, lines, "\n")
                            print "<!-- psf-security-patches CVE-2026-129448/CVE-2026-82384: mapping removed -->"
                            for (i=1;i<=n;i++) { if (lines[i] != "") print "<!-- " lines[i] " -->" }
                        } else {
                            printf "%s", buf
                        }
                        next
                    }
                    next
                }
                { print }
            ' "$f" > "$tmp"
        else
            awk -v marker="$MARKER" '
                BEGIN{depth=0}
                /<(context-param|init-param)>/ { depth=1; buf=$0"\n"; pname=""; next }
                depth==1 {
                    buf = buf $0 "\n"
                    if (/<param-name>/) { t=$0; sub(/.*<param-name>/,"",t); sub(/<\/param-name>.*/,"",t); gsub(/^[[:space:]]+|[[:space:]]+$/,"",t); pname=t }
                    if (/<\/(context-param|init-param)>/) {
                        depth=0
                        if (pname=="enabledForExtensions") {
                            gsub(/<param-value>[^<]*<\/param-value>/, "<param-value>false</param-value>", buf)
                        }
                        printf "%s", buf
                        next
                    }
                    next
                }
                { print }
            ' "$f" > "$tmp"
        fi
        if ! cmp -s "$f" "$tmp"; then
            if [ "$dry" = "1" ]; then
                inf "Would edit $f:"
                diff -u "$f" "$tmp" 2>/dev/null | sed -n '3,$p' | sed 's/^/      /'
                changed=1
                rm -f "$tmp"
                continue
            fi
            backup_file "$f"
            cp "$tmp" "$f"
            if xml_wellformed "$f"; then
                ok "Edited $f"
                changed=1
            else
                warn "$f is not well-formed XML after editing; rolling back this file."
                local base; base="$(grep "^${f}	" "${BACKUP_DIR}/.manifest.tsv" | tail -1 | cut -f2)"
                [ -n "$base" ] && cp -a "$base" "$f"
            fi
        fi
        rm -f "$tmp"
    done < <(roller_webxml_roots | sort -u)
    if [ "$dry" = "1" ]; then
        if [ "$changed" -eq 1 ]; then
            inf "Dry run: no files were changed."
        else
            inf "Dry run: nothing found that mitigate would change."
        fi
        return 0
    fi
    if [ "$changed" -eq 0 ]; then
        note "No change made. Either no Roller web.xml was found, every one found already looks patched or worked around, or the edit would not have changed anything (see 'check')."
        return 0
    fi
    note "web.xml changed on disk. Neither Tomcat nor any other container picks this up by itself for this bug: restart Roller's servlet container (or pass --restart to try it now), then re-run 'check'."
    return 0
}

restart_container() {
    [ "${RESTART:-0}" -eq 1 ] || return 0
    local u did=0
    if command -v systemctl >/dev/null 2>&1; then
        for u in $(systemctl list-unit-files 2>/dev/null | awk '/^tomcat[^ ]*\.service/{print $1}'); do
            systemctl restart "$u" && inf "restarted ${u}"; did=1
        done
    fi
    [ "$did" -eq 1 ] || note "--restart given but no systemd Tomcat unit was found: restart the container yourself."
}

do_rollback() {
    local dry="${1:-0}"
    [ "$dry" = "1" ] || need_root "rollback changes the host"
    [ -f "${BACKUP_DIR}/.manifest.tsv" ] || { warn "No backup manifest found at $BACKUP_DIR; nothing to roll back."; return 2; }
    local failed=0
    tac "${BACKUP_DIR}/.manifest.tsv" 2>/dev/null | while IFS=$'\t' read -r orig backup; do
        [ -f "$backup" ] || { warn "Backup missing: $backup"; failed=1; continue; }
        if [ "$dry" = "1" ]; then
            inf "Would restore $orig from $backup"
        else
            cp -a "$backup" "$orig" && ok "Restored $orig" || { warn "Failed to restore $orig"; failed=1; }
        fi
    done
    return "$failed"
}

do_rules() {
    cat <<'RULES'
Apache Roller XML-RPC deserialization (CVE-2026-129448 / CVE-2026-82384)

Fix: upgrade to Apache Roller 6.1.6 or later (6.1.7 is current and also
fixes CVE-2026-123374 and 15 other issues).

If you cannot upgrade yet, Apache's own advisory names two workarounds,
either one sufficient on its own:

  1. In WEB-INF/web.xml, set the XmlRpcServlet's enabledForExtensions
     init-param to false (what this script's 'mitigate' does by default).
  2. Remove (or comment out) the <servlet-mapping> whose <url-pattern> is
     /roller-services/xmlrpc (what 'mitigate --remove-mapping' does).

Either way, restart Roller's servlet container: a context reload is not
reliably enough, since the affected servlet and its handler mapping are
built once when the context starts.

Disabling XML-RPC in Roller's own admin settings UI
(webservices.enableXmlRpc) does NOT help on an unpatched install: the
servlet deserializes the request before that setting is ever read. It is
only effective from 6.1.6 onward, where a new filter checks it first.
RULES
}

case "${1:-check}" in
    --help|-h) print_help; exit 0 ;;
esac

verdict() {
    printf '\n===== Verdict =====\n'
    case "$1" in
        0) ok "Not exposed, by what this check can see." ;;
        1) warn "Exposed: see the findings above. Upgrade, or preview the interim measure with 'mitigate --dry-run'." ;;
        *) note "Undetermined: no install was found, or not enough could be read to decide. See the notes above." ;;
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

case "${1:-check}" in
    check) do_check; rc=$?; [ -z "${NA_MSG:-}" ] || na_exit "$NA_MSG"; verdict "$rc"; exit "$rc" ;;
    hunt) do_hunt; exit $? ;;
    mitigate)
        shift; remove_mapping=0; RESTART=0; dry=0; force=0
        for a in "$@"; do
            case "$a" in
                --remove-mapping) remove_mapping=1 ;;
                --restart) RESTART=1 ;;
                --dry-run) dry=1 ;;
                --force) force=1 ;;
                *) die "Unknown mitigate option: $a (--remove-mapping --restart --dry-run --force)" ;;
            esac
        done
        do_mitigate "$remove_mapping" "$dry" "$force"; rc=$?
        [ "$rc" != "0" ] || [ "$dry" = "1" ] || restart_container
        exit "$rc"
        ;;
    rollback)
        shift; RESTART=0; dry=0
        for a in "$@"; do
            case "$a" in
                --restart) RESTART=1 ;;
                --dry-run) dry=1 ;;
                *) die "Unknown rollback option: $a (--restart --dry-run)" ;;
            esac
        done
        do_rollback "$dry"; rc=$?
        [ "$rc" != "0" ] || [ "$dry" = "1" ] || restart_container
        exit "$rc"
        ;;
    rules) do_rules; exit 0 ;;
    version|--version|-V) echo "${SCRIPT_NAME} ${SCRIPT_VERSION} (${SCRIPT_DATE})"; exit 0 ;;
    *) die "Usage: $0 {check|hunt|mitigate [--remove-mapping] [--restart] [--dry-run] [--force]|rollback [--restart] [--dry-run]|rules|version}" ;;
esac

# Assisted-by: Claude Sonnet 5
