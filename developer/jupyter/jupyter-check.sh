#!/usr/bin/env bash
# SPDX-License-Identifier: CC0-1.0
# =============================================================================
# Jupyter Server and nbconvert October 2026: read-only checker  (v1)
# CVE-2026-114135 (Jupyter Server, gateway kernel authorization bypass)
# CVE-2026-114140 (nbconvert, path traversal file write)
#
# If this software is helpful, consider a donation to our 501c3 nonprofit:
# https://privacysafe.foundation
#
# CVE-2026-114135  Jupyter Server 2.0.0 up to 2.6.0. When GatewayClient.url is set,
#                  the normal kernel WebSocket handler is replaced by a gateway
#                  handler that authenticates the user but never asks the
#                  configured Authorizer whether that user may EXECUTE on kernels.
#                  A user the Authorizer denies can still open a kernel channel and
#                  send messages to the upstream kernel. CVSS 8.8. Fixed: 2.6.0.
#                  It only matters when BOTH are true: a gateway is configured, AND
#                  a restrictive Authorizer is in use. With the default
#                  AllowAllAuthorizer nobody is denied, so there is nothing to
#                  bypass. Even in 2.6.0 and later the bypass remains possible if a
#                  deployment manually registers the deprecated
#                  jupyter_server.gateway.handlers module.
#
# CVE-2026-114140  nbconvert 5.4.0 up to 7.17.2. ExtractOutputPreprocessor joins the
#                  attacker-controlled "filename" in a cell's output metadata to the
#                  output directory without checking the result, so converting a
#                  MALICIOUS NOTEBOOK to markdown, LaTeX, reStructuredText or
#                  AsciiDoc writes attacker-controlled data to arbitrary locations
#                  the victim can write to. Needs the victim to convert the notebook
#                  (user interaction). CVSS 8.8 (some trackers 9.0). Fixed: 7.17.2.
#
# This script is read-only. It finds installed copies (dist-info and egg-info) and
# declared pins (requirements, poetry.lock, uv.lock, pdm.lock, Pipfile.lock), and for
# Jupyter Server reads the Jupyter configuration files for GatewayClient.url and
# authorizer_class. It cannot see settings given only on the command line or in the
# environment (JUPYTER_GATEWAY_URL, --gateway-url): it reads the arguments of running
# jupyter processes for those, and says so when it cannot.
#
# Usage:
#   ./jupyter-check.sh [command] [DIR ...]
#
#   check (default)  scan DIR (default /usr/lib /usr/local/lib /opt /srv /var/www
#                    /var/lib /home /root). Exit 0 = nothing exposed, 1 = an affected
#                    nbconvert, or an affected Jupyter Server with a gateway and a
#                    custom authorizer.
#   version          print the script version.
# Containers: with no directory argument the check also reads the project files it needs from
# running docker and podman containers (SCAN_CONTAINERS=1, the default; 0 skips them), through a
# read-only probe, and judges them like host projects. The copies are temporary: a path shown as
# .../docker_NAME/PATH is the PATH inside the container NAME.
# =============================================================================

# Commands run as "cmd_${CMD}", which shellcheck can't follow
# shellcheck disable=SC2317,SC2329
set -uo pipefail

SCRIPT_NAME="jupyter-check.sh"
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

# ---------- version rules ----------------------------------------------------
server_status() {   # prints vulnerable | fixed | notaffected | unknown
    local n; n="$(norm_ver "$1")"; is_semver "$n" || { echo unknown; return; }
    ver_lt "$n" "2.0.0" && { echo notaffected; return; }
    ver_lt "$n" "2.6.0" && echo vulnerable || echo fixed
}
nbconvert_status() {
    local n; n="$(norm_ver "$1")"; is_semver "$n" || { echo unknown; return; }
    ver_lt "$n" "5.4.0" && { echo notaffected; return; }
    ver_lt "$n" "7.17.2" && echo vulnerable || echo fixed
}

# ---------- configuration (Jupyter Server) -----------------------------------
GATEWAY_ON=0; CUSTOM_AUTH=0; CONF_READ=0; CONF_FILES=""
read_jupyter_config() {   # directories to search
    local f flat
    GATEWAY_ON=0; CUSTOM_AUTH=0; CONF_READ=0; CONF_FILES=""
    while IFS= read -r f; do
        [[ -n "$f" && -r "$f" ]] || continue
        CONF_READ=1; CONF_FILES+="${f}"$'\n'
        case "$f" in
            *.py)
                sed -E 's/^[[:space:]]*#.*$//' "$f" | grep -E "^[[:space:]]*c\.GatewayClient\.url[[:space:]]*=[[:space:]]*['\"][^'\"]+['\"]" >/dev/null && GATEWAY_ON=1
                sed -E 's/^[[:space:]]*#.*$//' "$f" | grep -E "^[[:space:]]*c\.ServerApp\.authorizer_class[[:space:]]*=" | grep -v "AllowAllAuthorizer" >/dev/null && CUSTOM_AUTH=1 ;;
            *.json)
                flat="$(tr -d '\n\r' < "$f")"
                grep -qE '"GatewayClient"[[:space:]]*:[[:space:]]*\{[^}]*"url"[[:space:]]*:[[:space:]]*"[^"]+"' <<<"$flat" && GATEWAY_ON=1
                grep -oE '"authorizer_class"[[:space:]]*:[[:space:]]*"[^"]*"' <<<"$flat" | grep -v "AllowAllAuthorizer" >/dev/null && CUSTOM_AUTH=1 ;;
        esac
    done < <(
        for d in "$@"; do
            [[ -d "$d" ]] && find "$d" -maxdepth 6 \( -name node_modules -o -name site-packages -o -name dist-packages \) -prune -o \
                \( -name 'jupyter_server_config.py' -o -name 'jupyter_server_config.json' -o -name 'jupyter_config.py' -o -name 'jupyter_config.json' \
                   -o -name 'jupyter_notebook_config.py' -o -name 'jupyter_notebook_config.json' -o -path '*/jupyter_server_config.d/*.json' \) -type f -print 2>/dev/null
        done | sort -u)
}
process_hints() {   # sets GATEWAY_ON / CUSTOM_AUTH from the arguments of running jupyter processes
    have ps || return 0
    local args; args="$(ps -eo args= 2>/dev/null | grep -iE 'jupyter' | grep -v grep)"
    [[ -n "$args" ]] || return 0
    grep -qE -- '--gateway-url|--GatewayClient\.url' <<<"$args" && { GATEWAY_ON=1; inf "a running jupyter process was started with a gateway URL on its command line"; }
    grep -E -- '--ServerApp\.authorizer_class' <<<"$args" | grep -v AllowAllAuthorizer >/dev/null && { CUSTOM_AUTH=1; inf "a running jupyter process was started with a custom authorizer_class on its command line"; }
    return 0
}

# ---------- reporting --------------------------------------------------------
AFFECTED_NB=0; SERVER_EXPOSED=0
report() {   # kind label version src projdir
    local kind="$1" label="$2" ver="$3" src="$4" st
    if [[ "$kind" == server ]]; then st="$(server_status "$ver")"; else st="$(nbconvert_status "$ver")"; fi
    case "$st" in
        fixed)       ok "${label}: ${kind/server/jupyter_server} ${ver} has the fix"; [[ "$kind" == server ]] && inf "even on a fixed Jupyter Server, do not manually register the deprecated jupyter_server.gateway.handlers module: it still omits the authorization check"; return 0 ;;
        notaffected) caution "${label}: ${kind/server/jupyter_server} ${ver} is older than the affected range named here, but is not confirmed clear of other issues: update regardless"; return 1 ;;
        unknown)     caution "${label}: cannot parse version '${ver}'; treating it as not confirmed fixed"; return 1 ;;
    esac
    inf "source: ${src}"
    if [[ "$kind" == nbconvert ]]; then
        bad "${label}: nbconvert ${ver} is affected by CVE-2026-114140 (fixed in 7.17.2): converting a malicious notebook to markdown, LaTeX, reST or AsciiDoc can write attacker-controlled data to arbitrary paths"
        inf "this only matters if you convert notebooks you did not write (including JupyterLab's Download as on a shared hub or a notebook-rendering service)"
        AFFECTED_NB=$((AFFECTED_NB+1)); return 1
    fi
    # jupyter_server: exposure depends on configuration
    if [[ $GATEWAY_ON -eq 1 && $CUSTOM_AUTH -eq 1 ]]; then
        bad "${label}: jupyter_server ${ver} is affected by CVE-2026-114135 (fixed in 2.6.0), a gateway IS configured and a custom authorizer IS set: a user the authorizer denies can still execute on kernels"
        SERVER_EXPOSED=$((SERVER_EXPOSED+1)); return 1
    elif [[ $GATEWAY_ON -eq 1 ]]; then
        caution "${label}: jupyter_server ${ver} is in the affected range and a gateway is configured, but no custom authorizer was found: with the default allow-all authorizer there is nothing to bypass. Update anyway, and check whether an authorizer is set elsewhere."
        return 0
    elif [[ $CONF_READ -eq 1 ]]; then
        ok "${label}: jupyter_server ${ver} is in the affected range, but no GatewayClient.url is set in the configuration read, so the vulnerable gateway handler is not in use"
        caution "update anyway: a gateway enabled later, or through the command line or JUPYTER_GATEWAY_URL, would activate it"
        return 0
    else
        caution "${label}: jupyter_server ${ver} is in the affected range; no Jupyter configuration file was found, so the defaults (no gateway) apply. Settings on the command line or in JUPYTER_GATEWAY_URL cannot be seen here: update anyway."
        return 0
    fi
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
                esac
            done <<<"$out"
            [[ -z "$s" ]] || STAGED_DIRS+=("$s")
        done < <("$rt" ps --format '{{.ID}} {{.Names}}' 2>/dev/null)
    done
}

JUPYTER_PROBE="$(cat <<'EOS'
R="/usr/lib /usr/local/lib /opt /srv /var/www /var/lib /home /root"
find $R -xdev -maxdepth 9 -type d \( -iname "jupyter_server-*.dist-info" -o -iname "jupyter-server-*.dist-info" -o -iname "jupyter_server-*.egg-info" -o -iname "nbconvert-*.dist-info" -o -iname "nbconvert-*.egg-info" \) 2>/dev/null | head -n 40 | while read -r d; do
  echo "D $d"; [ -f "$d/METADATA" ] && echo "E $d/METADATA"; [ -f "$d/PKG-INFO" ] && echo "E $d/PKG-INFO"
done
find $R -maxdepth 6 \( -name node_modules -o -name site-packages -o -name dist-packages \) -prune -o \( -name "jupyter_server_config.py" -o -name "jupyter_server_config.json" -o -name "jupyter_config.py" -o -name "jupyter_config.json" -o -name "jupyter_notebook_config.py" -o -name "jupyter_notebook_config.json" -o -path "*/jupyter_server_config.d/*.json" \) -type f -print 2>/dev/null | head -n 40 | while read -r f; do echo "F $f"; done
find $R -xdev -maxdepth 8 \( -name node_modules -o -name site-packages -o -name dist-packages \) -prune -o \( -name "requirements*.txt" -o -name poetry.lock -o -name uv.lock -o -name pdm.lock -o -name Pipfile.lock \) -type f -print 2>/dev/null | head -n 200 | while read -r f; do
  grep -qiE "jupyter[-_]server|nbconvert" "$f" 2>/dev/null && echo "F $f"
done
exit 0
EOS
)"

cmd_check() {
    # running containers: stage once, here in the main shell, then pass the staged directories on
    # as ordinary directory arguments
    if [[ $# -eq 0 ]]; then
        stage_probe "$JUPYTER_PROBE"
        if [[ ${#STAGED_DIRS[@]} -gt 0 ]]; then
            local _d; local -a _a=()
            for _d in /usr/lib /usr/local/lib /opt /srv /var/www /var/lib /home /root; do [[ -d "$_d" ]] && _a+=("$_d"); done
            set -- ${_a[@]:+"${_a[@]}"} "${STAGED_DIRS[@]}"
        fi
    fi
    local -a dirs=() existing=()
    local rc=0 found=0 d base ver f pin line pkg
    if [[ $# -gt 0 ]]; then dirs=("$@"); else dirs=(/usr/lib /usr/local/lib /opt /srv /var/www /var/lib /home /root); fi
    for d in "${dirs[@]}"; do [[ -d "$d" ]] && existing+=("$d"); done
    step "Looking for Jupyter Server and nbconvert"
    if [[ ${#existing[@]} -eq 0 ]]; then info "None of the search directories exist"; return 0; fi
    # configuration first, from the search roots plus the usual Jupyter locations
    local -a confdirs=("${existing[@]}")
    for d in /etc/jupyter /usr/local/etc/jupyter /usr/etc/jupyter "$HOME/.jupyter"; do [[ -d "$d" ]] && confdirs+=("$d"); done
    read_jupyter_config "${confdirs[@]}"
    process_hints
    if [[ $CONF_READ -eq 1 ]]; then
        inf "read $(grep -c . <<<"$CONF_FILES") Jupyter configuration file(s); gateway configured: $([[ $GATEWAY_ON -eq 1 ]] && echo yes || echo no); custom authorizer: $([[ $CUSTOM_AUTH -eq 1 ]] && echo yes || echo no)"
    else
        inf "no Jupyter configuration file found in the search directories or the usual locations"
    fi

    step "Installed copies (dist-info and egg-info metadata)"
    while IFS= read -r d; do
        [[ -n "$d" ]] || continue
        base="$(basename "$d")"
        pkg="$(tr 'A-Z_' 'a-z-' <<<"${base%%-[0-9]*}")"
        ver="${base#*-}"; ver="${ver%.dist-info}"; ver="${ver%.egg-info}"
        [[ "$ver" =~ ^[0-9] ]] || continue
        ver="$(norm_ver "$ver")"
        case "$pkg" in
            jupyter-server) found=$((found+1)); report server "$(dirname "$d")" "$ver" "$d" || rc=1 ;;
            nbconvert)      found=$((found+1)); report nbconvert "$(dirname "$d")" "$ver" "$d" || rc=1 ;;
        esac
    done < <(find "${existing[@]}" -xdev -maxdepth 9 -type d \
                \( -iname 'jupyter_server-*.dist-info' -o -iname 'jupyter-server-*.dist-info' -o -iname 'jupyter_server-*.egg-info' -o -iname 'nbconvert-*.dist-info' -o -iname 'nbconvert-*.egg-info' \) 2>/dev/null | sort -u)

    step "Lock files and requirements (declared pins, not installed copies)"
    while IFS= read -r f; do
        [[ -n "$f" ]] || continue
        for pkg in server nbconvert; do
            pin=""
            local nm
            if [[ "$pkg" == server ]]; then nm='jupyter[-_.]server'; else nm='nbconvert'; fi
            case "$(basename "$f")" in
                poetry.lock|uv.lock|pdm.lock)
                    pin="$(awk -v re="^name = \"${nm//\[-_.\]/[-_.]}\"" 'tolower($0) ~ re {f=1; next} f && /^version = / {gsub(/[" ]/,"",$3); print $3; exit}' "$f")" ;;
                Pipfile.lock)
                    pin="$(awk -v re="\"${nm//\[-_.\]/[-_.]}\": *\\\\{" 'tolower($0) ~ re {f=1; next} f && /"version":/ {gsub(/[",=]/,"",$2); print $2; exit}' "$f")" ;;
                *)
                    line="$(grep -iE "^[[:space:]]*${nm}[[:space:]]*==" "$f" | head -n1)"
                    pin="$(sed -E "s/^[[:space:]]*[A-Za-z_.-]+[[:space:]]*==[[:space:]]*([0-9][0-9A-Za-z.]*).*/\1/" <<<"$line")"
                    [[ -z "$line" ]] && pin="" ;;
            esac
            [[ -n "$pin" ]] || continue
            found=$((found+1))
            report "$pkg" "$f" "$pin" "pinned in $(basename "$f")" || rc=1
        done
    done < <(find "${existing[@]}" -xdev -maxdepth 8 \( -name node_modules -o -name site-packages -o -name dist-packages \) -prune -o \
                \( -name 'requirements*.txt' -o -name poetry.lock -o -name uv.lock -o -name pdm.lock -o -name Pipfile.lock \) -type f -print 2>/dev/null | sort -u)

    step "Verdict"
    if [[ $found -eq 0 ]]; then
        info "No Jupyter Server or nbconvert found under: ${existing[*]}"
    elif [[ $rc -eq 0 ]]; then
        info "Nothing exposed (${found} copy or pin checked). An affected Jupyter Server without the gateway and authorizer conditions still needs the update."
    else
        warn "Exposed Jupyter component found. Upgrade: pip install --upgrade 'jupyter_server>=2.6.0' 'nbconvert>=7.17.2'"
        inf "PrivacySafe recommendation for nbconvert: do not convert notebooks from untrusted sources to markdown, LaTeX, reST or AsciiDoc, and run conversions in a throwaway directory as an unprivileged user. Re-running a cell replaces the malicious output metadata; merely converting the notebook does not."
        inf "PrivacySafe recommendation for Jupyter Server: remove GatewayClient.url if you do not need a gateway."
    fi
    return "$rc"
}

# ---------- dispatch ---------------------------------------------------------
main() {
    CMD="${1:-check}"; [[ $# -gt 0 ]] && shift
    case "$CMD" in -V|--version|version) echo "${SCRIPT_NAME} ${SCRIPT_VERSION} (${SCRIPT_DATE})"; exit 0 ;; esac
    case "$CMD" in -h|--help|help) print_help; exit 0 ;; esac
    echo "${SCRIPT_NAME} ${SCRIPT_VERSION} (${SCRIPT_DATE}) - ${CMD} on $(hostname 2>/dev/null || echo '?') at $(date -u +%FT%TZ)"
    echo "CVE-2026-114135 (fixed in jupyter_server 2.6.0) and CVE-2026-114140 (fixed in nbconvert 7.17.2)"
    case "$CMD" in
        check) cmd_check "$@" ;;
        *) die "Unknown command: ${CMD} (check|version)" ;;
    esac
}
main "$@"; exit

# Assisted-by: Claude Sonnet 5.5
