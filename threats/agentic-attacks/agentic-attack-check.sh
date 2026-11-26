#!/usr/bin/env bash
# SPDX-License-Identifier: CC0-1.0
# =============================================================================
# AI-driven attack frameworks: indicators of compromise on GNU/Linux hosts (v2)
# ARTEX, CAIRN, CyberStrikeAI, HexStrike AI, PentAGI, Strix, Hermes, RedAmon, Xalgorix,
# PentestSwarm and Agent Zero. No CVE: these are attack tools, not flaws.
#
# If this software is helpful, consider a donation to our 501c3 nonprofit:
# https://privacysafe.foundation
#
# Agentic attack frameworks hand an intrusion to a team of AI agents: a planner decides what to
# try, workers run nmap, curl, sqlmap, Metasploit and the rest, and every result feeds the next
# step. Built for authorized testing, they have been used since August 2026 by state-aligned and
# criminal groups (Google GTIG, Microsoft, CrowdStrike, Wiz, Datadog, the FBI's FLASH of 13
# November 2026 on ARTEX). GTIG saw CAIRN against US aerospace targets and a customized PentAGI
# scanning organizations across Asia; CyberStrikeAI runs a Go command-and-control server with
# implants; HexStrike AI wires an AI client to 150 tools over MCP.
#
# A GNU/Linux host meets them three ways, and this tool looks at each:
#   - as an operator's host: a framework, its console, container or MCP server runs here, or a
#     backdoored copy (the ARTEX images on Docker Hub hand the host to whoever planted them)
#   - as a victim: what the agents leave behind (web shells, marker files, implants, accounts,
#     scheduled jobs) and what they leave in logs (user agents, probe requests, source addresses)
#   - as a target: the weaknesses the agents look for first on a host
#
# Usage:
#   ./agentic-attack-check.sh [command] [arguments]
#
#   check (default)  Read-only. Images and containers (docker, podman) of the
#                    frameworks; consoles answering on this host's own ports (page
#                    title, page text and favicon hash, asked over loopback);
#                    running processes whose command line or environment names a
#                    framework; framework files and folders; files whose SHA-256
#                    or MD5 is a published one; AI clients (Claude, Cursor, Codex,
#                    VS Code, goose) wired to an offensive MCP server; and the
#                    weaknesses the agents use (source maps in web folders, MySQL
#                    logs written into a web folder, an empty secure_file_priv).
#                    Exit 0 = nothing, 1 = a finding or something to look at,
#                    2 = the indicator file could not be read.
#   hunt             Read-only. Web access logs (user agents, probe requests,
#                    headers, source addresses), the auth log and the journal
#                    (addresses, domains), web folders (web shells, marker files
#                    and strings), shell histories, cron and systemd units, and
#                    what runs now: shells under web and database services, and
#                    connections to published addresses. Exit 0 = nothing,
#                    1 = leads, 2 = no log could be read.
#   list             The indicators by framework, type and confidence. (The list writes
#                    every dash as a plain hyphen; pages are compared the same way.)
#   export TYPE      Prints indicators for other tools, one per line: ips,
#                    domains, user-agents, hashes, images or strings. Add
#                    --min high|medium|low (default medium). Changes nothing.
#   version          Prints the script version.
#
# Confidence: a high-confidence indicator is a finding; a medium one is a lead to look at; a
# low one (shared with ordinary tools) is counted, never acted on. No match proves nothing:
# addresses rotate within minutes and the agents choose many names at run time.
#
# Env overrides:
#   INDICATORS_FILE    the indicator list (default: indicators.tsv beside this script)
#   FRAMEWORKS="cairn pentagi"   only these frameworks (default: all)
#   WEB_ROOTS="/var/www /srv /usr/share/nginx /opt /home/*/public_html /home/*/www"
#   SEARCH_ROOTS="/root /home /opt /srv /app /usr/local /tmp /var/tmp /dev/shm"
#   MAX_DEPTH=6        how deep SEARCH_ROOTS and WEB_ROOTS are searched
#   HOME_DIRS="/root /home/*"   home folders read for framework folders and AI client settings
#   HASH_MAX_FILES=5000  most files hashed in check
#   HUNT_LOG_FILES     access logs, instead of the Apache, nginx and Caddy defaults
#   HUNT_SYS_LOG_FILES system logs, instead of auth.log, secure, syslog and messages
#   HUNT_DAYS=120      how far back logs are read
#   PROBE_PORTS        extra local ports to ask for a console page
#   MYSQL_CNF_DIRS="/etc/mysql /etc/my.cnf.d /etc"   MYSQL_QUERY=1   (0 skips the live query)
#   SCAN_CONTAINERS=1  0 skips docker and podman
#
# Output and automation (every command):
#   --output jsonl      JSON Lines for programs and language models: a start record,
#                       an event for each finding, a text record for any other line
#                       and a verdict, written when the command ends (format in
#                       automation/README.md; psf-report turns it into Markdown, HTML
#                       or PDF). --output text, the default, is the output above.
#   PSF_READ_ONLY=1     has nothing to refuse here: this tool never changes the host.
# =============================================================================

# shellcheck disable=SC2317,SC2329
set -uo pipefail

SCRIPT_NAME="agentic-attack-check.sh"
SCRIPT_VERSION="2.1.0"
SCRIPT_DATE="2026-11-25"
SELF="$0"
SELF_DIR="$(cd "$(dirname "$0")" 2>/dev/null && pwd)"
INDICATORS_FILE="${INDICATORS_FILE:-${SELF_DIR}/indicators.tsv}"
FRAMEWORKS="${FRAMEWORKS:-}"
WEB_ROOTS="${WEB_ROOTS:-/var/www /srv /usr/share/nginx /opt /home/*/public_html /home/*/www}"
SEARCH_ROOTS="${SEARCH_ROOTS:-/root /home /opt /srv /app /usr/local /tmp /var/tmp /dev/shm}"
MAX_DEPTH="${MAX_DEPTH:-6}"
HOME_DIRS="${HOME_DIRS:-/root /home/*}"
HASH_MAX_FILES="${HASH_MAX_FILES:-5000}"
HUNT_DAYS="${HUNT_DAYS:-120}"
MYSQL_CNF_DIRS="${MYSQL_CNF_DIRS:-/etc/mysql /etc/my.cnf.d /etc}"
MYSQL_QUERY="${MYSQL_QUERY:-1}"
# Ports that consoles of these frameworks commonly use, besides the ones in the indicator list.
COMMON_PORTS="80 443 3000 5000 8000 8001 8080 8443 8787 8788 8888 9000 18089"

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; CYAN='\033[0;36m'; NC='\033[0m'
[[ -t 1 ]] || { RED=''; GREEN=''; YELLOW=''; CYAN=''; NC=''; }
info()    { echo -e "${GREEN}[+]${NC} $*"; }
warn()    { echo -e "${YELLOW}[!]${NC} $*"; }
step()    { echo -e "\n${CYAN}=====${NC} $* ${CYAN}=====${NC}"; }
die()     { echo -e "${RED}[-] FATAL:${NC} $*" >&2; exit 2; }
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
have()    { command -v "$1" >/dev/null 2>&1; }
is_root() { [[ "${EUID:-$(id -u)}" -eq 0 ]]; }
SELF_CMD="$(printf '%q ' "$0" "$@")"; SELF_CMD="${SELF_CMD% }"
PSF_TMP=()
trap '[[ ${#PSF_TMP[@]} -eq 0 ]] || rm -f "${PSF_TMP[@]}"' EXIT
# mk_tmp VAR: a new temporary file, named in VAR and removed when the script ends. It sets the variable
# directly: called as "$(...)", the registration would happen in a subshell and the file would be left.
mk_tmp() { local t; t="$(mktemp)" || die "Cannot make a temporary file."; PSF_TMP+=("$t"); printf -v "$1" '%s' "$t"; }
# limited_view WHAT: a hunt run without root sees only what this account can read. Say so where a reader
# would otherwise take "none" for a clean result. Says nothing when running as root. Always returns 0,
# so it is safe under set -e.
limited_view() {
    is_root && return 0
    if command -v sudo >/dev/null 2>&1; then caution "not running as root: ${1:-files and logs} that belong to other users or to system services may not be readable, so a clean result covers only what this account can see. Run it with sudo: sudo ${SELF_CMD}"
    else caution "not running as root: ${1:-files and logs} that belong to other users or to system services may not be readable, so a clean result covers only what this account can see. Run it as root."; fi
}

# ---------- the indicator list -------------------------------------------------
# ioc TYPE[,TYPE] [MINCONF] -> "framework<TAB>confidence<TAB>value", for the chosen frameworks
ioc() {
    local types="$1" min="${2:-low}"
    awk -F'\t' -v T=",$types," -v M="$min" -v F=" ${FRAMEWORKS} " '
        BEGIN { r["low"] = 1; r["medium"] = 2; r["high"] = 3 }
        /^#/ || NF < 4 { next }
        index(T, "," $2 ",") == 0 { next }
        (r[$3] + 0) < (r[M] + 0) { next }
        F != "  " { n = split($1, fw, " "); ok = 0; for (i = 1; i <= n; i++) if (index(F, " " fw[i] " ")) ok = 1; if (!ok) next }
        { print $1 "\t" $3 "\t" $4 }' "$INDICATORS_FILE"
}
need_indicators() { [[ -r "$INDICATORS_FILE" ]] || die "cannot read the indicator list ${INDICATORS_FILE} (set INDICATORS_FILE)"; }
# Strings worth searching for on a host: every high-confidence one, and medium ones that name a
# framework. Medium strings such as tool-function names live in model traffic, not on disks.
FW_WORDS='artex|artx|antifox|scopeweaver|cairn|tsec_|cyberstrike|hexstrike|hermes|gh0st|pentagi|pentestswarm|redamon|rdmn|strix|xalgorix|agent zero|agent-zero'
host_strings() {
    ioc string medium | awk -F'\t' -v W="$FW_WORDS" '$2 == "high" || tolower($3) ~ W'
}

N_FIND=0; N_REVIEW=0; N_WEAK=0
judge() {   # <confidence> <text>
    case "$1" in
        high) N_FIND=$((N_FIND + 1)); bad "$2" ;;
        medium) N_REVIEW=$((N_REVIEW + 1)); caution "$2" ;;
        *) N_WEAK=$((N_WEAK + 1)); inf "weak: $2" ;;
    esac
}
in_web_root() {   # <path>
    local r p="$1"; for r in $WEB_ROOTS /var/lib/tomcat /var/lib/tomcat9 /var/lib/tomcat10; do [[ "$p" == "${r%/}/"* ]] && return 0; done
    case "$p" in */htdocs/*|*/public_html/*|*/webapps/*|*/www/*|*.jsp|*.jspx|*.php) return 0 ;; esac
    return 1
}

SELF_REAL="$(readlink -f "$SELF" 2>/dev/null || echo "$SELF")"
# Regular files only, never through a link; this tool and its indicator list hold every indicator,
# so they are left out.
files_under() {   # <roots> <depth> [find tests...]
    local roots="$1" depth="$2" r; shift 2
    for r in $roots; do [[ -d "$r" ]] && find "$r" -xdev -maxdepth "$depth" -type f ! -path "$SELF_REAL" ! -name 'agentic-attack-check.sh' ! -name 'indicators.tsv' "$@" 2>/dev/null; done
}

web_files() { files_under "$WEB_ROOTS" 8 "$@"; }
# Files a user owns (shell histories) may be links to anything, or FIFOs that never end: only regular
# files that are not links are read.
regular_files() { local f; for f in "$@"; do [[ -f "$f" && ! -L "$f" ]] && printf '%s\n' "$f"; done; }

# ---------- check: containers --------------------------------------------------
check_containers() {
    local e img id name fw conf val n=0 list
    list="$(ioc docker_image)"
    for e in docker podman; do
        have "$e" || continue
        "$e" info >/dev/null 2>&1 || { caution "${e}: present but not answering (run as root)"; continue; }
        while read -r img id; do
            [[ -n "$img" ]] || continue
            while IFS=$'\t' read -r fw conf val; do
                [[ "${img,,}" == *"${val,,}"* ]] || continue
                n=$((n + 1)); judge "$conf" "${e} image ${img} (${id}): ${fw}$([[ "$conf" == high ]] && echo ", a known malicious or attack-only image" || echo ": an attack framework's image. Find out who runs it and why")"
            done <<<"$list"
        done < <("$e" images --format '{{.Repository}}:{{.Tag}} {{.ID}}' 2>/dev/null)
        while read -r name img; do
            [[ -n "$name" ]] || continue
            while IFS=$'\t' read -r fw conf val; do
                [[ "${img,,}" == *"${val,,}"* ]] && { n=$((n + 1)); judge "$conf" "${e} container ${name} runs or ran ${img} (${fw})"; }
            done <<<"$list"
        done < <("$e" ps -a --format '{{.Names}} {{.Image}}' 2>/dev/null)
    done
    [[ $n -gt 0 ]] || inf "no image or container of these frameworks in docker or podman"
}

# ---------- check: consoles on this host's ports --------------------------------
# Shodan-style favicon hash: MurmurHash3 (x86, 32-bit, seed 0) of the Base64 text of the icon,
# wrapped at 76 characters with a newline after each line, as a signed number.
MMH3_PY="$(cat <<'EOS'
import base64, sys
data = base64.encodebytes(sys.stdin.buffer.read())
def mmh3(key, seed=0):
    c1, c2, h, n = 0xcc9e2d51, 0x1b873593, seed, len(key)
    r = lambda x, s: ((x << s) | (x >> (32 - s))) & 0xffffffff
    for i in range(0, n - n % 4, 4):
        k = int.from_bytes(key[i:i + 4], "little")
        k = r((k * c1) & 0xffffffff, 15); k = (k * c2) & 0xffffffff
        h = r(h ^ k, 13); h = (h * 5 + 0xe6546b64) & 0xffffffff
    t = key[n - n % 4:]; k = 0
    if len(t) >= 3: k ^= t[2] << 16
    if len(t) >= 2: k ^= t[1] << 8
    if len(t) >= 1:
        k ^= t[0]; k = r((k * c1) & 0xffffffff, 15); k = (k * c2) & 0xffffffff; h ^= k
    h ^= n; h ^= h >> 16; h = (h * 0x85ebca6b) & 0xffffffff; h ^= h >> 13
    h = (h * 0xc2b2ae35) & 0xffffffff; h ^= h >> 16
    return h - 0x100000000 if h & 0x80000000 else h
print(mmh3(data) if data else "")
EOS
)"
probe_ports() {   # ports to ask: listening ones that are in the indicator list, the common list or PROBE_PORTS
    local p lo hi want=" " l
    while IFS=$'\t' read -r _ _ p; do
        if [[ "$p" == *-* ]]; then lo="${p%-*}"; hi="${p#*-}"; want+="R${lo}:${hi} "; else want+="${p} "; fi
    done < <(ioc port)
    want+="${COMMON_PORTS} ${PROBE_PORTS:-} "
    while read -r l; do
        p="${l##*:}"; [[ "$p" =~ ^[0-9]+$ ]] || continue
        if [[ "$want" == *" $p "* ]]; then echo "$p"; continue; fi
        for r in $want; do [[ "$r" == R* ]] || continue; lo="${r#R}"; hi="${lo#*:}"; lo="${lo%:*}"
            [[ "$p" -ge "$lo" && "$p" -le "$hi" ]] && { echo "$p"; break; }; done
    done < <(ss -ltnH 2>/dev/null | awk '{print $4}') | sort -un | head -n 64
}
check_consoles() {
    local p body h n=0 scheme url fw conf val hit strs favs
    have ss || { caution "ss not found: consoles on this host not checked"; return; }
    have curl || { caution "curl not found: consoles on this host not checked"; return; }
    strs="$(ioc string,user_agent medium)"; favs="$(ioc favicon_mmh3)"
    for p in $(probe_ports); do
        body=""; url=""
        for scheme in http https; do
            body="$(curl -sk --max-time 4 --max-filesize 2000000 "${scheme}://127.0.0.1:${p}/" 2>/dev/null | head -c 400000)"
            [[ -n "$body" ]] && { url="${scheme}://127.0.0.1:${p}"; break; }
        done
        [[ -n "$url" ]] || continue
        # The indicator list writes dashes as plain hyphens; pages often use en and em dashes.
        body="${body//$'\xe2\x80\x94'/-}"; body="${body//$'\xe2\x80\x93'/-}"
        hit=""
        while IFS=$'\t' read -r fw conf val; do
            [[ ${#val} -ge 8 ]] || continue
            [[ "$body" == *"$val"* ]] && { hit="${fw}|${conf}|${val}"; [[ "$conf" == high ]] && break; }
        done <<<"$strs"
        if [[ -z "$hit" ]] && have python3; then
            h="$(curl -sk --max-time 4 --max-filesize 1000000 "${url}/favicon.ico" 2>/dev/null | python3 -c "$MMH3_PY" 2>/dev/null)"
            if [[ -n "$h" ]]; then
                while IFS=$'\t' read -r fw conf val; do [[ "$val" == "$h" ]] && { hit="${fw}|${conf}|favicon hash ${h}"; break; }; done <<<"$favs"
            fi
        fi
        if [[ -n "$hit" ]]; then
            IFS='|' read -r fw conf val <<<"$hit"; n=$((n + 1))
            judge "$conf" "port ${p}: a ${fw} console or service answers here (${val:0:60}); $(ss -ltnpH "sport = :$p" 2>/dev/null | head -n1 | grep -o 'users:.*' | cut -c1-80)"
        fi
    done
    [[ $n -gt 0 ]] || inf "no framework console answers on this host's web ports"
}

# ---------- check: processes, files, hashes, AI clients ---------------------------
check_processes() {
    local p cmd envn fw conf val n=0 strs names
    strs="$(host_strings)"; names="$(ioc file_name medium | awk -F'\t' 'length($3) >= 6')"
    for p in /proc/[0-9]*; do
        [[ "$p" == "/proc/$$" ]] && continue
        cmd="$(tr '\0' ' ' 2>/dev/null < "$p/cmdline")"; [[ -n "$cmd" ]] || continue
        [[ "$cmd" == *agentic-attack-check* ]] && continue
        envn="$(tr '\0' '\n' 2>/dev/null < "$p/environ" | cut -d= -f1 | tr '\n' ' ')"
        while IFS=$'\t' read -r fw conf val; do
            [[ -n "$val" ]] || continue
            if [[ "$cmd" == *"$val"* ]]; then n=$((n + 1)); judge "$conf" "pid ${p#/proc/}: its command line names ${fw} (${val:0:50}): ${cmd:0:120}"; break; fi
            if [[ "$val" =~ ^[A-Z][A-Z0-9_]+$ && " $envn " == *" $val "* ]]; then n=$((n + 1)); judge "$conf" "pid ${p#/proc/}: has ${val} in its environment (${fw}): ${cmd:0:120}"; break; fi
        done < <(printf '%s\n%s\n' "$strs" "$names")
    done
    [[ $n -gt 0 ]] || inf "no running process names a framework"
}
check_files() {
    local fw conf val f n=0 h tests=()
    while IFS=$'\t' read -r fw conf val; do
        case "$val" in
            [A-Za-z]:\\*) continue ;;                                         # a Windows path
            /.*) for h in $HOME_DIRS; do [[ -e "$h${val%/}" ]] && { n=$((n + 1)); judge "$conf" "$h${val}: a ${fw} $([[ "$val" == */ ]] && echo folder || echo file)"; }; done; continue ;;
            /*/) [[ -d "$val" ]] && { n=$((n + 1)); judge "$conf" "${val}: a ${fw} folder"; } ;;
            /*) [[ -e "$val" ]] && { n=$((n + 1)); judge "$conf" "${val}: ${fw}"; } ;;
            */) for h in $HOME_DIRS; do [[ -d "$h/${val#/}" ]] && { n=$((n + 1)); judge "$conf" "$h/${val#/}: a ${fw} folder"; }; done ;;
        esac
        case "$val" in /tmp/*|/var/tmp/*|/dev/shm/*)
            for f in "${val%/}"*; do [[ -e "$f" && "$f" != "${val%/}*" && "$f" != "$val" ]] && { n=$((n + 1)); judge "$conf" "${f}: ${fw}"; }; done ;;
        esac
    done < <(ioc file_path; ioc string high | awk -F'\t' '$3 ~ /^\/(tmp|var\/tmp|dev\/shm)\//')
    while IFS=$'\t' read -r fw conf val; do
        [[ ${#val} -ge 5 && "$val" != *\\* ]] || continue
        if [[ "$val" == *- ]]; then tests=(-name "${val}*"); else tests=(-name "$val"); fi
        while IFS= read -r f; do n=$((n + 1)); judge "$conf" "${f}: a ${fw} file name"; done < <(files_under "$SEARCH_ROOTS" "$MAX_DEPTH" "${tests[@]}" | head -n 20)
    done < <(ioc file_name medium)
    [[ $n -gt 0 ]] || inf "no framework file or folder under ${SEARCH_ROOTS}"
}
check_hashes() {
    local t hashes f s m n=0 c=0
    have sha256sum || { caution "sha256sum not found: hashes not checked"; return; }
    mk_tmp hashes; ioc sha256,md5 | awk -F'\t' '{print tolower($3) "\t" $1}' > "$hashes"
    [[ -s "$hashes" ]] || return 0
    while IFS= read -r f; do
        c=$((c + 1)); [[ $c -le $HASH_MAX_FILES ]] || { caution "stopped after ${HASH_MAX_FILES} files (HASH_MAX_FILES)"; break; }
        s="$(timeout 20 sha256sum "$f" 2>/dev/null | cut -d' ' -f1)"; m=""
        t="$(awk -F'\t' -v h="$s" '$1 == h {print $2; exit}' "$hashes")"
        if [[ -z "$t" ]] && have md5sum; then m="$(timeout 20 md5sum "$f" 2>/dev/null | cut -d' ' -f1)"; t="$(awk -F'\t' -v h="$m" '$1 == h {print $2; exit}' "$hashes")"; fi
        [[ -n "$t" ]] && { n=$((n + 1)); judge high "${f}: its hash is a published ${t} file (${s:0:16}...)"; }
    done < <(files_under "$SEARCH_ROOTS" 4 -size +1k -size -100M \( -perm -u+x -o -name '*.py' -o -name '*.php' -o -name '*.jsp' -o -name '*.dll' -o -name '*.exe' -o -name '*.bin' -o -name '*.so' -o -name '*.js' -o -name '*.tar*' -o -name '*.zip' \))
    inf "hashed ${c} file(s) under ${SEARCH_ROOTS}; ${n} match a published hash"
}
check_ai_clients() {
    local f n=0 hit
    while IFS= read -r f; do
        [[ -f "$f" && ! -L "$f" ]] || continue
        hit="$(grep -oiE 'hexstrike|cyberstrike|pentagi|pentestswarm|redamon|xalgorix|strix-agent|cairn|artex|agent-zero|hermes' "$f" 2>/dev/null | sort -u | tr '\n' ' ')"
        [[ -n "$hit" ]] && { n=$((n + 1)); judge medium "${f}: an AI client configured with an offensive framework (${hit% })"; }
    done < <(for h in $HOME_DIRS; do
                 printf '%s\n' "$h/.claude.json" "$h/.claude/settings.json" "$h/.cursor/mcp.json" "$h/.config/Claude/claude_desktop_config.json" \
                     "$h/.codex/config.toml" "$h/.config/goose/config.yaml" "$h/.vscode/mcp.json" "$h/.config/Code/User/mcp.json" "$h/.gemini/settings.json"
             done)
    [[ $n -gt 0 ]] || inf "no AI client on this host is wired to an offensive MCP server or provider"
}
check_accounts() {
    local fw conf val n=0
    while IFS=$'\t' read -r fw conf val; do
        grep -qiF -- "$val" /etc/passwd 2>/dev/null && { n=$((n + 1)); judge "$conf" "an account named like ${val} (${fw})"; }
    done < <(ioc account_name)
    [[ $n -gt 0 ]] || inf "no account named after a framework"
}
check_gaps() {
    local f n=0 maps cfg
    maps="$(web_files \( -name '*.js.map' -o -name '*.mjs.map' \) | grep -vE '/node_modules/|/\.git/|/vendor/|/src/' | head -n 200)"
    if [[ -n "$maps" ]]; then
        N_REVIEW=$((N_REVIEW + 1))
        caution "$(wc -l <<<"$maps") source map(s) in web folders. Served to visitors, they hand an agent your internal API routes; keep them off production. First ones:"
        head -n 5 <<<"$maps" | while IFS= read -r f; do inf "  ${f}"; done
    fi
    cfg="$(web_files \( -name env.js -o -path '*/assets/config.json' \) | grep -vE '/node_modules/|/\.git/' | head -n 20)"
    if [[ -n "$cfg" ]]; then N_REVIEW=$((N_REVIEW + 1)); caution "runtime configuration files in web folders, which the agents read first: check they hold nothing secret:"; head -n 5 <<<"$cfg" | while IFS= read -r f; do inf "  ${f}"; done; fi
    # MySQL: a log file inside a web folder (or named like a script) is how the agents wrote a web shell
    local d k v
    while IFS=: read -r f k v; do
        v="$(sed -E 's/^[[:space:]]*=?[[:space:]]*//; s/[[:space:]"]+$//; s/^"//' <<<"$v")"
        [[ -n "$v" ]] || continue
        if in_web_root "$v"; then n=$((n + 1)); N_FIND=$((N_FIND + 1)); bad "${f}: ${k} = ${v}: a MySQL log written into a web folder or as a script file, the way the agents planted web shells"; fi
    done < <(for d in $MYSQL_CNF_DIRS; do [[ -d "$d" ]] && find "$d" -maxdepth 3 -type f \( -name '*.cnf' -o -name 'my.cnf' \) 2>/dev/null; done \
             | while IFS= read -r f; do grep -HiE '^[[:space:]]*(general[_-]log[_-]file|slow[_-]query[_-]log[_-]file|log[_-]error)[[:space:]]*=' "$f" 2>/dev/null \
                 | sed -E 's/^([^:]+):[[:space:]]*([A-Za-z_-]+)[[:space:]]*=/\1:\2:/'; done)
    if [[ "$MYSQL_QUERY" == 1 ]] && have mysql; then
        local out gl glf sqf sfp ddir
        out="$(mysql --connect-timeout=5 --batch --skip-column-names -e 'SELECT @@general_log, @@general_log_file, @@slow_query_log_file, IFNULL(@@secure_file_priv, "<NULL>"), @@datadir' 2>/dev/null)"
        if [[ -n "$out" ]]; then
            IFS=$'\t' read -r gl glf sqf sfp ddir <<<"$out"
            # a relative log file name is relative to the data directory
            [[ "$glf" == /* ]] || glf="${ddir%/}/${glf}"; [[ "$sqf" == /* ]] || sqf="${ddir%/}/${sqf}"
            for v in "$glf" "$sqf"; do in_web_root "$v" && { N_FIND=$((N_FIND + 1)); bad "the running MySQL writes a log to ${v}, inside a web folder or as a script file$([[ "$gl" == 1 ]] && echo ", and the general log is ON")"; }; done
            # secure_file_priv: NULL turns file import and export off (safe); an empty value allows any path
            if [[ -z "$sfp" ]]; then N_REVIEW=$((N_REVIEW + 1)); caution "the running MySQL has secure_file_priv empty: an account with FILE can read and write anywhere the server can. Set it to a dedicated folder, or to NULL to turn file import and export off"
            else inf "running MySQL: general log ${gl} at ${glf}, secure_file_priv ${sfp}"; fi
        else inf "MySQL not reachable without a password here: its live log settings were not read (the configuration files were)"; fi
    fi
    [[ $n -gt 0 ]] || inf "no MySQL log file in a web folder in the configuration files"
}

cmd_check() {
    [[ $# -eq 0 ]] || die "check takes no arguments"
    need_indicators; limited_view "containers, processes, files and configuration"
    step "Images and containers"; if [[ "${SCAN_CONTAINERS:-1}" == 1 ]]; then check_containers; else inf "skipped (SCAN_CONTAINERS=0)"; fi
    step "Consoles answering on this host"; check_consoles
    step "Processes"; check_processes
    step "Files and folders"; check_files
    step "Published hashes"; check_hashes
    step "AI clients wired to offensive tools"; check_ai_clients
    step "Accounts"; check_accounts
    step "Weaknesses the agents look for on this host"; check_gaps
    step "Verdict"
    if [[ $N_FIND -gt 0 ]]; then
        warn "${N_FIND} finding(s). A framework or its console nobody can account for is an intruder or an insider; a backdoored image or a published implant means the host is someone else's: keep the evidence, take it off the network and rebuild it."
        return 1
    fi
    if [[ $N_REVIEW -gt 0 ]]; then warn "${N_REVIEW} item(s) to look at (above): a framework here may be an authorized tester's. Find out who runs it. Then run 'hunt'."; return 1; fi
    info "No framework, console, published file or listed weakness was found on this host."
    return 0
}

# ---------- hunt -----------------------------------------------------------------
recent() { local p f; for p in "$@"; do for f in $p; do [[ -f "$f" ]] && find "$f" -maxdepth 0 -mtime "-${HUNT_DAYS}" 2>/dev/null; done; done | awk '!seen[$0]++'; }
# scan_lines <patterns file: conf TAB fw TAB kind TAB value> <label> < lines: classify each line once
scan_lines() {
    awk -F'\t' -v L="$2" 'NR == FNR { n++; conf[n] = $1; fw[n] = $2; kind[n] = $3; v[n] = tolower($4); next }
        { l = tolower($0); best = 0
          for (i = 1; i <= n; i++) if (index(l, v[i])) { r = (conf[i] == "high" ? 3 : conf[i] == "medium" ? 2 : 1); if (r > best) { best = r; b = i } }
          if (best) print conf[b] "\t" fw[b] "\t" kind[b] "\t" L "\t" $0 }' "$1" -
}
cmd_hunt() {
    [[ $# -eq 0 ]] || die "hunt takes no arguments"
    need_indicators; limited_view "logs, folders and processes"
    local pats hits f n_read=0 line conf fw kind where text n
    mk_tmp pats; mk_tmp hits
    # web requests: user agents, probe paths, header names, and source addresses at the start of the line
    { ioc user_agent | awk -F'\t' '{print $2 "\t" $1 "\tuser agent\t" $3}'
      ioc uri_string | awk -F'\t' '{print $2 "\t" $1 "\tprobe request\t" $3}'
      ioc http_header | awk -F'\t' '{print $2 "\t" $1 "\theader\t" $3 ":"}'
      ioc string high | awk -F'\t' 'length($3) >= 10 {print $2 "\t" $1 "\tmarker\t" $3}'
    } > "$pats"
    local access="${HUNT_LOG_FILES:-/var/log/apache2/*access*.log* /var/log/httpd/*access_log* /var/log/httpd/*access*.log* /var/log/nginx/*access*.log* /var/log/caddy/*.log*}"
    local ipmap; mk_tmp ipmap; ioc ipv4,ipv6 | awk -F'\t' '{print $3 "\t" $2 "\t" $1}' > "$ipmap"
    step "Web access logs (last ${HUNT_DAYS} days)"
    while IFS= read -r f; do
        n_read=$((n_read + 1))
        zcat -f "$f" 2>/dev/null | scan_lines "$pats" "${f##*/}" >> "$hits"
        # the client address is the first field of the common, combined and Caddy text formats
        zcat -f "$f" 2>/dev/null | awk -F'\t' -v L="${f##*/}" 'NR == FNR { c[$1] = $2; w[$1] = $3; next }
            { split($0, a, /[ ,]/); if (a[1] in c) print c[a[1]] "\t" w[a[1]] "\taddress\t" L "\t" $0 }' "$ipmap" - >> "$hits"
    done < <(recent $access)
    # system logs and the journal: addresses and domains
    { ioc ipv4,ipv6 medium | awk -F'\t' '{print $2 "\t" $1 "\taddress\t" $3}'
      ioc domain,url medium | awk -F'\t' '{v = $3; sub(/^[a-z]+:\/\//, "", v); print $2 "\t" $1 "\tdomain\t" v}'
    } > "$pats"
    local sys="${HUNT_SYS_LOG_FILES:-/var/log/auth.log* /var/log/secure* /var/log/syslog* /var/log/messages*}"
    while IFS= read -r f; do n_read=$((n_read + 1)); zcat -f "$f" 2>/dev/null | scan_lines "$pats" "${f##*/}" | awk -F'\t' '$3 != "address" || $5 ~ /[^0-9.]/' >> "$hits"; done < <(recent $sys)
    if have journalctl && [[ -z "${HUNT_SYS_LOG_FILES:-}" ]]; then n_read=$((n_read + 1)); journalctl --no-pager -q -o short-iso --since "-${HUNT_DAYS}d" 2>/dev/null | scan_lines "$pats" journal >> "$hits"; fi
    if [[ -s "$hits" ]]; then
        awk -F'\t' '{c[$1 " " $2 " " $3]++} END {for (k in c) print c[k] "\t" k}' "$hits" | sort -rn | head -n 20 | while IFS=$'\t' read -r c k; do inf "${k}: ${c} line(s)"; done
        while IFS=$'\t' read -r conf fw kind where text; do
            [[ "$conf" == low ]] && { N_WEAK=$((N_WEAK + 1)); continue; }
            judge "$conf" "${where}: ${fw} ${kind}: ${text:0:200}"
        done < <(awk -F'\t' '$1 != "low"' "$hits" | sort -u | head -n 40; awk -F'\t' '$1 == "low"' "$hits")
    else inf "nothing from the indicator list in the logs read"; fi

    step "Web folders"
    n=0
    while IFS=$'\t' read -r fw conf val; do
        [[ ${#val} -ge 5 && "$val" != *\\* ]] || continue
        local t=(-name "$val"); [[ "$val" == *- ]] && t=(-name "${val}*")
        while IFS= read -r f; do n=$((n + 1)); judge "$conf" "${f}: a file name ${fw} left ($(date -r "$f" '+%F %R' 2>/dev/null))"; done < <(files_under "$WEB_ROOTS" 8 "${t[@]}" | head -n 20)
    done < <(ioc file_name medium)
    local margs=() m; while IFS=$'\t' read -r _ _ m; do [[ ${#m} -ge 10 ]] && margs+=(-e "$m"); done < <(host_strings)
    if [[ ${#margs[@]} -gt 0 ]]; then
        while IFS= read -r f; do n=$((n + 1)); judge high "${f}: holds a framework marker string ($(grep -oF "${margs[@]}" "$f" 2>/dev/null | head -n1 | cut -c1-40))"; done \
            < <(files_under "$WEB_ROOTS" 8 -size -2M -print0 | timeout 300 xargs -0 -r grep -lF "${margs[@]}" 2>/dev/null | head -n 50)
    fi
    [[ $n -gt 0 ]] || inf "no framework file name or marker under ${WEB_ROOTS}"

    step "Shell histories, cron and systemd units"
    n=0
    local hp h hist=(); mk_tmp hp
    for h in $HOME_DIRS; do hist+=("$h/.bash_history" "$h/.zsh_history"); done
    { host_strings; ioc docker_image,domain medium; ioc file_name high; } | awk -F'\t' 'length($3) >= 6 {print $3}' | sort -u > "$hp"
    while IFS= read -r line; do n=$((n + 1)); judge medium "${line:0:220}"; done < <(
        regular_files /etc/crontab /etc/cron.d/* /var/spool/cron/* /var/spool/cron/crontabs/* /etc/systemd/system/*.service \
            /etc/systemd/system/*.timer "${hist[@]}" \
            | xargs -r -d '\n' timeout 60 grep -HiF -f "$hp" 2>/dev/null | head -n 30)
    [[ $n -gt 0 ]] || inf "nothing from the indicator list in histories, cron or units"

    step "Running now"
    n=0
    while IFS= read -r line; do n=$((n + 1)); judge medium "${line:0:220}"; done < <(ps -eo pid=,ppid=,comm=,args= 2>/dev/null | awk '
        { pid[$1] = $3; par[$1] = $2; line[$1] = $0 }
        END { for (p in pid) { c = pid[p]; q = pid[par[p]]
              if (c ~ /^(sh|bash|dash|zsh|curl|wget|nc|ncat|socat|python3?|perl)$/ && q ~ /^(nginx|apache2|httpd|php-fpm.*|php|java|node|mysqld|mariadbd|postgres|tomcat.*|uwsgi|gunicorn)$/)
                  print "started by " q ": " line[p] } }')
    if have ss; then
        local ips; mk_tmp ips; ioc ipv4,ipv6 medium | awk -F'\t' '{print $3 "\t" $1}' > "$ips"
        while IFS= read -r line; do
            a="$(awk '{print $6}' <<<"$line")"; a="${a%:*}"; a="${a#[}"; a="${a%]}"
            fw="$(awk -F'\t' -v a="$a" '$1 == a {print $2; exit}' "$ips")"
            [[ -n "$fw" ]] && { n=$((n + 1)); judge high "connection to ${a}, a published ${fw} address: ${line:0:160}"; }
        done < <(ss -tunpH 2>/dev/null)
    fi
    [[ $n -gt 0 ]] || inf "no shell under a web or database service, no connection to a published address"

    step "Verdict"
    [[ $N_WEAK -eq 0 ]] || inf "${N_WEAK} weak match(es) on low-confidence indicators shared with ordinary tools: counted, not acted on"
    if [[ $N_FIND -gt 0 || $N_REVIEW -gt 0 ]]; then
        warn "$((N_FIND + N_REVIEW)) lead(s). Keep the logs first. A request is reconnaissance; a shell, an implant or a new account is an incident: remove it, rotate every secret on the host, and report it (the FBI asks for ARTEX reports at ic3.gov)."
        return 1
    fi
    if [[ $n_read -eq 0 ]]; then warn "Nothing found, but no log could be read (set HUNT_LOG_FILES), so this is not a clean result."; return 2; fi
    info "Nothing from the indicator list was found. That does not prove these frameworks never reached this host."
    return 0
}

# ---------- list and export ---------------------------------------------------------
cmd_list() {
    need_indicators
    step "Indicators in ${INDICATORS_FILE}"
    ioc "account_name,docker_image,domain,favicon_mmh3,file_name,file_path,http_header,ipv4,ipv6,md5,port,sha256,string,uri_string,url,user_agent" \
        | awk -F'\t' '{split($1, f, " "); c[f[1] "\t" $2]++; t[f[1]]++} END {for (k in t) print t[k] "\t" k}' | sort -rn | while IFS=$'\t' read -r c fw; do inf "${fw}: ${c}"; done
    inf "types: $(awk -F'\t' '!/^#/ && NF >= 4 {c[$2]++} END {for (k in c) printf "%s %d, ", k, c[k]}' "$INDICATORS_FILE" | sed 's/, $//')"
}
cmd_export() {
    need_indicators
    local what="${1:-}" min=medium; shift || true
    [[ "${1:-}" == --min ]] && { min="${2:-}"; [[ "$min" =~ ^(high|medium|low)$ ]] || die "--min takes high, medium or low"; }
    case "$what" in
        ips) ioc ipv4,ipv6 "$min" ;;
        domains) ioc domain,url "$min" ;;
        user-agents) ioc user_agent "$min" ;;
        hashes) ioc sha256,md5 "$min" ;;
        images) ioc docker_image "$min" ;;
        strings) ioc string "$min" ;;
        *) die "export takes ips, domains, user-agents, hashes, images or strings" ;;
    esac | cut -f3 | sort -u
}

main() {
    local CMD="${1:-check}"; [[ $# -gt 0 ]] && shift
    case "$CMD" in -V|--version|version) echo "${SCRIPT_NAME} ${SCRIPT_VERSION} (${SCRIPT_DATE})"; exit 0 ;; esac
    case "$CMD" in -h|--help|help) awk 'f && /^# =+$/ {exit} f {sub(/^# ?/,""); print} /^# =+$/ {f=1}' "$SELF"; exit 0 ;; esac
    if [[ "$CMD" == export ]]; then cmd_export "$@"; exit; fi
    echo "${SCRIPT_NAME} ${SCRIPT_VERSION} (${SCRIPT_DATE}) - ${CMD} on $(hostname 2>/dev/null || echo '?') at $(date -u +%FT%TZ)"
    echo "AI-driven attack frameworks: ARTEX, CAIRN, CyberStrikeAI, HexStrike AI, PentAGI and others (no CVE)"
    case "$CMD" in
        check) cmd_check "$@" ;;
        hunt) cmd_hunt "$@" ;;
        list) cmd_list "$@" ;;
        *) die "Unknown command: ${CMD} (check|hunt|list|export|version)" ;;
    esac
}
main "$@"; exit

# Assisted-by: Claude Opus 5.5
