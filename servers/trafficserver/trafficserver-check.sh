#!/usr/bin/env bash
# SPDX-License-Identifier: CC0-1.0
# =============================================================================
# Apache Traffic Server experimental plugins, October 2026: read-only checker  (v1)
# CVE-2026-111813 (magick plugin, CVSS 10.0)
# CVE-2026-111811 (tsmemcache plugin, CVSS 9.0)
#
# If this software is helpful, consider a donation to our 501c3 nonprofit:
# https://privacysafe.foundation
#
# Apache Traffic Server (ATS) is a caching reverse and forward proxy used in front
# of large sites and CDNs. The October 2026 release fixes 15 vulnerabilities. Two of
# them sit in EXPERIMENTAL plugins and are the severe ones:
#
# CVE-2026-111813  The magick plugin passes client query strings unfiltered to
#                  ImageMagick's convert in its default (unsigned) configuration,
#                  so an unauthenticated client controls convert's arguments:
#                  command injection / argument injection. CVSS 10.0, critical.
# CVE-2026-111811  The tsmemcache plugin exposes the shared proxy cache over the
#                  network with no authentication: unauthenticated read, write and
#                  deletion of the cache. CVSS 9.0 by Apache's rating (Moderate on
#                  their scale), listed as 9.4 Critical by some aggregators.
#
#   Affected: 8.0.0 through 8.1.11, 9.0.0 through 9.2.15, 10.0.0 through 10.1.4, 10.2.0
#             (the magick plugin from 8.0.1)
#   Fixed:    9.2.16, 10.1.5 and 10.2.1 (released 20 October 2026)
#   Move to:  a fixed branch. 8.x, 9.0, 9.1 and 10.0 are end of life branches
#
# Both flaws only matter when the plugin is LOADED. The script therefore reads the
# configuration (plugin.config and the remap files) for magick.so and tsmemcache.so
# rather than looking for files: the plugins are experimental, are not enabled by
# default, and a magick.so on disk can just as well be an ImageMagick coder.
#
# The same release fixes thirteen other flaws (request smuggling, cache poisoning,
# denial of service) that only the update fixes.
#
# This script is read-only. It finds traffic_server (PATH, usual locations and running
# processes), reads its version from "traffic_server -V", reads the configuration
# directory, and checks the owning package's changelog for a backported fix.
#
# Usage:
#   ./trafficserver-check.sh [command] [PATH-TO-traffic_server ...]
#
#   check (default)  Exit 0 = nothing exposed, 1 = an affected version loads one of
#                    the two plugins, or its configuration could not be read.
#   version          print the script version.
#
# Environment: ATS_CONFIG_DIR (space separated directories) replaces config discovery.
# Containers: with no argument the check also looks in running docker and podman containers
# (SCAN_CONTAINERS=1, the default; 0 skips them). A read-only probe captures the output of
# traffic_server -V and the configuration files with every line that does not load magick.so or
# tsmemcache.so blanked inside the container (so credentials never leave it, and line numbers stay
# exact) into a private temporary directory, and this script then runs once per container in
# isolation against that copy. Paths shown as .../docker_NAME/... are inside the container NAME.
# =============================================================================

# Commands run as "cmd_${CMD}", which shellcheck can't follow
# shellcheck disable=SC2317,SC2329
set -uo pipefail

SCRIPT_NAME="trafficserver-check.sh"
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


# distro_mentions FILE CVE...
# Distributions often backport a fix without changing the upstream version
# string. This looks at the changelog of the package that owns FILE.
#   return 0: changelog mentions one of the CVE ids (DISTRO_HIT, DISTRO_PKG set)
#   return 1: FILE is package-managed but the changelog does not mention them
#   return 2: FILE is not owned by a dpkg or rpm package
DISTRO_PKG=""; DISTRO_HIT=""
distro_mentions() {
    local f real pkg="" cl="" c id
    f="$1"; shift
    real="$(readlink -f "$f" 2>/dev/null || echo "$f")"
    if have dpkg; then
        pkg="$(dpkg -S "$real" 2>/dev/null | head -n1 | cut -d: -f1)"
        if [[ -n "$pkg" ]]; then
            for c in "/usr/share/doc/${pkg}/changelog.Debian.gz" "/usr/share/doc/${pkg}/changelog.gz"; do
                [[ -r "$c" ]] && cl+="$(zcat "$c" 2>/dev/null)"
            done
        fi
    fi
    if [[ -z "$pkg" ]] && have rpm; then
        pkg="$(rpm -qf "$real" 2>/dev/null | head -n1)"
        [[ "$pkg" == *"not owned"* ]] && pkg=""
        [[ -n "$pkg" ]] && cl="$(rpm -q --changelog "$pkg" 2>/dev/null)"
    fi
    [[ -n "$pkg" ]] || return 2
    DISTRO_PKG="$pkg"
    for id in "$@"; do
        if grep -qF "$id" <<<"$cl"; then DISTRO_HIT="$id"; return 0; fi
    done
    return 1
}

# Print the help text: everything between the first two ===== lines of this file.
print_help() { awk 'f && /^# =+$/ {exit} f {sub(/^# ?/,""); print} /^# =+$/ {f=1}' "$SELF"; }

# ---------- version rule -----------------------------------------------------
# prints: vulnerable | eol | fixed | outside | unknown
ats_status() {
    local v="$1" maj min pat
    [[ "$v" =~ ^([0-9]+)\.([0-9]+)\.([0-9]+) ]] || { echo unknown; return; }
    maj="${BASH_REMATCH[1]}"; min="${BASH_REMATCH[2]}"; pat="${BASH_REMATCH[3]}"
    (( maj < 8 )) && { echo outside; return; }
    (( maj == 8 )) && { echo eol; return; }
    if (( maj == 9 )); then
        (( min < 2 )) && { echo eol; return; }
        (( min == 2 )) && { (( pat < 16 )) && echo vulnerable || echo fixed; return; }
        echo fixed; return
    fi
    if (( maj == 10 )); then
        (( min == 0 )) && { echo eol; return; }
        (( min == 1 )) && { (( pat < 5 )) && echo vulnerable || echo fixed; return; }
        (( min == 2 )) && { (( pat < 1 )) && echo vulnerable || echo fixed; return; }
        echo fixed; return
    fi
    echo fixed
}

bin_version() {
    timeout 15 "$1" -V 2>&1 | grep -oE 'traffic_server - [0-9]+\.[0-9]+\.[0-9]+' | head -n1 | sed 's/^traffic_server - //'
}

discover_bins() {
    local -a out=()
    local b pid exe
    for b in "$(command -v traffic_server 2>/dev/null)" /usr/bin/traffic_server /usr/local/bin/traffic_server /opt/ts/bin/traffic_server /opt/trafficserver/bin/traffic_server; do
        [[ -n "$b" && -x "$b" && -f "$b" ]] && out+=("$(readlink -f "$b")")
    done
    if have ps; then
        while read -r pid; do
            exe="$(readlink "/proc/${pid}/exe" 2>/dev/null)"
            [[ -n "$exe" && "$exe" != *"(deleted)" && -x "$exe" ]] && out+=("$exe")
        done < <(ps -eo pid=,comm= 2>/dev/null | awk '$2=="traffic_server"{print $1}')
    fi
    [[ ${#out[@]} -gt 0 ]] || return 0
    printf '%s\n' "${out[@]}" | awk 'NF && !seen[$0]++'
}

config_dirs() {
    local d
    if [[ -n "${ATS_CONFIG_DIR:-}" ]]; then for d in $ATS_CONFIG_DIR; do [[ -d "$d" ]] && echo "$d"; done; return 0; fi
    for d in /etc/trafficserver /usr/local/etc/trafficserver /opt/ts/etc/trafficserver /opt/trafficserver/etc/trafficserver; do
        [[ -d "$d" ]] && echo "$d"
    done
}

# lines that load a plugin by name; comments are ignored. Prints  file:line:plugin
PLUGIN_HITS=""
scan_plugins() {   # config dir
    local dir="$1" f out
    for f in "$dir"/plugin.config "$dir"/remap.config "$dir"/remap.yaml "$dir"/plugin.yaml "$dir"/*.config "$dir"/*.yaml; do
        [[ -r "$f" && -f "$f" ]] || continue
        case " ${SEEN_F:-} " in *" $f "*) continue ;; esac
        SEEN_F="${SEEN_F:-} $f"
        out="$(sed -E 's/^[[:space:]]*#.*$//' "$f" | grep -nE '(^|[[:space:]=@/"'"'"'-])(magick|tsmemcache)\.so([[:space:]"'"'"']|$)' | sed -E 's/^([0-9]+):.*(magick|tsmemcache)\.so.*/\1:\2/' )"
        [[ -n "$out" ]] && PLUGIN_HITS+="$(sed "s#^#${f}:#" <<<"$out")"$'\n'
    done
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
#   L <path> <text>   write one short sanitized line of text
#   B <path> <base64> write a decoded blob (size-capped): captured command output, or a configuration
#                     file with its secrets already redacted INSIDE the container
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
                    B) [[ ${#rest} -le 200000 && "$rest" != *[!A-Za-z0-9+/=]* ]] || continue
                       mkdir -p "$s$(dirname "$p")"
                       printf '%s' "$rest" | base64 -d > "$s$p" 2>/dev/null || rm -f "$s$p" ;;
                esac
            done <<<"$out"
            [[ -z "$s" ]] || STAGED_DIRS+=("$s")
        done < <("$rt" ps --format '{{.ID}} {{.Names}}' 2>/dev/null)
    done
}

ATS_PROBE="$(cat <<'EOS'
n=""
for c in /usr/bin/traffic_server /usr/local/bin/traffic_server /opt/ts/bin/traffic_server /opt/trafficserver/bin/traffic_server; do [ -x "$c" ] && [ -f "$c" ] && { n=$c; break; }; done
[ -n "$n" ] || exit 0
echo "B /.out_V $("$n" -V 2>&1 | head -n 5 | base64 | tr -d '\n')"
for d in /etc/trafficserver /usr/local/etc/trafficserver /opt/ts/etc/trafficserver /opt/trafficserver/etc/trafficserver; do
  [ -d "$d" ] || continue
  echo "D $d"
  for f in "$d"/*.config "$d"/*.yaml; do
    [ -f "$f" ] && [ "$(wc -c < "$f")" -lt 512000 ] && echo "B $f $(awk '/magick\.so|tsmemcache\.so/ {print; next} {print ""}' "$f" | base64 | tr -d '\n')"
  done
done
exit 0
EOS
)"

container_run() {   # <staged directory> : Traffic Server in one container, judged by this script run in isolation
    local s="$1" out rc
    [[ -s "$s/.out_V" ]] || return 0
    printf '#!/bin/sh\ncase "$1" in\n  -V) cat "%s/.out_V" ;;\nesac\n' "$s" > "$s/traffic_server"; chmod 755 "$s/traffic_server"
    step "Apache Traffic Server in a container (${s##*/})"
    out="$(SCAN_CONTAINERS=0 ATS_CONFIG_DIR="$s/etc/trafficserver $s/usr/local/etc/trafficserver $s/opt/ts/etc/trafficserver $s/opt/trafficserver/etc/trafficserver" bash "$SELF" check "$s/traffic_server" 2>&1)"; rc=$?
    tail -n +3 <<<"$out"
    return "$rc"
}

# shellcheck disable=SC2120
cmd_check() {
    local rc=0 crc=0 _s
    if [[ $# -eq 0 && "${SCAN_CONTAINERS:-1}" == 1 ]]; then
        stage_probe "$ATS_PROBE"
        for _s in ${STAGED_DIRS[@]:+"${STAGED_DIRS[@]}"}; do
            container_run "$_s" || crc=1
        done
    fi
    cmd_check_host "$@" || rc=$?
    if [[ $crc -eq 1 && $rc -eq 0 ]]; then rc=1; fi
    return "$rc"
}

cmd_check_host() {
    local -a bins=()
    local rc=0 found=0 b ver st d read_any hit pl magick tsm
    if [[ $# -gt 0 ]]; then bins=("$@")
    else while IFS= read -r b; do [[ -n "$b" ]] && bins+=("$b"); done < <(discover_bins); fi
    step "Looking for Apache Traffic Server"
    if [[ ${#bins[@]} -eq 0 ]]; then info "No traffic_server found on this host"; return 0; fi
    for b in "${bins[@]}"; do
        [[ -x "$b" ]] || { caution "${b}: not an executable file"; continue; }
        ver="$(bin_version "$b")"
        [[ -n "$ver" ]] || { caution "${b}: could not read a version from -V; treating it as not confirmed fixed"; rc=1; found=$((found+1)); continue; }
        found=$((found+1))
        step "Apache Traffic Server ${ver} at ${b}"
        st="$(ats_status "$ver")"
        case "$st" in
            fixed)   ok "Traffic Server ${ver} has the fix (9.2.16, 10.1.5, 10.2.1 or newer)"; continue ;;
            outside) caution "Traffic Server ${ver} is older than 8.0: outside the stated range of this CVE, but long end of life and not confirmed clear of other issues: update regardless"; rc=1; continue ;;
            unknown) caution "cannot parse version '${ver}'; treating it as not confirmed fixed"; rc=1; continue ;;
            eol)     bad "Traffic Server ${ver} is on an end-of-life branch (8.x, 9.0, 9.1 or 10.0): in the affected range and Apache will not patch it. Move to 9.2.16, 10.1.5 or 10.2.1 or newer." ;;
            vulnerable) bad "Traffic Server ${ver} is in the affected range (fixed in 9.2.16, 10.1.5 and 10.2.1)" ;;
        esac
        if distro_mentions "$b" CVE-2026-111813 CVE-2026-111811; then
            ok "package ${DISTRO_PKG} changelog mentions ${DISTRO_HIT}: the distribution has probably backported the fix"
            continue
        elif [[ $? -eq 1 ]]; then
            inf "package ${DISTRO_PKG} owns this binary and its changelog does not mention either CVE yet"
        fi
        PLUGIN_HITS=""; SEEN_F=""; read_any=0
        while IFS= read -r d; do
            [[ -n "$d" ]] || continue
            read_any=1; scan_plugins "$d"; inf "read ${d}"
        done < <(config_dirs)
        if [[ $read_any -eq 0 ]]; then
            caution "no readable Traffic Server configuration directory found: plugin use cannot be checked, treating as exposed (set ATS_CONFIG_DIR to point at it)"
            rc=1; continue
        fi
        magick=0; tsm=0
        while IFS= read -r hit; do
            [[ -n "$hit" ]] || continue
            pl="${hit##*:}"
            [[ "$pl" == magick ]] && magick=1
            [[ "$pl" == tsmemcache ]] && tsm=1
        done <<<"$PLUGIN_HITS"
        if [[ $magick -eq 1 ]]; then
            bad "the experimental magick plugin is LOADED (CVE-2026-111813, CVSS 10: unauthenticated clients control ImageMagick convert arguments), at:"
            grep -E ':magick$' <<<"$PLUGIN_HITS" | sed -E 's/:magick$//; s/^/        /' | head -n4; rc=1
        fi
        if [[ $tsm -eq 1 ]]; then
            bad "the experimental tsmemcache plugin is LOADED (CVE-2026-111811: unauthenticated network read, write and deletion of the shared cache), at:"
            grep -E ':tsmemcache$' <<<"$PLUGIN_HITS" | sed -E 's/:tsmemcache$//; s/^/        /' | head -n4; rc=1
        fi
        if [[ $magick -eq 0 && $tsm -eq 0 ]]; then
            ok "neither the magick nor the tsmemcache plugin is loaded in the configuration read: these two flaws are not reachable here"
            caution "update anyway: the same release fixes thirteen other flaws (request smuggling, cache poisoning, denial of service) that only the update fixes"
        fi
        [[ "$st" == eol && $magick -eq 0 && $tsm -eq 0 ]] && inf "an end-of-life branch has no upstream fix for those other flaws: plan the move to a supported branch"
    done
    step "Verdict"
    if [[ $found -eq 0 ]]; then
        info "No Traffic Server version could be read"
    elif [[ $rc -eq 0 ]]; then
        info "No exposed Traffic Server found (${found} checked). An affected version without these two plugins still needs the update."
    else
        warn "Exposed or unverifiable Traffic Server found. Upgrade to 9.2.16, 10.1.5 or 10.2.1 (or a distribution build that carries the fix)."
        inf "PrivacySafe recommendation: remove magick.so and tsmemcache.so from plugin.config and the remap files and restart Traffic Server; neither plugin is enabled by default and both are experimental."
        inf "Advisory: https://trafficserver.apache.org/security-2026-10.html"
    fi
    return "$rc"
}

# ---------- dispatch ---------------------------------------------------------
main() {
    CMD="${1:-check}"; [[ $# -gt 0 ]] && shift
    case "$CMD" in -V|--version|version) echo "${SCRIPT_NAME} ${SCRIPT_VERSION} (${SCRIPT_DATE})"; exit 0 ;; esac
    case "$CMD" in -h|--help|help) print_help; exit 0 ;; esac
    echo "${SCRIPT_NAME} ${SCRIPT_VERSION} (${SCRIPT_DATE}) - ${CMD} on $(hostname 2>/dev/null || echo '?') at $(date -u +%FT%TZ)"
    echo "CVE-2026-111813 and CVE-2026-111811; fixed in Apache Traffic Server 9.2.16, 10.1.5 and 10.2.1"
    case "$CMD" in
        check) cmd_check "$@" ;;
        *) die "Unknown command: ${CMD} (check|version)" ;;
    esac
}
main "$@"; exit

# Assisted-by: Claude Sonnet 5.5
